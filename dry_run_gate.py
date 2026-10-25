#!/usr/bin/env python3
"""dry-run-gate: prove in CI that a skill's --dry-run makes no outbound
connection, starts no process and leaks no secret.

One file, standard library only, Python 3.9+, Linux and macOS.
README.md documents the frontmatter convention, the checks and the limits.
"""
from __future__ import annotations

import argparse
import ast
import binascii
import contextlib
import glob
import io
import ipaddress
import json
import math
import os
import re
import runpy
import secrets
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import warnings
import weakref

try:
    import fcntl
except ImportError:  # Windows is out of scope (D3)
    fcntl = None

__version__ = "0.1.0"
GATE_PATH = os.path.abspath(__file__)

EXIT_OK, EXIT_FAIL, EXIT_CONFIG, EXIT_ISOLATION = 0, 1, 2, 3
PASS, FAIL, WARN, UNVERIFIED, SKIP = "PASS", "FAIL", "WARN", "UNVERIFIED", "SKIP"

TAGS = {
    "spend": "paid usage",
    "social": "social posts",
    "email": "email sends",
    "sms": "SMS sends",
    "message": "chat sends (Signal, Slack, Discord)",
    "publish": "deploys, CMS posts, releases, git push",
    "remote-write": "creating or changing remote records",
    "delete": "destructive remote operations",
}
GATE_KEYS = ("side-effects", "writes", "dry-run", "dry-run-args", "dry-run-test", "dry-run-secrets")
AGENT_CONFIRM = "agent-confirm"
CANARY_PREFIX = "dryrungate-canary-"
CHILD_ENV_COPIED = ("PATH", "LANG", "LC_ALL", "LC_CTYPE")
CHILD_ENV_SET = ("HOME", "TMPDIR", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "PYTHONPATH")
NETNS_MARKER = "netns"      # file in the per-run temp dir that tells the guard it runs under unshare
GUARD_LOG_FAILED = 70       # child exit code when the guard cannot write its log
PREVIEW_LINES = 40

TOP_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+:")
META_LINE_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(.*)$")
SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HEADING_RE = re.compile(r"^#{1,6}(\s|$)")
B64_RUN_RE = re.compile(rb"[A-Za-z0-9+/=_-]{16,}")
URLSAFE_TO_STD = bytes.maketrans(b"-_", b"+/")


class GateError(Exception):
    """Ends the run before any check: exit 2 (usage, discovery) or 3 (isolation)."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class ConfigError(Exception):
    """A frontmatter or config rule violation in one SKILL.md (P0, exit 2)."""


# ---------------------------------------------------------------- parsing

def split_frontmatter(text):
    """Return (frontmatter lines, body lines). Lines are split on \\n with one trailing \\r dropped."""
    lines = [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]
    if lines[0] != "---":
        raise ConfigError("SKILL.md must start with a line that is exactly '---'")
    for i in range(1, len(lines)):
        if lines[i] == "---":
            return lines[1:i], lines[i + 1:]
    raise ConfigError("frontmatter has no closing '---' line")


def plain_value(raw, lineno, key):
    """Unquote a metadata value; reject anything a YAML parser would read differently."""
    value = raw.strip()
    if not value:
        return ""
    quote = value[0]
    if quote in "\"'":
        if len(value) < 2 or value[-1] != quote:
            raise ConfigError(f"line {lineno}: {key}: unmatched {quote} quote")
        inner = value[1:-1]
        if quote in inner or (quote == '"' and "\\" in inner):
            raise ConfigError(f"line {lineno}: {key}: quotes or backslashes inside a quoted value are not supported")
        return inner
    if (value[0] in ",[]{}#&*!|>%@`" or value[:2] in ("- ", "? ", ": ") or value in ("-", "?", ":")
            or " #" in value or "\t#" in value or ": " in value or value.endswith(":")):
        raise ConfigError(f"line {lineno}: {key}: value must be a plain string (no YAML syntax or comments); quote it")
    return value


def parse_frontmatter(lines):
    """Return (display name or None, metadata dict of key -> string)."""
    name, name_multiline = None, False
    meta = None
    current = None
    for i, line in enumerate(lines):
        lineno = i + 2  # line 1 is the opening ---
        match = TOP_KEY_RE.match(line)
        if match:
            key = match.group(0)[:-1]
            rest = line[match.end():].strip()
            if key in GATE_KEYS:
                raise ConfigError(f"line {lineno}: {key} must sit under metadata, not at top level")
            if (key == "name" and name is not None) or (key == "metadata" and meta is not None):
                raise ConfigError(f"line {lineno}: duplicate top-level key {key}")
            current = key
            if key == "metadata":
                if rest and not rest.startswith("#"):
                    raise ConfigError(f"line {lineno}: metadata must be a block of '  key: value' lines")
                meta = {}
            elif key == "name":
                name = rest
            continue
        stripped = line.strip()
        if current == "metadata":
            if not stripped or stripped.startswith("#"):
                continue
            mline = META_LINE_RE.match(line)
            if not mline:
                raise ConfigError(f"line {lineno}: lines under metadata must be '  key: value' (exactly two spaces)")
            key = mline.group(1)
            if key in meta:
                raise ConfigError(f"line {lineno}: duplicate metadata key {key}")
            meta[key] = plain_value(mline.group(2), lineno, key)
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if line[0] in " \t":
            if current is None:
                raise ConfigError(f"line {lineno}: indented line before the first top-level key")
            if current == "name":
                name_multiline = True
            continue
        raise ConfigError(f"line {lineno}: expected a top-level 'key:' line")
    if name is not None:
        if name_multiline or not name or name[0] in "|>":
            name = None
        elif len(name) >= 2 and name[0] == name[-1] and name[0] in "\"'":
            name = name[1:-1]
    return name, (meta or {})


def split_words(value):
    return [word for word in re.split(r"[\s,]+", value) if word]


class Skill:
    """One discovered skill dir and its gate config."""

    def __init__(self, path, root):
        self.path = path                        # as shown in the report
        self.dir = os.path.abspath(path)
        self.root = root                        # absolute PATH argument it was found under
        self.name = os.path.basename(self.dir)
        self.tags = []
        self.entry = ""                         # metadata dry-run value
        self.args = []
        self.test = ""
        self.secrets = []
        self.body = []
        self.error = None                       # config error message (exit 2)

    @property
    def tagged(self):
        return bool(self.tags)

    @property
    def agent_confirm(self):
        return self.entry == AGENT_CONFIRM


def apply_config(skill, meta):
    if "writes" in meta and "side-effects" in meta:
        raise ConfigError("metadata has both writes (legacy) and side-effects; keep side-effects")
    words = split_words(meta.get("side-effects", meta.get("writes", "")))
    unknown = [word for word in words if word != "none" and word not in TAGS]
    if unknown:
        raise ConfigError(f"unknown side-effects tag(s) {', '.join(unknown)}; allowed: none, {', '.join(TAGS)}")
    tags = list(dict.fromkeys(word for word in words if word != "none"))
    if tags and "none" in words:
        raise ConfigError("side-effects: none cannot be combined with other tags")
    try:
        args = shlex.split(meta.get("dry-run-args", ""))
    except ValueError as exc:
        raise ConfigError(f"dry-run-args: {exc}")
    names = split_words(meta.get("dry-run-secrets", ""))
    for secret in names:
        if not SECRET_NAME_RE.match(secret):
            raise ConfigError(f"dry-run-secrets: {secret!r} is not an environment variable name")
        if secret in CHILD_ENV_COPIED + CHILD_ENV_SET:
            raise ConfigError(f"dry-run-secrets: {secret} is set by the gate itself")
    skill.tags = tags
    skill.entry = meta.get("dry-run", "").strip()
    skill.args = args
    skill.test = meta.get("dry-run-test", "").strip()
    skill.secrets = list(dict.fromkeys(names))


def load_skill(path, root):
    skill = Skill(path, root)
    try:
        try:
            with open(os.path.join(skill.dir, "SKILL.md"), "rb") as fh:
                text = fh.read().decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ConfigError(f"cannot read SKILL.md as UTF-8: {exc}")
        frontmatter, skill.body = split_frontmatter(text)
        name, meta = parse_frontmatter(frontmatter)
        apply_config(skill, meta)
        if name:
            skill.name = name
    except ConfigError as exc:
        skill.error = str(exc)
    return skill


def discover(paths):
    """Return [(skill dir as shown, absolute PATH argument)] for PATH/SKILL.md and PATH/skills/*/SKILL.md."""
    found, seen = [], set()
    for path in paths:
        if not os.path.exists(path):
            raise GateError(EXIT_CONFIG, f"{path}: no such path")
        dirs = []
        if os.path.isfile(os.path.join(path, "SKILL.md")):
            dirs.append(path)
        pattern = os.path.join(glob.escape(path), "skills", "*", "SKILL.md")
        dirs += [os.path.dirname(f) for f in sorted(glob.glob(pattern)) if os.path.isfile(f)]
        if not dirs:
            raise GateError(EXIT_CONFIG, f"{path}: no SKILL.md at PATH/SKILL.md or PATH/skills/*/SKILL.md")
        for skill_dir in dirs:
            key = os.path.realpath(skill_dir)
            if key not in seen:
                seen.add(key)
                found.append((os.path.normpath(skill_dir), os.path.abspath(path)))
    return found


# ---------------------------------------------------------------- static checks

class Check:
    __slots__ = ("id", "status", "detail", "output")

    def __init__(self, cid, status, detail="", output=None):
        self.id, self.status, self.detail, self.output = cid, status, detail, output or []

    def as_json(self):
        return {"id": self.id, "status": self.status, "detail": self.detail}


def python_files(root):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        files += [os.path.join(dirpath, f) for f in sorted(filenames) if f.endswith(".py")]
    return files


def parse_ast(path):
    """Return (tree, None) or (None, reason)."""
    try:
        with open(path, "rb") as fh:
            source = fh.read()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(source, filename=path), None
    except SyntaxError as exc:
        return None, f"line {exc.lineno}: {exc.msg}"
    except Exception as exc:  # unreadable, null bytes, recursion: all fail closed
        return None, f"{type(exc).__name__}: {exc}"


def has_dry_run_constant(tree):
    return any(isinstance(node, ast.Constant) and node.value == "--dry-run" for node in ast.walk(tree))


def check_p1(skill):
    files = python_files(skill.dir)
    bad = []
    for path in files:
        rel = os.path.relpath(path, skill.dir)
        try:
            with open(path, "rb") as fh:
                source = fh.read()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                compile(source, path, "exec", dont_inherit=True)
        except SyntaxError as exc:
            bad.append(f"{rel}:{exc.lineno}: {exc.msg}")
        except Exception as exc:
            bad.append(f"{rel}: {type(exc).__name__}: {exc}")
    if bad:
        return Check("P1", FAIL, "; ".join(bad))
    return Check("P1", PASS, f"{len(files)} Python file(s) compile")


def _script_check(cid, skill, rel, what):
    """Shared S1/S2 body: rel must be a relative path to a file whose AST has the "--dry-run" constant."""
    if os.path.isabs(rel):
        return Check(cid, FAIL, f"{rel}: {what} must be relative to the skill dir")
    path = os.path.join(skill.dir, rel)
    if not os.path.isfile(path):
        return Check(cid, FAIL, f"{rel}: {what} not found")
    tree, reason = parse_ast(path)
    if tree is None:
        return Check(cid, FAIL, f"{rel}: cannot parse ({reason})")
    if not has_dry_run_constant(tree):
        return Check(cid, FAIL, f'{rel}: no "--dry-run" string constant (comments do not count)')
    return Check(cid, PASS, f'{rel} has a "--dry-run" string constant')


def check_s1(skill):
    if not skill.entry.endswith(".py"):
        return Check("S1", FAIL, f"{skill.entry}: entry script must be a .py file")
    return _script_check("S1", skill, skill.entry, "entry script")


def check_s2(skill):
    if not skill.test:
        return Check("S2", FAIL, "path entry has no metadata dry-run-test")
    return _script_check("S2", skill, skill.test, "dry-run-test")


def has_dry_run_section(body):
    for i, line in enumerate(body):
        if line.rstrip().lower() != "## dry run":
            continue
        for following in body[i + 1:]:
            if HEADING_RE.match(following):
                break
            if following.strip():
                return True
    return False


def check_a1(skill):
    if has_dry_run_section(skill.body):
        return Check("A1", UNVERIFIED, "agent-confirm: instruction-only dry run under '## Dry run', not executed (D8)")
    return Check("A1", FAIL, "agent-confirm needs a '## Dry run' heading followed by at least one non-blank line")


H1_SEND_MODULES = ("smtplib", "twilio", "tweepy")
H1_HTTP_MODULES = ("requests", "httpx", "aiohttp", "urllib3")
H1_HTTP_METHODS = ("post", "put", "patch", "delete", "request")
H1_WRITE_VERBS = ("POST", "PUT", "PATCH", "DELETE")


def _dotted(node):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def h1_hits(tree):
    """Return sorted [(line, description)] of write-capable patterns in an AST."""
    hits, http_calls, imports_http = [], [], False
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom):
                modules = [node.module] if node.level == 0 and node.module else []
            else:
                modules = [alias.name for alias in node.names]
            for module in modules:
                top = module.split(".")[0]
                if top in H1_SEND_MODULES:
                    hits.append((node.lineno, f"import {module}"))
                if top in H1_HTTP_MODULES:
                    imports_http = True
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in H1_HTTP_METHODS:
                http_calls.append((node.lineno, f".{func.attr}() call with an HTTP client imported"))
            name = _dotted(func)
            keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            if name in ("urlopen", "urllib.request.urlopen") and (len(node.args) >= 2 or "data" in keywords):
                hits.append((node.lineno, f"{name}() with data"))
            if name in ("Request", "urllib.request.Request"):
                method = keywords.get("method")
                if "data" in keywords:
                    hits.append((node.lineno, f"{name}() with data"))
                elif isinstance(method, ast.Constant) and method.value in H1_WRITE_VERBS:
                    hits.append((node.lineno, f"{name}(method={method.value!r})"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for phrase in ("git push", "gh release"):
                if phrase in node.value:
                    hits.append((node.lineno, f"string containing {phrase!r}"))
        elif isinstance(node, (ast.List, ast.Tuple)) and len(node.elts) >= 2:
            first = node.elts[:2]
            if all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in first):
                pair = (first[0].value, first[1].value)
                if pair in (("git", "push"), ("gh", "release")):
                    hits.append((node.lineno, f"argv starting {pair[0]!r}, {pair[1]!r}"))
    if imports_http:
        hits += http_calls
    return sorted(set(hits))


def check_h1(skill):
    checks = []
    for path in python_files(skill.dir):
        tree, _ = parse_ast(path)
        if tree is None:
            continue  # P1 already reports it
        hits = h1_hits(tree)
        if hits:
            rel = os.path.relpath(path, skill.dir)
            checks.append(Check("H1", WARN, f"{rel}: " + "; ".join(f"L{line} {what}" for line, what in hits)))
    return checks or [Check("H1", PASS, "no write-capable code found")]


# ---------------------------------------------------------------- canary

def _base64_decodings(token):
    """Decode a base64-looking run every way a careless print could have produced it."""
    seen = set()
    for piece in [token] + token.split(b"="):
        for offset in range(4):
            core = piece[offset:].rstrip(b"=")
            for alphabet in (core, core.translate(URLSAFE_TO_STD)):
                for candidate in (alphabet + b"=" * (-len(alphabet) % 4), alphabet[:len(alphabet) // 4 * 4]):
                    if not candidate or candidate in seen:
                        continue
                    seen.add(candidate)
                    try:
                        yield binascii.a2b_base64(candidate)
                    except (binascii.Error, ValueError):
                        pass


def find_canaries(data, canaries):
    """Return [(secret name, "literal" | "base64")] for canaries present in data (bytes)."""
    found = []
    wanted = {name: value.encode("ascii") for name, value in canaries.items()}
    for name, value in wanted.items():
        if value in data:
            found.append((name, "literal"))
    remaining = [name for name in wanted if name not in {n for n, _ in found}]
    for match in B64_RUN_RE.finditer(data) if remaining else ():
        for decoded in _base64_decodings(match.group(0)):
            for name in list(remaining):
                if wanted[name] in decoded:
                    found.append((name, "base64"))
                    remaining.remove(name)
        if not remaining:
            break
    return found


# ---------------------------------------------------------------- running the child

class RunResult:
    def __init__(self):
        self.returncode = None
        self.timed_out = False
        self.stdout = b""
        self.stderr = b""
        self.blocked = []
        self.notes = []
        self.log_error = None
        self.leaks = []         # [(secret name, stream, how)]


def import_path(skill):
    entries = [skill.dir]
    if os.path.isdir(os.path.join(skill.dir, "scripts")):
        entries.append(os.path.join(skill.dir, "scripts"))
    entries.append(skill.root)
    if os.path.isdir(os.path.join(skill.root, "scripts")):
        entries.append(os.path.join(skill.root, "scripts"))
    return entries


def child_env(skill, home, tmpdir, canaries):
    env = {name: os.environ[name] for name in CHILD_ENV_COPIED if name in os.environ}
    env.update({
        "HOME": home,
        "TMPDIR": tmpdir,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": os.pathsep.join(import_path(skill)),
    })
    env.update(canaries)
    return env


def read_guard_log(path):
    """Return (blocked, notes, error). Any unreadable line or a missing log is an error (fail closed)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return [], [], "guard log missing"
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    blocked, notes = [], []
    for lineno, raw in enumerate(lines, 1):
        try:
            record = json.loads(raw.decode("utf-8"))
            valid = (isinstance(record, dict) and set(record) == {"kind", "event", "detail"}
                     and record["kind"] in ("blocked", "note")
                     and all(isinstance(v, str) for v in record.values()))
        except ValueError:
            valid = False
        if not valid:
            return blocked, notes, f"guard log line {lineno} unparseable"
        (blocked if record["kind"] == "blocked" else notes).append(record)
    return blocked, notes, None


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def run_guarded(skill, target, opts, state):
    """Run target argv in a fresh guarded child and return a RunResult."""
    result = RunResult()
    tmp = tempfile.mkdtemp(prefix="dry-run-gate-")
    try:
        home, tmpdir = os.path.join(tmp, "home"), os.path.join(tmp, "tmp")
        os.mkdir(home)
        os.mkdir(tmpdir)
        logfile = os.path.join(tmp, "guard.log")
        cmd = [sys.executable, GATE_PATH, "--_guard", logfile, "--"] + target
        if opts.isolation == "netns":
            with open(os.path.join(tmp, NETNS_MARKER), "w"):
                pass
            cmd = [opts.unshare, "-rn"] + cmd
        canaries = {name: CANARY_PREFIX + secrets.token_hex(8) for name in skill.secrets}
        try:
            proc = subprocess.Popen(cmd, cwd=skill.dir, env=child_env(skill, home, tmpdir, canaries),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, start_new_session=True)
        except OSError as exc:
            result.log_error = f"could not start the child: {exc}"
            return result
        try:
            result.stdout, result.stderr = proc.communicate(timeout=opts.timeout)
        except subprocess.TimeoutExpired:
            result.timed_out = True
            _kill_group(proc)
            try:
                result.stdout, result.stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:  # an escaped process still holds the pipes
                for pipe in (proc.stdout, proc.stderr):
                    pipe.close()
        finally:
            if proc.poll() is None:
                _kill_group(proc)
                proc.wait()
        result.returncode = proc.returncode
        result.blocked, result.notes, result.log_error = read_guard_log(logfile)
        for stream, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            result.leaks += [(name, stream, how) for name, how in find_canaries(data, canaries)]
        state.loopback += [n["detail"] for n in result.notes if n["event"] == "loopback"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return result


def describe_events(events):
    counts = {}
    for event in events:
        key = f"{event['event']} {event['detail']}".rstrip()
        counts[key] = counts.get(key, 0) + 1
    listed = [key if n == 1 else f"{key} (x{n})" for key, n in counts.items()]
    return f"{len(events)} guard event(s): " + "; ".join(listed)


def _output_lines(data, limit=PREVIEW_LINES):
    lines = data.decode("utf-8", "replace").splitlines()
    shown = [line[:300] for line in lines[:limit]]
    if len(lines) > limit:
        shown.append(f"... {len(lines) - limit} more line(s)")
    return shown


def judge_run(cid, run, opts, needs_banner):
    reasons = []
    if run.timed_out:
        reasons.append(f"timeout after {opts.timeout:g}s")
    elif run.returncode is not None and run.returncode < 0:
        reasons.append(f"killed by signal {-run.returncode}")
    elif run.returncode != 0:
        reasons.append(f"exit {run.returncode}")
    if run.log_error:
        reasons.append(run.log_error)
    if run.blocked:
        reasons.append(describe_events(run.blocked))
    if needs_banner and b"dry run" not in run.stdout.lower():
        reasons.append("stdout lacks DRY RUN (D14)")
    reasons += [f"canary for {name} in {stream} ({how})" for name, stream, how in run.leaks]
    output = [f"stdout | {line}" for line in _output_lines(run.stdout)]
    if reasons:
        output += [f"stderr | {line}" for line in _output_lines(run.stderr)]
        return Check(cid, FAIL, "; ".join(reasons), output)
    banner = ", DRY RUN shown" if needs_banner else ""
    return Check(cid, PASS, f"exit 0, no guard events{banner}, no canary", output if needs_banner else [])


def check_path_entry(skill, opts, state):
    d0 = Check("D0", PASS, f"dry-run: {skill.entry}") if skill.entry else \
        Check("D0", FAIL, "tagged skill has no metadata dry-run value")
    s1 = check_s1(skill) if skill.entry else Check("S1", SKIP, "skipped: no dry-run value")
    s2 = check_s2(skill)
    checks = [d0, s1, s2]
    failed = [c.id for c in checks if c.status == FAIL]
    if failed:
        return checks + [Check(cid, SKIP, f"skipped: {', '.join(failed)} FAIL") for cid in ("R1", "R2", "C1")]
    entry = os.path.normpath(os.path.join(skill.dir, skill.entry))
    r1_run = run_guarded(skill, [entry, "--dry-run"] + skill.args, opts, state)
    r2_run = run_guarded(skill, ["-m", opts.runner, skill.test], opts, state)
    libs = [n["detail"] for run in (r1_run, r2_run) for n in run.notes if n["event"] == "ctypes.dlopen"]
    c1 = Check("C1", WARN, "ctypes.dlopen: " + ", ".join(dict.fromkeys(libs))) if libs else \
        Check("C1", PASS, "no ctypes.dlopen")
    return checks + [judge_run("R1", r1_run, opts, True), judge_run("R2", r2_run, opts, False), c1]


def check_skill(skill, opts, state):
    if skill.error:
        return [Check("P0", FAIL, "config error: " + skill.error)]
    checks = [Check("P0", PASS, "frontmatter and config valid"), check_p1(skill)]
    if not skill.tagged:
        checks += check_h1(skill)
    elif skill.agent_confirm:
        checks += [Check("D0", PASS, f"dry-run: {AGENT_CONFIRM}"), check_a1(skill)]
    else:
        checks += check_path_entry(skill, opts, state)
    for check in checks:
        if check.status == WARN and opts.strict:
            check.status, check.detail = FAIL, check.detail + " (WARN is FAIL under --strict)"
        elif check.status == UNVERIFIED and opts.forbid_agent_confirm:
            check.status, check.detail = FAIL, check.detail + " (--forbid-agent-confirm)"
    return checks


# ---------------------------------------------------------------- isolation

_UNSHARE_PROBE = {}


def netns_unshare():
    """Path of an `unshare` for which `unshare -rn true` works, else None. Probed once per process."""
    if "path" not in _UNSHARE_PROBE:
        path = shutil.which("unshare") if sys.platform.startswith("linux") else None
        if path:
            try:
                probe = subprocess.run([path, "-rn", "true"], stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                if probe.returncode != 0:
                    path = None
            except (OSError, subprocess.SubprocessError):
                path = None
        _UNSHARE_PROBE["path"] = path
    return _UNSHARE_PROBE["path"]


def resolve_isolation(mode):
    """Return (mode, unshare path) for audit|netns|auto; exit 3 when netns is requested but unavailable."""
    if mode == "audit":
        return "audit", None
    unshare = netns_unshare()
    if unshare:
        return "netns", unshare
    if mode == "netns":
        raise GateError(EXIT_ISOLATION, "--isolation netns: `unshare -rn true` does not work on this host")
    return "audit", None


def pytest_importable():
    try:
        probe = subprocess.run([sys.executable, "-I", "-c", "import pytest"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120,
                               env={"PATH": os.environ.get("PATH", os.defpath)})
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.returncode == 0


# ---------------------------------------------------------------- guard (runs inside the child)

HOOK_ADDRESS = ("socket.connect", "socket.sendto", "socket.sendmsg")
HOOK_DNS = ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr", "socket.getnameinfo")
HOOK_PROCESS = ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.fork", "os.forkpty")
HOOKED = frozenset(("socket.bind", "ctypes.dlopen") + HOOK_ADDRESS + HOOK_DNS + HOOK_PROCESS)
DNS_ALLOWED = frozenset(("localhost", "127.0.0.1", "::1"))
LOOPBACK_V4 = ipaddress.ip_network("127.0.0.0/8")
LOOPBACK_V6 = ipaddress.ip_address("::1")
INET_FAMILIES = (socket.AF_INET, socket.AF_INET6)
AF_UNIX = getattr(socket, "AF_UNIX", object())


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value if isinstance(value, str) else str(value)


def is_loopback(host):
    host = _text(host)
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip in LOOPBACK_V4 if ip.version == 4 else ip == LOOPBACK_V6


def process_name(event, args):
    """Executable basename for a process event (os.system: first word); never arguments or env."""
    try:
        if event == "os.system":
            words = _text(args[0]).split()
            return words[0] if words else ""
        if event == "subprocess.Popen":
            executable, argv = args[0], args[1]
            if executable is None:
                single = isinstance(argv, (str, bytes, os.PathLike))
                executable = argv if single else (list(argv) or [""])[0]
        elif event == "os.spawn":
            executable = args[1]
        elif event in ("os.exec", "os.posix_spawn"):
            executable = args[0]
        else:
            return ""  # os.fork and os.forkpty take no arguments
        if isinstance(executable, os.PathLike):
            executable = os.fspath(executable)
        return os.path.basename(_text(executable))
    except Exception:
        return "?"


class Guard:
    """Audit hook state for one child: the log descriptor and the loopback sockets it bound."""

    def __init__(self, logfile):
        self.fd = os.open(logfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        stat = os.fstat(self.fd)
        self.ident = (stat.st_dev, stat.st_ino)
        self.bound = weakref.WeakSet()

    def write(self, kind, event, detail):
        line = (json.dumps({"kind": kind, "event": event, "detail": detail}) + "\n").encode("ascii")
        try:
            stat = os.fstat(self.fd)
            if (stat.st_dev, stat.st_ino) != self.ident or os.write(self.fd, line) != len(line):
                raise OSError("guard log descriptor changed")
        except OSError:
            os._exit(GUARD_LOG_FAILED)  # a run whose log cannot be trusted must fail

    def own_port(self, port):
        if not isinstance(port, int) or port == 0:
            return False
        for sock in list(self.bound):
            try:
                name = sock.getsockname()
            except OSError:
                continue
            if isinstance(name, tuple) and len(name) >= 2 and name[1] == port:
                return True
        return False

    def blocked_detail(self, event, args):
        """None to allow the call, else the detail string for its guard event."""
        if event in HOOK_ADDRESS:
            sock, address = args[0], args[1]
            if event == "socket.sendmsg" and address is None:
                return None
            family = getattr(sock, "family", None)
            if family == AF_UNIX:
                return None
            if family in INET_FAMILIES and isinstance(address, tuple) and len(address) >= 2:
                host, port = address[0], address[1]
                if is_loopback(host) and self.own_port(port):
                    return None
                return f"{_text(host)}:{port}"
            return f"address family {family}"
        if event in HOOK_DNS:
            host = args[0] if args else None
            while isinstance(host, tuple) and host:
                host = host[0]
            host = _text(host)
            return None if host in DNS_ALLOWED else host
        return process_name(event, args)

    def hook(self, event, args):
        if event not in HOOKED:
            return
        if event == "socket.bind":
            try:
                sock, address = args[0], args[1]
                if sock.family in INET_FAMILIES and isinstance(address, tuple) and is_loopback(address[0]):
                    self.bound.add(sock)
            except Exception:
                pass  # never blocked; an unrecorded socket only makes later connects stricter
            return
        if event == "ctypes.dlopen":
            self.write("note", event, _text(args[0] if args else None))
            return
        try:
            detail = self.blocked_detail(event, args)
        except Exception:
            detail = "unreadable arguments"
        if detail is None:
            return
        self.write("blocked", event, detail)
        raise PermissionError(f"dry-run-gate blocked {event} {detail}".rstrip())


def loopback_up():
    """Bring `lo` up inside a fresh network namespace (SIOCGIFFLAGS, then SIOCSIFFLAGS with IFF_UP)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        request = bytearray(40)                 # struct ifreq; IFNAMSIZ is 16
        request[:2] = b"lo"
        fcntl.ioctl(sock.fileno(), 0x8913, request)
        flags = struct.unpack_from("h", request, 16)[0]
        struct.pack_into("h", request, 16, flags | 1)
        fcntl.ioctl(sock.fileno(), 0x8914, request)
        return True
    except (OSError, ValueError, AttributeError, struct.error):
        return False
    finally:
        sock.close()


def guard_main(argv):
    """Child side: dry_run_gate.py --_guard LOGFILE -- TARGET..."""
    if len(argv) < 3 or argv[1] != "--" or (argv[2] == "-m" and len(argv) < 4):
        print("dry-run-gate: usage: --_guard LOGFILE -- (SCRIPT | -m MODULE) [ARGS...]", file=sys.stderr)
        return EXIT_CONFIG
    logfile, target = argv[0], argv[2:]
    guard = Guard(logfile)
    if os.path.exists(os.path.join(os.path.dirname(logfile), NETNS_MARKER)):
        guard.write("note", "loopback", "up" if loopback_up() else "down")
    skill_dir = os.getcwd()
    if sys.path and os.path.realpath(sys.path[0] or ".") == os.path.dirname(os.path.realpath(GATE_PATH)):
        sys.path[0] = skill_dir
    else:
        sys.path.insert(0, skill_dir)
    sys.addaudithook(guard.hook)
    if target[0] == "-m":
        sys.argv = target[1:]
        runpy.run_module(target[1], run_name="__main__", alter_sys=True)
    else:
        sys.argv = list(target)
        runpy.run_path(target[0], run_name="__main__")
    return EXIT_OK


# ---------------------------------------------------------------- CLI

class Options:
    pass


class RunState:
    def __init__(self):
        self.loopback = []


class Report:
    def __init__(self):
        self.exit = EXIT_OK
        self.results = []       # [(Skill, [Check])]
        self.isolation = None
        self.loopback = None

    def as_json(self):
        return {
            "skills": [{"path": s.path, "name": s.name, "tags": s.tags, "checks": [c.as_json() for c in checks]}
                       for s, checks in self.results],
            "isolation": self.isolation,
            "loopback": self.loopback,
            "exit": self.exit,
        }


def build_parser():
    parser = argparse.ArgumentParser(
        prog="dry_run_gate.py", allow_abbrev=False,
        description="Prove that skills with side effects ship a --dry-run that makes no outbound "
                    "connection, starts no process and leaks no secret.")
    parser.add_argument("paths", nargs="*", metavar="PATH", help="repo or skill dir (default: .)")
    parser.add_argument("--strict", action="store_true", help="WARN (H1, C1) becomes FAIL")
    parser.add_argument("--isolation", choices=("auto", "audit", "netns"), help="default: auto")
    parser.add_argument("--timeout", type=float, metavar="SECONDS", help="per child process (default: 30)")
    parser.add_argument("--runner", choices=("unittest", "pytest"), help="R2 test runner (default: unittest)")
    parser.add_argument("--json", action="store_true", help="JSON report on stdout, human report on stderr")
    parser.add_argument("--forbid-agent-confirm", action="store_true", help="UNVERIFIED (agent-confirm) becomes FAIL")
    parser.add_argument("--list", action="store_true", help="list discovered skills and run nothing")
    parser.add_argument("--selftest", action="store_true", help="run the built-in selftest cases")
    return parser


def parse_options(argv):
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        raise GateError(exc.code if isinstance(exc.code, int) else EXIT_CONFIG, "")
    opts = Options()
    opts.paths = args.paths or ["."]
    opts.strict, opts.json, opts.list, opts.selftest = args.strict, args.json, args.list, args.selftest
    opts.forbid_agent_confirm = args.forbid_agent_confirm
    opts.isolation = args.isolation or "auto"
    opts.timeout = 30.0 if args.timeout is None else args.timeout
    opts.runner = args.runner or "unittest"
    opts.unshare = None
    if args.selftest and (args.paths or args.strict or args.json or args.list or args.forbid_agent_confirm
                          or args.isolation or args.timeout is not None or args.runner):
        raise GateError(EXIT_CONFIG, "--selftest takes no PATH and no other option")
    if args.list and args.json:
        raise GateError(EXIT_CONFIG, "--list and --json cannot be combined")
    if not (math.isfinite(opts.timeout) and opts.timeout > 0):
        raise GateError(EXIT_CONFIG, "--timeout must be a positive number of seconds")
    return opts


def print_skill(stream, skill, checks):
    tags = " ".join(skill.tags) or "none"
    entry = skill.entry or "-"
    print(f"{skill.path}  name: {skill.name}  tags: {tags}  dry-run: {entry}", file=stream)
    for check in checks:
        print(f"  {check.id:<3} {check.status:<10} {check.detail}".rstrip(), file=stream)
        for line in check.output:
            print(f"        {line}", file=stream)


def summarize_loopback(states):
    """up only if at least one netns child reported up and none reported down (fail closed)."""
    return "up" if states and all(state == "up" for state in states) else "down"


def run(argv, out=None, err=None):
    """Run the gate in process and return a Report. main() is the CLI wrapper."""
    out = out or sys.stdout
    err = err or sys.stderr
    report = Report()
    as_json = "--json" in argv
    try:
        opts = parse_options(argv)
        if opts.selftest:
            report.exit = selftest(out)
            return report
        if not opts.list:
            opts.isolation, opts.unshare = resolve_isolation(opts.isolation)
            report.isolation = opts.isolation
            if opts.runner == "pytest" and not pytest_importable():
                raise GateError(EXIT_CONFIG, "--runner pytest: pytest cannot be imported")
        skills = [load_skill(path, root) for path, root in discover(opts.paths)]
    except GateError as exc:
        if str(exc):
            print(f"dry-run-gate: {exc}", file=err)
        report.exit = exc.code
        if as_json and exc.code != EXIT_OK:
            print(json.dumps(report.as_json(), indent=2), file=out)
        return report

    if opts.list:
        for skill in skills:
            if skill.error:
                print(f"{skill.path}  config error: {skill.error}", file=out)
            else:
                tags = " ".join(skill.tags) or "none"
                print(f"{skill.path}  name: {skill.name}  tags: {tags}  dry-run: {skill.entry or '-'}", file=out)
        report.exit = EXIT_CONFIG if any(s.error for s in skills) else EXIT_OK
        return report

    human = err if opts.json else out
    state = RunState()
    print(f"dry-run-gate {__version__}: {len(skills)} skill(s), isolation {opts.isolation}", file=human)
    for skill in skills:
        checks = check_skill(skill, opts, state)
        report.results.append((skill, checks))
        print_skill(human, skill, checks)
    if opts.isolation == "netns":
        report.loopback = summarize_loopback(state.loopback)
    statuses = [c.status for _, checks in report.results for c in checks]
    if any(s.error for s, _ in report.results):
        report.exit = EXIT_CONFIG
    elif FAIL in statuses:
        report.exit = EXIT_FAIL
    counts = ", ".join(f"{statuses.count(s)} {s}" for s in (FAIL, WARN, UNVERIFIED, SKIP))
    print(f"isolation: {opts.isolation}", file=human)
    if report.loopback:
        print(f"loopback: {report.loopback}", file=human)
    print(f"exit: {report.exit} ({counts})", file=human)
    if opts.json:
        print(json.dumps(report.as_json(), indent=2), file=out)
    return report


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["--_guard"]:
        return guard_main(argv[1:])
    return run(argv).exit


# ---------------------------------------------------------------- selftest

class SelftestSkip(Exception):
    """A selftest case this platform cannot run."""


ST_SECRET = "SELFTEST_API_KEY"
ST_META = (("side-effects", "email"), ("dry-run", "scripts/send.py"),
           ("dry-run-test", "test_dry_run.py"), ("dry-run-secrets", ST_SECRET))
ST_BANNER = "DRY RUN: would POST https://example.invalid/send"
ST_TEST = '''import unittest


class DryRunFlagTest(unittest.TestCase):
    def test_flag(self):
        self.assertEqual(["--dry-run"][0].lstrip("-"), "dry-run")
'''
ST_LOOPBACK_TEST = '''import socket
import threading
import unittest

FLAG = "--dry-run"


class LoopbackTest(unittest.TestCase):
    def test_own_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.settimeout(5)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        received = []

        def serve():
            conn, _ = server.accept()
            with conn:
                received.append(conn.recv(4))
                conn.sendall(b"pong")

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
                client.sendall(b"ping")
                self.assertEqual(client.recv(4), b"pong")
        finally:
            thread.join(5)
            server.close()
        self.assertEqual(received, [b"ping"])
'''


def st_entry(before="", banner=ST_BANNER, code=0):
    """A dry-run entry script; `before` runs inside main() before the banner is printed."""
    body = "".join(f"    {line}\n" for line in before.splitlines())
    return ("import os\nimport socket\nimport sys\n\n\n"
            "def main(argv):\n"
            "    if \"--dry-run\" not in argv:\n"
            "        return 2\n"
            f"{body}"
            f"    print({banner!r})\n"
            f"    return {code}\n\n\n"
            "if __name__ == \"__main__\":\n"
            "    sys.exit(main(sys.argv[1:]))\n")


def st_write(base, rel, text):
    path = os.path.join(base, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def st_skill(tmp, name, meta=ST_META, files=None, top="", body="Selftest skill.\n", quote=True):
    skill_dir = os.path.join(tmp, "skills", name)
    lines = ["---", f"name: {name}", "description: dry-run-gate selftest case"]
    if top:
        lines.append(top)
    if meta:
        lines.append("metadata:")
        lines += [f'  {k}: "{v}"' if quote else f"  {k}: {v}" for k, v in meta]
    lines.append("---")
    st_write(skill_dir, "SKILL.md", "\n".join(lines) + "\n\n" + body)
    for rel, text in (files or {}).items():
        st_write(skill_dir, rel, text)
    return skill_dir


def st_path_skill(tmp, name, before="", banner=ST_BANNER, code=0, meta=ST_META, files=None, quote=True):
    all_files = {"scripts/send.py": st_entry(before, banner, code), "test_dry_run.py": ST_TEST}
    all_files.update(files or {})
    return st_skill(tmp, name, meta, all_files, quote=quote)


def st_gate(tmp, *flags):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        report = run(list(flags) + [tmp], out=buf, err=buf)
    return report, buf.getvalue()


def st_expect(result, exit=None, checks=()):
    """checks: (id, status[, substring of detail[, skill name]])."""
    report, text = result
    if exit is not None and report.exit != exit:
        raise AssertionError(f"exit {report.exit}, expected {exit}\n{text}")
    for cid, status, *rest in checks:
        needle = rest[0] if rest else None
        skill_name = rest[1] if len(rest) > 1 else None
        found = [c for s, cs in report.results if skill_name in (None, s.name) for c in cs if c.id == cid]
        if not found:
            raise AssertionError(f"no {cid} check\n{text}")
        if found[0].status != status or (needle and needle not in found[0].detail):
            raise AssertionError(f"{cid} {found[0].status} {found[0].detail!r}, expected {status} {needle or ''}\n{text}")
    return report


def swallow(code):
    return "try:\n" + "".join(f"    {line}\n" for line in code.splitlines()) + "except OSError:\n    pass"


def _st01(tmp):
    st_skill(tmp, "untagged", meta=None)
    st_expect(st_gate(tmp), 0, [("P1", PASS), ("H1", PASS)])


def _st02(tmp):
    st_skill(tmp, "syntax-error", meta=None, files={"scripts/bad.py": "def broken(:\n"})
    st_expect(st_gate(tmp), 1, [("P1", FAIL, "bad.py")])


def _st03(tmp):
    st_skill(tmp, "fax", meta=(("side-effects", "fax"),))
    st_expect(st_gate(tmp), 2, [("P0", FAIL, "fax")])


def _st04(tmp):
    st_path_skill(tmp, "email-ok")
    st_expect(st_gate(tmp), 0, [("D0", PASS), ("S1", PASS), ("S2", PASS), ("R1", PASS), ("R2", PASS), ("C1", PASS)])


def _st05(tmp):
    st_path_skill(tmp, "exit-1", code=1)
    st_expect(st_gate(tmp), 1, [("R1", FAIL, "exit 1"), ("R2", PASS)])


def _st06(tmp):
    st_path_skill(tmp, "sleeper", before="import time\ntime.sleep(60)")
    st_expect(st_gate(tmp, "--timeout", "2"), 1, [("R1", FAIL, "timeout")])


def _st07(tmp):
    st_path_skill(tmp, "legacy-spend", meta=(("writes", "spend"),) + ST_META[1:], quote=False)
    report = st_expect(st_gate(tmp), 0, [("R1", PASS), ("R2", PASS)])
    if report.results[0][0].tags != ["spend"]:
        raise AssertionError(f"tags {report.results[0][0].tags}, expected ['spend']")


def _st08(tmp):
    st_skill(tmp, "legacy-none", meta=(("writes", "none"),), quote=False)
    report = st_expect(st_gate(tmp), 0, [("H1", PASS)])
    if report.results[0][0].tags:
        raise AssertionError("writes: none must be untagged")


def _st09(tmp):
    connect = ('s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\ns.settimeout(1)\n'
               's.connect(("192.0.2.1", 443))')
    st_path_skill(tmp, "testnet-connect", before=swallow(connect))
    st_expect(st_gate(tmp), 1, [("R1", FAIL, "socket.connect 192.0.2.1:443")])


def _st10(tmp):
    st_path_skill(tmp, "dns", before=swallow('socket.gethostbyname("example.com")'))
    st_expect(st_gate(tmp), 1, [("R1", FAIL, "socket.gethostbyname example.com")])


def _st11(tmp):
    send = 'u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\nu.sendto(b"x", ("192.0.2.1", 9))'
    st_path_skill(tmp, "udp", before=swallow(send))
    st_expect(st_gate(tmp), 1, [("R1", FAIL, "socket.sendto 192.0.2.1:9")])


def _st12(tmp):
    st_path_skill(tmp, "subprocess", before="import subprocess\n" + swallow('subprocess.run(["true"])'))
    st_expect(st_gate(tmp), 1, [("R1", FAIL, "subprocess.Popen true")])


def _st13(tmp):
    st_path_skill(tmp, "prints-canary", before=f'print("DRY RUN key:", os.environ["{ST_SECRET}"])')
    st_expect(st_gate(tmp), 1, [("R1", FAIL, f"canary for {ST_SECRET} in stdout (literal)")])


def _st14(tmp):
    st_path_skill(tmp, "no-banner", banner="preview: would POST https://example.invalid/send")
    st_expect(st_gate(tmp), 1, [("R1", FAIL, "lacks DRY RUN")])


def _st15(tmp):
    entry = "import sys\n\n# supports --dry-run\nprint('DRY RUN')\n"
    st_path_skill(tmp, "comment-only", files={"scripts/send.py": entry})
    st_expect(st_gate(tmp), 1, [("S1", FAIL, "comments do not count"), ("R1", SKIP), ("R2", SKIP)])


def _st16(tmp):
    meta = ST_META[:2] + (("dry-run-test", "test_missing.py"),) + ST_META[3:]
    st_path_skill(tmp, "missing-test", meta=meta)
    st_expect(st_gate(tmp), 1, [("S2", FAIL, "not found"), ("R1", SKIP)])


def _st17(tmp):
    st_skill(tmp, "no-dry-run", meta=(("side-effects", "email"),))
    st_expect(st_gate(tmp), 1, [("D0", FAIL), ("R1", SKIP)])


def _st18(tmp):
    st_skill(tmp, "top-level", meta=None, top='side-effects: "email"')
    st_expect(st_gate(tmp), 2, [("P0", FAIL, "not at top level")])


def _st19(tmp):
    st_skill(tmp, "both-keys", meta=(("writes", "spend"), ("side-effects", "spend")))
    st_expect(st_gate(tmp), 2, [("P0", FAIL, "both writes")])


def _st20(tmp):
    st_skill(tmp, "none-email", meta=(("side-effects", "none email"),))
    st_expect(st_gate(tmp), 2, [("P0", FAIL, "none cannot be combined")])


AGENT_META = (("side-effects", "email"), ("dry-run", AGENT_CONFIRM))


def _st21(tmp):
    st_skill(tmp, "agent-no-heading", meta=AGENT_META, body="## Usage\n\nSends mail.\n")
    st_expect(st_gate(tmp), 1, [("A1", FAIL)])


def _st22(tmp):
    st_skill(tmp, "agent-heading", meta=AGENT_META, body="## Dry run\n\nShow the draft and ask before sending.\n")
    st_expect(st_gate(tmp), 0, [("A1", UNVERIFIED)])
    st_expect(st_gate(tmp, "--forbid-agent-confirm"), 1, [("A1", FAIL)])


def _st23(tmp):
    skill_dir = st_path_skill(tmp, "folded")
    st_write(skill_dir, "SKILL.md", "\n".join([
        "---",
        "name: folded",
        "description: >",
        "  A folded description that mentions --- in a sentence",
        "  ---",
        "  and holds an indented line of only dashes, which must not end the frontmatter.",
        "metadata:",
    ] + [f'  {k}: "{v}"' for k, v in ST_META] + ["---", "", "Body.", ""]))
    report = st_expect(st_gate(tmp), 0, [("R1", PASS)])
    if report.results[0][0].tags != ["email"]:
        raise AssertionError("metadata after the folded description was not read")


def _st24(tmp):
    st_skill(tmp, "smtp", meta=None, files={"scripts/notify.py": "import smtplib\n"})
    st_expect(st_gate(tmp), 0, [("H1", WARN, "import smtplib")])
    st_expect(st_gate(tmp, "--strict"), 1, [("H1", FAIL, "import smtplib")])


def _parent_home(tmp):
    home = os.path.join(tmp, "parent-home")
    os.mkdir(home)
    os.environ["HOME"] = home
    return home


def _st25(tmp):
    _parent_home(tmp)
    os.environ["DRYRUNGATE_SELFTEST_SECRET"] = "selftest-parent-secret"
    os.environ["HTTPS_PROXY"] = "http://192.0.2.1:3128"
    check = 'if "DRYRUNGATE_SELFTEST_SECRET" in os.environ or "HTTPS_PROXY" in os.environ:\n    return 1'
    st_path_skill(tmp, "env-allowlist", before=check)
    st_expect(st_gate(tmp), 0, [("R1", PASS)])


def _st26(tmp):
    meta = ST_META[:2] + (("dry-run-test", "test_loopback.py"),) + ST_META[3:]
    st_path_skill(tmp, "loopback", meta=meta, files={"test_loopback.py": ST_LOOPBACK_TEST})
    report, text = st_gate(tmp)
    if report.isolation == "netns" and report.loopback == "down":
        raise SelftestSkip("loopback: down under netns, so a loopback server cannot work")
    st_expect((report, text), 0, [("R2", PASS)])


def _st27(tmp):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        st_path_skill(tmp, "parent-port", before=swallow(f'socket.create_connection(("127.0.0.1", {port}), timeout=2)'))
        st_expect(st_gate(tmp), 1, [("R1", FAIL, f"socket.connect 127.0.0.1:{port}")])
    finally:
        listener.close()


def _st28(tmp):
    st_skill(tmp, "a-bad-config", meta=(("side-effects", "fax"),))
    st_path_skill(tmp, "b-r1-fail", code=1)
    st_expect(st_gate(tmp), 2, [("P0", FAIL, "fax", "a-bad-config"), ("R1", FAIL, "exit 1", "b-r1-fail")])


def _st29(tmp):
    if netns_unshare():
        raise SelftestSkip("`unshare -rn true` works on this host")
    st_path_skill(tmp, "netns")
    st_expect(st_gate(tmp, "--isolation", "netns"), 3)


def _st30(tmp):
    st_path_skill(tmp, "os-system", before=swallow('os.system("true")'))
    st_expect(st_gate(tmp), 1, [("R1", FAIL, "os.system true")])


def _st31(tmp):
    if not hasattr(os, "fork"):
        raise SelftestSkip("os.fork does not exist here")
    fork = "pid = None\n" + swallow("pid = os.fork()") + "\nif pid == 0:\n    os._exit(0)\nif pid:\n    os.waitpid(pid, 0)"
    st_path_skill(tmp, "fork", before=fork)
    st_expect(st_gate(tmp), 1, [("R1", FAIL, "os.fork")])


def _st32(tmp):
    if not hasattr(os, "posix_spawn"):
        raise SelftestSkip("os.posix_spawn does not exist here")
    if shutil.which("true") is None:
        raise SelftestSkip("no `true` on PATH")
    spawn = ('import shutil\npath = shutil.which("true")\npid = None\n'
             + swallow("pid = os.posix_spawn(path, [path], dict(os.environ))") + "\nif pid:\n    os.waitpid(pid, 0)")
    st_path_skill(tmp, "posix-spawn", before=spawn)
    st_expect(st_gate(tmp), 1, [("R1", FAIL, "os.posix_spawn true")])


def _st33(tmp):
    home = _parent_home(tmp)
    st_write(home, ".netrc", "machine example.invalid login user password dryrungate-netrc-marker\n")
    check = ('netrc = os.path.expanduser("~/.netrc")\n'
             'if os.path.exists(netrc):\n'
             '    with open(netrc) as fh:\n'
             '        print("marker seen" if "dryrungate-netrc-marker" in fh.read() else "netrc seen")\n'
             '    return 1')
    st_path_skill(tmp, "netrc", before=check)
    st_expect(st_gate(tmp), 0, [("R1", PASS)])


def _st34(tmp):
    basic = ('import base64\n'
             f'token = base64.b64encode(("user:" + os.environ["{ST_SECRET}"]).encode()).decode()\n'
             'print("Authorization: Basic " + token)')
    st_path_skill(tmp, "basic-auth", before=basic)
    st_expect(st_gate(tmp), 1, [("R1", FAIL, f"canary for {ST_SECRET} in stdout (base64)")])


def _st35(tmp):
    st_write(os.path.join(tmp, "skills", "not-a-skill"), "README.md", "No SKILL.md here.\n")
    st_expect(st_gate(tmp), 2)


def _st36(tmp):
    meta = ST_META[:2] + (("dry-run-test", "tests/test_dry_run.py"),) + ST_META[3:]
    files = {"tests/__init__.py": "", "tests/test_dry_run.py": ST_TEST}
    st_path_skill(tmp, "tests-package", meta=meta, files=files)
    st_expect(st_gate(tmp), 0, [("R2", PASS)])


def _st37(tmp):
    meta = (ST_META[0], ("dry-run", "scripts/send.sh")) + ST_META[2:]
    st_path_skill(tmp, "shell-entry", meta=meta, files={"scripts/send.sh": "#!/bin/sh\necho 'DRY RUN' # --dry-run\n"})
    st_expect(st_gate(tmp), 1, [("S1", FAIL, ".py"), ("R1", SKIP), ("R2", SKIP)])


SELFTEST_CASES = [
    (1, "untagged, no Python files", _st01),
    (2, "untagged, a .py with a syntax error", _st02),
    (3, 'side-effects: "fax"', _st03),
    (4, "tagged email, correct dry-run and test", _st04),
    (5, "tagged, dry-run exits 1", _st05),
    (6, "tagged, dry-run sleeps past --timeout 2", _st06),
    (7, "legacy writes: spend, correct dry-run and test", _st07),
    (8, "legacy writes: none", _st08),
    (9, "dry-run connects to 192.0.2.1:443 and swallows the exception", _st09),
    (10, 'dry-run calls socket.gethostbyname("example.com") and swallows the exception', _st10),
    (11, "dry-run sendto a UDP datagram to 192.0.2.1", _st11),
    (12, 'dry-run calls subprocess.run(["true"])', _st12),
    (13, "dry-run prints its canary", _st13),
    (14, "dry-run output lacks DRY RUN", _st14),
    (15, "--dry-run appears only in a comment", _st15),
    (16, "dry-run-test file missing", _st16),
    (17, "tagged, no dry-run key", _st17),
    (18, "side-effects at top level", _st18),
    (19, "writes and side-effects both under metadata", _st19),
    (20, 'side-effects: "none email"', _st20),
    (21, "agent-confirm without a ## Dry run heading", _st21),
    (22, "agent-confirm with heading and body", _st22),
    (23, "folded multi-line description containing ---", _st23),
    (24, "untagged, imports smtplib", _st24),
    (25, "parent env sets a secret and HTTPS_PROXY; neither reaches the child", _st25),
    (26, "test binds 127.0.0.1:0, serves in a thread, connects to its own port", _st26),
    (27, "dry-run connects to a loopback port the selftest parent is listening on", _st27),
    (28, "two skills: one exit-2 config, one R1 FAIL", _st28),
    (29, "--isolation netns on a host without unshare", _st29),
    (30, 'dry-run calls os.system("true")', _st30),
    (31, "dry-run calls os.fork()", _st31),
    (32, 'dry-run calls os.posix_spawn on shutil.which("true")', _st32),
    (33, "parent HOME holds a .netrc marker; the child's ~/.netrc does not exist", _st33),
    (34, 'dry-run prints Authorization: Basic base64("user:" + canary)', _st34),
    (35, "a PATH with no SKILL.md at either discovery pattern", _st35),
    (36, "dry-run-test is tests/test_dry_run.py with tests/__init__.py", _st36),
    (37, 'tagged, dry-run: "scripts/send.sh"', _st37),
]


def selftest(out):
    passed, skipped, failed = 0, [], []
    for number, title, case in SELFTEST_CASES:
        saved_env = dict(os.environ)
        tmp = tempfile.mkdtemp(prefix=f"dry-run-gate-selftest-{number:02d}-")
        try:
            case(tmp)
            passed += 1
            print(f"case {number:02d} ok    {title}", file=out)
        except SelftestSkip as exc:
            skipped.append(number)
            print(f"case {number:02d} SKIP  {title}: {exc}", file=out)
        except Exception as exc:
            failed.append(number)
            print(f"case {number:02d} FAIL  {title}: {type(exc).__name__}: {exc}", file=out)
        finally:
            for name in set(os.environ) - set(saved_env):
                del os.environ[name]
            for name, value in saved_env.items():
                if os.environ.get(name) != value:
                    os.environ[name] = value
            shutil.rmtree(tmp, ignore_errors=True)
        out.flush()
    print(f"selftest: {len(SELFTEST_CASES)} cases, {passed} ok, {len(skipped)} skipped"
          f"{' ' + str(skipped) if skipped else ''}, {len(failed)} failed{' ' + str(failed) if failed else ''}",
          file=out)
    return EXIT_FAIL if failed else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
