# dry-run-gate

A skill that sends, posts, publishes, spends or deletes must prove in CI that its `--dry-run` makes no outbound connection, starts no process and leaks no secret. dry-run-gate is the check that enforces this. It targets careless dry-runs; it does not claim to stop a deliberately evasive one (see [Stated limits](#stated-limits)).

One file, `dry_run_gate.py`: Python 3.9 or newer, standard library only, Linux and macOS. Windows is not supported.

When the spec behind this tool leaves something open, the gate fails closed: a config ambiguity is exit 2, a run ambiguity is FAIL.

## Quick start

Run the gate against a fresh clone or copy of the skill repo, never your working checkout. A dry-run can change files that `git status` does not show (ignored files, or files outside the repo).

```
git clone <skill repo> /tmp/gate-check && cd /tmp/gate-check
python3 ~/Developer/repos/sites/_incoming/dry-run-gate/dry_run_gate.py .
```

`python3 dry_run_gate.py --list .` shows what the gate discovered without running anything. `python3 dry_run_gate.py --selftest` runs the 40 built-in cases.

## Terms

- **Skill dir**: a directory holding a `SKILL.md`.
- **Tagged**: a skill whose `side-effects` (or legacy `writes`) names at least one tag.
- **Path entry**: a tagged skill whose `dry-run` value is anything other than `agent-confirm`.
- **Entry script**: the file a path entry's `dry-run` value points to.
- **Child** (guarded process): the separate Python process in which the gate runs an entry script or its test under the guard.
- **Canary**: a random placeholder value the gate puts in a secret's env var for one run, so it can detect the secret being printed.
- **Guard event**: one line in the guard log, written only for a blocked call. Nothing else counts as a guard event.
- **netns**: a Linux network namespace created with `unshare -rn`, which has no network access.
- **Audit-only**: a run where netns is unavailable and only the Python audit hook guards the child.
- **H1 heuristic**: the static check for write-capable code in untagged skills.
- **Consumer CI**: the dry-run-gate workflow running in a skill repo.
- **Check statuses**: PASS (no effect on exit); FAIL (exit 1); WARN (exit 0, or 1 under `--strict`); UNVERIFIED (exit 0, or 1 under `--forbid-agent-confirm`); SKIP (no effect by itself; used after an earlier FAIL in the same skill, or for a selftest case the platform cannot run). Under `--strict` a WARN is reported as FAIL, and under `--forbid-agent-confirm` an UNVERIFIED is reported as FAIL. Exit 2 and 3 come from config and isolation errors, not from a status.

## Frontmatter convention

All gate keys sit under `metadata`, and every value is a plain string.

```yaml
---
name: klaviyo-send
description: >
  Sends a Klaviyo campaign. Folded descriptions are fine.
metadata:
  side-effects: "email remote-write"
  dry-run: "scripts/send.py"
  dry-run-args: "--campaign tests/fixtures/campaign.json"
  dry-run-test: "tests/test_dry_run.py"
  dry-run-secrets: "KLAVIYO_API_KEY"
---
```

| Key | Value |
|---|---|
| `side-effects` | tags from the closed set below, separated by spaces or commas; absent, empty or `none` means untagged |
| `dry-run` | a path relative to the skill dir to the entry script, or the literal `agent-confirm` |
| `dry-run-args` | extra args, split with `shlex.split`, appended after `--dry-run` |
| `dry-run-test` | a test file path relative to the skill dir |
| `dry-run-secrets` | env var names, separated by spaces or commas |

### Tags

The tag set is closed:

| Tag | Meaning |
|---|---|
| `spend` | paid usage |
| `social` | social posts |
| `email` | email sends |
| `sms` | SMS sends |
| `message` | chat sends (Signal, Slack, Discord) |
| `publish` | deploys, CMS posts, releases, git push |
| `remote-write` | creating or changing remote records |
| `delete` | destructive remote operations |

### Config rules

Each of these is exit 2:

- A tag outside the closed set (tags are case-sensitive).
- `none` together with any other tag.
- `metadata.writes` and `metadata.side-effects` both present. Legacy `writes` (values `spend`, `social`, `none`) is otherwise read as `side-effects` with the same value.
- Any of `side-effects`, `writes`, `dry-run`, `dry-run-args`, `dry-run-test`, `dry-run-secrets` at top level instead of under `metadata`.
- A `dry-run-args` value `shlex` cannot split, or a `dry-run-secrets` name that is not an env var name or is one the gate sets itself (`PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, `HOME`, `TMPDIR`, `PYTHONDONTWRITEBYTECODE`, `PYTHONNOUSERSITE`, `PYTHONPATH`).

### Discovery and parsing

For each PATH argument (default `.`), the gate checks `PATH/SKILL.md` and `PATH/skills/*/SKILL.md`. A PATH that does not exist, or one where neither pattern finds a `SKILL.md`, is exit 2. A skill dir reached through two PATH arguments runs once.

Frontmatter is the lines between a first line that is exactly `---` and the next line that is exactly `---`. A `SKILL.md` that does not open with `---`, or has no closing line, is exit 2. A trailing `\r` is ignored, so CRLF files work.

- A top-level key line matches `^[A-Za-z0-9_-]+:` at column 0. Indented lines, blank lines and comments belong to the key above them and are skipped (except under `metadata`). Any other column-0 line, or an indented line before the first key, is exit 2.
- The gate reads only `name` (for display; a multi-line name falls back to the skill dir name), `metadata`, and the forbidden top-level keys. Every other key and its continuation lines are skipped unread, so a folded or literal-block `description` is never parsed.
- Under `metadata:`, every non-blank, non-comment line must match `^  [A-Za-z0-9_-]+:\s*(.*)$` (exactly two spaces). A value is bare or in matching single or double quotes. A duplicate key, an unmatched quote, a quote or backslash inside a quoted value, or a bare value that YAML would read as something else (flow collections, anchors, block scalars, a `#` comment, `: `) is exit 2. The block ends at the next column-0 key line or the closing `---`.

## Checks

| ID | Applies to | Check | Failure |
|---|---|---|---|
| P0 | all | frontmatter and config rules above | exit 2 |
| P1 | all | every `*.py` under the skill dir compiles with `compile()` (no exec, no `.pyc`) | FAIL |
| D0 | tagged | `dry-run` is present and non-empty | FAIL |
| S1 | path entry | the entry script exists, ends in `.py`, and its AST contains the string constant `--dry-run` (comments do not count) | FAIL |
| S2 | path entry | `dry-run-test` is present, the file exists, and its AST contains the string constant `--dry-run` | FAIL |
| R1 | path entry | the entry script runs in the child with `--dry-run <args>`. Pass requires exit 0, zero guard events, `DRY RUN` (case-insensitive) in stdout, and the canary check on stdout and stderr | FAIL, listing each guard event |
| R2 | path entry | the test runs in the child: `-m unittest <dry-run-test>` by default, `-m pytest <dry-run-test>` with `--runner pytest`. Pass requires exit 0, zero guard events and the canary check | FAIL |
| A1 | tagged, `agent-confirm` | the `SKILL.md` body has a `## Dry run` heading (case-insensitive) followed by at least one non-blank line before the next heading | FAIL if missing, otherwise UNVERIFIED |
| H1 | untagged | heuristic, below | WARN (FAIL under `--strict`) |
| C1 | path entry | the guard noted `ctypes.dlopen` during R1 or R2 | WARN (FAIL under `--strict`) |

If D0, S1 or S2 fails, R1, R2 and C1 are recorded as SKIP and the skill is FAIL. `--runner pytest` when pytest cannot be imported is exit 2.

`agent-confirm` is for instruction-only skills that cannot be executed: it reports UNVERIFIED and does not change the exit code. `--forbid-agent-confirm` makes it FAIL. `--strict` does not affect it.

The R1 stdout is printed under the check, so a human reading the CI log sees the preview.

**Canary check.** FAIL if a canary appears in stdout or stderr, either literally or inside a base64 token. A base64 token is any run of 16 or more characters from `A-Za-z0-9+/=_-`. Each token is decoded with the standard and URL-safe alphabets (padding added as needed, decode errors ignored), also from each of its first four offsets and from each piece between `=` signs, so a token glued to a prefix such as `auth=` is still read.

**H1 matcher** (AST only, never source text). A skill gets one WARN per file, listing every hit:

- an import of `smtplib`, `twilio` or `tweepy`;
- a file that imports `requests`, `httpx`, `aiohttp` or `urllib3` and contains a call whose function is an attribute named `post`, `put`, `patch`, `delete` or `request`;
- a call to `urlopen` (bare or as `urllib.request.urlopen`) with a second positional argument or a `data` keyword;
- a call to `Request` (bare or as `urllib.request.Request`) with a `data` keyword or a `method` keyword whose constant is `POST`, `PUT`, `PATCH` or `DELETE`;
- a string constant containing `git push` or `gh release`, or a list or tuple whose first two elements are the string constants `"git", "push"` or `"gh", "release"`.

## The guard

R1 and R2 start a child: `python -I dry_run_gate.py --_guard LOGFILE -- <target>`, with the skill dir as cwd. Under netns the command is prefixed with `unshare -rn`. LOGFILE is `guard.log` in a fresh temp dir that also holds the child's empty `HOME` and `TMPDIR`; the gate removes the temp dir after reading the log. On timeout (default 30 s per child) the gate kills the child's whole process group.

**Environment.** The child environment is built from scratch, not inherited. It holds only `PATH`, `LANG`, `LC_ALL` and `LC_CTYPE` copied from the parent when set; `HOME` and `TMPDIR` inside the per-run temp dir; `PYTHONDONTWRITEBYTECODE=1`; `PYTHONNOUSERSITE=1`; `PYTHONPATH`; and each `dry-run-secrets` name set to `dryrungate-canary-<16 hex>`, fresh per run. Proxy variables and real credentials are absent, and lookups through `HOME` or `~` (for example `~/.netrc`) see an empty dir. On macOS, CoreFoundation adds `__CF_USER_TEXT_ENCODING` inside the child; it holds no secret. Because the child runs in isolated mode (`-I`), the interpreter itself ignores every `PYTHON*` variable and the user site; the guard sets `sys.dont_write_bytecode = True` itself and reads `PYTHONPATH` from the environment to build the import path (below).

Packages installed with `pip install --user` are not importable in the child. Install skill dependencies into the interpreter or a venv instead.

**Import path.** `PYTHONPATH` is, in order: the skill dir, the skill dir's `scripts/` if it exists, the PATH argument the skill was found under, and that PATH's `scripts/` if it exists. The child starts with none of these on `sys.path` and without the gate's own directory (`-I` adds no script dir), so nothing from the skill can run while the interpreter and the gate start up: a skill file named like a module they import, such as `scripts/secrets.py` or `site.py`, is never loaded in its place. The guard then sets `sys.dont_write_bytecode`, installs the audit hook and the `_posixsubprocess.fork_exec` wrapper, and only after that puts the `PYTHONPATH` entries at the front of `sys.path`, skill dir first, before running the target. A skill's own `tests/` package is therefore never shadowed by the gate's.

**Hooked events** (from the [Python 3.9 audit events table](https://docs.python.org/3.9/library/audit_events.html)). Each blocked call writes one guard event, then raises `PermissionError`. Any guard event fails the run, even if the target caught the exception.

| Event | Action |
|---|---|
| `socket.bind` | never blocked or logged; a socket bound to a loopback address is remembered |
| `socket.connect`, `socket.sendto`, `socket.sendmsg` | allowed only to a loopback address whose port is that of a socket the child itself bound to loopback and still holds, so a local fake server works and a local proxy does not; otherwise blocked. `sendmsg` without an address is allowed (connected socket, already checked at connect). `AF_UNIX` is allowed |
| `socket.getaddrinfo`, `socket.gethostbyname`, `socket.gethostbyaddr`, `socket.getnameinfo` | blocked unless the host is `localhost`, `127.0.0.1` or `::1` |
| `subprocess.Popen`, `os.system`, `os.exec`, `os.posix_spawn`, `os.spawn`, `os.fork`, `os.forkpty`, `_posixsubprocess.fork_exec` | always blocked |
| `ctypes.dlopen` | never blocked; noted for C1 |

All other events are ignored. Loopback means `127.0.0.0/8`, `::1` or `localhost`.

`multiprocessing`'s spawn and forkserver start methods create processes through `_posixsubprocess.fork_exec` without going through `subprocess`, and Python 3.9 raises no audit event for that call. So besides hooking the `_posixsubprocess.fork_exec` event where Python raises it, the guard replaces `_posixsubprocess.fork_exec` with a wrapper that blocks it, on every version, before the target runs.

The log holds one JSON object per line: `{"kind": "blocked" | "note", "event": ..., "detail": ...}`. `detail` is `host:port` for socket events, the hostname for DNS events, the executable's basename for process events (`os.system`: the first word of the command) and the library name for `ctypes.dlopen`. Arguments, environment, headers and body data are never written. A missing log, an unparseable line, a child killed by a signal, or a timeout is FAIL. If the guard cannot write its log, the child exits 70.

## Isolation

`--isolation auto|audit|netns`, default `auto`.

- `audit`: the audit-hook guard only.
- `netns`: Linux only. The child runs under `unshare -rn`, which removes network access for the whole process tree, including C code; the guard still runs inside it and brings the loopback interface up. If `unshare -rn true` fails, exit 3. On macOS, `--isolation netns` always exits 3.
- `auto`: `netns` when `unshare -rn true` works, otherwise `audit`.

The summary prints `isolation: <mode>` and, under netns, `loopback: up` or `loopback: down` (down if any child could not bring `lo` up).

**GitHub runners without namespaces.** If `unshare -rn` does not work on a GitHub runner, consumer CI runs audit-only. That is accepted: the summary line then says `isolation: audit`, and audit mode still catches every Python-level call. A repo that wants the namespace guarantee passes `--isolation netns`, which exits 3 on a runner without namespaces instead of silently degrading.

## CLI and exit codes

```
python3 dry_run_gate.py [PATH ...] [--strict] [--isolation MODE]
    [--timeout SECONDS] [--runner unittest|pytest] [--json]
    [--forbid-agent-confirm] [--list] [--selftest]
```

| Exit | Meaning |
|---|---|
| 0 | all checks pass (WARN and UNVERIFIED allowed) |
| 1 | at least one FAIL, or a WARN under `--strict` |
| 2 | config or usage error, including a PATH with no skills |
| 3 | `--isolation netns` requested but unavailable |

When several apply across skills, the precedence is 3, then 2, then 1, then 0. Skills after a config error are still checked and reported.

- `--list` prints each discovered skill with its tags and entry and runs nothing (no isolation probe either). It cannot be combined with `--json`.
- `--json` prints `{"skills": [{"path", "name", "tags", "checks": [{"id", "status", "detail"}]}], "isolation", "loopback", "exit"}` to stdout; the human report and summary go to stderr.
- `--timeout` is per child, default 30 seconds. Worst-case runtime is about 2 x timeout x tagged skills, plus dependency install time.
- `--selftest` takes no PATH and no other option.

## Writing the dry-run test

`templates/test_dry_run.py` is a unittest file. Copy it to `<skill dir>/tests/test_dry_run.py`, add an empty `tests/__init__.py`, and edit only the four constants at the top:

```python
ENTRY = "scripts/send.py"          # relative to the skill dir
ARGS = ["--campaign", "tests/fixtures/campaign.json"]
EXPECT_METHOD = "POST"
EXPECT_URL_PREFIX = "https://a.klaviyo.com/"
```

The test loads `ENTRY` by path, patches `socket.socket.connect`, `socket.create_connection` and `socket.getaddrinfo` to record and raise, calls `main(["--dry-run", *ARGS])` from the skill dir, and asserts: return 0 or `SystemExit(0)`; zero recorded calls; `DRY RUN` (case-insensitive) in the captured stdout; `EXPECT_METHOD` and `EXPECT_URL_PREFIX` in the captured stdout. Entry scripts should therefore expose `main(argv) -> int`; the gate itself does not check that. In a multi-skill repo, each skill gets its own copy.

## Composite action

```yaml
- uses: andrewluxem/dry-run-gate@<sha>
  with:
    args: ". --strict"
```

`args` defaults to `.` and is passed to `dry_run_gate.py` unquoted, so several words become several arguments. The action runs `python3 "$GITHUB_ACTION_PATH/dry_run_gate.py"`, so set up Python first.

## Consumer workflow

Two phases. **Phase 1** reports without blocking: the gate step has `continue-on-error: true`, so P0, P1 and any FAIL show in the log without turning the run red. After that repo's backfill (tags and dry-runs added to its skills), **Phase 2** removes `continue-on-error` and sets `args: ". --strict"`.

Pin `actions/checkout` and `actions/setup-python` to the SHAs below (the ones dry-run-gate's own CI uses), and pin `andrewluxem/dry-run-gate` to the `main` commit SHA recorded when the repo was made public: `<not yet public>`.

The job timeout is 30 minutes. With the 30-second default, the worst case (2 x 30 s per tagged skill) reaches that limit at about 25 tagged skills plus install time; a repo with more raises `timeout-minutes`. A job-level timeout turns even a Phase 1 run red.

```yaml
name: dry-run-gate
on:
  push:
  pull_request:
permissions:
  contents: read
jobs:
  gate:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.12"
      - name: Install skill dependencies
        run: |
          for f in requirements.txt skills/*/requirements.txt; do
            if [ -f "$f" ]; then python -m pip install -r "$f"; fi
          done
      - uses: andrewluxem/dry-run-gate@<sha>
        continue-on-error: true    # Phase 1 only; remove in Phase 2
        with:
          args: "."
```

## Stated limits

- Audit hooks see Python-level calls only, so C code can bypass them outside netns. That includes CPython's own C code: a hostname passed straight to `socket.connect` is resolved before the `socket.connect` event fires, so the DNS lookup happens even though the connect is then blocked.
- The gate targets careless dry-runs. A deliberately evasive target can defeat audit mode, for example by truncating its own log or calling libc through `ctypes`.
- Entries must be Python.
- The child keeps the user's file access by absolute path. It can read files such as credentials outside `HOME` lookups, and can write or delete anywhere the user can. Run the gate on a fresh clone (see Quick start).
- The gate proves the declared test passes with the network blocked and mentions `--dry-run`; it cannot prove the test is meaningful.

## Development

```
python3 dry_run_gate.py --selftest
python3 -m unittest discover -s tests -v
python3 dry_run_gate.py tests/fixtures/pass     # exit 0
python3 dry_run_gate.py tests/fixtures/fail     # exit 1, names 192.0.2.1
```

CI runs these on Python 3.9 and 3.13 on `ubuntu-latest` and 3.13 on `macos-latest`, plus a job that runs the composite action with `uses: ./`. The selftest never sends a packet: the TEST-NET address 192.0.2.1 it uses is blocked by the guard before connect.

## Prior art

[SupercmoHQ/superCMO-skills](https://github.com/SupercmoHQ/superCMO-skills) (Apache-2.0), `scripts/listing_gate.py` at tag v0.1.27, compiles skill scripts and runs `--dry-run` for tagged skills with vendor keys unset; dry-run-gate is written fresh and adds network and process blocking, AST-based checks, a strict frontmatter reader, a required test and canary checks.

## License

MIT. Copyright (c) 2026 Andrew Luxem.
