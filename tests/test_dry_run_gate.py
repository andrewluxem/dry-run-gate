"""Unit tests for dry_run_gate.py. Standard library unittest only.

Run from the repo root: python -m unittest discover -s tests -v
Nothing here reads or writes the real HOME; every child gets a temp HOME.
"""
from __future__ import annotations

import ast
import base64
import contextlib
import difflib
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import unittest
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import dry_run_gate as gate  # noqa: E402

FIXTURES = os.path.join(REPO, "tests", "fixtures")
TEMPLATE = os.path.join(REPO, "templates", "test_dry_run.py")
CONSTANT_NAMES = ("ENTRY", "ARGS", "EXPECT_METHOD", "EXPECT_URL_PREFIX")


def frontmatter(*lines):
    return "\n".join(("---",) + lines + ("---", "", "Body.", ""))


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dry-run-gate-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, rel, text):
        gate.st_write(self.tmp, rel, text)
        return os.path.join(self.tmp, rel)

    def load(self, text, name="skill"):
        """Write SKILL.md for skills/<name> and load it."""
        self.write(f"skills/{name}/SKILL.md", text)
        return gate.load_skill(os.path.join(self.tmp, "skills", name), self.tmp)

    def run_gate(self, *argv, paths=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            report = gate.run(list(argv) + (paths if paths is not None else [self.tmp]), out=out, err=err)
        return report, out.getvalue(), err.getvalue()

    def checks(self, report, cid, skill=None):
        return [c for s, cs in report.results if skill in (None, s.name) for c in cs if c.id == cid]

    def status(self, report, cid, skill=None):
        found = self.checks(report, cid, skill)
        self.assertTrue(found, f"no {cid} check")
        return found[0].status

    def detail(self, report, cid, skill=None):
        return self.checks(report, cid, skill)[0].detail


# ---------------------------------------------------------------- frontmatter parser

class FrontmatterTests(TempDirCase):
    def test_reads_name_and_metadata(self):
        skill = self.load(frontmatter(
            "name: klaviyo-send", "description: Sends a campaign.", "metadata:",
            '  side-effects: "email remote-write"', '  dry-run: "scripts/send.py"',
            '  dry-run-args: "--campaign tests/fixtures/campaign.json"',
            '  dry-run-test: "tests/test_dry_run.py"', '  dry-run-secrets: "KLAVIYO_API_KEY"'))
        self.assertIsNone(skill.error)
        self.assertEqual(skill.name, "klaviyo-send")
        self.assertEqual(skill.tags, ["email", "remote-write"])
        self.assertEqual(skill.entry, "scripts/send.py")
        self.assertEqual(skill.args, ["--campaign", "tests/fixtures/campaign.json"])
        self.assertEqual(skill.test, "tests/test_dry_run.py")
        self.assertEqual(skill.secrets, ["KLAVIYO_API_KEY"])

    def test_missing_opening_line_is_config_error(self):
        self.assertIn("must start", self.load("name: x\n---\n").error)

    def test_missing_closing_line_is_config_error(self):
        self.assertIn("no closing", self.load("---\nname: x\nmetadata:\n  side-effects: email\n").error)

    def test_folded_description_containing_dashes_is_skipped(self):
        skill = self.load(frontmatter(
            "name: x", "description: >", "  uses --- inline", "  ---", "  side-effects: fax",
            "metadata:", "  side-effects: email"))
        self.assertIsNone(skill.error)
        self.assertEqual(skill.tags, ["email"])

    def test_literal_block_with_key_like_lines_is_never_parsed(self):
        skill = self.load(frontmatter("name: x", "description: |", "  metadata:", "    side-effects: fax"))
        self.assertIsNone(skill.error)
        self.assertEqual(skill.tags, [])

    def test_crlf_line_endings(self):
        skill = self.load(frontmatter("name: x", "metadata:", "  side-effects: email").replace("\n", "\r\n"))
        self.assertIsNone(skill.error)
        self.assertEqual(skill.tags, ["email"])

    def test_metadata_indent_must_be_exactly_two_spaces(self):
        for line in ("    side-effects: email", " side-effects: email", "\tside-effects: email"):
            with self.subTest(line=line):
                self.assertIn("exactly two spaces", self.load(frontmatter("name: x", "metadata:", line)).error)

    def test_nested_metadata_value_is_config_error(self):
        skill = self.load(frontmatter("name: x", "metadata:", "  tags:", "    - a"))
        self.assertIn("exactly two spaces", skill.error)

    def test_yaml_syntax_in_values_is_config_error(self):
        for value in ("[a, b]", "{a: b}", "&anchor x", "*alias", "|", ">", "email # comment", "a: b", "- x"):
            with self.subTest(value=value):
                skill = self.load(frontmatter("name: x", "metadata:", f"  author: {value}"))
                self.assertIn("plain string", skill.error)

    def test_quoted_and_bare_values(self):
        skill = self.load(frontmatter(
            "name: x", "metadata:", "  side-effects: 'email'", '  dry-run: "scripts/a b.py"',
            "  dry-run-test: tests/test_x.py", '  dry-run-args: ""'))
        self.assertIsNone(skill.error)
        self.assertEqual((skill.tags, skill.entry, skill.test, skill.args), (["email"], "scripts/a b.py", "tests/test_x.py", []))

    def test_unmatched_or_escaped_quotes_are_config_errors(self):
        for value, needle in (('"email', "unmatched"), ("'email", "unmatched"), ('"a\\"b"', "not supported"),
                              ("'it''s'", "not supported")):
            with self.subTest(value=value):
                self.assertIn(needle, self.load(frontmatter("name: x", "metadata:", f"  author: {value}")).error)

    def test_comments_and_blank_lines_under_metadata(self):
        skill = self.load(frontmatter("name: x", "metadata:", "", "  # gate keys", "# column-0 comment",
                                      "  side-effects: email"))
        self.assertIsNone(skill.error)
        self.assertEqual(skill.tags, ["email"])

    def test_gate_keys_at_top_level_are_config_errors(self):
        for key in gate.GATE_KEYS:
            with self.subTest(key=key):
                self.assertIn("not at top level", self.load(frontmatter("name: x", f"{key}: email")).error)

    def test_duplicate_keys_are_config_errors(self):
        self.assertIn("duplicate metadata key",
                      self.load(frontmatter("name: x", "metadata:", "  dry-run: a.py", "  dry-run: b.py")).error)
        self.assertIn("duplicate top-level key metadata",
                      self.load(frontmatter("name: x", "metadata:", "  a: b", "other: 1", "metadata:")).error)

    def test_indented_line_before_first_key_is_config_error(self):
        self.assertIn("before the first", self.load(frontmatter("  metadata:", "    side-effects: email")).error)

    def test_column_zero_non_key_line_is_config_error(self):
        for line in ("- item", "just text", '"metadata": x', "metadata :"):
            with self.subTest(line=line):
                self.assertIn("top-level 'key:'", self.load(frontmatter("name: x", line)).error)

    def test_inline_metadata_value_is_config_error(self):
        self.assertIn("block", self.load(frontmatter("name: x", "metadata: {side-effects: email}")).error)

    def test_metadata_block_ends_at_next_top_level_key(self):
        skill = self.load(frontmatter("metadata:", "  side-effects: email", "license: MIT", "  - indented under license"))
        self.assertIsNone(skill.error)
        self.assertEqual(skill.tags, ["email"])

    def test_multiline_or_missing_name_uses_dir_name(self):
        for lines in (("name: >", "  folded name"), ("name:",), ("name: first", "  second"), ("description: x",)):
            with self.subTest(lines=lines):
                self.assertEqual(self.load(frontmatter(*lines), name="dir-name").name, "dir-name")
        self.assertEqual(self.load(frontmatter('name: "quoted"')).name, "quoted")

    def test_non_utf8_skill_md_is_config_error(self):
        os.makedirs(os.path.join(self.tmp, "skills", "bin"))
        with open(os.path.join(self.tmp, "skills", "bin", "SKILL.md"), "wb") as fh:
            fh.write(b"---\nname: \xff\n---\n")
        self.assertIn("UTF-8", gate.load_skill(os.path.join(self.tmp, "skills", "bin"), self.tmp).error)


# ---------------------------------------------------------------- config rules

class ConfigRuleTests(TempDirCase):
    def meta(self, *lines):
        return self.load(frontmatter("name: x", "metadata:", *lines))

    def test_unknown_tag(self):
        self.assertIn("unknown side-effects tag(s) fax", self.meta("  side-effects: email fax").error)
        self.assertIn("unknown", self.meta("  side-effects: Email").error)

    def test_none_with_another_tag(self):
        self.assertIn("cannot be combined", self.meta("  side-effects: none,email").error)

    def test_spaces_and_commas_separate_tags(self):
        self.assertEqual(self.meta('  side-effects: "spend, social  sms,email"').tags, ["spend", "social", "sms", "email"])

    def test_every_closed_set_tag_is_accepted(self):
        self.assertEqual(self.meta("  side-effects: " + " ".join(gate.TAGS)).tags, list(gate.TAGS))

    def test_untagged_values(self):
        for line in ("  side-effects: none", '  side-effects: ""', "  side-effects:", "  author: someone"):
            with self.subTest(line=line):
                skill = self.meta(line)
                self.assertIsNone(skill.error)
                self.assertFalse(skill.tagged)

    def test_legacy_writes_read_as_side_effects(self):
        self.assertEqual(self.meta("  writes: spend").tags, ["spend"])
        self.assertEqual(self.meta("  writes: social").tags, ["social"])
        self.assertEqual(self.meta("  writes: none").tags, [])

    def test_writes_and_side_effects_together(self):
        self.assertIn("both writes", self.meta("  writes: spend", "  side-effects: spend").error)

    def test_secret_names_are_validated(self):
        self.assertEqual(self.meta("  dry-run-secrets: A_KEY, B_TOKEN C").secrets, ["A_KEY", "B_TOKEN", "C"])
        self.assertIn("not an environment variable name", self.meta("  dry-run-secrets: 9LIVES").error)
        for reserved in ("HOME", "PATH", "PYTHONPATH", "TMPDIR"):
            with self.subTest(reserved=reserved):
                self.assertIn("set by the gate", self.meta(f"  dry-run-secrets: {reserved}").error)

    def test_dry_run_args_are_shlex_split(self):
        self.assertEqual(self.meta("  dry-run-args: \"--name 'a b' --n 2\"").args, ["--name", "a b", "--n", "2"])
        self.assertIn("dry-run-args", self.meta("  dry-run-args: \"--name 'open\"").error)


# ---------------------------------------------------------------- discovery

class DiscoveryTests(TempDirCase):
    def test_root_and_skills_patterns(self):
        self.write("SKILL.md", frontmatter("name: root"))
        self.write("skills/b/SKILL.md", frontmatter("name: b"))
        self.write("skills/a/SKILL.md", frontmatter("name: a"))
        self.write("skills/c/README.md", "no skill here")
        self.write("skills/a/nested/skills/d/SKILL.md", frontmatter("name: d"))
        found = gate.discover([self.tmp])
        self.assertEqual([os.path.relpath(p, self.tmp) for p, _ in found], [".", "skills/a", "skills/b"])
        self.assertTrue(all(root == os.path.abspath(self.tmp) for _, root in found))

    def test_missing_path_is_exit_2(self):
        with self.assertRaises(gate.GateError) as ctx:
            gate.discover([os.path.join(self.tmp, "nope")])
        self.assertEqual(ctx.exception.code, 2)

    def test_path_without_skills_is_exit_2(self):
        self.write("skills/x/README.md", "")
        report, _, err = self.run_gate()
        self.assertEqual(report.exit, 2)
        self.assertIn("no SKILL.md", err)

    def test_same_skill_named_twice_runs_once(self):
        self.write("skills/a/SKILL.md", frontmatter("name: a"))
        report, _, _ = self.run_gate(paths=[self.tmp, os.path.join(self.tmp, "skills", "a")])
        self.assertEqual(len(report.results), 1)


# ---------------------------------------------------------------- canary decoder

class CanaryTests(unittest.TestCase):
    CANARY = "dryrungate-canary-0123456789abcdef"

    def find(self, text):
        return gate.find_canaries(text.encode(), {"KEY": self.CANARY})

    def test_literal(self):
        self.assertEqual(self.find(f"token={self.CANARY}"), [("KEY", "literal")])

    def test_standard_base64(self):
        token = base64.b64encode(("user:" + self.CANARY).encode()).decode()
        self.assertEqual(self.find(f"Authorization: Basic {token}"), [("KEY", "base64")])

    def test_urlsafe_base64_without_padding(self):
        token = base64.urlsafe_b64encode(b"\xfb\xff" + self.CANARY.encode()).decode().rstrip("=")
        self.assertTrue("-" in token or "_" in token)
        self.assertEqual(self.find(f"jwt {token}"), [("KEY", "base64")])

    def test_base64_glued_to_other_characters(self):
        token = base64.b64encode(("u:" + self.CANARY).encode()).decode()
        self.assertEqual(self.find(f"BasicX{token}"), [("KEY", "base64")])
        self.assertEqual(self.find(f"auth={token}&x=1"), [("KEY", "base64")])
        # an "=" at the 4th position of a quantum stops a lenient decode at every offset;
        # only decoding the piece after the "=" finds the canary
        self.assertEqual(self.find(f"xyz=w{token}"), [("KEY", "base64")])

    def test_every_offset_of_the_canary(self):
        for prefix in ("", "a", "ab", "abc"):
            with self.subTest(prefix=prefix):
                token = base64.b64encode((prefix + self.CANARY).encode()).decode()
                self.assertEqual(self.find(token), [("KEY", "base64")])

    def test_no_false_positive(self):
        other = base64.b64encode(b"dryrungate-canary-ffffffffffffffff").decode()
        self.assertEqual(self.find(f"DRY RUN {other} {'A' * 64} short=abc"), [])

    def test_several_canaries(self):
        found = gate.find_canaries(b"a=" + base64.b64encode(b"x" + self.CANARY.encode()) + b" dryrungate-canary-ffffffffffffffff",
                                   {"A": self.CANARY, "B": "dryrungate-canary-ffffffffffffffff"})
        self.assertEqual(sorted(found), [("A", "base64"), ("B", "literal")])


# ---------------------------------------------------------------- guard internals

class GuardTests(TempDirCase):
    def setUp(self):
        super().setUp()
        self.log = os.path.join(self.tmp, "guard.log")
        self.guard = gate.Guard(self.log)
        self.addCleanup(os.close, self.guard.fd)
        self.sockets = []

    def tearDown(self):
        for sock in self.sockets:
            sock.close()

    def sock(self, family=socket.AF_INET, kind=socket.SOCK_STREAM):
        sock = socket.socket(family, kind)
        self.sockets.append(sock)
        return sock

    def events(self):
        return gate.read_guard_log(self.log)

    def assert_blocked(self, event, args, detail):
        with self.assertRaises(PermissionError):
            self.guard.hook(event, args)
        blocked, _, error = self.events()
        self.assertIsNone(error)
        self.assertEqual(blocked[-1], {"kind": "blocked", "event": event, "detail": detail})

    def test_is_loopback(self):
        for host in ("127.0.0.1", "127.8.9.10", "::1", "localhost", b"127.0.0.1"):
            self.assertTrue(gate.is_loopback(host), host)
        for host in ("192.0.2.1", "0.0.0.0", "", "::ffff:127.0.0.1", "LOCALHOST", "127.1", "example.com", None):
            self.assertFalse(gate.is_loopback(host), host)

    def test_connect_to_remote_is_blocked(self):
        self.assert_blocked("socket.connect", (self.sock(), ("192.0.2.1", 443)), "192.0.2.1:443")

    def test_connect_to_own_loopback_port_is_allowed(self):
        server = self.sock()
        self.guard.hook("socket.bind", (server, ("127.0.0.1", 0)))
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        self.guard.hook("socket.connect", (self.sock(), ("127.0.0.1", port)))
        self.guard.hook("socket.sendto", (self.sock(kind=socket.SOCK_DGRAM), ("localhost", port)))
        self.assertEqual(self.events()[0], [])

    def test_connect_to_loopback_port_bound_elsewhere_is_blocked(self):
        other = self.sock()
        other.bind(("127.0.0.1", 0))  # bound without the hook seeing it, like a port the parent owns
        port = other.getsockname()[1]
        self.assert_blocked("socket.connect", (self.sock(), ("127.0.0.1", port)), f"127.0.0.1:{port}")

    def test_bind_to_wildcard_does_not_whitelist_its_port(self):
        server = self.sock()
        self.guard.hook("socket.bind", (server, ("0.0.0.0", 0)))
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        self.assert_blocked("socket.connect", (self.sock(), ("127.0.0.1", port)), f"127.0.0.1:{port}")

    def test_closed_bound_socket_no_longer_counts(self):
        server = self.sock()
        self.guard.hook("socket.bind", (server, ("127.0.0.1", 0)))
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.close()
        self.assert_blocked("socket.connect", (self.sock(), ("127.0.0.1", port)), f"127.0.0.1:{port}")

    def test_sendmsg_without_address_and_unix_sockets_are_allowed(self):
        self.guard.hook("socket.sendmsg", (self.sock(kind=socket.SOCK_DGRAM), None))
        self.guard.hook("socket.connect", (self.sock(family=socket.AF_UNIX), "/tmp/some.sock"))
        self.assertEqual(self.events()[0], [])

    def test_sendto_remote_is_blocked(self):
        self.assert_blocked("socket.sendto", (self.sock(kind=socket.SOCK_DGRAM), ("192.0.2.1", 9)), "192.0.2.1:9")

    def test_dns_allow_list(self):
        for args in (("localhost", 80, 0, 0, 0), ("127.0.0.1", 80, 0, 0, 0), ("::1", 80, 0, 0, 0)):
            self.guard.hook("socket.getaddrinfo", args)
        self.assert_blocked("socket.getaddrinfo", ("example.com", 443, 0, 0, 0), "example.com")
        self.assert_blocked("socket.getaddrinfo", ("127.0.0.2", 443, 0, 0, 0), "127.0.0.2")
        self.assert_blocked("socket.getaddrinfo", (None, 443, 0, 0, 0), "None")
        self.assert_blocked("socket.gethostbyname", ("example.com",), "example.com")
        self.assert_blocked("socket.gethostbyaddr", ("192.0.2.1",), "192.0.2.1")
        self.assert_blocked("socket.getnameinfo", (("192.0.2.1", 80),), "192.0.2.1")

    def test_process_events_are_always_blocked_with_basename_only(self):
        self.assert_blocked("subprocess.Popen", ("/usr/bin/curl", ["/usr/bin/curl", "-H", "secret"], None, {"K": "v"}), "curl")
        self.assert_blocked("subprocess.Popen", (None, ["git", "push"], None, None), "git")
        self.assert_blocked("os.system", (b"curl -d secret https://x",), "curl")
        self.assert_blocked("os.exec", ("/bin/sh", ["sh", "-c", "x"], None), "sh")
        self.assert_blocked("os.posix_spawn", ("/usr/bin/true", ["true"], {}), "true")
        self.assert_blocked("os.spawn", (0, "/usr/bin/true", ["true"], {}), "true")
        self.assert_blocked("os.fork", (), "")
        self.assert_blocked("os.forkpty", (), "")
        with open(self.log) as fh:
            self.assertNotIn("secret", fh.read())

    def test_fork_exec_audit_event_is_blocked(self):
        # the event's arguments are (executable_list, argv, env) where Python raises it (D17)
        self.assert_blocked(gate.FORK_EXEC, ([b"/usr/bin/python3"], [b"python3", "-c", "secret"], None), "python3")
        self.assert_blocked(gate.FORK_EXEC, ([], ["/usr/bin/true"], None), "true")

    def test_fork_exec_wrapper_blocks_multiprocessing_spawn_path(self):
        import _posixsubprocess
        import multiprocessing.util
        original = gate.install_fork_exec_wrapper(self.guard)
        self.addCleanup(setattr, _posixsubprocess, "fork_exec", original)
        self.assertIsNot(_posixsubprocess.fork_exec, original)
        with self.assertRaises(PermissionError):
            multiprocessing.util.spawnv_passfds(os.fsencode(shutil.which("true") or "/usr/bin/true"),
                                                [b"true", b"secret"], ())
        blocked, _, error = self.events()
        self.assertIsNone(error)
        self.assertEqual(blocked, [{"kind": "blocked", "event": gate.FORK_EXEC, "detail": "true"}])

    def test_ctypes_dlopen_is_a_note_not_a_block(self):
        self.guard.hook("ctypes.dlopen", ("libc.so.6",))
        blocked, notes, error = self.events()
        self.assertEqual((blocked, error), ([], None))
        self.assertEqual(notes, [{"kind": "note", "event": "ctypes.dlopen", "detail": "libc.so.6"}])

    def test_unhooked_events_are_ignored(self):
        self.guard.hook("urllib.Request", ("https://x", None, {}, "POST"))
        self.guard.hook("open", ("/etc/hosts", "r", 0))
        self.assertFalse(os.path.getsize(self.log))

    def test_unreadable_arguments_fail_closed(self):
        self.assert_blocked("socket.getaddrinfo", (), "None")
        self.assert_blocked("socket.connect", (object(), ("192.0.2.1", 1)), "address family None")
        self.assert_blocked("socket.connect", (self.sock(),), "unreadable arguments")


class GuardLogTests(TempDirCase):
    def log(self, data):
        path = os.path.join(self.tmp, "guard.log")
        with open(path, "wb") as fh:
            fh.write(data)
        return gate.read_guard_log(path)

    def test_missing_log_is_an_error(self):
        self.assertEqual(gate.read_guard_log(os.path.join(self.tmp, "absent"))[2], "guard log missing")

    def test_empty_log_is_clean(self):
        self.assertEqual(self.log(b""), ([], [], None))

    def test_blocked_and_note_lines(self):
        blocked, notes, error = self.log(
            b'{"kind": "blocked", "event": "os.fork", "detail": ""}\n'
            b'{"kind": "note", "event": "loopback", "detail": "up"}\n')
        self.assertIsNone(error)
        self.assertEqual([b["event"] for b in blocked], ["os.fork"])
        self.assertEqual([n["detail"] for n in notes], ["up"])

    def test_unparseable_lines_are_errors(self):
        for data in (b"not json\n", b'{"kind": "other", "event": "x", "detail": ""}\n',
                     b'{"kind": "note", "event": "x"}\n', b'{"kind": "note", "event": "x", "detail": 1}\n',
                     b'{"kind": "note", "event": "x", "detail": "", "more": 1}\n', b"\n\n", b"[]\n", b"\xff\n"):
            with self.subTest(data=data):
                self.assertIn("unparseable", self.log(data)[2])


# ---------------------------------------------------------------- H1 matcher

class H1Tests(unittest.TestCase):
    def hits(self, source):
        return [what for _, what in gate.h1_hits(ast.parse(source))]

    def test_send_library_imports(self):
        self.assertEqual(self.hits("import smtplib"), ["import smtplib"])
        self.assertEqual(self.hits("from twilio.rest import Client"), ["import twilio.rest"])
        self.assertEqual(self.hits("import tweepy as t"), ["import tweepy"])
        self.assertEqual(self.hits("from . import smtplib"), [])

    def test_http_write_methods_need_an_http_import(self):
        self.assertEqual(len(self.hits("import requests\nrequests.post('u')")), 1)
        self.assertEqual(len(self.hits("from httpx import Client\nClient().put('u')")), 1)
        self.assertEqual(len(self.hits("import aiohttp\ns.request('GET', 'u')\ns.delete('u')")), 2)
        self.assertEqual(self.hits("session.post('u')"), [])
        self.assertEqual(self.hits("import requests\nrequests.get('u')"), [])

    def test_urlopen_with_data(self):
        self.assertEqual(len(self.hits("urlopen(req, b'x')")), 1)
        self.assertEqual(len(self.hits("import urllib.request\nurllib.request.urlopen(u, data=b'x')")), 1)
        self.assertEqual(self.hits("urlopen(req)"), [])
        self.assertEqual(self.hits("urlopen(req, timeout=3)"), [])

    def test_request_with_data_or_write_method(self):
        self.assertEqual(len(self.hits("Request(u, data=b'x')")), 1)
        self.assertEqual(len(self.hits("urllib.request.Request(u, method='DELETE')")), 1)
        self.assertEqual(self.hits("Request(u, method='GET')"), [])
        self.assertEqual(self.hits("Request(u)"), [])

    def test_git_push_and_gh_release(self):
        self.assertEqual(len(self.hits("cmd = 'git push origin main'")), 1)
        self.assertEqual(len(self.hits("run(['git', 'push', remote])")), 1)
        self.assertEqual(len(self.hits("run(('gh', 'release', 'create'))")), 1)
        self.assertEqual(self.hits("run(['git', 'status'])"), [])
        self.assertEqual(self.hits("# git push\nx = 1"), [])

    def test_hits_are_sorted_by_line(self):
        lines = [line for line, _ in gate.h1_hits(ast.parse("import smtplib\n\nx = 'gh release'\nimport tweepy"))]
        self.assertEqual(lines, [1, 3, 4])


# ---------------------------------------------------------------- A1 heading

class DryRunSectionTests(unittest.TestCase):
    def test_heading_rules(self):
        cases = [
            (["## Dry run", "", "Ask first."], True),
            (["## DRY RUN  ", "text"], True),
            (["## Dry run", "", "## Next", "text"], False),
            (["## Dry run", "   "], False),
            (["### Dry run", "text"], False),
            (["## Dry-run", "text"], False),
            (["## Usage", "text"], False),
        ]
        for body, expected in cases:
            with self.subTest(body=body):
                self.assertIs(gate.has_dry_run_section(body), expected)


# ---------------------------------------------------------------- checks, end to end

class CheckTests(TempDirCase):
    def test_p0_pass_and_fail(self):
        gate.st_skill(self.tmp, "ok", meta=None)
        gate.st_skill(self.tmp, "bad", meta=(("side-effects", "fax"),))
        report, _, _ = self.run_gate()
        self.assertEqual(self.status(report, "P0", "ok"), gate.PASS)
        self.assertEqual(self.status(report, "P0", "bad"), gate.FAIL)
        self.assertEqual([c.id for c in self.checks(report, "P0", "bad")], ["P0"])
        self.assertEqual(report.exit, 2)

    def test_p1_pass_and_fail(self):
        gate.st_skill(self.tmp, "ok", meta=None, files={"a.py": "x = 1\n", "sub/b.py": "def f():\n    return 2\n"})
        gate.st_skill(self.tmp, "bad", meta=None, files={"sub/c.py": "def f():\nreturn 2\n",
                                                          "d.py": "return 1\n"})
        report, _, _ = self.run_gate()
        self.assertEqual(self.status(report, "P1", "ok"), gate.PASS)
        self.assertEqual(self.status(report, "P1", "bad"), gate.FAIL)
        self.assertIn("sub/c.py:2", self.detail(report, "P1", "bad"))
        self.assertIn("d.py:1", self.detail(report, "P1", "bad"))  # compile(), not just ast.parse()
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "skills", "ok", "__pycache__")))

    def test_d0_pass_and_fail(self):
        gate.st_path_skill(self.tmp, "ok")
        gate.st_skill(self.tmp, "none", meta=(("side-effects", "sms"), ("dry-run", "")))
        report, _, _ = self.run_gate()
        self.assertEqual(self.status(report, "D0", "ok"), gate.PASS)
        self.assertEqual(self.status(report, "D0", "none"), gate.FAIL)
        self.assertEqual({c.status for c in self.checks(report, "R1", "none")}, {gate.SKIP})

    def test_s1_pass_and_fail(self):
        gate.st_path_skill(self.tmp, "ok")
        abs_meta = (gate.ST_META[0], ("dry-run", "/usr/bin/send.py")) + gate.ST_META[2:]
        gate.st_path_skill(self.tmp, "absolute", meta=abs_meta)
        missing = (gate.ST_META[0], ("dry-run", "scripts/missing.py")) + gate.ST_META[2:]
        gate.st_path_skill(self.tmp, "missing", meta=missing)
        gate.st_path_skill(self.tmp, "unparseable", files={"scripts/send.py": "def (:\n"})
        report, _, _ = self.run_gate()
        self.assertEqual(self.status(report, "S1", "ok"), gate.PASS)
        self.assertIn("relative", self.detail(report, "S1", "absolute"))
        self.assertIn("not found", self.detail(report, "S1", "missing"))
        self.assertIn("cannot parse", self.detail(report, "S1", "unparseable"))
        for name in ("absolute", "missing", "unparseable"):
            self.assertEqual(self.status(report, "R2", name), gate.SKIP)

    def test_s2_pass_and_fail(self):
        gate.st_path_skill(self.tmp, "ok")
        gate.st_path_skill(self.tmp, "no-flag", files={"test_dry_run.py": "import unittest\n"})
        gate.st_path_skill(self.tmp, "no-key", meta=gate.ST_META[:2] + gate.ST_META[3:])
        report, _, _ = self.run_gate()
        self.assertEqual(self.status(report, "S2", "ok"), gate.PASS)
        self.assertIn("no \"--dry-run\"", self.detail(report, "S2", "no-flag"))
        self.assertIn("no metadata dry-run-test", self.detail(report, "S2", "no-key"))
        self.assertEqual(self.status(report, "R1", "no-flag"), gate.SKIP)

    def test_r1_pass_and_fail(self):
        gate.st_path_skill(self.tmp, "ok")
        gate.st_path_skill(self.tmp, "crash", before="raise RuntimeError('boom')")
        gate.st_path_skill(self.tmp, "killed", before="import signal\nos.kill(os.getpid(), signal.SIGKILL)")
        gate.st_path_skill(self.tmp, "stderr-canary", before=f"sys.stderr.write(os.environ['{gate.ST_SECRET}'])")
        report, out, _ = self.run_gate()
        self.assertEqual(self.status(report, "R1", "ok"), gate.PASS)
        self.assertIn(gate.ST_BANNER, out)  # the preview is shown in the log (D14)
        self.assertIn("exit 1", self.detail(report, "R1", "crash"))
        self.assertIn("RuntimeError: boom", out)
        self.assertIn("killed by signal 9", self.detail(report, "R1", "killed"))
        self.assertIn("in stderr (literal)", self.detail(report, "R1", "stderr-canary"))

    def test_r1_blocks_fork_exec_reached_without_subprocess(self):
        spawn = ("import multiprocessing.util\nimport shutil\n"
                 + gate.swallow('multiprocessing.util.spawnv_passfds(os.fsencode(shutil.which("true")), [b"true"], ())'))
        gate.st_path_skill(self.tmp, "spawnv", before=spawn)
        report, out, _ = self.run_gate()
        self.assertEqual(self.status(report, "R1"), gate.FAIL, out)
        self.assertIn(f"{gate.FORK_EXEC} true", self.detail(report, "R1"))

    def test_child_is_isolated_and_writes_no_bytecode(self):
        # D18: python -I, sys.dont_write_bytecode, PYTHONPATH entries first and in order
        checks = ("import sys\n"
                  "assert sys.flags.isolated == 1, sys.flags\n"
                  "assert sys.dont_write_bytecode is True\n"
                  "entries = os.environ['PYTHONPATH'].split(os.pathsep)\n"
                  "assert sys.path[:len(entries)] == entries, sys.path\n"
                  "assert not any(os.path.isfile(os.path.join(p or '.', 'dry_run_gate.py')) for p in sys.path), sys.path\n")
        test = ("import os\nimport sys\nimport unittest\n\nimport tests.helper_module\n\n\n"
                "class T(unittest.TestCase):\n    def test(self):\n"
                + "".join(f"        {line}\n" for line in checks.splitlines())
                + "        self.assertTrue('--dry-run')\n")
        meta = gate.ST_META[:2] + (("dry-run-test", "tests/test_dry_run.py"),) + gate.ST_META[3:]
        skill_dir = gate.st_path_skill(self.tmp, "isolated", before="import helper\n" + checks, meta=meta, files={
            "scripts/helper.py": "", "tests/__init__.py": "", "tests/helper_module.py": "",
            "tests/test_dry_run.py": test})
        report, out, _ = self.run_gate()
        self.assertEqual(self.status(report, "R1"), gate.PASS, out)
        self.assertEqual(self.status(report, "R2"), gate.PASS, out)
        caches = [os.path.join(d, n) for d, dirs, _ in os.walk(skill_dir) for n in dirs if n == "__pycache__"]
        self.assertEqual(caches, [])

    def test_r1_runs_with_args_cwd_and_import_path(self):
        meta = gate.ST_META + (("dry-run-args", "--n 'two words'"),)
        allowed = set(gate.CHILD_ENV_COPIED + gate.CHILD_ENV_SET + (gate.ST_SECRET,))
        allowed.add("__CF_USER_TEXT_ENCODING")  # set inside the child by macOS CoreFoundation
        before = ("import helper\n"
                  "assert argv == ['--dry-run', '--n', 'two words'], argv\n"
                  "assert os.getcwd() == os.path.realpath(os.path.dirname(os.path.dirname(__file__)))\n"
                  f"assert set(os.environ) <= set({sorted(allowed)!r}), sorted(os.environ)\n"
                  "assert os.path.dirname(os.environ['HOME']) == os.path.dirname(os.environ['TMPDIR'])\n"
                  "assert os.environ['HOME'] != os.environ['TMPDIR']\n"
                  "assert not os.listdir(os.environ['HOME'])\n"
                  "assert os.environ['PYTHONNOUSERSITE'] == os.environ['PYTHONDONTWRITEBYTECODE'] == '1'\n"
                  f"assert os.environ['{gate.ST_SECRET}'].startswith('dryrungate-canary-')")
        gate.st_path_skill(self.tmp, "args", before=before, meta=meta, files={"scripts/helper.py": ""})
        report, out, _ = self.run_gate()
        self.assertEqual(self.status(report, "R1"), gate.PASS, out)

    def test_r2_pass_and_fail(self):
        gate.st_path_skill(self.tmp, "ok")
        failing = 'import unittest\n\n\nclass T(unittest.TestCase):\n    def test(self):\n        self.fail("--dry-run")\n'
        gate.st_path_skill(self.tmp, "failing-test", files={"test_dry_run.py": failing})
        network = ("import socket\nimport unittest\n\n\nclass T(unittest.TestCase):\n    def test(self):\n"
                   "        try:\n            socket.getaddrinfo('example.com', 443)\n        except OSError:\n"
                   "            pass\n        self.assertTrue('--dry-run')\n")
        gate.st_path_skill(self.tmp, "network-test", files={"test_dry_run.py": network})
        report, _, _ = self.run_gate()
        self.assertEqual(self.status(report, "R2", "ok"), gate.PASS)
        self.assertEqual(self.status(report, "R1", "failing-test"), gate.PASS)
        self.assertIn("exit 1", self.detail(report, "R2", "failing-test"))
        self.assertIn("socket.getaddrinfo example.com", self.detail(report, "R2", "network-test"))

    def test_r2_pytest_runner(self):
        fake = ("import sys\n"
                "print('fake pytest', sys.argv[1:])\n"
                "raise SystemExit(0 if sys.argv[1:] == ['test_dry_run.py'] else 5)\n")
        gate.st_path_skill(self.tmp, "pytest", files={"pytest/__init__.py": "", "pytest/__main__.py": fake})
        with mock.patch.object(gate, "pytest_importable", return_value=True):
            report, out, _ = self.run_gate("--runner", "pytest")
        self.assertEqual(self.status(report, "R2"), gate.PASS, out)
        with mock.patch.object(gate, "pytest_importable", return_value=False):
            report, _, err = self.run_gate("--runner", "pytest")
        self.assertEqual(report.exit, 2)
        self.assertIn("pytest cannot be imported", err)

    def test_a1_unverified_and_fail(self):
        gate.st_skill(self.tmp, "ok", meta=gate.AGENT_META, body="## Dry run\nShow the draft first.\n")
        gate.st_skill(self.tmp, "empty", meta=gate.AGENT_META, body="## Dry run\n\n## Usage\nx\n")
        report, _, _ = self.run_gate()
        self.assertEqual(self.status(report, "A1", "ok"), gate.UNVERIFIED)
        self.assertEqual(self.status(report, "A1", "empty"), gate.FAIL)
        self.assertFalse(self.checks(report, "R1", "ok"))

    def test_h1_pass_and_warn(self):
        gate.st_skill(self.tmp, "quiet", meta=None, files={"a.py": "import json\n"})
        gate.st_skill(self.tmp, "loud", meta=None, files={
            "a.py": "import requests\nrequests.post('https://x')\n",
            "b.py": "import subprocess\nsubprocess.run(['git', 'push'])\n",
            "c.py": "x = 1\n"})
        report, _, _ = self.run_gate()
        self.assertEqual(self.status(report, "H1", "quiet"), gate.PASS)
        warns = self.checks(report, "H1", "loud")
        self.assertEqual([c.status for c in warns], [gate.WARN, gate.WARN])
        self.assertTrue(warns[0].detail.startswith("a.py: L2"))
        self.assertTrue(warns[1].detail.startswith("b.py: L2"))
        self.assertEqual(report.exit, 0)

    def test_h1_ignores_tagged_skills(self):
        gate.st_path_skill(self.tmp, "tagged", files={"scripts/notify.py": "import smtplib\n"})
        report, _, _ = self.run_gate()
        self.assertFalse(self.checks(report, "H1"))

    def test_c1_pass_and_warn(self):
        gate.st_path_skill(self.tmp, "plain")
        gate.st_path_skill(self.tmp, "ctypes", before="import ctypes")
        report, _, _ = self.run_gate()
        self.assertEqual(self.status(report, "C1", "plain"), gate.PASS)
        self.assertEqual(self.status(report, "C1", "ctypes"), gate.WARN)
        self.assertIn("ctypes.dlopen: None", self.detail(report, "C1", "ctypes"))
        self.assertEqual(self.status(report, "R1", "ctypes"), gate.PASS)
        self.assertEqual(report.exit, 0)
        report, _, _ = self.run_gate("--strict")
        self.assertEqual(self.status(report, "C1", "ctypes"), gate.FAIL)
        self.assertEqual(report.exit, 1)

    def test_skill_tests_package_wins_over_the_gate_tests_package(self):
        # sys.path[0] is the skill dir in the child, not dry-run-gate's dir (R46)
        meta = gate.ST_META[:2] + (("dry-run-test", "tests/test_dry_run.py"),) + gate.ST_META[3:]
        test = "import unittest\nimport tests.marker\n\n\nclass T(unittest.TestCase):\n    def test(self):\n        self.assertTrue('--dry-run')\n"
        gate.st_path_skill(self.tmp, "pkg", meta=meta, files={
            "tests/__init__.py": "", "tests/marker.py": "", "tests/test_dry_run.py": test})
        report, out, _ = self.run_gate()
        self.assertEqual(self.status(report, "R2"), gate.PASS, out)


# ---------------------------------------------------------------- exit codes and CLI

class ExitCodeTests(TempDirCase):
    def test_config_error_beats_fail(self):
        gate.st_skill(self.tmp, "a", meta=(("side-effects", "fax"),))
        gate.st_path_skill(self.tmp, "b", code=1)
        report, _, _ = self.run_gate()
        self.assertEqual(report.exit, 2)
        self.assertEqual(self.status(report, "R1", "b"), gate.FAIL)

    def test_isolation_error_beats_config_error(self):
        if gate.netns_unshare():
            self.skipTest("unshare -rn works here")
        report, _, _ = self.run_gate("--isolation", "netns", paths=[os.path.join(self.tmp, "missing")])
        self.assertEqual(report.exit, 3)

    def test_fail_and_warn_and_unverified(self):
        gate.st_skill(self.tmp, "warn", meta=None, files={"a.py": "import smtplib\n"})
        gate.st_skill(self.tmp, "agent", meta=gate.AGENT_META, body="## Dry run\nAsk.\n")
        self.assertEqual(self.run_gate()[0].exit, 0)
        self.assertEqual(self.run_gate("--strict")[0].exit, 1)
        self.assertEqual(self.run_gate("--forbid-agent-confirm")[0].exit, 1)
        report = self.run_gate("--strict")[0]
        self.assertEqual(self.status(report, "A1"), gate.UNVERIFIED)  # --strict does not affect A1 (D8)

    def test_usage_errors_are_exit_2(self):
        gate.st_skill(self.tmp, "ok", meta=None)
        for argv in (["--bogus"], ["--timeout", "0"], ["--timeout", "nan"], ["--isolation", "jail"],
                     ["--selftest"], ["--list", "--json"], ["--str"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.run_gate(*argv)[0].exit, 2)

    def test_audit_isolation_is_reported(self):
        gate.st_skill(self.tmp, "ok", meta=None)
        report, out, _ = self.run_gate("--isolation", "audit")
        self.assertEqual(report.isolation, "audit")
        self.assertIn("isolation: audit", out)
        self.assertNotIn("loopback:", out)

    def test_guard_usage_error(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(gate.main(["--_guard", "log"]), 2)
            self.assertEqual(gate.main(["--_guard", "log", "--", "-m"]), 2)

    def test_loopback_summary_fails_closed(self):
        self.assertEqual(gate.summarize_loopback(["up", "up"]), "up")
        self.assertEqual(gate.summarize_loopback(["up", "down"]), "down")
        self.assertEqual(gate.summarize_loopback([]), "down")


class CliTests(TempDirCase):
    def test_list_runs_nothing(self):
        before = "open(os.path.join(os.path.dirname(__file__), 'ran'), 'w').close()"
        gate.st_path_skill(self.tmp, "entry", before=before)
        gate.st_skill(self.tmp, "plain", meta=None)
        report, out, _ = self.run_gate("--list")
        self.assertEqual(report.exit, 0)
        self.assertIn("name: entry  tags: email  dry-run: scripts/send.py", out)
        self.assertIn("name: plain  tags: none  dry-run: -", out)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "skills", "entry", "scripts", "ran")))

    def test_list_reports_config_errors(self):
        gate.st_skill(self.tmp, "bad", meta=(("side-effects", "fax"),))
        report, out, _ = self.run_gate("--list")
        self.assertEqual(report.exit, 2)
        self.assertIn("config error", out)

    def test_json_goes_to_stdout_alone(self):
        gate.st_path_skill(self.tmp, "ok")
        report, out, err = self.run_gate("--json")
        data = json.loads(out)
        self.assertEqual(set(data), {"skills", "isolation", "loopback", "exit"})
        self.assertEqual(set(data["skills"][0]), {"path", "name", "tags", "checks"})
        self.assertEqual(set(data["skills"][0]["checks"][0]), {"id", "status", "detail"})
        self.assertEqual([c["id"] for c in data["skills"][0]["checks"]], ["P0", "P1", "D0", "S1", "S2", "R1", "R2", "C1"])
        self.assertEqual((data["exit"], data["isolation"]), (0, report.isolation))
        self.assertIn(f"isolation: {report.isolation}", err)

    def test_json_on_error(self):
        report, out, _ = self.run_gate("--json", paths=[os.path.join(self.tmp, "missing")])
        self.assertEqual(json.loads(out)["exit"], 2)


# ---------------------------------------------------------------- template and repo fixtures

class TemplateTests(TempDirCase):
    def constant_lines(self, path):
        with open(path) as fh:
            return [line for line in fh.read().splitlines() if line.split(" = ")[0] in CONSTANT_NAMES]

    def test_template_constants_are_the_spec_block(self):
        self.assertEqual(self.constant_lines(TEMPLATE), [
            'ENTRY = "scripts/send.py"          # relative to the skill dir',
            'ARGS = ["--campaign", "tests/fixtures/campaign.json"]',
            'EXPECT_METHOD = "POST"',
            'EXPECT_URL_PREFIX = "https://a.klaviyo.com/"',
        ])

    def test_fixture_tests_differ_from_template_only_in_constants(self):
        with open(TEMPLATE) as fh:
            template = fh.read().splitlines()
        for fixture in ("pass/skills/email-ok", "fail/skills/testnet-connect"):
            with self.subTest(fixture=fixture):
                with open(os.path.join(FIXTURES, fixture, "tests", "test_dry_run.py")) as fh:
                    copy = fh.read().splitlines()
                changed = [line[1:] for line in difflib.unified_diff(template, copy, lineterm="", n=0)
                           if line[:1] in "+-" and line[:3] not in ("+++", "---")]
                self.assertTrue(changed)
                self.assertTrue(all(line.split(" = ")[0] in CONSTANT_NAMES for line in changed), changed)

    def test_pass_fixture_exits_0_with_r2_pass(self):
        report, out, _ = self.run_gate(paths=[os.path.join(FIXTURES, "pass")])
        self.assertEqual(report.exit, 0, out)
        self.assertEqual(self.status(report, "R2"), gate.PASS)

    def test_fail_fixture_exits_1_naming_testnet(self):
        report, out, _ = self.run_gate(paths=[os.path.join(FIXTURES, "fail")])
        self.assertEqual(report.exit, 1)
        self.assertIn("socket.connect 192.0.2.1:443", self.detail(report, "R1"))
        self.assertEqual(self.status(report, "R2"), gate.FAIL)  # the template catches it too
        self.assertIn("192.0.2.1", out)

    def template_skill(self, name, before="", banner="DRY RUN: would POST https://a.klaviyo.com/api/campaigns"):
        """A skill whose dry-run-test is an unedited copy of the template (run under the gate, so the
        guard backs the template's patches and no packet can leave even if a patch were missing)."""
        meta = gate.ST_META[:2] + (("dry-run-test", "tests/test_dry_run.py"),) + gate.ST_META[3:]
        with open(TEMPLATE) as fh:
            template = fh.read()
        gate.st_path_skill(self.tmp, name, before=before, banner=banner, meta=meta, files={
            "tests/__init__.py": "", "tests/test_dry_run.py": template, "tests/fixtures/campaign.json": "{}"})

    def test_template_passes_a_correct_entry(self):
        self.template_skill("good", banner="dry run: POST https://a.klaviyo.com/api/campaigns")
        report, out, _ = self.run_gate()
        self.assertEqual(self.status(report, "R2"), gate.PASS, out)

    def test_template_catches_each_patched_call(self):
        calls = ("socket.socket().connect(('192.0.2.1', 443))",
                 "socket.create_connection(('192.0.2.1', 443))",
                 "socket.getaddrinfo('example.com', 443)")
        for number, call in enumerate(calls):
            self.template_skill(f"call-{number}", before=gate.swallow(call))
        report, out, _ = self.run_gate()
        for number, call in enumerate(calls):
            with self.subTest(call=call):
                self.assertEqual(self.status(report, "R1", f"call-{number}"), gate.FAIL)
                # the template's own assertion failed it; the guard saw nothing in R2
                self.assertEqual(self.detail(report, "R2", f"call-{number}"), "exit 1", out)

    def test_template_checks_method_url_and_banner(self):
        self.template_skill("no-method", banner="DRY RUN: would send to https://a.klaviyo.com/api")
        self.template_skill("no-url", banner="DRY RUN: would POST https://example.invalid/")
        self.template_skill("no-banner", banner="preview: POST https://a.klaviyo.com/api")
        report, out, _ = self.run_gate()
        for name in ("no-method", "no-url", "no-banner"):
            with self.subTest(name=name):
                self.assertEqual(self.detail(report, "R2", name), "exit 1", out)


if __name__ == "__main__":
    unittest.main()
