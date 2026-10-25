"""Dry-run test for one skill, from dry-run-gate's templates/test_dry_run.py.

Copy this file to <skill dir>/tests/test_dry_run.py (add an empty
tests/__init__.py next to it) and edit only the four constants below.
The test loads ENTRY by path, blocks the network with patches, calls
main(["--dry-run", *ARGS]) and checks the preview it prints.

Run it from the skill dir:  python -m unittest tests/test_dry_run.py
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import socket
import sys
import unittest
from unittest import mock

ENTRY = "scripts/publish.py"       # relative to the skill dir
ARGS = ["--name", "example"]
EXPECT_METHOD = "PUT"
EXPECT_URL_PREFIX = "https://192.0.2.1/"

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class DryRunTest(unittest.TestCase):
    def test_dry_run_prints_preview_without_network(self):
        calls = []

        def blocked(name):
            def fake(*args, **kwargs):
                calls.append(name)
                raise OSError(f"test_dry_run: network call blocked ({name})")
            return fake

        entry_path = os.path.join(SKILL_DIR, ENTRY)
        entry_dir = os.path.dirname(entry_path)
        module_name = "dry_run_entry_under_test"
        printed = io.StringIO()
        old_cwd = os.getcwd()
        sys.path.insert(0, entry_dir)
        try:
            os.chdir(SKILL_DIR)  # relative ARGS resolve as they do under the gate
            spec = importlib.util.spec_from_file_location(module_name, entry_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            with mock.patch.object(socket.socket, "connect", blocked("socket.socket.connect")), \
                    mock.patch.object(socket, "create_connection", blocked("socket.create_connection")), \
                    mock.patch.object(socket, "getaddrinfo", blocked("socket.getaddrinfo")), \
                    contextlib.redirect_stdout(printed):
                spec.loader.exec_module(module)
                try:
                    code = module.main(["--dry-run", *ARGS])
                except SystemExit as exc:
                    code = exc.code
        finally:
            os.chdir(old_cwd)
            sys.path.remove(entry_dir)
            sys.modules.pop(module_name, None)
        output = printed.getvalue()
        self.assertEqual(code, 0, f"main() must return 0 or raise SystemExit(0)\n{output}")
        self.assertEqual(calls, [], f"network call attempted during --dry-run\n{output}")
        self.assertIn("DRY RUN", output.upper(), "the preview must say DRY RUN")
        self.assertIn(EXPECT_METHOD, output)
        self.assertIn(EXPECT_URL_PREFIX, output)


if __name__ == "__main__":
    unittest.main()
