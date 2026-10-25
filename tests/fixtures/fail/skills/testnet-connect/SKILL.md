---
name: testnet-connect
description: >
  Fixture for dry-run-gate's own CI. Publishes a record to an example API,
  but its --dry-run "checks the API is reachable" first.
metadata:
  side-effects: "remote-write"
  dry-run: "scripts/publish.py"
  dry-run-args: "--name example"
  dry-run-test: "tests/test_dry_run.py"
  dry-run-secrets: "EXAMPLE_RECORDS_TOKEN"
---

# testnet-connect

A careless dry-run: it opens a TCP connection to 192.0.2.1:443 (TEST-NET-1,
RFC 5737) and swallows the error. The gate must fail it (exit 1) and name
192.0.2.1 in its output. The guard blocks the call before any packet leaves.
