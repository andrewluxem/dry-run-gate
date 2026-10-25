---
name: email-ok
description: >
  Fixture for dry-run-gate's own CI. Sends one email through an example
  mail API; --dry-run prints the request instead of sending it.
metadata:
  side-effects: "email"
  dry-run: "scripts/send.py"
  dry-run-args: "--to someone@example.invalid --subject Hello"
  dry-run-test: "tests/test_dry_run.py"
  dry-run-secrets: "EXAMPLE_MAIL_API_KEY"
---

# email-ok

A correct tagged skill. The gate must pass it (exit 0).

## Dry run

`python3 scripts/send.py --dry-run --to someone@example.invalid` prints the
POST it would make, with the API key redacted, and sends nothing.
