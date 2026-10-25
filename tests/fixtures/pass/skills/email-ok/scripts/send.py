"""Send one email through the example mail API (dry-run-gate pass fixture)."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request

API_URL = "https://api.mail.example.invalid/v1/send"


def build_payload(to: str, subject: str) -> dict:
    return {"to": to, "subject": subject, "text": "Hello from the email-ok fixture."}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="send.py")
    parser.add_argument("--to", required=True)
    parser.add_argument("--subject", default="Hello")
    parser.add_argument("--dry-run", action="store_true", help="print the request and send nothing")
    args = parser.parse_args(argv)
    payload = build_payload(args.to, args.subject)

    if args.dry_run:
        print("DRY RUN: would POST " + API_URL)
        print("Authorization: Bearer <EXAMPLE_MAIL_API_KEY redacted>")
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": "Bearer " + os.environ["EXAMPLE_MAIL_API_KEY"],
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        print(f"sent: HTTP {response.status}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
