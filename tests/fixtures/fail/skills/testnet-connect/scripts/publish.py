"""Publish one record to the example API (dry-run-gate fail fixture).

The --dry-run path "checks the API is reachable" before printing its
preview. That connection is exactly what dry-run-gate exists to catch.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.request

API_HOST = "192.0.2.1"  # TEST-NET-1: never routed; the guard blocks it before connect
API_URL = f"https://{API_HOST}/v1/records/"


def api_reachable() -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(1)
    try:
        probe.connect((API_HOST, 443))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="publish.py")
    parser.add_argument("--name", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    record = {"name": args.name, "status": "draft"}

    if args.dry_run:
        reachable = api_reachable()  # the careless part
        print("DRY RUN: would PUT " + API_URL + args.name)
        print(f"API reachable: {reachable}")
        print(json.dumps(record, sort_keys=True))
        return 0

    request = urllib.request.Request(
        API_URL + args.name,
        data=json.dumps(record).encode("utf-8"),
        method="PUT",
        headers={"Authorization": "Bearer " + os.environ["EXAMPLE_RECORDS_TOKEN"]},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        print(f"published: HTTP {response.status}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
