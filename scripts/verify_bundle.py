#!/usr/bin/env python3
"""Verify an exported TIGRESS evidence bundle.

Recomputes the evidence hash against the manifest, checks the record count, and
verifies the manifest signature when present — the independent verification step
described in the bundle's chain-of-custody note. Exits non-zero if any check
fails, so it can gate an evidence handoff.

Usage:
    python scripts/verify_bundle.py ./evidence_bundle
"""

import argparse
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.core.evidence import verify_bundle  # noqa: E402


def main():
    """Verify the bundle and print each check; exit 1 on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle_dir", help="Path to the evidence bundle directory")
    parser.add_argument(
        "--public-key", default=None,
        help="Require the bundle to be signed by this base64 public key "
             "(establishes authenticity, not just integrity)",
    )
    args = parser.parse_args()

    report = verify_bundle(args.bundle_dir, expected_public_key=args.public_key)
    for check in report["checks"]:
        mark = "PASS" if check["passed"] else "FAIL"
        print(f"  [{mark}] {check['name']}: {check['detail']}")

    status = "VALID" if report["ok"] else "INVALID"
    print(f"\nBundle {status}", file=sys.stderr)
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
