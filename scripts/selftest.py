#!/usr/bin/env python3
"""Validate TIGRESS against its frozen golden dataset and record the result.

Runs the detection engine over a known dataset, confirms the expected
detections fire, and (by default) writes a versioned validation record —
mirroring the NIJ practice of validating a forensic tool against a known
dataset and retaining the report. Exits non-zero if any check fails, so it can
gate CI or a release.

Usage:
    python scripts/selftest.py [--record-dir data/validation] [--no-record]
"""

import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.core.selftest import run_selftest  # noqa: E402


def main():
    """Run the self-test and print the report; exit 1 on any failed check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record-dir", default="data/validation",
                        help="Where to write the versioned validation record")
    parser.add_argument("--no-record", action="store_true",
                        help="Run the checks without writing a record file")
    args = parser.parse_args()

    report = run_selftest(record_dir=None if args.no_record else args.record_dir)
    print(json.dumps(report, indent=2))

    status = "PASS" if report["ok"] else "FAIL"
    print(f"\nSelf-test {status} "
          f"({sum(c['passed'] for c in report['checks'])}/{len(report['checks'])} checks)",
          file=sys.stderr)
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
