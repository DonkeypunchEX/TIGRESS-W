#!/usr/bin/env python3
"""Export a signed, hashed TIGRESS evidence bundle from the forensic log.

Produces a self-contained bundle — evidence records, a separately-stored
SHA-256 manifest, an optional ECDSA signature, and a chain-of-custody note —
following NIST IR 8387 / NIJ digital-evidence-preservation practice.

Usage:
    python scripts/export_evidence.py --out ./evidence_bundle \\
        [--forensic-log data/alerts/forensic.jsonl] \\
        [--since 2026-01-01T00:00:00+00:00] [--until ...] \\
        [--types detection] [--case-id CASE-123] [--sign]
"""

import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.core.evidence import EvidenceExporter  # noqa: E402


def main():
    """Parse arguments and write the evidence bundle."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="Output directory for the bundle")
    parser.add_argument("--forensic-log", default="data/alerts/forensic.jsonl")
    parser.add_argument("--since", default=None, help="ISO timestamp lower bound")
    parser.add_argument("--until", default=None, help="ISO timestamp upper bound")
    parser.add_argument("--types", nargs="*", default=None, help="Event types to include")
    parser.add_argument("--case-id", default=None, help="Case identifier for provenance")
    parser.add_argument(
        "--sign", action="store_true",
        help="Sign the manifest with the node's audit-log ECDSA key",
    )
    parser.add_argument("--audit-dir", default="data/audit", help="Audit key/log directory")
    args = parser.parse_args()

    signer = None
    if args.sign:
        from src.security.audit_log import AuditLog
        signer = AuditLog(log_path=args.audit_dir)

    exporter = EvidenceExporter(args.forensic_log, signer=signer)
    manifest = exporter.export(
        args.out, since=args.since, until=args.until,
        event_types=args.types, case_id=args.case_id,
    )
    print(json.dumps(manifest, indent=2))
    print(f"\nEvidence bundle written to {manifest['output_dir']}", file=sys.stderr)


if __name__ == "__main__":
    main()
