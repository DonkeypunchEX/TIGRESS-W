"""Forensic evidence export with provenance, hashing, and signatures.

Turns TIGRESS forensic records into a self-contained, tamper-evident evidence
bundle following digital-evidence-preservation practice (NIST IR 8387 §3.2 and
the NIJ Digital Evidence Policies & Procedures Manual):

  * a NIST-approved SHA-256 hash of the evidence, recorded in a **manifest that
    is stored separately** from the data itself;
  * an optional ECDSA signature over that manifest;
  * documented **chain of custody / provenance** — which tool and version
    produced it, on which host, over which capture window, and how.
"""

import hashlib
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.version import __version__

_CHUNK = 65536


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 of a file, read in bounded chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def provenance(extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build the chain-of-custody provenance block for an artifact.

    Records the producing tool and version, the host, and a UTC creation
    timestamp so every artifact is attributable to the software and machine
    that created it.
    """
    prov = {
        "tool": "TIGRESS",
        "version": __version__,
        "host": socket.gethostname(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if extra:
        prov.update(extra)
    return prov


def _record_timestamp(record: Dict[str, Any]) -> Optional[str]:
    """Best-effort extraction of a record's ISO timestamp, if any."""
    data = record.get("data")
    if isinstance(data, dict):
        ts = data.get("timestamp")
        if isinstance(ts, str):
            return ts
    return None


def _parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into a timezone-aware UTC datetime.

    Accepts a trailing ``Z`` and naive timestamps (assumed UTC) so comparisons
    are normalized regardless of the original offset/representation.
    """
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _in_window(
    record: Dict[str, Any], since: Optional[datetime], until: Optional[datetime]
) -> bool:
    """True if the record falls within the [since, until] UTC window.

    Records without a parseable timestamp are always included — they cannot be
    excluded on time and dropping them would lose context. Bounds are compared
    as timezone-aware datetimes, so equivalent instants with different offsets
    match.
    """
    if since is None and until is None:
        return True
    ts = _record_timestamp(record)
    if ts is None:
        return True
    try:
        moment = _parse_ts(ts)
    except ValueError:
        return True
    if since is not None and moment < since:
        return False
    if until is not None and moment > until:
        return False
    return True


class EvidenceExporter:
    """Export forensic records into a signed, hashed evidence bundle."""

    def __init__(self, forensic_log: str, signer: Optional[Any] = None):
        """``signer`` is an optional object exposing ``sign_bytes`` and
        ``public_key_b64`` (e.g. :class:`~src.security.audit_log.AuditLog`)."""
        self.forensic_log = Path(forensic_log)
        self.signer = signer

    def _read_records(
        self, since: Optional[datetime], until: Optional[datetime],
        event_types: Optional[List[str]],
    ) -> List[Dict[str, Any]]:
        # Fail closed: a missing source or a corrupt line must not silently
        # yield an incomplete-but-signed evidence bundle.
        if not self.forensic_log.exists():
            raise FileNotFoundError(f"Forensic log not found: {self.forensic_log}")
        records: List[Dict[str, Any]] = []
        types = set(event_types) if event_types else None
        with open(self.forensic_log) as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"Invalid JSON at {self.forensic_log}:{lineno}: {e}"
                    ) from e
                if not isinstance(rec, dict):
                    raise ValueError(
                        f"Expected a JSON object at {self.forensic_log}:{lineno}"
                    )
                if types is not None and rec.get("type") not in types:
                    continue
                if not _in_window(rec, since, until):
                    continue
                records.append(rec)
        return records

    def export(
        self,
        output_dir: str,
        since: Optional[str] = None,
        until: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        case_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Write an evidence bundle to ``output_dir`` and return its manifest.

        The bundle contains ``evidence.jsonl`` (the selected records),
        ``manifest.json`` (provenance + the separately-stored SHA-256 of both
        the evidence and the custody note), ``manifest.sig`` (present only when
        a signer is configured), and ``CHAIN_OF_CUSTODY.txt`` describing how it
        was produced.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        # A stale signature from a previous export of this directory would make
        # an unsigned (or re-signed) bundle verify against the wrong manifest.
        (out / "manifest.sig").unlink(missing_ok=True)

        since_dt = _parse_ts(since) if since else None
        until_dt = _parse_ts(until) if until else None

        records = self._read_records(since_dt, until_dt, event_types)
        evidence_path = out / "evidence.jsonl"
        with open(evidence_path, "w") as f:
            for rec in records:
                f.write(json.dumps(rec, sort_keys=True) + "\n")

        digest = sha256_file(evidence_path)
        signed = self.signer is not None
        manifest: Dict[str, Any] = {
            "provenance": provenance({"case_id": case_id} if case_id else None),
            "capture_window": {"since": since, "until": until},
            "event_types": event_types,
            "source": str(self.forensic_log),
            "evidence_file": evidence_path.name,
            "record_count": len(records),
            "sha256": digest,
            "hash_algorithm": "SHA-256",
        }

        # Write the custody note first and fold its hash into the manifest, so
        # the signature covers the custody claims too — otherwise the custody
        # note could be altered while the bundle still verified.
        custody_path = out / "CHAIN_OF_CUSTODY.txt"
        custody_path.write_text(self._custody_note(manifest, signed))
        manifest["custody_file"] = custody_path.name
        manifest["custody_sha256"] = sha256_file(custody_path)

        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
        (out / "manifest.json").write_bytes(manifest_bytes)

        if signed:
            signature = {
                "signature": self.signer.sign_bytes(manifest_bytes),
                "public_key": self.signer.public_key_b64,
                "algorithm": "ECDSA-SHA512",
                "signed_file": "manifest.json",
            }
            (out / "manifest.sig").write_text(json.dumps(signature, indent=2))

        manifest["signed"] = signed
        manifest["output_dir"] = str(out)
        return manifest

    @staticmethod
    def _custody_note(manifest: Dict[str, Any], signed: bool) -> str:
        prov = manifest["provenance"]
        window = manifest["capture_window"]
        lines = [
            "TIGRESS Evidence Bundle — Chain of Custody",
            "=" * 44,
            f"Produced by : {prov['tool']} {prov['version']}",
            f"Host        : {prov['host']}",
            f"Generated   : {prov['generated_at']}",
            f"Case ID     : {prov.get('case_id') or '(none)'}",
            f"Source log  : {manifest['source']}",
            f"Window      : {window['since'] or 'start'} .. {window['until'] or 'end'}",
            f"Records     : {manifest['record_count']}",
            f"SHA-256     : {manifest['sha256']}  (stored separately in manifest.json)",
            f"Signature   : {'ECDSA-SHA512 (manifest.sig)' if signed else 'unsigned'}",
            "",
            "How created : records were selected from the source forensic log by",
            "              the criteria above, written to evidence.jsonl, then",
            "              hashed. To verify, recompute the SHA-256 of",
            "              evidence.jsonl and compare it to manifest.json; if a",
            "              signature is present, verify manifest.sig against the",
            "              included public key.",
        ]
        return "\n".join(lines) + "\n"


def _confined_file(bundle_root: Path, name: str) -> Optional[Path]:
    """Resolve ``name`` to a regular file confined to ``bundle_root``.

    Returns None when the name is absolute, escapes the bundle via ``..`` or a
    symlink, or is not an existing regular file — so a malicious manifest cannot
    point verification at ``/etc/passwd``, a device, or a file outside the
    bundle.
    """
    candidate = bundle_root / name
    if candidate.is_symlink():
        return None
    try:
        resolved = candidate.resolve()
        root = bundle_root.resolve()
    except OSError:
        return None
    if resolved != root and root not in resolved.parents:
        return None
    if not resolved.is_file():
        return None
    return resolved


def verify_bundle(
    bundle_dir: str, expected_public_key: Optional[str] = None
) -> Dict[str, Any]:
    """Re-verify an exported evidence bundle's integrity.

    Recomputes the SHA-256 of ``evidence.jsonl`` against ``manifest.json``,
    checks the record count, and — when ``manifest.sig`` is present — verifies
    the ECDSA signature over the manifest. Returns ``{"ok", "checks"}`` where
    each check is ``{"name", "passed", "detail"}``.

    A valid signature alone only proves the manifest is internally consistent
    with *whatever* key ships in the bundle — an attacker who edits the evidence
    can re-sign with their own key. Pass ``expected_public_key`` (the trusted
    signer's base64 key, e.g. ``AuditLog.public_key_b64``) to also require the
    bundle to be signed by that specific key, which is what establishes
    authenticity.
    """
    d = Path(bundle_dir)
    checks: List[Dict[str, Any]] = []

    def _add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    manifest_path = d / "manifest.json"
    if not manifest_path.exists():
        _add("manifest_present", False, f"{manifest_path} not found")
        return {"ok": False, "checks": checks}

    manifest_bytes = manifest_path.read_bytes()
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        _add("manifest_parse", False, f"manifest.json is not valid JSON: {e}")
        return {"ok": False, "checks": checks}

    evidence_name = manifest.get("evidence_file", "evidence.jsonl")
    evidence_path = _confined_file(d, evidence_name)
    if evidence_path is None:
        _add("evidence_present", False, f"{evidence_name!r} missing or outside the bundle")
    else:
        # Stream the file: hash and count non-empty lines in one bounded pass,
        # so a huge evidence file cannot exhaust memory during verification.
        digest = hashlib.sha256()
        line_count = 0
        with open(evidence_path, "rb") as fh:
            for line in fh:
                digest.update(line)
                if line.strip():
                    line_count += 1
        actual = digest.hexdigest()
        expected = manifest.get("sha256")
        _add(
            "evidence_sha256", actual == expected,
            "hash matches manifest" if actual == expected
            else f"expected {expected}, got {actual}",
        )
        expected_count = manifest.get("record_count")
        _add(
            "record_count", line_count == expected_count,
            f"{line_count} record(s)" if line_count == expected_count
            else f"expected {expected_count}, found {line_count}",
        )

    # Verify the custody note is the one covered by the (signed) manifest.
    custody_expected = manifest.get("custody_sha256")
    if custody_expected is not None:
        custody_path = _confined_file(d, manifest.get("custody_file", "CHAIN_OF_CUSTODY.txt"))
        if custody_path is None:
            _add("custody_sha256", False, "custody note missing or outside the bundle")
        else:
            custody_actual = sha256_file(custody_path)
            _add(
                "custody_sha256", custody_actual == custody_expected,
                "custody note matches manifest" if custody_actual == custody_expected
                else "custody note does NOT match manifest",
            )

    sig_path = d / "manifest.sig"
    if not sig_path.exists():
        # An unsigned bundle cannot be authenticated; only pass when the caller
        # did not require a specific signer.
        if expected_public_key:
            _add("manifest_signature", False, "expected a signed bundle, but manifest.sig is missing")
        else:
            _add("manifest_signature", True, "unsigned bundle (no manifest.sig)")
    else:
        try:
            sig = json.loads(sig_path.read_text())
            from src.security.audit_log import AuditLog
            ok = AuditLog.verify_bytes(
                manifest_bytes, sig["signature"], sig["public_key"]
            )
            _add(
                "manifest_signature", ok,
                "signature valid" if ok else "signature does NOT match manifest.json",
            )
            if expected_public_key is not None:
                pinned = sig.get("public_key") == expected_public_key
                _add(
                    "public_key_pinned", pinned,
                    "signed by the expected key" if pinned
                    else "signed by an UNEXPECTED key (not the trusted signer)",
                )
        except Exception as e:  # malformed sig file or missing crypto
            _add("manifest_signature", False, f"could not verify signature: {e}")

    return {"ok": all(c["passed"] for c in checks), "checks": checks}
