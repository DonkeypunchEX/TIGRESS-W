"""Tamper-evident audit log with ECDSA signatures and hash chaining."""

import base64
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
    load_der_public_key,
)

logger = logging.getLogger(__name__)

_INIT_HASH = hashlib.sha256(b"TIGRESS_AUDIT_INIT").digest()


class AuditLog:
    """Append-only, ECDSA-signed, hash-chained audit log."""

    def __init__(self, log_path: str = "data/audit", node_id: Optional[str] = None):
        self.log_path = Path(log_path)
        self.log_path.mkdir(exist_ok=True, parents=True)
        self.node_id = node_id or hashlib.sha256(os.urandom(32)).hexdigest()[:16]
        self._signing_key = self._load_or_generate_key()
        self._verifying_key = self._signing_key.public_key()
        self._chain: bytes = self._load_chain()
        self._current_log = self.log_path / f"audit_{datetime.now():%Y%m%d}.log"

    def _load_or_generate_key(self) -> ec.EllipticCurvePrivateKey:
        key_file = self.log_path / "signing_key.der"
        if key_file.exists():
            return load_der_private_key(key_file.read_bytes(), password=None)
        key = ec.generate_private_key(ec.SECP384R1())
        key_file.write_bytes(
            key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        )
        return key

    def _load_chain(self) -> bytes:
        chain_file = self.log_path / "chain.hash"
        return chain_file.read_bytes() if chain_file.exists() else _INIT_HASH

    def _save_chain(self):
        chain_file = self.log_path / "chain.hash"
        chain_file.write_bytes(self._chain)
        chain_file.chmod(0o600)

    def log(self, event_type: str, data: Dict[str, Any], severity: str = "INFO") -> str:
        """Append a signed, hash-chained entry and return its id."""
        entry = {
            "id": hashlib.sha256(os.urandom(32)).hexdigest()[:16],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "node": self.node_id,
            "type": event_type,
            "severity": severity,
            "data": data,
            "prev_hash": self._chain.hex(),
        }

        entry_bytes = json.dumps(entry, sort_keys=True).encode()
        entry_hash = hashlib.sha256(entry_bytes).digest()
        entry["hash"] = entry_hash.hex()
        entry["signature"] = base64.b64encode(
            self._signing_key.sign(entry_hash, ec.ECDSA(hashes.SHA512()))
        ).decode()

        with open(self._current_log, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())

        self._chain = hashlib.sha256(self._chain + entry_hash).digest()
        self._save_chain()
        return entry["id"]

    def verify_integrity(self) -> bool:
        """Return True iff every entry's hash, signature, and chain are intact."""
        return self.verify_detailed()["ok"]

    def verify_detailed(self) -> Dict[str, Any]:
        """Verify every entry and localize any corruption.

        Rather than failing on the first bad record, this checks each entry
        independently (hash, signature, chain linkage) and reports *which*
        records are suspect — the "block hashes to limit the amount of data
        that is suspect" practice from NIST IR 8387 §3.2.1.c. After a chain
        break the expected previous hash is resynced to the offending entry so
        one tampered record does not cascade into every record after it.

        Returns a dict ``{"ok", "entries_checked", "errors"}`` where each error
        is ``{"file", "line", "id", "reason"}``.
        """
        prev_hash = _INIT_HASH
        checked = 0
        errors: List[Dict[str, Any]] = []
        for log_file in sorted(self.log_path.glob("audit_*.log")):
            with open(log_file) as f:
                for lineno, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    checked += 1
                    loc = {"file": log_file.name, "line": lineno}
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError as e:
                        errors.append({**loc, "id": None, "reason": f"unparseable JSON: {e}"})
                        continue
                    entry_id = entry.get("id")
                    chain_ok = entry.get("prev_hash") == prev_hash.hex()
                    try:
                        sig = base64.b64decode(entry.pop("signature"))
                        stored_hash = bytes.fromhex(entry.pop("hash"))
                    except Exception as e:  # missing/malformed hash or signature
                        errors.append(
                            {**loc, "id": entry_id, "reason": f"malformed hash/signature: {e}"}
                        )
                        # No trustworthy stored hash to resync from; the next
                        # entry's chain check will flag the gap.
                        continue

                    recomputed = hashlib.sha256(
                        json.dumps(entry, sort_keys=True).encode()
                    ).digest()
                    if recomputed != stored_hash:
                        errors.append({**loc, "id": entry_id, "reason": "content hash mismatch"})
                    else:
                        try:
                            self._verifying_key.verify(
                                sig, recomputed, ec.ECDSA(hashes.SHA512())
                            )
                        except Exception as e:
                            errors.append(
                                {**loc, "id": entry_id, "reason": f"invalid signature: {e}"}
                            )
                    if not chain_ok:
                        errors.append({**loc, "id": entry_id, "reason": "hash chain break"})
                    # Always resync to this entry's stored hash so one bad record
                    # is isolated instead of cascading into every record after it
                    # (including when the signature check above failed).
                    prev_hash = hashlib.sha256(prev_hash + stored_hash).digest()
        return {"ok": not errors, "entries_checked": checked, "errors": errors}

    def sign_bytes(self, data: bytes) -> str:
        """Return a base64-encoded ECDSA signature over ``data``.

        Lets other components (e.g. the evidence exporter) sign artifacts with
        the same node key that protects the audit log.
        """
        digest = hashlib.sha256(data).digest()
        return base64.b64encode(
            self._signing_key.sign(digest, ec.ECDSA(hashes.SHA512()))
        ).decode()

    @property
    def public_key_b64(self) -> str:
        """Base64 DER SubjectPublicKeyInfo of this node's verifying key."""
        return base64.b64encode(
            self._verifying_key.public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()

    @staticmethod
    def verify_bytes(data: bytes, signature_b64: str, public_key_b64: str) -> bool:
        """Verify a :meth:`sign_bytes` signature with the given public key."""
        try:
            pub = load_der_public_key(base64.b64decode(public_key_b64))
            pub.verify(
                base64.b64decode(signature_b64),
                hashlib.sha256(data).digest(),
                ec.ECDSA(hashes.SHA512()),
            )
            return True
        except Exception:
            return False

    def export_for_forensics(self, output_path: str):
        """Write all log entries plus the public key and chain hash to a file."""
        pub_key = self.public_key_b64
        with open(output_path, "w") as out:
            out.write(f"# TIGRESS Audit Export\n# Public Key: {pub_key}\n# Node: {self.node_id}\n\n")
            for log_file in sorted(self.log_path.glob("audit_*.log")):
                out.write(log_file.read_text())
            out.write(f"\n# Final Chain Hash: {self._chain.hex()}\n")
