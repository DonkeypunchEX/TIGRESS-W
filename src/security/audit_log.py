"""Tamper-evident audit log with ECDSA signatures and hash chaining."""

import base64
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
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
        """Verify every entry's hash, signature, and chain linkage."""
        prev_hash = _INIT_HASH
        for log_file in sorted(self.log_path.glob("audit_*.log")):
            with open(log_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        if entry.get("prev_hash") != prev_hash.hex():
                            logger.error(f"Hash chain break in {log_file}")
                            return False
                        sig = base64.b64decode(entry.pop("signature"))
                        stored_hash = bytes.fromhex(entry.pop("hash"))
                        recomputed = hashlib.sha256(
                            json.dumps(entry, sort_keys=True).encode()
                        ).digest()
                        if recomputed != stored_hash:
                            return False
                        self._verifying_key.verify(sig, recomputed, ec.ECDSA(hashes.SHA512()))
                        prev_hash = hashlib.sha256(prev_hash + recomputed).digest()
                    except Exception as e:
                        logger.error(f"Integrity check error: {e}")
                        return False
        return True

    def export_for_forensics(self, output_path: str):
        """Write all log entries plus the public key and chain hash to a file."""
        pub_key = base64.b64encode(
            self._verifying_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        ).decode()
        with open(output_path, "w") as out:
            out.write(f"# TIGRESS Audit Export\n# Public Key: {pub_key}\n# Node: {self.node_id}\n\n")
            for log_file in sorted(self.log_path.glob("audit_*.log")):
                out.write(log_file.read_text())
            out.write(f"\n# Final Chain Hash: {self._chain.hex()}\n")
