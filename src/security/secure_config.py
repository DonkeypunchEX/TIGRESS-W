"""Encrypted configuration with hardware-backed key derivation where available."""

import base64
import hashlib
import hmac
import json
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Raised when decryption or integrity verification fails."""
    pass


class SecureConfig:
    """Encrypted configuration store with HMAC integrity."""

    def __init__(self, config_path: str = "config/secure"):
        self.config_path = Path(config_path)
        self.config_path.mkdir(exist_ok=True, parents=True)
        self._master_key = self._derive_master_key()
        self._fernet = Fernet(self._master_key)

    def _derive_master_key(self) -> bytes:
        key = self._try_android_keystore()
        if key:
            return base64.urlsafe_b64encode(key[:32])

        entropy = self._collect_device_entropy()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=b"TIGRESS_v1_2026",
            iterations=600_000,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(entropy))

    def _try_android_keystore(self) -> Optional[bytes]:
        try:
            result = subprocess.run(
                ["termux-keystore", "get", "tigress_master"],
                capture_output=True, timeout=2
            )
            if result.returncode == 0:
                return base64.b64decode(result.stdout.strip())
            key = os.urandom(32)
            subprocess.run(
                ["termux-keystore", "set", "tigress_master", base64.b64encode(key).decode()],
                check=True, timeout=2
            )
            return key
        except Exception:
            return None

    def _collect_device_entropy(self) -> bytes:
        sources = []
        for path in ["/proc/sys/kernel/random/boot_id", "/proc/cpuinfo"]:
            try:
                sources.append(Path(path).read_bytes())
            except OSError:
                pass
        try:
            r = subprocess.run(["ip", "link"], capture_output=True, timeout=1)
            sources.append(r.stdout)
        except Exception:
            pass
        return b"".join(sources) or os.urandom(64)

    def save(self, name: str, config: Dict[str, Any]) -> str:
        """Encrypt and store a config; return its id."""
        config_id = hashlib.sha256(name.encode()).hexdigest()[:16]
        payload = {
            "id": config_id,
            "name": name,
            "created": datetime.now(timezone.utc).isoformat(),
            "data": config,
            "hmac": self._hmac(json.dumps(config, sort_keys=True).encode()),
        }
        encrypted = self._fernet.encrypt(json.dumps(payload, sort_keys=True).encode())
        (self.config_path / f"{config_id}.enc").write_bytes(encrypted)
        return config_id

    def load(self, config_id: str) -> Dict[str, Any]:
        """Decrypt, verify the HMAC, and return a stored config."""
        enc_file = self.config_path / f"{config_id}.enc"
        if not enc_file.exists():
            raise ValueError(f"Config '{config_id}' not found")
        try:
            payload = json.loads(self._fernet.decrypt(enc_file.read_bytes()))
        except Exception as e:
            raise SecurityError(f"Decryption failed: {e}") from e

        expected = payload.get("hmac", "")
        computed = self._hmac(json.dumps(payload["data"], sort_keys=True).encode())
        if not hmac.compare_digest(expected, computed):
            raise SecurityError("HMAC verification failed — config may be tampered")
        return payload["data"]

    def _hmac(self, data: bytes) -> str:
        import hmac as _hmac
        return _hmac.new(self._master_key, data, hashlib.sha512).hexdigest()
