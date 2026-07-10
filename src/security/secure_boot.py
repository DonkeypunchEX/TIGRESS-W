"""Boot-time manifest verification and runtime protection launcher."""

import base64
import hashlib
import hmac
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

TIGRESS_CORE_FILES = [
    "src/core/detection_engine.py",
    "src/security/secure_config.py",
    "src/security/audit_log.py",
    "config/config.yaml",
    "config/rules.yaml",
]


class SecureBoot:
    def __init__(self, manifest_path: str = "config/manifest.json"):
        self.manifest_path = Path(manifest_path)

    def measure(self) -> Dict[str, str]:
        measurements: Dict[str, str] = {}
        try:
            measurements["kernel"] = hashlib.sha512(Path("/proc/version").read_bytes()).hexdigest()
        except OSError:
            pass
        python = Path("/data/data/com.termux/files/usr/bin/python")
        if python.exists():
            measurements["python"] = hashlib.sha512(python.read_bytes()).hexdigest()
        for file in TIGRESS_CORE_FILES:
            p = Path(file)
            if p.exists():
                measurements[file] = hashlib.sha512(p.read_bytes()).hexdigest()
        return measurements

    def create_manifest(self, output_path: Optional[str] = None):
        measurements = self.measure()
        manifest = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hashes": measurements,
            "signature": self._sign(measurements),
        }
        out = Path(output_path or self.manifest_path)
        out.write_text(json.dumps(manifest, indent=2))
        out.chmod(0o600)
        logger.info(f"Boot manifest written to {out}")

    def verify_manifest(self) -> bool:
        if not self.manifest_path.exists():
            logger.warning("No boot manifest found — run harden.sh first")
            return False
        manifest = json.loads(self.manifest_path.read_text())
        current = self.measure()
        for key, expected in manifest.get("hashes", {}).items():
            if current.get(key) != expected:
                logger.error(f"Boot measurement mismatch: {key}")
                return False
        return True

    def _sign(self, measurements: Dict) -> str:
        data = json.dumps(measurements, sort_keys=True).encode()
        try:
            result = subprocess.run(
                ["termux-keystore", "sign", "tigress_manifest", base64.b64encode(data).decode()],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip().decode()
        except Exception:
            pass
        key_file = Path("config/manifest.key")
        if not key_file.exists():
            key_file.write_bytes(os.urandom(32))
            key_file.chmod(0o600)
        return hmac.new(key_file.read_bytes(), data, hashlib.sha512).hexdigest()


def start_runtime_protection(config: Optional[Dict] = None):
    """Verify boot integrity and start runtime monitoring.

    Reads the optional ``security`` config section for process-monitoring
    settings: ``process_monitoring`` (bool), ``process_whitelist`` (extra
    allowed process names), and ``monitor_interval`` (seconds). Call from the
    app entrypoint.
    """
    security = (config or {}).get("security", {})
    boot = SecureBoot()
    if not boot.verify_manifest():
        logger.critical("Boot verification failed — halting")
        sys.exit(1)
    logger.info("Boot verification passed")
    from src.security.anti_tamper import RuntimeProtection
    protector = RuntimeProtection(
        {Path(f) for f in TIGRESS_CORE_FILES if Path(f).exists()},
        process_whitelist=security.get("process_whitelist"),
        monitor_processes=bool(security.get("process_monitoring", False)),
    )
    protector.start_monitoring(interval=int(security.get("monitor_interval", 30)))
    return protector
