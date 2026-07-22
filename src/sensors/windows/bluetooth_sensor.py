"""Bluetooth scanning sensor backed by Windows PowerShell ``Get-PnpDevice``.

The Windows counterpart of :class:`src.sensors.bluetooth_sensor.BluetoothSensor`.
Windows' mainline PowerShell has no dependency-free live BLE-advertisement
sweep, so this sensor enumerates the Bluetooth devices the OS stack currently
sees (paired/connected classic and BLE devices) via ``Get-PnpDevice -Class
Bluetooth -PresentOnly`` and maps them into the same reading schema the
detection engine consumes — ``devices`` with ``address``/``name`` keys — so
Bluetooth rules, enrichment, and correlation work unchanged.

This is OS-visible enumeration, not a raw RF sweep: a device must be known to
the Windows Bluetooth stack to appear. A WinRT ``BluetoothLEAdvertisementWatcher``
would give a true passive scan and is a natural future enhancement; the parsing
here is factored out so that backend can slot in without touching the pipeline.
"""

import json
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from src.sensors.base_sensor import BaseSensor
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Bluetooth device addresses show up in a PnP InstanceId as "Dev_AABBCCDDEEFF"
# (classic) or a bare 12-hex run inside the BTHLE path (low energy).
_DEV_ADDR_RE = re.compile(r"[Dd]ev_([0-9A-Fa-f]{12})")
_BARE_ADDR_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{12})(?![0-9A-Fa-f])")

_PS_COMMAND = (
    "Get-PnpDevice -Class Bluetooth -PresentOnly | "
    "Select-Object FriendlyName,InstanceId,Status | ConvertTo-Json -Compress"
)


def _format_mac(hex12: str) -> str:
    """Format 12 hex characters as a lowercase colon-separated MAC address."""
    h = hex12.lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def _address_from_instance_id(instance_id: str) -> Optional[str]:
    """Extract a Bluetooth MAC from a PnP InstanceId, or None if absent."""
    if not instance_id:
        return None
    m = _DEV_ADDR_RE.search(instance_id)
    if m:
        return _format_mac(m.group(1))
    m = _BARE_ADDR_RE.search(instance_id.replace(":", ""))
    if m:
        return _format_mac(m.group(1))
    return None


class WindowsBluetoothSensor(BaseSensor):
    """Enumerates Windows Bluetooth devices and tracks newly-seen addresses."""

    def __init__(self, sensor_id: str, config: dict):
        super().__init__(sensor_id, "bluetooth", config)
        self._interval = config.get("scan_interval", 30)
        self._known_file = Path(config.get("known_devices_file", "data/known_bt_devices.txt"))
        self._known_addrs: set = self._load_known()
        self._thread: Optional[threading.Thread] = None

    def _load_known(self) -> set:
        """Load previously-seen device addresses from disk."""
        if not self._known_file.exists():
            return set()
        return {line.strip() for line in self._known_file.read_text().splitlines() if line.strip()}

    def _save_known(self):
        """Persist the set of known device addresses to disk."""
        self._known_file.parent.mkdir(exist_ok=True, parents=True)
        self._known_file.write_text("\n".join(sorted(self._known_addrs)) + "\n")

    def connect(self) -> bool:
        """Check that PowerShell is available; return True on success."""
        if shutil.which("powershell") is None and shutil.which("pwsh") is None:
            logger.warning("powershell not found — Windows Bluetooth sensor disabled")
            return False
        self.connected = True
        return True

    def disconnect(self):
        """Stop recording and mark the sensor disconnected."""
        self.stop_recording()  # already persists known devices
        self.connected = False

    def start_recording(self) -> bool:
        """Start the background sampling thread; return True on success."""
        if not self.connected:
            return False
        self.recording = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop_recording(self):
        """Stop the background sampling thread."""
        self.recording = False
        if self._thread:
            self._thread.join(timeout=5)
        self._save_known()

    def _loop(self):
        while self.recording:
            scan = self._scan()
            if scan:
                self.record(scan)
            time.sleep(self._interval)

    @staticmethod
    def parse_devices(raw: str) -> List[dict]:
        """Parse ``Get-PnpDevice ... | ConvertTo-Json`` output into devices.

        Returns one dict per device with ``address``/``name``/``status`` keys
        (matching the Termux Bluetooth schema). ``ConvertTo-Json`` emits a bare
        object for a single device and an array for several, and devices whose
        InstanceId carries no resolvable address are skipped.
        """
        raw = (raw or "").strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return []
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return []

        devices: List[dict] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            addr = _address_from_instance_id(entry.get("InstanceId", ""))
            if not addr:
                continue
            devices.append({
                "address": addr,
                "name": entry.get("FriendlyName"),
                "status": entry.get("Status"),
            })
        return devices

    def _scan(self) -> Optional[dict]:
        """Run one enumeration and build a reading, or None on failure."""
        try:
            shell = shutil.which("powershell") or shutil.which("pwsh")
            if not shell:
                return None
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", _PS_COMMAND],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            devices = self.parse_devices(result.stdout)
            addrs = {d["address"] for d in devices if d.get("address")}
            new_addrs = addrs - self._known_addrs
            self._known_addrs.update(new_addrs)

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sensor_id": self.sensor_id,
                "sensor_type": "bluetooth",
                "devices": devices,
                "device_count": len(devices),
                "new_device_count": len(new_addrs),
                "new_devices": list(new_addrs),
            }
        except Exception as e:
            logger.error(f"Windows Bluetooth scan error: {e}")
            return None
