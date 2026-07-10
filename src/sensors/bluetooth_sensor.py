"""Bluetooth/BLE scanning sensor backed by termux-bluetooth-scaninfo."""

import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.sensors.base_sensor import BaseSensor
from src.utils.logger import get_logger

logger = get_logger(__name__)


class BluetoothSensor(BaseSensor):
    """Polls `termux-bluetooth-scaninfo` and tracks newly-seen devices."""

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
        """Check the sensor backend is available; return True on success."""
        result = subprocess.run(["which", "termux-bluetooth-scaninfo"], capture_output=True)
        if result.returncode != 0:
            logger.warning("termux-bluetooth-scaninfo not found — Bluetooth sensor disabled")
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
    def _address(device: dict) -> str:
        """Extract a device address from a scan record, tolerating key variants."""
        return device.get("address") or device.get("mac") or device.get("BLUETOOTH_ADDRESS") or ""

    def _scan(self) -> Optional[dict]:
        """Run one BLE scan and build a reading, or None on failure."""
        try:
            result = subprocess.run(
                ["termux-bluetooth-scaninfo"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            devices = json.loads(result.stdout)
            if not isinstance(devices, list):
                return None

            addrs = {self._address(d) for d in devices if self._address(d)}
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
            logger.error(f"Bluetooth scan error: {e}")
            return None
