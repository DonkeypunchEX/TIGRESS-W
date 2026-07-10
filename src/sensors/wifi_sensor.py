"""WiFi scanning sensor backed by termux-wifi-scaninfo."""

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


class WiFiSensor(BaseSensor):
    """Polls `termux-wifi-scaninfo` and tracks newly-seen BSSIDs."""

    def __init__(self, sensor_id: str, config: dict):
        super().__init__(sensor_id, "wifi", config)
        self._interval = config.get("scan_interval", 30)
        self._known_file = Path(config.get("known_bssids_file", "data/known_bssids.txt"))
        self._known_bssids: set = self._load_known()
        self._thread: Optional[threading.Thread] = None

    def _load_known(self) -> set:
        if not self._known_file.exists():
            return set()
        return {line.strip() for line in self._known_file.read_text().splitlines() if line.strip()}

    def _save_known(self):
        self._known_file.parent.mkdir(exist_ok=True, parents=True)
        self._known_file.write_text("\n".join(sorted(self._known_bssids)) + "\n")

    def connect(self) -> bool:
        """Check the sensor backend is available; return True on success."""
        result = subprocess.run(["which", "termux-wifi-scaninfo"], capture_output=True)
        if result.returncode != 0:
            logger.warning("termux-wifi-scaninfo not found — WiFi sensor disabled")
            return False
        self.connected = True
        return True

    def disconnect(self):
        """Stop recording and mark the sensor disconnected."""
        self.stop_recording()
        self._save_known()
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

    def _scan(self) -> Optional[dict]:
        try:
            result = subprocess.run(
                ["termux-wifi-scaninfo"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            networks = json.loads(result.stdout)
            bssids = {net.get("BSSID", "") for net in networks if net.get("BSSID")}
            new_bssids = bssids - self._known_bssids
            self._known_bssids.update(new_bssids)

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sensor_id": self.sensor_id,
                "sensor_type": "wifi",
                "networks": networks,
                "ap_count": len(networks),
                "new_ap_count": len(new_bssids),
                "new_bssids": list(new_bssids),
            }
        except Exception as e:
            logger.error(f"WiFi scan error: {e}")
            return None
