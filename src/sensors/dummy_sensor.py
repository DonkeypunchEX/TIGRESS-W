"""Synthetic sensor that emits random readings for testing."""

import random
import threading
import time
from datetime import datetime, timezone
from typing import Optional

from src.sensors.base_sensor import BaseSensor


class DummySensor(BaseSensor):
    """Synthetic sensor for testing without real hardware."""

    def __init__(self, sensor_id: str, sensor_type: str, config: dict):
        super().__init__(sensor_id, sensor_type, config)
        self._thread: Optional[threading.Thread] = None

    def connect(self) -> bool:
        """Always connect — the synthetic sensor needs no backend."""
        self.connected = True
        return True

    def disconnect(self):
        """Stop recording and mark the sensor disconnected."""
        self.stop_recording()
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

    def _loop(self):
        while self.recording:
            dp = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sensor_id": self.sensor_id,
                "sensor_type": self.sensor_type,
                "dummy": True,
                "magnitude": random.gauss(9.8, 0.2) if self.sensor_type == "phone" else 0,
                "ap_count": random.randint(3, 12) if self.sensor_type == "wifi" else 0,
                "new_ap_count": random.randint(0, 2) if self.sensor_type == "wifi" else 0,
                "new_bssids": [],
                "networks": [],
                "device_count": random.randint(2, 10) if self.sensor_type == "bluetooth" else 0,
                "new_device_count": random.randint(0, 2) if self.sensor_type == "bluetooth" else 0,
                "new_devices": [],
                "devices": [],
                "tamper_suspect": False,
            }
            self.record(dp)
            time.sleep(5)
