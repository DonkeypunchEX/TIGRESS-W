"""Accelerometer sensor backed by termux-sensor."""

import json
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import numpy as np

from src.sensors.base_sensor import BaseSensor
from src.utils.logger import get_logger

logger = get_logger(__name__)


class PhoneSensor(BaseSensor):
    """Samples an accelerometer via `termux-sensor` to detect physical tamper."""

    def __init__(self, sensor_id: str, config: dict):
        super().__init__(sensor_id, "phone", config)
        self._sensor_type = config.get("sensor_type", "accelerometer")
        self._rate = config.get("sample_rate", 1.0)
        self._tamper_threshold = config.get("tamper_threshold", 2.0)
        self._stability_samples = config.get("stability_samples", 10)
        self._recent_magnitudes: deque = deque(maxlen=self._stability_samples)
        self._thread: Optional[threading.Thread] = None

    def connect(self) -> bool:
        """Check the sensor backend is available; return True on success."""
        result = subprocess.run(["which", "termux-sensor"], capture_output=True)
        if result.returncode != 0:
            logger.warning("termux-sensor not found — phone sensor disabled")
            return False
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
        cmd = ["termux-sensor", "-s", self._sensor_type, "-n", "1"]
        interval = 1.0 / max(self._rate, 0.1)
        while self.recording:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    self._process(result.stdout)
            except Exception as e:
                logger.error(f"Phone sensor error: {e}")
            time.sleep(interval)

    def _process(self, raw_output: str):
        raw = json.loads(raw_output)

        values = accuracy = sensor_key = None
        for k, v in raw.items():
            if isinstance(v, dict) and "values" in v:
                values = v["values"]
                accuracy = v.get("accuracy")
                sensor_key = k
                break

        if not values:
            return

        magnitude = float(np.linalg.norm(values)) if len(values) >= 3 else 0.0
        self._recent_magnitudes.append(magnitude)

        tamper = False
        if len(self._recent_magnitudes) == self._stability_samples:
            baseline = list(self._recent_magnitudes)[:-1]
            variance = float(np.var(baseline))
            delta = abs(magnitude - float(np.mean(baseline)))
            tamper = variance < 0.5 and delta > self._tamper_threshold

        dp = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sensor_id": self.sensor_id,
            "sensor_type": "phone",
            "sensor_name": sensor_key or self._sensor_type,
            "values": values,
            "accuracy": accuracy,
            "magnitude": magnitude,
            "tamper_suspect": tamper,
        }
        self.record(dp)
