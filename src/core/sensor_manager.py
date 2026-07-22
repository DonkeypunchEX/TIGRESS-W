"""Sensor lifecycle manager: starts sensors and routes readings to detection."""

import threading
from typing import Callable, Dict, List

from src.core.detection_engine import DetectionEngine
from src.core.platform import is_windows
from src.sensors.base_sensor import BaseSensor
from src.sensors.bluetooth_sensor import BluetoothSensor
from src.sensors.dummy_sensor import DummySensor
from src.sensors.phone_sensor import PhoneSensor
from src.sensors.wifi_sensor import WiFiSensor
from src.sensors.windows.bluetooth_sensor import WindowsBluetoothSensor
from src.sensors.windows.wifi_sensor import WindowsWiFiSensor
from src.utils.config_loader import ConfigLoader
from src.utils.logger import get_logger

logger = get_logger(__name__)

#: Termux/Android + POSIX sensor backends (the default target).
SENSOR_REGISTRY = {
    "wifi": WiFiSensor,
    "phone": PhoneSensor,
    "bluetooth": BluetoothSensor,
}

#: Windows sensor backends (netsh / PowerShell). No accelerometer analogue, so
#: the ``phone`` sensor is intentionally absent and skipped on Windows.
WINDOWS_SENSOR_REGISTRY = {
    "wifi": WindowsWiFiSensor,
    "bluetooth": WindowsBluetoothSensor,
}


def active_sensor_registry() -> dict:
    """Return the sensor registry for the current host OS."""
    return WINDOWS_SENSOR_REGISTRY if is_windows() else SENSOR_REGISTRY


class SensorManager:
    """Starts/stops configured sensors and feeds their data to the engine."""

    def __init__(
        self,
        config_path: str = "config/config.yaml",
        dummy: bool = False,
        training: bool = False,
    ):
        self.config = ConfigLoader.load_config(config_path)
        self.dummy = dummy
        self._sensors: Dict[str, BaseSensor] = {}
        self._global_subs: List[Callable] = []
        self._lock = threading.Lock()
        self._running = False
        self.detection_engine = DetectionEngine(config_path, training_mode=training)

    def start_all(self):
        """Connect and start every enabled sensor."""
        cfg = self.config.get("sensors", {})
        registry = active_sensor_registry()
        for stype in cfg.get("enabled", []):
            scfg = cfg.get(stype, {})
            sid = f"{stype}_sensor"

            if self.dummy:
                sensor = DummySensor(sid, stype, scfg)
            else:
                cls = registry.get(stype)
                if not cls:
                    logger.warning(
                        f"No sensor class registered for '{stype}' on this platform"
                    )
                    continue
                sensor = cls(sid, scfg)

            if not sensor.connect():
                logger.warning(f"Could not connect sensor '{sid}' — skipping")
                continue

            sensor.subscribe(lambda dp, _sid=sid: self._on_data(_sid, dp))
            sensor.start_recording()
            self._sensors[sid] = sensor

        self._running = True
        logger.info(f"Started {len(self._sensors)} sensor(s): {list(self._sensors)}")

    def stop_all(self):
        """Stop and disconnect all running sensors."""
        for sensor in self._sensors.values():
            try:
                sensor.stop_recording()
                sensor.disconnect()
            except Exception as e:
                logger.error(f"Error stopping sensor: {e}")
        self._running = False
        logger.info("All sensors stopped")

    def subscribe_global(self, cb: Callable):
        """Register a callback invoked for every reading from any sensor."""
        with self._lock:
            self._global_subs.append(cb)

    def list_sensors(self) -> List[dict]:
        """Return status dicts for all managed sensors."""
        return [s.get_status() for s in self._sensors.values()]

    @property
    def is_running(self) -> bool:
        """Whether the manager is started (set by ``start_all``, cleared by
        ``stop_all``); does not guarantee any sensor actually connected."""
        return self._running

    def _on_data(self, sid: str, dp: dict):
        """Fan a new reading to global subscribers and the detection engine."""
        stype = sid.split("_")[0]

        with self._lock:
            subs = list(self._global_subs)

        for cb in subs:
            try:
                cb(sid, dp)
            except Exception as e:
                logger.error(f"Global subscriber error: {e}")

        sensor = self._sensors.get(sid)
        if not sensor:
            return

        buffer = sensor.get_buffer()
        if stype == "wifi":
            detections = self.detection_engine.analyze_wifi(buffer)
        elif stype == "phone":
            detections = self.detection_engine.analyze_phone(buffer)
        elif stype == "bluetooth":
            detections = self.detection_engine.analyze_bluetooth(buffer)
        else:
            detections = []

        if detections:
            logger.warning(f"{len(detections)} detection(s) from {stype}")
