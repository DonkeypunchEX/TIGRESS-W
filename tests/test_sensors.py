import time

from src.core.sensor_manager import SensorManager
from src.sensors.dummy_sensor import DummySensor


def test_record_notifies_subscribers():
    sensor = DummySensor("wifi_sensor", "wifi", {})
    seen = []
    sensor.subscribe(lambda dp: seen.append(dp))
    sensor.record({"x": 1})
    assert seen == [{"x": 1}]
    assert sensor.get_buffer() == [{"x": 1}]


def test_buffer_is_bounded():
    sensor = DummySensor("wifi_sensor", "wifi", {"buffer_limit": 5})
    for i in range(20):
        sensor.record({"i": i})
    buf = sensor.get_buffer()
    assert len(buf) == 5
    assert buf[0]["i"] == 15 and buf[-1]["i"] == 19  # oldest trimmed, newest kept


def test_subscriber_exception_does_not_break_record():
    sensor = DummySensor("wifi_sensor", "wifi", {})

    def boom(_dp):
        raise RuntimeError("subscriber failure")

    sensor.subscribe(boom)
    sensor.record({"ok": True})  # must not raise
    assert sensor.get_buffer() == [{"ok": True}]


def test_manager_runs_dummy_sensors(config_path):
    manager = SensorManager(config_path=config_path, dummy=True)
    manager.start_all()
    try:
        time.sleep(0.2)
        assert manager.is_running
        ids = {s["id"] for s in manager.list_sensors()}
        assert ids == {"wifi_sensor", "phone_sensor", "bluetooth_sensor"}
    finally:
        manager.stop_all()
    assert manager.is_running is False
