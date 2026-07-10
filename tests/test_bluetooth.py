from src.core.detection_engine import DetectionEngine
from src.sensors.bluetooth_sensor import BluetoothSensor


def _scan(devices=None, new_device_count=0):
    devices = devices or []
    return {
        "devices": devices,
        "device_count": len(devices),
        "new_device_count": new_device_count,
        "new_devices": [],
    }


# --------------------------------------------------------------------------- #
# BluetoothSensor
# --------------------------------------------------------------------------- #

def test_address_tolerates_key_variants():
    assert BluetoothSensor._address({"address": "AA"}) == "AA"
    assert BluetoothSensor._address({"mac": "BB"}) == "BB"
    assert BluetoothSensor._address({"BLUETOOTH_ADDRESS": "CC"}) == "CC"
    assert BluetoothSensor._address({"name": "x"}) == ""


def test_known_devices_round_trip(tmp_path):
    f = tmp_path / "known.txt"
    sensor = BluetoothSensor("bluetooth_sensor", {"known_devices_file": str(f)})
    sensor._known_addrs = {"AA:BB", "CC:DD"}
    sensor._save_known()
    reloaded = BluetoothSensor("bluetooth_sensor", {"known_devices_file": str(f)})
    assert reloaded._known_addrs == {"AA:BB", "CC:DD"}


def test_connect_false_without_backend():
    # termux-bluetooth-scaninfo is not present in the test environment.
    assert BluetoothSensor("bluetooth_sensor", {}).connect() is False


# --------------------------------------------------------------------------- #
# DetectionEngine bluetooth path
# --------------------------------------------------------------------------- #

def test_proximity_rule_flags_strong_rssi(engine):
    scan = _scan([{"address": "AA", "name": "Watch", "rssi": -40}])
    detections = engine.analyze_bluetooth([scan])
    assert any(d.features.get("rule") == "ble_close_proximity" for d in detections)


def test_proximity_rule_ignores_weak_rssi(engine):
    scan = _scan([{"address": "AA", "name": "Watch", "rssi": -85}])
    detections = engine.analyze_bluetooth([scan])
    assert all(d.features.get("rule") != "ble_close_proximity" for d in detections)


def test_tracker_name_rule(engine):
    scan = _scan([{"address": "AA", "name": "John's AirTag", "rssi": -90}])
    detections = engine.analyze_bluetooth([scan])
    assert any(d.features.get("rule") == "ble_tracker_suspect" for d in detections)


def test_new_device_surge_alert(engine):
    detections = engine.analyze_bluetooth([_scan(new_device_count=9)])
    assert any(d.id.startswith("new_bt_") for d in detections)


def test_bluetooth_ml_untrained_does_not_raise(engine):
    assert engine.analyze_bluetooth([_scan([{"address": "AA", "rssi": -70}])]) is not None


def test_bluetooth_training_one_sample_per_call(config_path):
    engine = DetectionEngine(config_path, training_mode=True)  # training_samples = 3
    buffer = []
    for i in range(1, 4):
        buffer.append(_scan())
        engine.analyze_bluetooth(buffer)
        if i < 3:
            assert len(engine._training_data["bluetooth"]) == i
    assert engine._fitted["bluetooth"] is True


def test_bluetooth_detections_recorded_in_history(engine):
    engine.analyze_bluetooth([_scan([{"address": "AA", "name": "AirTag", "rssi": -40}])])
    recorded = engine.history.recent()
    assert recorded and all(d["sensor_type"] == "bluetooth" for d in recorded)
