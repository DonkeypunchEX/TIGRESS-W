"""Windows Bluetooth sensor: PnP JSON parsing and address extraction (hermetic)."""

import json

from src.sensors.windows.bluetooth_sensor import (
    WindowsBluetoothSensor,
    _address_from_instance_id,
)

# `Get-PnpDevice ... | ConvertTo-Json` for several devices -> a JSON array.
PNP_ARRAY = json.dumps([
    {
        "FriendlyName": "AirTag",
        "InstanceId": "BTHLE\\Dev_e0aabbccddee\\8&abc123&0&e0aabbccddee",
        "Status": "OK",
    },
    {
        "FriendlyName": "Wireless Mouse",
        "InstanceId": "BTHENUM\\Dev_A1B2C3D4E5F6\\7&1a2b&0",
        "Status": "OK",
    },
    {
        # A Bluetooth radio/host entry with no device address -> skipped.
        "FriendlyName": "Intel Wireless Bluetooth",
        "InstanceId": "USB\\VID_8087&PID_0026\\5&deadbeef",
        "Status": "OK",
    },
])

# `ConvertTo-Json` emits a bare object (not an array) for a single device.
PNP_SINGLE = json.dumps({
    "FriendlyName": "Galaxy Buds",
    "InstanceId": "BTHENUM\\Dev_112233445566\\7&x&0",
    "Status": "OK",
})


def test_address_extraction_variants():
    assert _address_from_instance_id("BTHENUM\\Dev_A1B2C3D4E5F6\\7") == "a1:b2:c3:d4:e5:f6"
    assert _address_from_instance_id("BTHLE\\Dev_e0aabbccddee\\8") == "e0:aa:bb:cc:dd:ee"
    assert _address_from_instance_id("USB\\VID_8087&PID_0026") is None
    assert _address_from_instance_id("") is None


def test_parse_devices_array_skips_addressless():
    devs = WindowsBluetoothSensor.parse_devices(PNP_ARRAY)
    addrs = {d["address"] for d in devs}
    assert addrs == {"e0:aa:bb:cc:dd:ee", "a1:b2:c3:d4:e5:f6"}
    airtag = next(d for d in devs if d["address"] == "e0:aa:bb:cc:dd:ee")
    assert airtag["name"] == "AirTag"  # tracker-name rule can match this


def test_parse_devices_single_object():
    devs = WindowsBluetoothSensor.parse_devices(PNP_SINGLE)
    assert len(devs) == 1
    assert devs[0]["address"] == "11:22:33:44:55:66"
    assert devs[0]["name"] == "Galaxy Buds"


def test_parse_devices_handles_empty_and_garbage():
    assert WindowsBluetoothSensor.parse_devices("") == []
    assert WindowsBluetoothSensor.parse_devices("not json") == []
    assert WindowsBluetoothSensor.parse_devices("[]") == []


def test_scan_tracks_new_devices(tmp_path, monkeypatch):
    known = tmp_path / "known_bt.txt"
    sensor = WindowsBluetoothSensor("bluetooth_sensor", {"known_devices_file": str(known)})

    class _Result:
        returncode = 0
        stdout = PNP_ARRAY

    monkeypatch.setattr(
        "src.sensors.windows.bluetooth_sensor.shutil.which", lambda _c: "powershell"
    )
    monkeypatch.setattr(
        "src.sensors.windows.bluetooth_sensor.subprocess.run",
        lambda *a, **k: _Result(),
    )

    first = sensor._scan()
    assert first["device_count"] == 2
    assert first["new_device_count"] == 2

    second = sensor._scan()
    assert second["new_device_count"] == 0


def test_connect_false_when_powershell_missing(monkeypatch):
    monkeypatch.setattr(
        "src.sensors.windows.bluetooth_sensor.shutil.which", lambda _c: None
    )
    sensor = WindowsBluetoothSensor("bluetooth_sensor", {})
    assert sensor.connect() is False
