"""Platform detection, sensor-registry selection, and the Windows alert channel."""

import src.core.platform as platform
from src.core.sensor_manager import (
    SENSOR_REGISTRY,
    WINDOWS_SENSOR_REGISTRY,
    active_sensor_registry,
)
from src.sensors.windows.bluetooth_sensor import WindowsBluetoothSensor
from src.sensors.windows.wifi_sensor import WindowsWiFiSensor
from src.utils.alerting import (
    AlertDispatcher,
    TermuxChannel,
    WindowsChannel,
    default_local_channel,
)


def test_current_platform_labels(monkeypatch):
    monkeypatch.setattr(platform.sys, "platform", "win32")
    assert platform.is_windows() is True
    assert platform.current_platform() == "windows"

    monkeypatch.setattr(platform.sys, "platform", "linux")
    monkeypatch.delenv("TERMUX_VERSION", raising=False)
    monkeypatch.setattr(platform, "is_termux", lambda: False)
    assert platform.is_windows() is False
    assert platform.current_platform() == "posix"


def test_is_termux_from_env(monkeypatch):
    monkeypatch.setattr(platform.sys, "platform", "linux")
    monkeypatch.setenv("TERMUX_VERSION", "0.118.0")
    assert platform.is_termux() is True
    assert platform.current_platform() == "termux"


def test_windows_registry_maps_to_windows_sensors():
    assert WINDOWS_SENSOR_REGISTRY["wifi"] is WindowsWiFiSensor
    assert WINDOWS_SENSOR_REGISTRY["bluetooth"] is WindowsBluetoothSensor
    # No accelerometer analogue on the desktop.
    assert "phone" not in WINDOWS_SENSOR_REGISTRY


def test_active_registry_follows_platform(monkeypatch):
    monkeypatch.setattr("src.core.sensor_manager.is_windows", lambda: True)
    assert active_sensor_registry() is WINDOWS_SENSOR_REGISTRY

    monkeypatch.setattr("src.core.sensor_manager.is_windows", lambda: False)
    assert active_sensor_registry() is SENSOR_REGISTRY


def test_default_local_channel_is_platform_aware(monkeypatch):
    monkeypatch.setattr("src.utils.alerting.is_windows", lambda: True)
    assert isinstance(default_local_channel(), WindowsChannel)

    monkeypatch.setattr("src.utils.alerting.is_windows", lambda: False)
    assert isinstance(default_local_channel(), TermuxChannel)


def test_windows_channel_maps_severity_to_priority():
    class _FakeNotifier:
        def __init__(self):
            self.kwargs = None

        def send(self, **kwargs):
            self.kwargs = kwargs
            return True

    fake = _FakeNotifier()
    ch = WindowsChannel(notifier=fake)
    assert ch.send("t", "c", severity=5) is True
    assert fake.kwargs["priority"] == "max"
    assert fake.kwargs["ongoing"] is True

    ch.send("t", "c", severity=2)
    assert fake.kwargs["priority"] == "default"


def test_from_config_builds_windows_channel():
    disp = AlertDispatcher.from_config({
        "channels": {"windows": {"enabled": True, "min_severity": 2}}
    })
    assert disp.channel_names == ["windows"]
    assert disp.channels[0].min_severity == 2
