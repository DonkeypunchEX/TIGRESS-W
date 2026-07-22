"""Windows WiFi sensor: netsh parsing and new-BSSID tracking (hermetic)."""

from src.sensors.windows.wifi_sensor import WindowsWiFiSensor, _signal_to_rssi

# Trimmed, representative `netsh wlan show networks mode=bssid` output: two
# SSIDs, the first advertising two BSSIDs (a mesh/roaming AP).
NETSH_SAMPLE = """
Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 90%
         Radio type         : 802.11ac
         Channel            : 36
         Basic rates (Mbps) : 6 12 24
    BSSID 2                 : aa:bb:cc:dd:ee:02
         Signal             : 40%
         Radio type         : 802.11n
         Channel            : 6

SSID 2 : CorpNet
    Network type            : Infrastructure
    Authentication          : WPA2-Enterprise
    Encryption              : CCMP
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 70%
         Radio type         : 802.11ax
         Channel            : 149
"""


def test_parse_networks_one_entry_per_bssid():
    nets = WindowsWiFiSensor.parse_networks(NETSH_SAMPLE)
    assert len(nets) == 3
    bssids = {n["BSSID"] for n in nets}
    assert bssids == {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "11:22:33:44:55:66"}


def test_parse_networks_fields_match_schema():
    nets = WindowsWiFiSensor.parse_networks(NETSH_SAMPLE)
    first = next(n for n in nets if n["BSSID"] == "aa:bb:cc:dd:ee:01")
    # Keys the detection engine + enrichment read.
    assert first["SSID"] == "HomeNet"
    assert first["signal_percent"] == 90
    assert first["RSSI"] == _signal_to_rssi(90) == -55
    assert first["channel"] == 36
    assert first["radio_type"] == "802.11ac"
    assert first["authentication"] == "WPA2-Personal"

    corp = next(n for n in nets if n["BSSID"] == "11:22:33:44:55:66")
    assert corp["SSID"] == "CorpNet"


def test_parse_networks_handles_empty_and_garbage():
    assert WindowsWiFiSensor.parse_networks("") == []
    assert WindowsWiFiSensor.parse_networks("no wireless interface") == []


def test_signal_to_rssi_mapping():
    assert _signal_to_rssi(0) == -100
    assert _signal_to_rssi(100) == -50
    assert _signal_to_rssi(50) == -75


def test_scan_tracks_new_bssids(tmp_path, monkeypatch):
    known = tmp_path / "known_bssids.txt"
    sensor = WindowsWiFiSensor("wifi_sensor", {"known_bssids_file": str(known)})

    class _Result:
        returncode = 0
        stdout = NETSH_SAMPLE

    monkeypatch.setattr(
        "src.sensors.windows.wifi_sensor.subprocess.run",
        lambda *a, **k: _Result(),
    )

    first = sensor._scan()
    assert first["ap_count"] == 3
    assert first["new_ap_count"] == 3  # all new on first scan

    second = sensor._scan()
    assert second["new_ap_count"] == 0  # nothing new the second time


def test_connect_false_when_netsh_missing(monkeypatch):
    monkeypatch.setattr(
        "src.sensors.windows.wifi_sensor.shutil.which", lambda _cmd: None
    )
    sensor = WindowsWiFiSensor("wifi_sensor", {})
    assert sensor.connect() is False
    assert sensor.connected is False
