import yaml

from src.core.enrichment import Enricher, mac_is_randomized, normalize_mac

# --------------------------------------------------------------------------- #
# MAC helpers
# --------------------------------------------------------------------------- #

def test_normalize_mac_variants():
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"
    assert normalize_mac("not-a-mac") is None
    assert normalize_mac("") is None
    assert normalize_mac(None) is None
    assert normalize_mac("zz:bb:cc:dd:ee:ff") is None


def test_mac_is_randomized_checks_locally_administered_bit():
    assert mac_is_randomized("02:00:00:00:00:01") is True
    assert mac_is_randomized("aa:bb:cc:dd:ee:ff") is True   # 0xaa has bit set
    assert mac_is_randomized("00:03:93:12:34:56") is False
    assert mac_is_randomized("garbage") is False


# --------------------------------------------------------------------------- #
# Enricher
# --------------------------------------------------------------------------- #

def test_vendor_lookup_from_seed_data():
    e = Enricher()
    assert e.vendor("00:03:93:12:34:56") == "Apple"
    assert e.vendor("de:ad:be:ef:00:01") is None


def test_bluetooth_tracker_by_name():
    e = Enricher()
    dev = e.enrich_bluetooth({"address": "de:ad:be:ef:00:01", "name": "Tile Mate"})
    assert dev["tracker_name_match"] is True
    assert dev["is_tracker"] is True


def test_bluetooth_tracker_by_vendor_oui():
    e = Enricher()
    dev = e.enrich_bluetooth({"address": "00:03:93:12:34:56", "name": "unnamed"})
    assert dev["vendor"] == "Apple"
    assert dev["tracker_name_match"] is False
    assert dev["is_tracker"] is True  # Apple is in tracker_vendors


def test_bluetooth_non_tracker():
    e = Enricher()
    dev = e.enrich_bluetooth({"address": "04:00:00:00:00:01", "name": "JBL Speaker"})
    assert dev["is_tracker"] is False
    assert dev["mac_randomized"] is False


def test_wifi_enrichment_fields():
    e = Enricher()
    net = e.enrich_wifi({"BSSID": "02:11:22:33:44:55", "SSID": "FreeWifi"})
    assert net["mac_randomized"] is True
    assert net["vendor"] is None
    assert net["SSID"] == "FreeWifi"  # original fields preserved


def test_custom_data_file_extends_defaults(tmp_path):
    f = tmp_path / "enrichment.yaml"
    f.write_text(yaml.safe_dump({
        "oui_vendors": {"DE:AD:BE": "EvilCorp"},
        "tracker_name_patterns": ["snitchtag"],
        "tracker_vendors": ["evilcorp"],
    }))
    e = Enricher(str(f))
    assert e.vendor("de:ad:be:ef:00:01") == "EvilCorp"
    assert e.vendor("00:03:93:12:34:56") == "Apple"  # defaults kept
    dev = e.enrich_bluetooth({"address": "de:ad:be:ef:00:01", "name": "SnitchTag 2"})
    assert dev["is_tracker"] is True


def test_missing_data_file_falls_back_to_seed():
    e = Enricher("does/not/exist.yaml")
    assert e.vendor("00:03:93:12:34:56") == "Apple"


# --------------------------------------------------------------------------- #
# Engine integration: rules can match enrichment fields
# --------------------------------------------------------------------------- #

def test_fingerprint_rule_fires_via_engine(engine):
    engine._rules.setdefault("bluetooth_rules", []).append({
        "id": "ble_tracker_fingerprint",
        "enabled": True,
        "description": "tracker fingerprint",
        "severity": 4,
        "confidence": 0.8,
        "conditions": [{"field": "is_tracker", "op": "eq", "value": True}],
    })
    scan = {
        "devices": [{"address": "de:ad:be:ef:00:01", "name": "SmartTag", "rssi": -80}],
        "device_count": 1, "new_device_count": 0, "new_devices": [],
    }
    detections = engine.analyze_bluetooth([scan])
    hits = [d for d in detections if d.features.get("rule") == "ble_tracker_fingerprint"]
    assert len(hits) == 1
    assert hits[0].features["is_tracker"] is True
    assert hits[0].features["pyramid_level"] == "tool"


def test_fingerprint_rule_ignores_non_tracker(engine):
    engine._rules.setdefault("bluetooth_rules", []).append({
        "id": "ble_tracker_fingerprint",
        "enabled": True,
        "description": "tracker fingerprint",
        "severity": 4,
        "confidence": 0.8,
        "conditions": [{"field": "is_tracker", "op": "eq", "value": True}],
    })
    scan = {
        "devices": [{"address": "04:00:00:00:00:01", "name": "JBL Speaker", "rssi": -80}],
        "device_count": 1, "new_device_count": 0, "new_devices": [],
    }
    detections = engine.analyze_bluetooth([scan])
    assert all(d.features.get("rule") != "ble_tracker_fingerprint" for d in detections)
