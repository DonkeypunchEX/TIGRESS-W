from src.core.correlation_engine import (
    PYRAMID_ARTIFACT,
    PYRAMID_TTP,
    CorrelationEngine,
    classify_pyramid_level,
)


def _det(sensor_type="bluetooth", address=None, bssid=None, severity=3):
    features = {}
    if address:
        features["address"] = address
    if bssid:
        features["bssid"] = bssid
    return {
        "id": "d1",
        "sensor_type": sensor_type,
        "confidence": 0.8,
        "severity": severity,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "sensor_id": f"{sensor_type}_sensor",
        "description": "test",
        "features": features,
    }


def _engine(**rules):
    """Engine with only the named rules enabled, deterministic thresholds."""
    all_rules = {
        "entity_persistence": {"enabled": False},
        "cross_sensor": {"enabled": False},
        "burst": {"enabled": False},
    }
    all_rules.update(rules)
    return CorrelationEngine({
        "enabled": True,
        "window_seconds": 600,
        "cooldown_seconds": 300,
        "rules": all_rules,
    })


# --------------------------------------------------------------------------- #
# entity persistence
# --------------------------------------------------------------------------- #

def test_persistence_fires_after_min_hits_and_span():
    eng = _engine(entity_persistence={
        "enabled": True, "min_hits": 3, "min_span_seconds": 60, "severity": 4,
    })
    assert eng.observe([_det(address="AA:BB")], now=0) == []
    assert eng.observe([_det(address="AA:BB")], now=100) == []  # hits=2
    meta = eng.observe([_det(address="AA:BB")], now=200)
    assert len(meta) == 1
    assert meta[0]["sensor_type"] == "correlation"
    assert meta[0]["features"]["rule"] == "entity_persistence"
    assert meta[0]["features"]["entity"] == "bt:aa:bb"
    assert meta[0]["features"]["pyramid_level"] == PYRAMID_TTP


def test_persistence_needs_time_span_not_just_hits():
    eng = _engine(entity_persistence={
        "enabled": True, "min_hits": 3, "min_span_seconds": 60,
    })
    # Three hits in the same instant: a busy scan, not persistence.
    meta = eng.observe([_det(address="AA:BB")] * 3, now=0)
    assert meta == []


def test_persistence_cooldown_blocks_immediate_refire():
    eng = _engine(entity_persistence={
        "enabled": True, "min_hits": 2, "min_span_seconds": 10,
    })
    eng.observe([_det(address="AA:BB")], now=0)
    assert len(eng.observe([_det(address="AA:BB")], now=100)) == 1
    assert eng.observe([_det(address="AA:BB")], now=150) == []   # cooling down
    assert len(eng.observe([_det(address="AA:BB")], now=500)) == 1  # cooled


def test_events_expire_outside_window():
    eng = _engine(entity_persistence={
        "enabled": True, "min_hits": 3, "min_span_seconds": 10,
    })
    eng.observe([_det(address="AA:BB")], now=0)
    eng.observe([_det(address="AA:BB")], now=100)
    # Third sighting arrives after the first two left the 600s window.
    assert eng.observe([_det(address="AA:BB")], now=1000) == []


# --------------------------------------------------------------------------- #
# cross-sensor and burst
# --------------------------------------------------------------------------- #

def test_cross_sensor_fires_on_two_domains():
    eng = _engine(cross_sensor={"enabled": True, "min_sensor_types": 2})
    assert eng.observe([_det(sensor_type="wifi", bssid="aa:bb:cc:dd:ee:ff")], now=0) == []
    meta = eng.observe([_det(sensor_type="phone")], now=10)
    assert len(meta) == 1
    assert meta[0]["features"]["rule"] == "cross_sensor"
    assert sorted(meta[0]["features"]["sensor_types"]) == ["phone", "wifi"]


def test_burst_fires_on_volume():
    eng = _engine(burst={"enabled": True, "min_detections": 4})
    assert eng.observe([_det(address="A1"), _det(address="A2")], now=0) == []
    meta = eng.observe([_det(address="A3"), _det(address="A4")], now=10)
    assert len(meta) == 1
    assert meta[0]["features"]["rule"] == "burst"


def test_correlation_output_is_never_recorrelated():
    eng = _engine(burst={"enabled": True, "min_detections": 2})
    meta = eng.observe(
        [{**_det(address="A1"), "sensor_type": "correlation"}] * 5, now=0
    )
    assert meta == []
    assert len(eng._events) == 0


def test_disabled_engine_is_inert():
    eng = CorrelationEngine({"enabled": False})
    assert eng.observe([_det(address="AA:BB")] * 10, now=0) == []


# --------------------------------------------------------------------------- #
# pyramid of pain classification + engine integration
# --------------------------------------------------------------------------- #

def test_pyramid_classification_bands():
    assert classify_pyramid_level("correlation", {}) == PYRAMID_TTP
    assert classify_pyramid_level("phone", {}) == PYRAMID_TTP
    assert classify_pyramid_level("bluetooth", {"is_tracker": True}) == "tool"
    assert classify_pyramid_level("wifi", {"ssid": "X"}) == PYRAMID_ARTIFACT
    assert classify_pyramid_level("wifi", {"bssid": "aa:bb"}) == "address"


def test_engine_dispatch_emits_cross_sensor_meta_detection(engine):
    engine.analyze_wifi([{
        "networks": [{"SSID": "EvilTwin", "BSSID": "aa:bb:cc:dd:ee:ff"}],
        "ap_count": 1, "new_ap_count": 0, "new_bssids": [],
    }])
    engine.analyze_phone([{
        "tamper_suspect": True,
        "timestamp": "2026-01-01T00:00:00",
        "sensor_id": "phone_sensor",
        "magnitude": 30.0,
        "sensor_name": "accelerometer",
    }])
    recorded = engine.history.recent()
    corr = [d for d in recorded if d["sensor_type"] == "correlation"]
    assert len(corr) == 1
    assert corr[0]["features"]["rule"] == "cross_sensor"
    # Every stored detection is tagged with its pyramid level.
    assert all(d["features"].get("pyramid_level") for d in recorded)
