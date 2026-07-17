from src.core.correlation_engine import CorrelationEngine
from src.core.network_ingest import eve_to_detection, eve_to_detections


def _eve(severity=1, dest_ip="203.0.113.9", signature="ET MALWARE C2 Beacon"):
    return {
        "timestamp": "2026-07-17T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.50",
        "dest_ip": dest_ip,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature": signature,
            "signature_id": 2027863,
            "category": "Malware Command and Control Activity Detected",
            "severity": severity,
        },
    }


# --------------------------------------------------------------------------- #
# EVE mapping
# --------------------------------------------------------------------------- #

def test_alert_maps_to_network_detection():
    det = eve_to_detection(_eve())
    assert det["sensor_type"] == "network"
    assert det["sensor_id"] == "suricata"
    assert det["severity"] == 5  # suricata severity 1 = most severe
    assert det["description"] == "ET MALWARE C2 Beacon"
    assert det["features"]["dest_ip"] == "203.0.113.9"
    assert det["features"]["signature_id"] == 2027863


def test_severity_mapping_bands():
    assert eve_to_detection(_eve(severity=1))["severity"] == 5
    assert eve_to_detection(_eve(severity=2))["severity"] == 4
    assert eve_to_detection(_eve(severity=3))["severity"] == 3
    assert eve_to_detection(_eve(severity=99))["severity"] == 2


def test_non_alert_records_rejected():
    assert eve_to_detection({"event_type": "flow", "src_ip": "1.2.3.4"}) is None
    assert eve_to_detection({"event_type": "dns"}) is None
    assert eve_to_detection("not a dict") is None
    dets, rejected = eve_to_detections([_eve(), {"event_type": "stats"}, None])
    assert len(dets) == 1
    assert rejected == 2


def test_single_record_payload_accepted():
    dets, rejected = eve_to_detections(_eve())
    assert len(dets) == 1
    assert rejected == 0


# --------------------------------------------------------------------------- #
# engine + correlation integration
# --------------------------------------------------------------------------- #

def test_engine_ingest_dispatches_to_history(engine):
    result = engine.ingest_network([_eve(), {"event_type": "flow"}])
    assert result == {"accepted": 1, "rejected": 1}
    recorded = engine.history.recent(sensor_type="network")
    assert len(recorded) == 1
    assert recorded[0]["features"]["pyramid_level"] == "artifact"  # has signature


def test_recurring_dest_ip_trips_persistence():
    eng = CorrelationEngine({
        "enabled": True,
        "window_seconds": 600,
        "cooldown_seconds": 300,
        "rules": {
            "entity_persistence": {"enabled": True, "min_hits": 3, "min_span_seconds": 60},
            "cross_sensor": {"enabled": False},
            "burst": {"enabled": False},
        },
    })
    det = eve_to_detection(_eve(dest_ip="203.0.113.9"))
    eng.observe([det], now=0)
    eng.observe([det], now=100)
    meta = eng.observe([det], now=200)
    assert len(meta) == 1
    assert meta[0]["features"]["entity"] == "ip:203.0.113.9"


def test_src_ip_is_not_an_entity():
    # The source (the user's own device/router) recurs in every alert and
    # must never look like a persisting threat entity.
    eng = CorrelationEngine({
        "enabled": True,
        "rules": {
            "entity_persistence": {"enabled": True, "min_hits": 2, "min_span_seconds": 10},
            "cross_sensor": {"enabled": False},
            "burst": {"enabled": False},
        },
    })
    for t, ip in ((0, "203.0.113.1"), (100, "203.0.113.2"), (200, "203.0.113.3")):
        meta = eng.observe([eve_to_detection(_eve(dest_ip=ip))], now=t)
        assert meta == []  # same src_ip throughout, distinct dest_ips


def test_allowlisted_dest_ip_excluded():
    eng = CorrelationEngine({
        "enabled": True,
        "allowlist": {"entities": ["ip:203.0.113.9"]},
        "rules": {
            "entity_persistence": {"enabled": True, "min_hits": 2, "min_span_seconds": 10},
            "cross_sensor": {"enabled": False},
            "burst": {"enabled": False},
        },
    })
    det = eve_to_detection(_eve(dest_ip="203.0.113.9"))
    eng.observe([det], now=0)
    assert eng.observe([det], now=100) == []
