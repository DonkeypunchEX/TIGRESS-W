import os

from src.core.detection_engine import DetectionEngine


def _wifi_scan(ssid="EvilTwin", new_ap_count=0):
    return {
        "networks": [{"SSID": ssid, "BSSID": "aa:bb:cc:dd:ee:ff"}],
        "ap_count": 1,
        "new_ap_count": new_ap_count,
        "new_bssids": [],
    }


def test_wifi_rule_flags_non_corpnet_ssid(engine):
    detections = engine.analyze_wifi([_wifi_scan(ssid="EvilTwin")])
    rule_hits = [d for d in detections if d.sensor_id == "wifi_sensor"]
    assert any(d.severity == 3 for d in rule_hits)


def test_wifi_rule_ignores_corpnet_ssid(engine):
    detections = engine.analyze_wifi([_wifi_scan(ssid="CorpNet-5G")])
    assert all(d.features.get("rule") != "ssid_spoof_suspect" for d in detections)


def test_new_ap_count_over_threshold_alerts(engine):
    detections = engine.analyze_wifi([_wifi_scan(ssid="CorpNet", new_ap_count=5)])
    assert any(d.id.startswith("new_ap_") for d in detections)


def test_ml_untrained_does_not_raise_keyerror(engine):
    # Regression: models/scalers/fitted were keyed by config name, not stype.
    assert engine.analyze_wifi([_wifi_scan()]) is not None
    assert engine.analyze_phone([{"magnitude": 9.8, "tamper_suspect": False}]) is not None


def test_training_accumulates_one_sample_per_call(config_path):
    # Regression: the engine used to re-scan the whole buffer each call, so a
    # growing buffer inflated the training sample count. It must add exactly the
    # newest reading per call.
    engine = DetectionEngine(config_path, training_mode=True)  # training_samples = 3
    buffer = []
    for i in range(1, 4):
        buffer.append(_wifi_scan(new_ap_count=i))
        engine.analyze_wifi(buffer)  # pass the whole growing buffer, as the manager does
        if i < 3:
            assert len(engine._training_data["wifi"]) == i
    assert engine._fitted["wifi"] is True
    assert engine.training_mode is False
    assert os.path.exists(engine._model_paths["wifi"])  # _save_model created the dir


def test_detections_are_recorded_in_history(engine):
    assert len(engine.history) == 0
    detections = engine.analyze_wifi([_wifi_scan(ssid="EvilTwin", new_ap_count=9)])
    assert len(detections) > 0
    recorded = engine.history.recent()
    assert len(recorded) == len(detections)
    assert {d["id"] for d in recorded} == {d.id for d in detections}


def test_phone_tamper_rule(engine):
    dp = {
        "tamper_suspect": True,
        "timestamp": "2026-01-01T00:00:00",
        "sensor_id": "phone_sensor",
        "magnitude": 30.0,
        "sensor_name": "accelerometer",
    }
    detections = engine.analyze_phone([dp])
    assert any(d.description.startswith("Possible physical tamper") for d in detections)


def test_rule_matches_operators(engine):
    net = {"SSID": "CorpNet-Guest", "signal": "-40"}
    assert engine._rule_matches(
        {"conditions": [{"field": "SSID", "op": "contains", "value": "Corp"}]}, net
    )
    assert not engine._rule_matches(
        {"conditions": [{"field": "SSID", "op": "not_contains", "value": "Corp"}]}, net
    )
    assert engine._rule_matches(
        {"conditions": [{"field": "signal", "op": "gt", "value": "-50"}]}, net
    )
    assert not engine._rule_matches(
        {"conditions": [{"field": "missing", "op": "eq", "value": "x"}]}, net
    )


def test_score_to_severity_thresholds():
    assert DetectionEngine._score_to_severity(0.95) == 5
    assert DetectionEngine._score_to_severity(0.75) == 4
    assert DetectionEngine._score_to_severity(0.55) == 3
    assert DetectionEngine._score_to_severity(0.35) == 2
    assert DetectionEngine._score_to_severity(0.1) == 1
