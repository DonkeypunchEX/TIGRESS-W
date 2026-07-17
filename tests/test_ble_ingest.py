def _payload(devices, node="bag-pi"):
    return {"node_id": node, "devices": devices}


def test_remote_scan_runs_through_rules(engine):
    result = engine.ingest_ble(_payload(
        [{"address": "DE:AD:BE:EF:00:01", "name": "John's AirTag", "rssi": -70}]
    ))
    assert result["devices"] == 1
    assert result["detections"] >= 1
    recorded = engine.history.recent(sensor_type="bluetooth")
    hit = next(d for d in recorded if d["features"].get("rule") == "ble_tracker_suspect")
    assert hit["features"]["node"] == "bag-pi"
    assert hit["features"]["address"] == "de:ad:be:ef:00:01"


def test_new_device_tracking_persists_across_calls(engine, tmp_path):
    engine.config.setdefault("sensors", {}).setdefault("bluetooth", {})[
        "known_remote_file"
    ] = str(tmp_path / "known_remote.txt")

    dev = {"address": "aa:bb:cc:00:00:01", "name": "x", "rssi": -80}
    first = engine.ingest_ble(_payload([dev]))
    assert first["new_devices"] == 1
    second = engine.ingest_ble(_payload([dev]))
    assert second["new_devices"] == 0
    # Seen-set survives an engine restart via the file.
    assert "aa:bb:cc:00:00:01" in (tmp_path / "known_remote.txt").read_text()


def test_new_device_surge_alerts(engine, tmp_path):
    engine.config.setdefault("sensors", {}).setdefault("bluetooth", {}).update(
        {"known_remote_file": str(tmp_path / "known.txt"), "alert_threshold": 3}
    )
    devices = [
        {"address": f"aa:bb:cc:00:00:{i:02x}", "name": "", "rssi": -80}
        for i in range(5)
    ]
    engine.ingest_ble(_payload(devices))
    recorded = engine.history.recent(sensor_type="bluetooth")
    assert any(d["id"].startswith("new_bt_") for d in recorded)


def test_malformed_payloads_rejected(engine):
    assert engine.ingest_ble("garbage") == {
        "devices": 0, "rejected": 1, "new_devices": 0, "detections": 0,
    }
    result = engine.ingest_ble(_payload(
        [{"name": "no address", "rssi": -50}, "not-a-dict"]
    ))
    assert result["devices"] == 0
    assert result["rejected"] == 2
    assert result["detections"] == 0


def test_ingest_survives_missing_ml_model_config(engine):
    # Regression: with no ml_models entry for a sensor type, _ml_anomaly
    # raised KeyError instead of skipping ML.
    engine._fitted.pop("bluetooth", None)
    result = engine.ingest_ble(_payload(
        [{"address": "aa:bb:cc:dd:ee:99", "name": "x", "rssi": -40}]
    ))
    assert result["detections"] >= 1  # proximity rule still ran


def test_bare_device_list_accepted(engine):
    result = engine.ingest_ble(
        [{"address": "de:ad:be:ef:00:02", "name": "Speaker", "rssi": -40}]
    )
    assert result["devices"] == 1
    assert result["detections"] == 1  # proximity rule (rssi > -50)
    recorded = engine.history.recent(sensor_type="bluetooth")
    assert recorded[0]["features"]["node"] == "remote"
