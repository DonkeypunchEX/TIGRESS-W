import yaml

from src.core.detection_engine import DetectionEngine
from src.core.posture import apply_posture


def _config():
    return {
        "posture": "normal",
        "sensors": {
            "wifi": {"scan_interval": 30, "alert_threshold": 3},
            "bluetooth": {"scan_interval": 30, "alert_threshold": 5},
            "phone": {"tamper_threshold": 2.0},
        },
        "detection": {
            "confidence_threshold": 0.6,
            "correlation": {
                "window_seconds": 600,
                "movement": {"delta_threshold": 1.5},
                "rules": {
                    "entity_persistence": {"min_hits": 3},
                    "burst": {"min_detections": 8},
                },
            },
        },
        "alerting": {
            "channels": {
                "termux": {"enabled": True, "min_severity": 1},
                "webhook": {"enabled": True, "min_severity": 3},
                "email": {"enabled": True, "min_severity": 4},
            },
        },
    }


def test_normal_posture_leaves_values_untouched():
    cfg = apply_posture(_config())
    assert cfg["posture_applied"] == "normal"
    assert cfg["sensors"]["wifi"]["scan_interval"] == 30
    assert cfg["detection"]["confidence_threshold"] == 0.6
    assert cfg["alerting"]["channels"]["email"]["min_severity"] == 4


def test_paranoid_posture_retunes_everything_together():
    base = _config()
    base["posture"] = "paranoid"
    cfg = apply_posture(base)
    assert cfg["posture_applied"] == "paranoid"
    assert cfg["sensors"]["wifi"]["scan_interval"] == 10          # 30 * 0.33
    assert cfg["sensors"]["wifi"]["alert_threshold"] == 1         # 3 * 0.4
    assert cfg["sensors"]["phone"]["tamper_threshold"] == 1.0     # 2.0 * 0.5
    assert cfg["detection"]["confidence_threshold"] == 0.3        # 0.6 * 0.5
    assert cfg["detection"]["severity_boost"] == 1
    corr = cfg["detection"]["correlation"]
    assert corr["window_seconds"] == 1200                         # 600 * 2.0
    assert corr["movement"]["delta_threshold"] == 0.75            # 1.5 * 0.5
    assert corr["rules"]["entity_persistence"]["min_hits"] == 2   # floor of 2
    assert corr["rules"]["burst"]["min_detections"] == 5          # 8 * 0.6
    channels = cfg["alerting"]["channels"]
    assert channels["termux"]["min_severity"] == 1                # clamped
    assert channels["webhook"]["min_severity"] == 1
    assert channels["email"]["min_severity"] == 2


def test_relaxed_posture_backs_off():
    base = _config()
    base["posture"] = "relaxed"
    cfg = apply_posture(base)
    assert cfg["sensors"]["wifi"]["scan_interval"] == 60
    assert cfg["detection"]["confidence_threshold"] == 0.75
    assert cfg["alerting"]["channels"]["email"]["min_severity"] == 5


def test_scan_interval_never_drops_below_floor():
    base = _config()
    base["posture"] = "paranoid"
    base["sensors"]["wifi"]["scan_interval"] = 6
    cfg = apply_posture(base)
    assert cfg["sensors"]["wifi"]["scan_interval"] == 5


def test_env_var_overrides_config(monkeypatch):
    monkeypatch.setenv("TIGRESS_POSTURE", "aggressive")
    cfg = apply_posture(_config())
    assert cfg["posture_applied"] == "aggressive"
    assert cfg["sensors"]["wifi"]["scan_interval"] == 15


def test_unknown_posture_falls_back_to_normal():
    base = _config()
    base["posture"] = "vicious"
    cfg = apply_posture(base)
    assert cfg["posture_applied"] == "normal"
    assert cfg["sensors"]["wifi"]["scan_interval"] == 30


def test_original_config_is_not_mutated():
    base = _config()
    base["posture"] = "paranoid"
    apply_posture(base)
    assert base["sensors"]["wifi"]["scan_interval"] == 30


def test_paranoid_engine_boosts_detection_severity(config_path, monkeypatch):
    # Rewrite the fixture config with paranoid posture; every detection's
    # severity should come out one band higher than the rule declares.
    monkeypatch.delenv("TIGRESS_POSTURE", raising=False)
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    cfg["posture"] = "paranoid"
    with open(config_path, "w") as f:
        yaml.safe_dump(cfg, f)

    engine = DetectionEngine(config_path)
    detections = engine.analyze_wifi([{
        "networks": [{"SSID": "EvilTwin", "BSSID": "aa:bb:cc:dd:ee:ff"}],
        "ap_count": 1, "new_ap_count": 0, "new_bssids": [],
    }])
    rule_hits = [d for d in detections if d.features.get("rule") == "ssid_spoof_suspect"]
    assert rule_hits and rule_hits[0].severity == 4  # rule says 3, paranoid +1
