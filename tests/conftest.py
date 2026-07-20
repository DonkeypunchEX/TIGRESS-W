"""Shared pytest fixtures for the TIGRESS test suite.

Every fixture keeps state inside a pytest ``tmp_path`` so tests never touch the
repository's real ``config/``, ``data/``, or ``models/`` directories.
"""

import os
import sys

import pytest
import yaml

# Ensure the repository root is importable ("from src.core... ").
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


@pytest.fixture(autouse=True)
def _silence_notifier(monkeypatch):
    """Stop the detection engine from shelling out to termux-notification."""
    from src.utils.termux_notify import notifier

    monkeypatch.setattr(notifier, "send", lambda *args, **kwargs: True)


@pytest.fixture
def config_path(tmp_path):
    """Write an isolated config + rules pair and return the config file path."""
    cfg = {
        "server": {"host": "127.0.0.1", "port": 8080},
        "sensors": {
            "enabled": ["wifi", "phone", "bluetooth"],
            "wifi": {"alert_threshold": 3, "buffer_limit": 50},
            "phone": {"buffer_limit": 50},
            "bluetooth": {
                "alert_threshold": 3,
                "buffer_limit": 50,
                "known_remote_file": str(tmp_path / "known_remote_ble.txt"),
            },
        },
        "detection": {
            "confidence_threshold": 0.6,
            "rules_file": str(tmp_path / "rules.yaml"),
            "ml_models": {
                "wifi": str(tmp_path / "models" / "wifi.pkl"),
                "phone": str(tmp_path / "models" / "phone.pkl"),
                "bluetooth": str(tmp_path / "models" / "bluetooth.pkl"),
            },
            "training_samples": 3,
        },
        "alerting": {"forensic_log": str(tmp_path / "alerts" / "forensic.jsonl")},
    }
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(cfg))

    rules = {
        "wifi_rules": [
            {
                "id": "ssid_spoof_suspect",
                "enabled": True,
                "description": "SSID not in corporate whitelist",
                "severity": 3,
                "confidence": 0.8,
                "conditions": [
                    {"field": "SSID", "op": "not_contains", "value": "CorpNet"}
                ],
            }
        ],
        "bluetooth_rules": [
            {
                "id": "ble_close_proximity",
                "enabled": True,
                "description": "Bluetooth device in very close proximity",
                "severity": 3,
                "confidence": 0.75,
                "conditions": [{"field": "rssi", "op": "gt", "value": "-50"}],
            },
            {
                "id": "ble_tracker_suspect",
                "enabled": True,
                "description": "Bluetooth device name matches a tracker pattern",
                "severity": 4,
                "confidence": 0.8,
                "conditions": [{"field": "name", "op": "contains", "value": "AirTag"}],
            },
        ],
    }
    (tmp_path / "rules.yaml").write_text(yaml.safe_dump(rules))
    return str(tmp_path / "config.yaml")


@pytest.fixture
def engine(config_path):
    from src.core.detection_engine import DetectionEngine

    return DetectionEngine(config_path)
