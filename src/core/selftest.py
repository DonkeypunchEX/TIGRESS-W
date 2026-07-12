"""Self-validation harness: prove the detector works against a known dataset.

Implements the NIJ Digital Evidence Policies & Procedures Manual practice of
validating a forensic tool against a fixed, known dataset and recording a
versioned validation report — and revalidating whenever the software changes.
:func:`run_selftest` feeds a frozen golden dataset through a real
:class:`~src.core.detection_engine.DetectionEngine` and confirms the expected
detections fire; :func:`needs_revalidation` reports when the last recorded
validation predates the current version.
"""

import hashlib
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.version import __version__

# --------------------------------------------------------------------------- #
# Frozen golden dataset — changing any of this changes GOLDEN_SHA256 below.
# --------------------------------------------------------------------------- #
GOLDEN_RULES: Dict[str, Any] = {
    "wifi_rules": [{
        "id": "ssid_spoof_suspect", "enabled": True,
        "description": "SSID not in corporate whitelist",
        "severity": 3, "confidence": 0.8,
        "conditions": [{"field": "SSID", "op": "not_contains", "value": "CorpNet"}],
    }],
    "bluetooth_rules": [
        {"id": "ble_close_proximity", "enabled": True,
         "description": "Bluetooth device in very close proximity (strong RSSI)",
         "severity": 3, "confidence": 0.75,
         "conditions": [{"field": "rssi", "op": "gt", "value": "-50"}]},
        {"id": "ble_tracker_suspect", "enabled": True,
         "description": "Bluetooth device name matches a tracker pattern",
         "severity": 4, "confidence": 0.8,
         "conditions": [{"field": "name", "op": "contains", "value": "AirTag"}]},
    ],
}

GOLDEN_WIFI: List[Dict[str, Any]] = [{
    "networks": [{"SSID": "Free_Airport_WiFi", "BSSID": "de:ad:be:ef:00:01"}],
    "ap_count": 1, "new_ap_count": 0, "new_bssids": [],
}]

GOLDEN_BLUETOOTH: List[Dict[str, Any]] = [{
    "devices": [{"address": "11:22:33:44:55:66", "name": "John's AirTag", "rssi": -38}],
    "device_count": 1, "new_device_count": 0, "new_devices": [],
}]

#: Each expected detection: (sensor_type, severity, description substring).
EXPECTED: List[Dict[str, Any]] = [
    {"name": "wifi_ssid_spoof", "sensor_type": "wifi",
     "severity": 3, "contains": "corporate whitelist"},
    {"name": "ble_tracker", "sensor_type": "bluetooth",
     "severity": 4, "contains": "tracker"},
    {"name": "ble_proximity", "sensor_type": "bluetooth",
     "severity": 3, "contains": "proximity"},
]


def dataset_hash() -> str:
    """Stable SHA-256 over the frozen golden dataset and expectations."""
    blob = json.dumps(
        {"rules": GOLDEN_RULES, "wifi": GOLDEN_WIFI,
         "bluetooth": GOLDEN_BLUETOOTH, "expected": EXPECTED},
        sort_keys=True,
    ).encode()
    return hashlib.sha256(blob).hexdigest()


def _write_env(tmp: Path) -> str:
    (tmp / "rules.yaml").write_text(yaml.safe_dump(GOLDEN_RULES))
    cfg = {
        "sensors": {"wifi": {"alert_threshold": 3}, "bluetooth": {"alert_threshold": 3}},
        "detection": {
            "confidence_threshold": 0.6,
            "rules_file": str(tmp / "rules.yaml"),
            "ml_models": {
                "wifi": str(tmp / "models" / "wifi.pkl"),
                "bluetooth": str(tmp / "models" / "bluetooth.pkl"),
            },
        },
        # No channels -> silent dispatcher (no termux shell-out) during validation.
        "alerting": {"forensic_log": str(tmp / "forensic.jsonl"), "channels": {}},
    }
    path = tmp / "config.yaml"
    path.write_text(yaml.safe_dump(cfg))
    return str(path)


def run_selftest(record_dir: Optional[str] = None) -> Dict[str, Any]:
    """Run the golden-dataset validation and return a report dict.

    When ``record_dir`` is given, the report is also written there as
    ``validation_<version>_<timestamp>.json`` so validations are retained per
    the source guidance. The report has ``ok``, ``version``, ``dataset_sha256``,
    ``generated_at``, and a per-check ``checks`` list.
    """
    from src.core.detection_engine import DetectionEngine

    with tempfile.TemporaryDirectory(prefix="tigress-selftest-") as td:
        tmp = Path(td)
        engine = DetectionEngine(_write_env(tmp))
        produced = engine.analyze_wifi(GOLDEN_WIFI) + engine.analyze_bluetooth(GOLDEN_BLUETOOTH)

        checks: List[Dict[str, Any]] = []
        for exp in EXPECTED:
            passed = any(
                d.sensor_type == exp["sensor_type"]
                and d.severity == exp["severity"]
                and exp["contains"].lower() in d.description.lower()
                for d in produced
            )
            checks.append({
                "name": exp["name"], "sensor_type": exp["sensor_type"],
                "severity": exp["severity"], "expects": exp["contains"], "passed": passed,
            })

    report = {
        "tool": "TIGRESS",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_sha256": dataset_hash(),
        "detections_produced": len(produced),
        "checks": checks,
        "ok": all(c["passed"] for c in checks),
    }

    if record_dir:
        rec_dir = Path(record_dir)
        rec_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        record_path = rec_dir / f"validation_{__version__}_{stamp}.json"
        record_path.write_text(json.dumps(report, indent=2))
        report["record_path"] = str(record_path)

    return report


def latest_validation(record_dir: str) -> Optional[Dict[str, Any]]:
    """Return the most recent validation record in ``record_dir``, or None."""
    rec_dir = Path(record_dir)
    # Sort by mtime, not filename: the filename embeds the version before the
    # timestamp, so alphabetic order misranks records across versions.
    records = sorted(rec_dir.glob("validation_*.json"), key=lambda p: p.stat().st_mtime)
    if not records:
        return None
    try:
        return json.loads(records[-1].read_text())
    except (OSError, json.JSONDecodeError):
        return None


def needs_revalidation(record_dir: str) -> bool:
    """True if there is no passing validation for the current version.

    Revalidation is required after any software update (NIJ Maintaining
    Validations): if the newest record is missing, failed, or was produced by a
    different version, the tool must be revalidated.
    """
    latest = latest_validation(record_dir)
    if latest is None:
        return True
    return not latest.get("ok") or latest.get("version") != __version__
