"""Detection engine: rule-based and Isolation Forest anomaly detection.

Combines per-reading YAML rules with an unsupervised ML model per sensor type
("wifi", "phone"), dispatching any resulting detections to the forensic log and
push notifier. Readings are enriched with local threat intel (vendor, tracker
fingerprints, randomized-MAC flags) before rules run, and every detection is
fed through the correlation engine, which can emit higher-order (TTP-level)
meta-detections.
"""

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from src.core.correlation_engine import CorrelationEngine, classify_pyramid_level
from src.core.detection_store import DetectionStore
from src.core.enrichment import Enricher
from src.core.movement import MovementTracker
from src.utils.alerting import AlertDispatcher
from src.utils.config_loader import ConfigLoader
from src.utils.forensic_logger import ForensicLogger
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class Detection:
    """A single detection emitted by a rule or the ML model."""

    id: str
    sensor_type: str
    confidence: float
    severity: int
    timestamp: str
    sensor_id: str
    description: str
    features: Dict[str, Any] = field(default_factory=dict)


class DetectionEngine:
    """Runs WiFi/phone readings through detection rules and an ML model."""

    def __init__(self, config_path: str = "config/config.yaml", training_mode: bool = False):
        self.config = ConfigLoader.load_config(config_path)
        det = self.config.get("detection", {})

        self._threshold = det.get("confidence_threshold", 0.6)
        self._training_samples = det.get("training_samples", 300)
        self._model_paths: Dict[str, str] = det.get("ml_models", {})
        self.training_mode = training_mode

        self._rules = ConfigLoader.load_yaml(det.get("rules_file", "config/rules.yaml"))
        alerting = self.config.get("alerting", {})
        self.forensic = ForensicLogger(
            alerting.get("forensic_log", "data/alerts/forensic.jsonl"),
            max_bytes=alerting.get("forensic_max_bytes", 0),
            retention_days=alerting.get("forensic_retention_days", 0),
        )
        self.history = DetectionStore(max_size=alerting.get("history_size", 500))
        self.alerts = AlertDispatcher.from_config(alerting)
        self.enricher = Enricher(det.get("enrichment_file"))
        corr_cfg = det.get("correlation") or {}
        self.movement = MovementTracker(corr_cfg.get("movement"))
        self.correlation = CorrelationEngine(corr_cfg, movement=self.movement)
        self._severity_boost = int(det.get("severity_boost", 0))

        self._models: Dict[str, IsolationForest] = {}
        self._scalers: Dict[str, StandardScaler] = {}
        self._fitted: Dict[str, bool] = {}
        self._training_data: Dict[str, List] = {"wifi": [], "phone": [], "bluetooth": []}

        self._load_models()

    def _load_models(self):
        for stype, path in self._model_paths.items():
            try:
                self._models[stype] = joblib.load(path)
                self._scalers[stype] = joblib.load(path + ".scaler")
                self._fitted[stype] = True
                logger.info(f"Loaded {stype} model from {path}")
            except FileNotFoundError:
                self._models[stype] = IsolationForest(
                    contamination=0.1, n_estimators=100, random_state=42
                )
                self._scalers[stype] = StandardScaler()
                self._fitted[stype] = False
                logger.info(f"Initialised fresh {stype} model (needs training)")

    def _save_model(self, stype: str):
        path = self._model_paths.get(stype)
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self._models[stype], path)
            joblib.dump(self._scalers[stype], path + ".scaler")
            logger.info(f"Saved {stype} model")

    def analyze_wifi(self, data: List[dict]) -> List[Detection]:
        """Analyze a WiFi scan buffer and dispatch any detections."""
        if not data:
            return []
        detections = self._wifi_rules(data[-1]) + self._ml_anomaly(data[-1:], "wifi")
        self._dispatch(detections)
        return detections

    def analyze_phone(self, data: List[dict]) -> List[Detection]:
        """Analyze a phone-sensor buffer and dispatch any detections."""
        if not data:
            return []
        # Every reading (not just detections) feeds the movement context that
        # lets correlation tell "following me" from "parked nearby".
        self.movement.record(data[-1].get("magnitude"))
        detections = self._phone_rules(data[-1]) + self._ml_anomaly(data[-1:], "phone")
        self._dispatch(detections)
        return detections

    def analyze_bluetooth(self, data: List[dict]) -> List[Detection]:
        """Analyze a Bluetooth scan buffer and dispatch any detections."""
        if not data:
            return []
        detections = self._bluetooth_rules(data[-1]) + self._ml_anomaly(data[-1:], "bluetooth")
        self._dispatch(detections)
        return detections

    def ingest_network(self, payload) -> Dict[str, int]:
        """Ingest Suricata EVE alert(s) as first-class network detections.

        ``payload`` is one EVE record or a list. Accepted alerts flow through
        the normal dispatch path (forensic log, history, alert channels,
        correlation). Returns ``{"accepted": n, "rejected": m}``.
        """
        from src.core.network_ingest import eve_to_detections

        dicts, rejected = eve_to_detections(payload)
        detections = [Detection(**d) for d in dicts]
        self._dispatch(detections)
        return {"accepted": len(detections), "rejected": rejected}

    def _dispatch(self, detections: List[Detection]):
        self._deliver(detections)
        # Correlation may promote these atomic indicators into TTP-level
        # meta-detections (persistence, cross-sensor, burst patterns).
        meta = self.correlation.observe([d.__dict__ for d in detections])
        self._deliver([Detection(**m) for m in meta])

    def _deliver(self, detections: List[Detection]):
        for d in detections:
            if self._severity_boost:
                d.severity = max(1, min(5, d.severity + self._severity_boost))
            d.features.setdefault(
                "pyramid_level", classify_pyramid_level(d.sensor_type, d.features)
            )
            self.forensic.log("detection", d.__dict__)
            self.history.add(d.__dict__)
            emoji = {5: "🔴", 4: "🟠", 3: "🟡"}.get(d.severity, "⚪")
            self.alerts.submit(
                title=f"{emoji} TIGRESS – Severity {d.severity}/5",
                content=f"{d.description} (conf: {d.confidence:.2f})",
                severity=d.severity,
            )

    def _ml_anomaly(self, data: List[dict], stype: str) -> List[Detection]:
        features = self._extract(data, stype)
        if features is None or len(features) == 0:
            return []

        if self.training_mode:
            self._training_data[stype].extend(features.tolist())
            n = len(self._training_data[stype])
            logger.info(f"Training {stype}: {n}/{self._training_samples} samples")
            if n >= self._training_samples:
                X = np.array(self._training_data[stype])
                self._scalers[stype].fit(X)
                self._models[stype].fit(self._scalers[stype].transform(X))
                self._fitted[stype] = True
                self._save_model(stype)
                self.training_mode = False
                logger.info(f"Training complete for {stype}")
            return []

        if not self._fitted[stype]:
            return []

        X = self._scalers[stype].transform(features)
        labels = self._models[stype].predict(X)
        scores = self._models[stype].decision_function(X)

        detections = []
        for label, score in zip(labels, scores):
            if label != -1:
                continue
            conf = float(np.clip(abs(score), 0, 1))
            if conf < self._threshold:
                continue
            detections.append(Detection(
                id=f"{stype}_{uuid.uuid4().hex[:8]}",
                sensor_type=stype,
                confidence=conf,
                severity=self._score_to_severity(conf),
                timestamp=pd.Timestamp.now(tz="UTC").isoformat(),
                sensor_id="ml",
                description=f"ML anomaly detected in {stype} data",
                features={"isolation_score": float(score)},
            ))
        return detections

    def _extract(self, data: List[dict], stype: str) -> Optional[np.ndarray]:
        if stype == "wifi":
            return np.array([[d.get("ap_count", 0), d.get("new_ap_count", 0)] for d in data])
        if stype == "phone":
            return np.array([[d.get("magnitude", 0)] for d in data])
        if stype == "bluetooth":
            return np.array(
                [[d.get("device_count", 0), d.get("new_device_count", 0)] for d in data]
            )
        return None

    def _wifi_rules(self, scan: dict) -> List[Detection]:
        detections = []
        networks = scan.get("networks", [])
        wifi_cfg = self.config.get("sensors", {}).get("wifi", {})

        for raw_net in networks:
            net = self.enricher.enrich_wifi(raw_net)
            for rule in self._rules.get("wifi_rules", []):
                if not rule.get("enabled", True):
                    continue
                if self._rule_matches(rule, net):
                    detections.append(Detection(
                        id=f"rule_{rule['id']}_{uuid.uuid4().hex[:6]}",
                        sensor_type="wifi",
                        confidence=float(rule.get("confidence", 0.8)),
                        severity=int(rule.get("severity", 3)),
                        timestamp=pd.Timestamp.now(tz="UTC").isoformat(),
                        sensor_id="wifi_sensor",
                        description=rule.get("description", rule["id"]),
                        features={
                            "rule": rule["id"],
                            "bssid": net.get("BSSID"),
                            "ssid": net.get("SSID"),
                            "vendor": net.get("vendor"),
                            "mac_randomized": net.get("mac_randomized"),
                        },
                    ))

        if scan.get("new_ap_count", 0) > wifi_cfg.get("alert_threshold", 3):
            detections.append(Detection(
                id=f"new_ap_{uuid.uuid4().hex[:6]}",
                sensor_type="wifi",
                confidence=0.7,
                severity=3,
                timestamp=pd.Timestamp.now(tz="UTC").isoformat(),
                sensor_id="wifi_sensor",
                description=f"{scan['new_ap_count']} new access points appeared",
                features={"new_bssids": scan.get("new_bssids", [])},
            ))

        return detections

    def _rule_matches(self, rule: dict, net: dict) -> bool:
        for cond in rule.get("conditions", []):
            value = net.get(cond.get("field"))
            if value is None:
                return False
            op, target = cond.get("op"), cond.get("value")
            if op == "not_contains" and target in str(value):
                return False
            elif op == "contains" and target not in str(value):
                return False
            elif op == "eq":
                # Bool-aware so rules can match enrichment flags (value: true).
                if isinstance(target, bool) or isinstance(value, bool):
                    if bool(value) != bool(target):
                        return False
                elif str(value) != str(target):
                    return False
            elif op == "gt":
                try:
                    if float(value) <= float(target):
                        return False
                except ValueError:
                    return False
        return True

    def _bluetooth_rules(self, scan: dict) -> List[Detection]:
        """Apply BLE rules to the latest scan and flag new-device surges."""
        detections = []
        devices = scan.get("devices", [])
        bt_cfg = self.config.get("sensors", {}).get("bluetooth", {})

        for raw_dev in devices:
            dev = self.enricher.enrich_bluetooth(raw_dev)
            for rule in self._rules.get("bluetooth_rules", []):
                if not rule.get("enabled", True):
                    continue
                if self._rule_matches(rule, dev):
                    detections.append(Detection(
                        id=f"rule_{rule['id']}_{uuid.uuid4().hex[:6]}",
                        sensor_type="bluetooth",
                        confidence=float(rule.get("confidence", 0.8)),
                        severity=int(rule.get("severity", 3)),
                        timestamp=pd.Timestamp.now(tz="UTC").isoformat(),
                        sensor_id="bluetooth_sensor",
                        description=rule.get("description", rule["id"]),
                        features={
                            "rule": rule["id"],
                            "address": (
                                dev.get("address")
                                or dev.get("mac")
                                or dev.get("BLUETOOTH_ADDRESS")
                            ),
                            "name": dev.get("name"),
                            "vendor": dev.get("vendor"),
                            "mac_randomized": dev.get("mac_randomized"),
                            "is_tracker": dev.get("is_tracker"),
                            "tracker_name_match": dev.get("tracker_name_match"),
                        },
                    ))

        if scan.get("new_device_count", 0) > bt_cfg.get("alert_threshold", 5):
            detections.append(Detection(
                id=f"new_bt_{uuid.uuid4().hex[:6]}",
                sensor_type="bluetooth",
                confidence=0.7,
                severity=3,
                timestamp=pd.Timestamp.now(tz="UTC").isoformat(),
                sensor_id="bluetooth_sensor",
                description=f"{scan['new_device_count']} new Bluetooth devices appeared",
                features={"new_devices": scan.get("new_devices", [])},
            ))

        return detections

    def _phone_rules(self, dp: dict) -> List[Detection]:
        if not dp.get("tamper_suspect"):
            return []
        return [Detection(
            id=f"tamper_{uuid.uuid4().hex[:6]}",
            sensor_type="phone",
            confidence=0.85,
            severity=4,
            timestamp=dp["timestamp"],
            sensor_id=dp["sensor_id"],
            description="Possible physical tamper detected",
            features={"magnitude": dp.get("magnitude"), "sensor": dp.get("sensor_name")},
        )]

    @staticmethod
    def _score_to_severity(conf: float) -> int:
        """Map a confidence in [0, 1] to a 1-5 severity band."""
        if conf >= 0.9:
            return 5
        if conf >= 0.7:
            return 4
        if conf >= 0.5:
            return 3
        if conf >= 0.3:
            return 2
        return 1
