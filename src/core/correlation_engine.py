"""Time-windowed correlation over the detection stream.

Single detections are atomic indicators — a new BSSID, a strong BLE RSSI, an
accelerometer spike. What matters for counter-surveillance is the *pattern*:
the same unknown device reappearing across scan windows while the phone is
moving is a fundamentally stronger signal than any one reading. This module
watches recent detections and emits meta-detections when configured patterns
fire.

Detections are exchanged as plain dicts (``Detection.__dict__``) so this
module has no import dependency on the detection engine.

Pyramid of Pain (David Bianco): indicators are ranked by how painful they are
for an adversary to change. TIGRESS maps its wireless world onto four bands:

- ``address``  – a BSSID/MAC (trivial to rotate, lowest pain)
- ``artifact`` – an SSID, device name, or vendor fingerprint
- ``tool``     – hardware/vendor class evidence (e.g. known tracker vendor)
- ``ttp``      – behaviour over time (persistence, coordinated activity);
                 the hardest thing for an adversary to change

Correlation meta-detections are TTP-level by construction.
"""

import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Set

import pandas as pd

from src.utils.logger import get_logger

logger = get_logger(__name__)

PYRAMID_ADDRESS = "address"
PYRAMID_ARTIFACT = "artifact"
PYRAMID_TOOL = "tool"
PYRAMID_TTP = "ttp"


def classify_pyramid_level(sensor_type: str, features: Dict[str, Any]) -> str:
    """Rank a detection's indicator on the Pyramid of Pain."""
    if sensor_type == "correlation":
        return PYRAMID_TTP
    if sensor_type == "phone":
        # Physical tamper/movement is behaviour, not an indicator the
        # adversary can rotate away from.
        return PYRAMID_TTP
    if features.get("is_tracker") or features.get("tracker_name_match"):
        return PYRAMID_TOOL
    if (
        features.get("vendor")
        or features.get("name")
        or features.get("ssid")
        or features.get("signature")  # IDS signature (network ingestion)
    ):
        return PYRAMID_ARTIFACT
    return PYRAMID_ADDRESS


def _normalize_allowlist(entries: Iterable[Any]) -> Set[str]:
    """Normalize allowlist entries to lower-cased namespaced entity keys.

    A bare MAC/BSSID (``aa:bb:cc:dd:ee:ff``) trusts the address in *both*
    namespaces; a namespaced entry (``bt:...`` / ``bssid:...``) trusts it in
    that namespace only.
    """
    out: Set[str] = set()
    for raw in entries:
        e = str(raw).strip().lower()
        if not e or e.startswith("#"):
            continue
        if e.startswith(("bt:", "bssid:", "ip:")):
            out.add(e)
        else:
            out.add(f"bt:{e}")
            out.add(f"bssid:{e}")
    return out


def _entities(detection: Dict[str, Any]) -> List[str]:
    """Extract stable entity keys (namespaced identifiers) from a detection."""
    feats = detection.get("features") or {}
    out = []
    if feats.get("bssid"):
        out.append(f"bssid:{str(feats['bssid']).lower()}")
    if feats.get("address"):
        out.append(f"bt:{str(feats['address']).lower()}")
    for b in feats.get("new_bssids") or []:
        out.append(f"bssid:{str(b).lower()}")
    for dev in feats.get("new_devices") or []:
        addr = dev.get("address") if isinstance(dev, dict) else dev
        if addr:
            out.append(f"bt:{str(addr).lower()}")
    # Network alerts (Suricata ingestion): only the destination is an entity.
    # The source is usually the user's own device/router, which would recur in
    # every alert and drown persistence in noise; a recurring *destination* is
    # the beaconing/C2 signal worth tracking.
    if feats.get("dest_ip"):
        out.append(f"ip:{str(feats['dest_ip']).lower()}")
    return out


class CorrelationEngine:
    """Evaluates persistence / cross-sensor / burst rules over recent detections.

    Configured from the ``detection.correlation`` section of the app config:

    .. code-block:: yaml

        correlation:
          enabled: true
          window_seconds: 600      # how far back the engine remembers
          cooldown_seconds: 300    # min gap before the same finding re-fires
          allowlist:               # your own gear, excluded from correlation
            entities: []           # inline MACs, optionally bt:/bssid: prefixed
            file: data/trusted_entities.txt   # one entry per line, # comments
          rules:
            entity_persistence:
              enabled: true
              min_hits: 3          # same entity in this many detections...
              min_span_seconds: 60 # ...spread over at least this long
              severity: 4
            cross_sensor:
              enabled: true
              min_sensor_types: 2  # distinct sensor types alerting together
              severity: 4
            burst:
              enabled: true
              min_detections: 8    # raw detection volume in the window
              severity: 4
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None, movement=None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))
        #: Optional MovementTracker; separates "following me" (entity recurs
        #: while I moved) from "parked nearby" (entity recurs while I sat still).
        self.movement = movement
        self.window = float(cfg.get("window_seconds", 600))
        self.cooldown = float(cfg.get("cooldown_seconds", 300))

        rules = cfg.get("rules") or {}
        self._persistence = {"enabled": True, "min_hits": 3, "min_span_seconds": 60,
                             "severity": 4, **(rules.get("entity_persistence") or {})}
        self._cross_sensor = {"enabled": True, "min_sensor_types": 2,
                              "severity": 4, **(rules.get("cross_sensor") or {})}
        self._burst = {"enabled": True, "min_detections": 8,
                       "severity": 4, **(rules.get("burst") or {})}

        # Trusted entities (the user's own gear) are excluded from correlation
        # entirely: your smartwatch at strong RSSI all day is not evidence of
        # a hostile environment. This must be user-curated trust — never seed
        # it from the sensors' known_* files, which record everything seen.
        allow = cfg.get("allowlist") or {}
        self._allowlist = _normalize_allowlist(allow.get("entities") or [])
        allow_file = allow.get("file")
        if allow_file:
            path = Path(allow_file)
            if path.exists():
                self._allowlist |= _normalize_allowlist(
                    path.read_text().splitlines()
                )
                logger.info(
                    f"Correlation allowlist: {len(self._allowlist)} trusted "
                    f"entity keys (including {allow_file})"
                )

        # (observed_at, sensor_type, severity, entities, detection_id)
        self._events: Deque[Dict[str, Any]] = deque()
        self._last_fired: Dict[str, float] = {}

    def observe(
        self, detections: List[Dict[str, Any]], now: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """Feed new detections in; return any meta-detections they trigger.

        ``now`` is injectable for tests; defaults to ``time.time()``.
        """
        if not self.enabled:
            return []
        now = time.time() if now is None else now

        for d in detections:
            if d.get("sensor_type") == "correlation":
                continue  # never correlate our own output
            entities = _entities(d)
            trusted = [e for e in entities if e in self._allowlist]
            if trusted and len(trusted) == len(entities):
                continue  # detection is entirely about the user's own gear
            self._events.append({
                "at": now,
                "sensor_type": d.get("sensor_type", "unknown"),
                "severity": int(d.get("severity", 1)),
                "entities": [e for e in entities if e not in self._allowlist],
                "id": d.get("id"),
            })

        cutoff = now - self.window
        while self._events and self._events[0]["at"] < cutoff:
            self._events.popleft()

        meta: List[Dict[str, Any]] = []
        meta.extend(self._check_persistence(now))
        meta.extend(self._check_cross_sensor(now))
        meta.extend(self._check_burst(now))
        return meta

    def _cooled_down(self, key: str, now: float) -> bool:
        last = self._last_fired.get(key)
        if last is not None and (now - last) < self.cooldown:
            return False
        self._last_fired[key] = now
        return True

    def _meta(self, rule: str, severity: int, description: str,
              features: Dict[str, Any]) -> Dict[str, Any]:
        features = {**features, "rule": rule, "pyramid_level": PYRAMID_TTP}
        return {
            "id": f"corr_{rule}_{uuid.uuid4().hex[:6]}",
            "sensor_type": "correlation",
            "confidence": 0.9,
            "severity": max(1, min(5, int(severity))),
            "timestamp": pd.Timestamp.now(tz="UTC").isoformat(),
            "sensor_id": "correlation_engine",
            "description": description,
            "features": features,
        }

    def _check_persistence(self, now: float) -> List[Dict[str, Any]]:
        """Same entity recurring across the window → tracking/following suspect."""
        if not self._persistence.get("enabled", True):
            return []
        min_hits = int(self._persistence.get("min_hits", 3))
        min_span = float(self._persistence.get("min_span_seconds", 60))

        seen: Dict[str, List[float]] = {}
        for ev in self._events:
            for ent in ev["entities"]:
                seen.setdefault(ent, []).append(ev["at"])

        out = []
        for ent, times in seen.items():
            if len(times) < min_hits or (max(times) - min(times)) < min_span:
                continue

            moved = None  # None = no movement context available
            if self.movement is not None and self.movement.has_data():
                moved = self.movement.moved_between(min(times), max(times))
            if (
                moved is not True
                and self.movement is not None
                and self.movement.require_movement
            ):
                continue  # stationary recurrence isn't following behaviour
            if not self._cooled_down(f"persistence:{ent}", now):
                continue

            severity = int(self._persistence.get("severity", 4))
            description = (
                f"Entity {ent} persisted across {len(times)} detections over "
                f"{int(max(times) - min(times))}s — possible tracking device or "
                f"following behaviour"
            )
            if moved is True:
                # Recurring across places, not just across time: the strongest
                # following signal this grid can produce.
                severity += self.movement.escalate_severity
                description += " WHILE THE DEVICE WAS IN MOTION — entity is following you"
            out.append(self._meta(
                "entity_persistence",
                severity,
                description,
                {"entity": ent, "hits": len(times),
                 "span_seconds": int(max(times) - min(times)),
                 "moved_during_span": moved},
            ))
        return out

    def _check_cross_sensor(self, now: float) -> List[Dict[str, Any]]:
        """Multiple sensor domains alerting in one window → coordinated activity."""
        if not self._cross_sensor.get("enabled", True):
            return []
        min_types = int(self._cross_sensor.get("min_sensor_types", 2))

        types = {ev["sensor_type"] for ev in self._events}
        if len(types) < min_types:
            return []
        if not self._cooled_down("cross_sensor", now):
            return []
        return [self._meta(
            "cross_sensor",
            self._cross_sensor.get("severity", 4),
            f"Correlated activity across {len(types)} sensor domains "
            f"({', '.join(sorted(types))}) within {int(self.window)}s",
            {"sensor_types": sorted(types), "event_count": len(self._events)},
        )]

    def _check_burst(self, now: float) -> List[Dict[str, Any]]:
        """Raw detection volume spike inside the window."""
        if not self._burst.get("enabled", True):
            return []
        min_det = int(self._burst.get("min_detections", 8))
        if len(self._events) < min_det:
            return []
        if not self._cooled_down("burst", now):
            return []
        return [self._meta(
            "burst",
            self._burst.get("severity", 4),
            f"{len(self._events)} detections within {int(self.window)}s — "
            f"environment is actively hostile or rapidly changing",
            {"event_count": len(self._events)},
        )]
