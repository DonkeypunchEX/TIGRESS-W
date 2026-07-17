"""Bounded, thread-safe in-memory store of recent detections.

Backs the dashboard's ``/detections`` API so alerts are queryable, not just
delivered as one-off push notifications. Detections are also persisted to the
forensic JSONL log; this store is the fast, in-memory view of the most recent
ones.
"""

import copy
import threading
from collections import deque
from typing import Any, Deque, Dict, List, Optional


class DetectionStore:
    """Keeps the most recent detections (as plain dicts) for querying."""

    def __init__(self, max_size: int = 500):
        self._items: Deque[Dict[str, Any]] = deque(maxlen=max(1, int(max_size)))
        self._lock = threading.Lock()

    def add(self, detection: Dict[str, Any]) -> None:
        """Record a detection (a ``Detection.__dict__``).

        The detection is deep-copied so later mutation of the caller's object
        (including nested values such as ``features``) cannot alter the store.
        """
        with self._lock:
            self._items.append(copy.deepcopy(detection))

    def recent(
        self,
        limit: int = 50,
        min_severity: int = 1,
        sensor_type: Optional[str] = None,
        pyramid_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return up to ``limit`` recent detections, newest first.

        Filters to detections with ``severity >= min_severity`` and, when
        given, to a single ``sensor_type`` and/or Pyramid of Pain
        ``pyramid_level`` (``address``/``artifact``/``tool``/``ttp``, read
        from ``features.pyramid_level``).
        """
        if limit <= 0:
            return []
        with self._lock:
            items = list(self._items)

        out: List[Dict[str, Any]] = []
        for d in reversed(items):
            if d.get("severity", 0) < min_severity:
                continue
            if sensor_type and d.get("sensor_type") != sensor_type:
                continue
            if pyramid_level and (
                (d.get("features") or {}).get("pyramid_level") != pyramid_level
            ):
                continue
            out.append(copy.deepcopy(d))  # isolate callers from stored data
            if len(out) >= limit:
                break
        return out

    def summary(self) -> Dict[str, Any]:
        """Return counts by severity, sensor type, and Pyramid of Pain band."""
        with self._lock:
            items = list(self._items)

        by_severity: Dict[int, int] = {}
        by_sensor_type: Dict[str, int] = {}
        by_pyramid_level: Dict[str, int] = {}
        for d in items:
            sev = d.get("severity", 0)
            by_severity[sev] = by_severity.get(sev, 0) + 1
            stype = d.get("sensor_type", "unknown")
            by_sensor_type[stype] = by_sensor_type.get(stype, 0) + 1
            level = (d.get("features") or {}).get("pyramid_level", "unknown")
            by_pyramid_level[level] = by_pyramid_level.get(level, 0) + 1

        return {
            "total": len(items),
            "by_severity": {str(k): by_severity[k] for k in sorted(by_severity)},
            "by_sensor_type": by_sensor_type,
            "by_pyramid_level": by_pyramid_level,
        }

    def clear(self) -> None:
        """Drop all stored detections."""
        with self._lock:
            self._items.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)
