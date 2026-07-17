"""Movement context from accelerometer readings.

Persistence alone can't distinguish "a tracker is following me" from "I'm
sitting near my neighbour's TV all evening": both look like the same entity
recurring across scan windows. The discriminator is whether *you* moved during
the entity's sighting span — a device that keeps reappearing across different
places is following you; one that recurs while you're stationary is just
nearby.

The tracker ingests raw accelerometer magnitudes (every phone reading, not
just detections) and answers one question: did the device move between two
points in time? A sample counts as motion when its magnitude deviates from
gravity (~9.81 m/s²) by more than ``delta_threshold``.
"""

import time
from collections import deque
from typing import Any, Deque, Dict, Optional, Tuple

GRAVITY = 9.81


class MovementTracker:
    """Sliding record of whether the device was in motion.

    Configured from ``detection.correlation.movement``:

    .. code-block:: yaml

        movement:
          enabled: true
          delta_threshold: 1.5     # m/s² deviation from gravity = motion
          escalate_severity: 1     # persistence severity bump when moving
          require_movement: false  # persistence only fires if device moved
          retention_seconds: 1800  # how much motion history to keep
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.delta_threshold = float(cfg.get("delta_threshold", 1.5))
        self.escalate_severity = int(cfg.get("escalate_severity", 1))
        self.require_movement = bool(cfg.get("require_movement", False))
        self._retention = float(cfg.get("retention_seconds", 1800))
        self._samples: Deque[Tuple[float, bool]] = deque()

    def record(self, magnitude: Any, now: Optional[float] = None) -> None:
        """Record one accelerometer magnitude sample."""
        if not self.enabled or magnitude is None:
            return
        try:
            moving = abs(float(magnitude) - GRAVITY) > self.delta_threshold
        except (TypeError, ValueError):
            return
        now = time.time() if now is None else now
        self._samples.append((now, moving))
        cutoff = now - self._retention
        while self._samples and self._samples[0][0] < cutoff:
            self._samples.popleft()

    def moved_between(self, t0: float, t1: float) -> bool:
        """Whether any motion sample fell inside ``[t0, t1]``."""
        return any(moving for at, moving in self._samples if t0 <= at <= t1)

    def has_data(self) -> bool:
        """Whether any samples have been recorded (movement context exists)."""
        return len(self._samples) > 0
