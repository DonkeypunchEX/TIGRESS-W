"""Security posture: one knob that coherently retunes the whole grid.

Instead of hand-editing half a dozen thresholds to make TIGRESS more or less
sensitive, set ``posture`` in the config (or the ``TIGRESS_POSTURE`` env var,
which wins) and every relevant setting is derived together:

- ``relaxed``    – quiet daily carry: slower scans, higher alert bars
- ``normal``     – config values used exactly as written (default)
- ``aggressive`` – hostile-adjacent: faster scans, lower thresholds
- ``paranoid``   – maximum aggression: fastest scans, lowest thresholds,
                   longest correlation memory, +1 severity on everything

Posture multiplies the values already in the config, so your config remains
the single source of truth and posture is a coherent scaling of it. Run
``posture: normal`` if you want your exact numbers untouched.
"""

import copy
import os
from typing import Any, Dict

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Per-posture scaling. interval/threshold/alert factors multiply config
# values; min_severity_offset shifts alert-channel floors; severity_boost is
# added to every detection's severity; corr_* retune the correlation engine.
POSTURES: Dict[str, Dict[str, float]] = {
    "relaxed": {
        "interval_factor": 2.0,
        "confidence_factor": 1.25,
        "alert_threshold_factor": 1.5,
        "tamper_threshold_factor": 1.5,
        "min_severity_offset": 1,
        "severity_boost": 0,
        "corr_window_factor": 0.75,
        "corr_threshold_factor": 1.5,
    },
    "normal": {
        "interval_factor": 1.0,
        "confidence_factor": 1.0,
        "alert_threshold_factor": 1.0,
        "tamper_threshold_factor": 1.0,
        "min_severity_offset": 0,
        "severity_boost": 0,
        "corr_window_factor": 1.0,
        "corr_threshold_factor": 1.0,
    },
    "aggressive": {
        "interval_factor": 0.5,
        "confidence_factor": 0.75,
        "alert_threshold_factor": 0.66,
        "tamper_threshold_factor": 0.75,
        "min_severity_offset": -1,
        "severity_boost": 0,
        "corr_window_factor": 1.5,
        "corr_threshold_factor": 0.75,
    },
    "paranoid": {
        "interval_factor": 0.33,
        "confidence_factor": 0.5,
        "alert_threshold_factor": 0.4,
        "tamper_threshold_factor": 0.5,
        "min_severity_offset": -2,
        "severity_boost": 1,
        "corr_window_factor": 2.0,
        "corr_threshold_factor": 0.6,
    },
}

MIN_SCAN_INTERVAL = 5  # seconds; never hammer termux-api faster than this


def _clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))


def apply_posture(config: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``config`` with posture-derived tuning applied.

    Posture comes from ``TIGRESS_POSTURE`` (env) or the top-level ``posture``
    key; unknown values fall back to ``normal`` with a warning. The applied
    posture is recorded at ``config["posture_applied"]``.
    """
    name = (os.environ.get("TIGRESS_POSTURE") or config.get("posture") or "normal")
    name = str(name).strip().lower()
    if name not in POSTURES:
        logger.warning(f"Unknown posture '{name}' — falling back to 'normal'")
        name = "normal"

    cfg = copy.deepcopy(config)
    cfg["posture_applied"] = name
    p = POSTURES[name]
    if name == "normal":
        return cfg

    sensors = cfg.get("sensors") or {}
    for stype in ("wifi", "bluetooth"):
        scfg = sensors.get(stype)
        if not isinstance(scfg, dict):
            continue
        if "scan_interval" in scfg:
            scfg["scan_interval"] = max(
                MIN_SCAN_INTERVAL, int(round(scfg["scan_interval"] * p["interval_factor"]))
            )
        if "alert_threshold" in scfg:
            scfg["alert_threshold"] = max(
                1, int(round(scfg["alert_threshold"] * p["alert_threshold_factor"]))
            )
    phone = sensors.get("phone")
    if isinstance(phone, dict) and "tamper_threshold" in phone:
        phone["tamper_threshold"] = round(
            phone["tamper_threshold"] * p["tamper_threshold_factor"], 3
        )

    det = cfg.get("detection")
    if isinstance(det, dict):
        if "confidence_threshold" in det:
            det["confidence_threshold"] = round(
                _clamp(det["confidence_threshold"] * p["confidence_factor"], 0.05, 0.95), 3
            )
        det["severity_boost"] = int(p["severity_boost"])

        corr = det.get("correlation")
        if isinstance(corr, dict):
            if "window_seconds" in corr:
                corr["window_seconds"] = int(
                    round(corr["window_seconds"] * p["corr_window_factor"])
                )
            movement = corr.get("movement")
            if isinstance(movement, dict) and "delta_threshold" in movement:
                # More aggressive postures treat smaller accelerations as
                # motion, same scaling as the tamper threshold.
                movement["delta_threshold"] = round(
                    movement["delta_threshold"] * p["tamper_threshold_factor"], 3
                )
            for rule, keys in (
                ("entity_persistence", ("min_hits",)),
                ("cross_sensor", ("min_sensor_types",)),
                ("burst", ("min_detections",)),
            ):
                rcfg = (corr.get("rules") or {}).get(rule)
                if not isinstance(rcfg, dict):
                    continue
                for key in keys:
                    if key in rcfg:
                        rcfg[key] = max(
                            2, int(round(rcfg[key] * p["corr_threshold_factor"]))
                        )

    channels = (cfg.get("alerting") or {}).get("channels")
    if isinstance(channels, dict):
        for ccfg in channels.values():
            if isinstance(ccfg, dict) and "min_severity" in ccfg:
                ccfg["min_severity"] = int(
                    _clamp(ccfg["min_severity"] + p["min_severity_offset"], 1, 5)
                )

    logger.info(f"Posture '{name}' applied to configuration")
    return cfg
