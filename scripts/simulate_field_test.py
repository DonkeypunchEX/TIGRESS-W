#!/usr/bin/env python
"""Simulated field test: a scripted day played through the real TIGRESS engine.

No Android, no sensors, no network — this drives the actual DetectionEngine
(rules, enrichment, correlation, movement context, allowlist, Suricata
ingestion) through a compressed day with a planted tracker:

  Phase A  home, stationary     — only your own (allowlisted) gear around
  Phase B  commute, in motion   — an unknown randomized-MAC device tags along
  Phase C  cafe, stationary     — the same device is *still* there
  Phase D  router alerts        — Suricata reports repeated C2 beaconing

Expected outcome: zero findings about your own gear, an entity-persistence
finding escalated because the device recurred WHILE you were moving,
cross-sensor correlation, and an ip-entity persistence finding from the
router — all queryable at TTP level, exactly like the /detections API.

Simulated time is injected by patching the clock used by the correlation and
movement modules, so a "day" plays out in milliseconds.

Usage:
    python scripts/simulate_field_test.py
"""

import os
import sys
import tempfile

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import src.core.correlation_engine as corr_mod  # noqa: E402
import src.core.movement as mov_mod  # noqa: E402
from src.core.detection_engine import DetectionEngine  # noqa: E402

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"

# The cast. WATCH is the user's own gear (allowlisted). TRACKER has the
# locally-administered bit set (0x4a & 0x02) — a randomized/rotating MAC.
WATCH = "f0:18:98:aa:bb:01"
HOME_BSSID = "00:1b:63:11:22:33"
TRACKER = "4a:11:22:33:44:55"
C2_IP = "203.0.113.66"


class SimClock:
    """Deterministic replacement for the ``time`` module in sim runs."""

    def __init__(self):
        self.t = 0.0

    def time(self) -> float:
        """Return the current simulated epoch seconds."""
        return self.t


def build_engine(workdir: str) -> DetectionEngine:
    """Write an isolated config into ``workdir`` and build a real engine."""
    trusted = os.path.join(workdir, "trusted_entities.txt")
    with open(trusted, "w") as f:
        f.write(f"# my gear\n{WATCH}\nbssid:{HOME_BSSID}\n")

    rules = {
        "wifi_rules": [],
        "bluetooth_rules": [
            {
                "id": "ble_close_proximity",
                "enabled": True,
                "description": "Bluetooth device in very close proximity (strong RSSI)",
                "severity": 3,
                "confidence": 0.75,
                "conditions": [{"field": "rssi", "op": "gt", "value": "-50"}],
            },
            {
                "id": "ble_randomized_mac_close",
                "enabled": True,
                "description": "Randomized-MAC device in close proximity (tracker-like)",
                "severity": 3,
                "confidence": 0.7,
                "conditions": [
                    {"field": "mac_randomized", "op": "eq", "value": True},
                    {"field": "rssi", "op": "gt", "value": "-60"},
                ],
            },
        ],
    }
    rules_path = os.path.join(workdir, "rules.yaml")
    with open(rules_path, "w") as f:
        yaml.safe_dump(rules, f)

    config = {
        "sensors": {
            "wifi": {"alert_threshold": 3},
            "bluetooth": {"alert_threshold": 5},
        },
        "detection": {
            "confidence_threshold": 0.6,
            "rules_file": rules_path,
            "ml_models": {
                "wifi": os.path.join(workdir, "m", "wifi.pkl"),
                "phone": os.path.join(workdir, "m", "phone.pkl"),
                "bluetooth": os.path.join(workdir, "m", "bt.pkl"),
            },
            "correlation": {
                "enabled": True,
                "window_seconds": 1800,
                "cooldown_seconds": 600,
                "allowlist": {"file": trusted},
                "movement": {"delta_threshold": 1.5, "escalate_severity": 1},
                "rules": {
                    "entity_persistence": {
                        "enabled": True, "min_hits": 3,
                        "min_span_seconds": 120, "severity": 4,
                    },
                    "cross_sensor": {"enabled": True, "min_sensor_types": 2,
                                     "severity": 4},
                    "burst": {"enabled": True, "min_detections": 12,
                              "severity": 4},
                },
            },
        },
        "alerting": {
            "forensic_log": os.path.join(workdir, "forensic.jsonl"),
            "async_dispatch": False,
            "channels": {"termux": {"enabled": False}},
        },
    }
    config_path = os.path.join(workdir, "config.yaml")
    with open(config_path, "w") as f:
        yaml.safe_dump(config, f)
    return DetectionEngine(config_path)


def wifi_scan(networks, new_bssids=()):
    """Build a WiFi scan reading in the shape the WiFi sensor produces."""
    return {
        "networks": networks,
        "ap_count": len(networks),
        "new_ap_count": len(new_bssids),
        "new_bssids": list(new_bssids),
    }


def bt_scan(devices):
    """Build a Bluetooth scan reading in the shape the BLE sensor produces."""
    return {
        "devices": devices,
        "device_count": len(devices),
        "new_device_count": 0,
        "new_devices": [],
    }


def hhmm(t: float) -> str:
    """Format simulated seconds as HH:MM for the timeline output."""
    return f"{int(t // 3600):02d}:{int(t % 3600 // 60):02d}"


class Reporter:
    """Prints newly dispatched detections after each simulated step."""

    def __init__(self, engine, clock):
        self.engine, self.clock, self.seen = engine, clock, 0

    def flush(self):
        """Print any detections dispatched since the last flush."""
        history = self.engine.history
        new = history.recent(limit=len(history))[: len(history) - self.seen]
        for d in reversed(new):
            feats = d["features"]
            tag = f"{d['sensor_type']}/{feats.get('pyramid_level', '?')}"
            print(f"  {hhmm(self.clock.t)}  [sev {d['severity']}] ({tag}) "
                  f"{d['description']}")
        self.seen = len(history)


def main():
    """Run the scripted day and return a shell exit code."""
    clock = SimClock()
    corr_mod.time = clock  # the modules call time.time(); give them sim time
    mov_mod.time = clock

    workdir = tempfile.mkdtemp(prefix="tigress_sim_")
    engine = build_engine(workdir)
    report = Reporter(engine, clock)

    watch = {"address": WATCH, "name": "My Watch", "rssi": -45}
    tracker = {"address": TRACKER, "name": "", "rssi": -52}

    print(f"{BOLD}=== Phase A (08:00) home, stationary — own gear only ==={RESET}")
    print(f"{DIM}  watch {WATCH} is allowlisted: atomic proximity alerts still fire"
          f" (rule-level noise), but correlation must stay silent about it{RESET}")
    for _ in range(10):
        clock.t += 30
        engine.analyze_phone([{"magnitude": 9.8, "tamper_suspect": False,
                               "timestamp": "", "sensor_id": "phone_sensor"}])
        engine.analyze_wifi([wifi_scan([{"SSID": "HomeNet", "BSSID": HOME_BSSID}])])
        engine.analyze_bluetooth([bt_scan([watch])])
        report.flush()
    corr_a = engine.history.recent(sensor_type="correlation", limit=1)
    print(f"  {hhmm(clock.t)}  correlation findings about your own gear: "
          f"{len(corr_a)} {'✅' if not corr_a else '❌'}\n")

    print(f"{BOLD}=== Phase B (08:05+) commute, IN MOTION — tracker appears ==={RESET}")
    print(f"{DIM}  unknown randomized-MAC device {TRACKER} rides along{RESET}")
    for i in range(10):
        clock.t += 60
        engine.analyze_phone([{"magnitude": 13.0, "tamper_suspect": False,
                               "timestamp": "", "sensor_id": "phone_sensor"}])
        if i == 4:  # passing through a transit hub: unfamiliar APs surge
            engine.analyze_wifi([wifi_scan(
                [{"SSID": "Metro-Free", "BSSID": "00:12:47:99:88:77"}],
                new_bssids=["a", "b", "c", "d"],
            )])
        engine.analyze_bluetooth([bt_scan([watch, tracker])])
        report.flush()
    print()

    print(f"{BOLD}=== Phase C cafe, stationary — tracker is STILL there ==={RESET}")
    for _ in range(10):
        clock.t += 60
        engine.analyze_phone([{"magnitude": 9.8, "tamper_suspect": False,
                               "timestamp": "", "sensor_id": "phone_sensor"}])
        engine.analyze_bluetooth([bt_scan([watch, tracker])])
        report.flush()
    print()

    print(f"{BOLD}=== Phase D router Suricata alerts — repeated C2 beaconing ==={RESET}")
    for _ in range(3):
        clock.t += 120
        engine.ingest_network({
            "event_type": "alert", "src_ip": "192.168.1.50", "dest_ip": C2_IP,
            "dest_port": 443, "proto": "TCP",
            "alert": {"signature": "ET MALWARE Cobalt Strike Beacon",
                      "signature_id": 2027863, "category": "C2", "severity": 1},
        })
        report.flush()
    print()

    print(f"{BOLD}=== Final state (the /detections API view) ==={RESET}")
    summary = engine.history.summary()
    print(f"  summary: {summary}")
    print(f"\n  {BOLD}'Am I being followed?' — pyramid_level=ttp&min_severity=4:{RESET}")
    for d in engine.history.recent(pyramid_level="ttp", min_severity=4):
        moved = d["features"].get("moved_during_span")
        print(f"    [sev {d['severity']}] {d['description']}"
              f"{DIM} (moved_during_span={moved}){RESET}")

    ttp = summary.get("by_pyramid_level", {}).get("ttp", 0)
    ok = ttp >= 2 and summary["by_sensor_type"].get("correlation", 0) >= 2
    print(f"\n{BOLD}{'✅ simulation produced the expected TTP findings' if ok else '❌ expected findings missing'}{RESET}")
    print(f"{DIM}  forensic log: {os.path.join(workdir, 'forensic.jsonl')}{RESET}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
