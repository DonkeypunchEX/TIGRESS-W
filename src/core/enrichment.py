"""Offline-first threat-intel enrichment for sensor readings.

Adds derived fields to WiFi networks and Bluetooth devices *before* rule
matching, so rules can target what a device *is* rather than the literal
string it advertises today:

- ``vendor``             – OUI prefix lookup against a local, extendable map
- ``mac_randomized``     – locally-administered bit set (privacy/rotating MAC)
- ``tracker_name_match`` – advertised name matches a known tracker pattern
- ``is_tracker``         – tracker by name or by tracker-vendor OUI

Everything works offline: the data ships in ``config/enrichment.yaml`` and is
user-extendable. No network calls, ever — this must run on a phone in a
hostile environment.

Note that modern trackers (AirTag, SmartTag) rotate randomized MACs and often
advertise no name at all, so name/OUI matching alone is deliberately treated
as the weakest signal. The strong detector is ``mac_randomized`` combined
with the correlation engine's entity-persistence rule: a rotating-MAC device
that keeps reappearing near you is tracker *behaviour*, whatever it calls
itself.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Built-in seed data, used when no enrichment file is configured or found.
# The YAML file extends/overrides these; treat both as starter lists to grow.
_DEFAULT_TRACKER_NAME_PATTERNS = [
    "airtag", "air tag", "tile", "smarttag", "smart tag",
    "chipolo", "itag", "tracker", "nut find",
]
_DEFAULT_TRACKER_VENDORS = ["apple", "tile", "samsung", "chipolo"]
_DEFAULT_OUI_VENDORS = {
    "00:03:93": "Apple",
    "00:0a:95": "Apple",
    "00:1b:63": "Apple",
    "f0:18:98": "Apple",
    "00:12:47": "Samsung",
    "00:15:99": "Samsung",
}


def normalize_mac(mac: Any) -> Optional[str]:
    """Lower-cased, colon-separated MAC, or None if it doesn't look like one."""
    if not mac:
        return None
    s = str(mac).strip().lower().replace("-", ":")
    parts = s.split(":")
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        return None
    try:
        [int(p, 16) for p in parts]
    except ValueError:
        return None
    return ":".join(parts)


def mac_is_randomized(mac: Any) -> bool:
    """True when the locally-administered bit is set (randomized/private MAC)."""
    norm = normalize_mac(mac)
    if norm is None:
        return False
    return bool(int(norm.split(":")[0], 16) & 0x02)


class Enricher:
    """Annotates readings using local OUI/tracker intelligence."""

    def __init__(self, data_file: Optional[str] = None):
        self._oui: Dict[str, str] = dict(_DEFAULT_OUI_VENDORS)
        self._tracker_patterns: List[str] = list(_DEFAULT_TRACKER_NAME_PATTERNS)
        self._tracker_vendors: List[str] = list(_DEFAULT_TRACKER_VENDORS)

        if data_file:
            path = Path(data_file)
            if path.exists():
                self._load(path)
            else:
                logger.warning(f"Enrichment file not found: {data_file} — using built-in seed data")

    def _load(self, path: Path):
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        for prefix, vendor in (data.get("oui_vendors") or {}).items():
            self._oui[str(prefix).strip().lower()] = str(vendor)
        self._tracker_patterns.extend(
            str(p).lower() for p in data.get("tracker_name_patterns") or []
        )
        self._tracker_vendors.extend(
            str(v).lower() for v in data.get("tracker_vendors") or []
        )
        logger.info(
            f"Enrichment data loaded: {len(self._oui)} OUI prefixes, "
            f"{len(self._tracker_patterns)} tracker name patterns"
        )

    def vendor(self, mac: Any) -> Optional[str]:
        """Vendor name for a MAC's OUI prefix, or None if unknown."""
        norm = normalize_mac(mac)
        if norm is None:
            return None
        return self._oui.get(norm[:8])

    def _tracker_name(self, name: Any) -> bool:
        if not name:
            return False
        lowered = str(name).lower()
        return any(p in lowered for p in self._tracker_patterns)

    def enrich_wifi(self, net: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of a WiFi network dict with enrichment fields added."""
        out = dict(net)
        mac = out.get("BSSID") or out.get("bssid")
        out["vendor"] = self.vendor(mac)
        out["mac_randomized"] = mac_is_randomized(mac)
        return out

    def enrich_bluetooth(self, dev: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy of a BT device dict with enrichment fields added."""
        out = dict(dev)
        mac = out.get("address") or out.get("mac") or out.get("BLUETOOTH_ADDRESS")
        vendor = self.vendor(mac)
        name_match = self._tracker_name(out.get("name"))
        out["vendor"] = vendor
        out["mac_randomized"] = mac_is_randomized(mac)
        out["tracker_name_match"] = name_match
        out["is_tracker"] = name_match or (
            vendor is not None and vendor.lower() in self._tracker_vendors
        )
        return out
