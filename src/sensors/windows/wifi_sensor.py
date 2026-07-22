"""WiFi scanning sensor backed by Windows ``netsh wlan show networks``.

The Windows counterpart of :class:`src.sensors.wifi_sensor.WiFiSensor`. It shells
out to ``netsh wlan show networks mode=bssid`` and parses the human-readable
output into the same reading schema the detection engine already consumes —
one ``networks`` entry per BSSID with ``BSSID``/``SSID`` keys — so WiFi
detection, enrichment, and correlation work unchanged on Windows.

``netsh`` output is localized to the OS display language; the parser matches
the English field labels (``SSID``, ``BSSID``, ``Signal``, ``Channel``). On a
non-English Windows install the field labels differ and parsing degrades
gracefully to whatever it can recognise.
"""

import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from src.sensors.base_sensor import BaseSensor
from src.utils.logger import get_logger

logger = get_logger(__name__)

_SSID_RE = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)$")
_BSSID_RE = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})\s*$")
_SIGNAL_RE = re.compile(r"^\s*Signal\s*:\s*(\d+)\s*%")
_CHANNEL_RE = re.compile(r"^\s*Channel\s*:\s*(\d+)")
_AUTH_RE = re.compile(r"^\s*Authentication\s*:\s*(.*)$")
_RADIO_RE = re.compile(r"^\s*Radio type\s*:\s*(.*)$")


def _signal_to_rssi(percent: int) -> int:
    """Convert a Windows signal-quality percentage (0-100) to approximate dBm.

    Windows exposes link quality as a percentage, not a raw RSSI. The standard
    linear mapping is ``dBm = (percent / 2) - 100`` (0% -> -100 dBm, 100% ->
    -50 dBm), which is good enough for proximity-style rules.
    """
    return (int(percent) // 2) - 100


class WindowsWiFiSensor(BaseSensor):
    """Polls ``netsh wlan show networks`` and tracks newly-seen BSSIDs."""

    def __init__(self, sensor_id: str, config: dict):
        super().__init__(sensor_id, "wifi", config)
        self._interval = config.get("scan_interval", 30)
        self._known_file = Path(config.get("known_bssids_file", "data/known_bssids.txt"))
        self._known_bssids: set = self._load_known()
        self._thread: Optional[threading.Thread] = None

    def _load_known(self) -> set:
        if not self._known_file.exists():
            return set()
        return {line.strip() for line in self._known_file.read_text().splitlines() if line.strip()}

    def _save_known(self):
        self._known_file.parent.mkdir(exist_ok=True, parents=True)
        self._known_file.write_text("\n".join(sorted(self._known_bssids)) + "\n")

    def connect(self) -> bool:
        """Check that ``netsh`` is available; return True on success."""
        if shutil.which("netsh") is None:
            logger.warning("netsh not found — Windows WiFi sensor disabled")
            return False
        self.connected = True
        return True

    def disconnect(self):
        """Stop recording and mark the sensor disconnected."""
        self.stop_recording()
        self._save_known()
        self.connected = False

    def start_recording(self) -> bool:
        """Start the background sampling thread; return True on success."""
        if not self.connected:
            return False
        self.recording = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop_recording(self):
        """Stop the background sampling thread."""
        self.recording = False
        if self._thread:
            self._thread.join(timeout=5)
        self._save_known()

    def _loop(self):
        while self.recording:
            scan = self._scan()
            if scan:
                self.record(scan)
            time.sleep(self._interval)

    @staticmethod
    def parse_networks(raw: str) -> List[dict]:
        """Parse ``netsh wlan show networks mode=bssid`` output.

        Returns one dict per BSSID with ``BSSID``/``SSID`` (matching the
        Termux WiFi schema) plus ``signal_percent``, ``RSSI``, ``channel``,
        ``authentication``, and ``radio_type`` where available. A single SSID
        advertising several BSSIDs yields one entry per BSSID.
        """
        networks: List[dict] = []
        ssid: Optional[str] = None
        auth: Optional[str] = None
        current: Optional[dict] = None

        for line in raw.splitlines():
            m = _SSID_RE.match(line)
            if m:
                ssid = m.group(1).strip()
                auth = None
                current = None
                continue

            m = _AUTH_RE.match(line)
            if m and current is None:
                auth = m.group(1).strip()
                continue

            m = _BSSID_RE.match(line)
            if m:
                current = {
                    "SSID": ssid or "",
                    "BSSID": m.group(1).lower(),
                    "authentication": auth,
                }
                networks.append(current)
                continue

            if current is None:
                continue

            m = _SIGNAL_RE.match(line)
            if m:
                pct = int(m.group(1))
                current["signal_percent"] = pct
                current["RSSI"] = _signal_to_rssi(pct)
                continue

            m = _CHANNEL_RE.match(line)
            if m:
                current["channel"] = int(m.group(1))
                continue

            m = _RADIO_RE.match(line)
            if m:
                current["radio_type"] = m.group(1).strip()

        return networks

    def _scan(self) -> Optional[dict]:
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            networks = self.parse_networks(result.stdout)
            bssids = {net["BSSID"] for net in networks if net.get("BSSID")}
            new_bssids = bssids - self._known_bssids
            self._known_bssids.update(new_bssids)

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sensor_id": self.sensor_id,
                "sensor_type": "wifi",
                "networks": networks,
                "ap_count": len(networks),
                "new_ap_count": len(new_bssids),
                "new_bssids": list(new_bssids),
            }
        except Exception as e:
            logger.error(f"Windows WiFi scan error: {e}")
            return None
