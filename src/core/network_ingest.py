"""Suricata EVE alert ingestion: the router as a TIGRESS sensor.

Packet-level inspection is the wrong job for a non-rooted phone (no raw
sockets, battery cost, and the phone's threat model is proximity, not
perimeter). The right architecture is Suricata/Snort running where packets
actually flow — a router or gateway you control — POSTing its EVE alerts to
the dashboard's ``/ingest/suricata`` endpoint. Alerts become first-class
``network`` detections: forensically logged, alerted, and fed to the
correlation engine, where a recurring destination IP (beaconing/C2) can trip
entity persistence and network + wireless + physical activity can trip
cross-sensor correlation.

Only the fields TIGRESS uses are read; unknown EVE fields are ignored.
"""

import base64
import uuid
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Suricata severity: 1 is most severe. TIGRESS severity: 5 is most severe.
_SEVERITY_MAP = {1: 5, 2: 4, 3: 3}

# TCP flag bits (Bvp47 "SYN knock" covert-channel detection).
_TCP_SYN = 0x02
_TCP_ACK = 0x10


def _payload_len(event: Dict[str, Any]) -> int:
    """Best-effort payload length from an EVE record's payload fields."""
    plen = event.get("payload_len")
    if isinstance(plen, int):
        return plen
    payload = event.get("payload")
    if isinstance(payload, str) and payload:
        try:
            return len(base64.b64decode(payload, validate=False))
        except ValueError:  # binascii.Error subclasses ValueError
            pass
    printable = event.get("payload_printable")
    if isinstance(printable, str):
        return len(printable)
    return 0


def _is_syn_only(event: Dict[str, Any]) -> bool:
    """True when the record describes a TCP SYN packet with no ACK set."""
    tcp = event.get("tcp")
    if not isinstance(tcp, dict):
        return False
    flags = tcp.get("tcp_flags")
    if isinstance(flags, str):
        try:
            value = int(flags, 16)
            return bool(value & _TCP_SYN) and not bool(value & _TCP_ACK)
        except ValueError:
            pass
    if "syn" in tcp or "ack" in tcp:
        return bool(tcp.get("syn")) and not bool(tcp.get("ack"))
    return False


def covert_channel_tag(event: Dict[str, Any]) -> Optional[str]:
    """Return a covert-channel tag for an EVE record, or ``None``.

    Detects the Bvp47 "SYN knock" technique: a TCP SYN packet (no ACK) that
    carries a data payload. Most perimeter sensors never inspect the payload of
    the initial handshake packet, so a SYN that carries data is a strong
    covert-channel indicator — a tool/TTP-band signal on the Pyramid of Pain —
    whether or not any IDS signature matched it.
    """
    if not isinstance(event, dict):
        return None
    if _is_syn_only(event) and _payload_len(event) > 0:
        return "syn_payload"
    return None


def covert_channel_detection(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Synthesize a network Detection for a covert channel with no IDS alert.

    Bvp47-class implants are built to evade signature detection, so the SYN
    knock often arrives with no ``alert`` object at all. This turns such a
    record into a first-class TTP-band ``network`` detection so the correlation
    engine still sees it.
    """
    tag = covert_channel_tag(event)
    if tag is None:
        return None
    timestamp = event.get("timestamp") or pd.Timestamp.now(tz="UTC").isoformat()
    return {
        "id": f"net_{uuid.uuid4().hex[:8]}",
        "sensor_type": "network",
        "confidence": 0.85,
        "severity": 4,
        "timestamp": str(timestamp),
        "sensor_id": "suricata",
        "description": "Covert channel suspected: payload in TCP SYN packet (SYN knock)",
        "phase": "covert_channel",
        "weight": 4.0,
        "features": {
            "rule": "covert_channel",
            "covert_channel": tag,
            "pyramid_level": "ttp",  # behaviour, not a rotatable indicator
            "src_ip": event.get("src_ip"),
            "dest_ip": event.get("dest_ip"),
            "dest_port": event.get("dest_port"),
            "proto": event.get("proto"),
        },
    }


def eve_to_detection(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map one Suricata EVE record to a Detection dict, or None to reject.

    Accepts ``event_type: alert`` records (or records with an ``alert``
    object); everything else (flow, dns, stats, ...) is rejected.
    """
    if not isinstance(event, dict):
        return None
    alert = event.get("alert")
    if not isinstance(alert, dict):
        return None
    if event.get("event_type") not in (None, "alert"):
        return None

    signature = str(alert.get("signature") or "Unknown network alert")
    severity = _SEVERITY_MAP.get(alert.get("severity"), 2)
    timestamp = event.get("timestamp") or pd.Timestamp.now(tz="UTC").isoformat()

    detection: Dict[str, Any] = {
        "id": f"net_{uuid.uuid4().hex[:8]}",
        "sensor_type": "network",
        "confidence": 0.9,  # a signature IDS match is a high-confidence event
        "severity": severity,
        "timestamp": str(timestamp),
        "sensor_id": "suricata",
        "description": signature,
        "features": {
            "rule": "suricata_alert",
            "signature": signature,
            "signature_id": alert.get("signature_id"),
            "category": alert.get("category"),
            "src_ip": event.get("src_ip"),
            "dest_ip": event.get("dest_ip"),
            "dest_port": event.get("dest_port"),
            "proto": event.get("proto"),
        },
    }

    # An alerting record that is *also* a SYN knock is escalated to the
    # tool/TTP band: the covert channel is the harder-to-change indicator.
    tag = covert_channel_tag(event)
    if tag:
        detection["features"]["covert_channel"] = tag
        detection["features"]["pyramid_level"] = "ttp"
        detection["phase"] = "covert_channel"
        detection["weight"] = 4.0
        detection["severity"] = max(severity, 4)

    return detection


def eve_to_detections(payload: Any) -> Tuple[List[Dict[str, Any]], int]:
    """Convert an EVE payload (one record or a list) to Detection dicts.

    Returns ``(detections, rejected_count)``.
    """
    events = payload if isinstance(payload, list) else [payload]
    detections: List[Dict[str, Any]] = []
    rejected = 0
    for event in events:
        det = eve_to_detection(event)
        if det is None:
            # No IDS alert — but a SYN knock still gets flagged, since
            # covert-channel implants are built to evade signature detection.
            det = covert_channel_detection(event) if isinstance(event, dict) else None
        if det is None:
            rejected += 1
        else:
            detections.append(det)
    if rejected:
        logger.warning(f"Rejected {rejected} non-alert/malformed EVE record(s)")
    return detections, rejected
