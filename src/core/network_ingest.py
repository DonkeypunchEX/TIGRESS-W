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

import uuid
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from src.utils.logger import get_logger

logger = get_logger(__name__)

# Suricata severity: 1 is most severe. TIGRESS severity: 5 is most severe.
_SEVERITY_MAP = {1: 5, 2: 4, 3: 3}


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

    return {
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
            rejected += 1
        else:
            detections.append(det)
    if rejected:
        logger.warning(f"Rejected {rejected} non-alert/malformed EVE record(s)")
    return detections, rejected
