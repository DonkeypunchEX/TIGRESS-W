#!/usr/bin/env python
"""Remote BLE scanner node: turn a Pi/laptop into a TIGRESS bluetooth sensor.

Termux's mainline API has no BLE scanning, and iPhones can't run background
scanners at all — so the grid model is: a cheap dedicated node does the radio
work and TIGRESS stays the correlation brain. This script scans BLE via
`bleak` and POSTs each scan to the dashboard's ``/ingest/ble`` endpoint,
where it flows through the same enrichment, rules, and correlation as an
on-device scan.

Runs on Raspberry Pi / Linux / macOS / Windows — anywhere bleak works.
Only third-party dependency is bleak (``pip install bleak``); HTTP is
standard library. Note: on macOS, addresses are OS-assigned UUIDs rather
than MACs, so vendor/randomized-MAC enrichment won't apply there — Linux
(Pi) nodes give the highest-fidelity data.

Usage:
    export TIGRESS_API_TOKEN=...        # must match the dashboard's token
    python scripts/ble_scanner_node.py --url http://192.168.1.20:8080 \
        --node bag-pi --interval 15 --min-rssi -85
"""

import argparse
import asyncio
import json
import os
import sys
import time
import urllib.error
import urllib.request

try:
    from bleak import BleakScanner
except ImportError:  # pragma: no cover - depends on node environment
    sys.exit("bleak is required on the scanner node: pip install bleak")


def post_scan(url: str, token: str, payload: dict, timeout: float = 10.0) -> dict:
    """POST one scan payload to /ingest/ble and return the parsed response."""
    req = urllib.request.Request(
        url.rstrip("/") + "/ingest/ble",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


async def scan_once(scan_seconds: float, min_rssi: int) -> list:
    """Run one BLE discovery pass and return device dicts above min_rssi."""
    found = await BleakScanner.discover(timeout=scan_seconds, return_adv=True)
    devices = []
    for device, adv in found.values():
        rssi = adv.rssi if adv.rssi is not None else -127
        if rssi < min_rssi:
            continue
        devices.append({
            "address": device.address,
            "name": device.name or adv.local_name or "",
            "rssi": rssi,
        })
    return devices


def main() -> int:
    """Scan forever, POSTing each pass to the TIGRESS dashboard."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True, help="TIGRESS dashboard base URL")
    parser.add_argument("--node", default="ble-node", help="Node ID reported with scans")
    parser.add_argument("--interval", type=float, default=15.0,
                        help="Seconds between scan passes")
    parser.add_argument("--scan-seconds", type=float, default=5.0,
                        help="Length of each BLE discovery pass")
    parser.add_argument("--min-rssi", type=int, default=-90,
                        help="Ignore devices weaker than this RSSI")
    args = parser.parse_args()

    token = os.environ.get("TIGRESS_API_TOKEN", "")
    if not token:
        sys.exit("Set TIGRESS_API_TOKEN (the dashboard rejects unauthenticated ingest)")

    print(f"🐯 TIGRESS BLE node '{args.node}' → {args.url} "
          f"(every {args.interval:.0f}s, min RSSI {args.min_rssi})")
    while True:
        started = time.time()
        try:
            devices = asyncio.run(scan_once(args.scan_seconds, args.min_rssi))
            result = post_scan(args.url, token, {"node_id": args.node, "devices": devices})
            print(f"[{time.strftime('%H:%M:%S')}] {len(devices)} device(s) → "
                  f"new={result.get('new_devices', 0)} "
                  f"detections={result.get('detections', 0)}")
        except urllib.error.HTTPError as e:
            print(f"[{time.strftime('%H:%M:%S')}] dashboard rejected scan: "
                  f"HTTP {e.code} {e.reason}")
        except Exception as e:  # keep scanning through transient BT/net errors
            print(f"[{time.strftime('%H:%M:%S')}] error: {e}")
        time.sleep(max(0.0, args.interval - (time.time() - started)))


if __name__ == "__main__":
    sys.exit(main())
