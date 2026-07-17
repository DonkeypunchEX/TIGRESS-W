"""FastAPI dashboard exposing sensor status and health endpoints."""

import argparse
import hmac
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Union

import uvicorn
from fastapi import Body, Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from src.core.sensor_manager import SensorManager
from src.utils.logger import get_logger

logger = get_logger(__name__)

_manager: SensorManager = None
#: Bearer token required for data endpoints; None disables auth (set in main()).
_api_token: Optional[str] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start sensors on app startup and stop them on shutdown."""
    _manager.start_all()
    yield
    _manager.stop_all()


app = FastAPI(title="TIGRESS", lifespan=lifespan)


def _require_token(authorization: Optional[str] = Header(default=None)):
    """Enforce bearer-token auth when a token is configured.

    A no-op when no token is set (``_api_token`` is None), preserving the
    previous open behaviour. Comparison is constant-time.
    """
    if not _api_token:
        return
    expected = f"Bearer {_api_token}"
    if authorization is None or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Unauthorized")


def _require_token_strict(authorization: Optional[str] = Header(default=None)):
    """Enforce bearer-token auth, refusing service when no token is set.

    Write endpoints (ingestion) must never fall open the way the read
    endpoints do: without a configured token, anyone on the network could
    inject fake detections into the forensic log and alert channels.
    """
    if not _api_token:
        raise HTTPException(
            status_code=403,
            detail="Ingestion disabled: set server.api_token or TIGRESS_API_TOKEN",
        )
    _require_token(authorization)


@app.get("/", dependencies=[Depends(_require_token)])
def root():
    """Root endpoint: overall status and sensor list."""
    return {"status": "running", "sensors": _manager.list_sensors() if _manager else []}


@app.get("/sensors", dependencies=[Depends(_require_token)])
def sensors():
    """Return per-sensor status."""
    return JSONResponse(_manager.list_sensors())


@app.get("/health")
def health():
    """Liveness probe reporting whether sensors are running (no auth required)."""
    return {"ok": True, "sensors_running": _manager.is_running if _manager else False}


@app.get("/detections", dependencies=[Depends(_require_token)])
def detections(
    limit: int = 50,
    min_severity: int = 1,
    sensor_type: Optional[str] = None,
    pyramid_level: Optional[str] = None,
):
    """Return recent detections, newest first, with optional filters.

    Query params: ``limit`` (max results), ``min_severity`` (1-5),
    ``sensor_type`` (e.g. ``wifi``, ``correlation``, ``network``), and
    ``pyramid_level`` (``address``/``artifact``/``tool``/``ttp``).
    """
    if not _manager:
        return []
    return _manager.detection_engine.history.recent(
        limit=limit,
        min_severity=min_severity,
        sensor_type=sensor_type,
        pyramid_level=pyramid_level,
    )


@app.get("/detections/summary", dependencies=[Depends(_require_token)])
def detections_summary():
    """Return counts of recent detections by severity and sensor type."""
    if not _manager:
        return {
            "total": 0,
            "by_severity": {},
            "by_sensor_type": {},
            "by_pyramid_level": {},
        }
    return _manager.detection_engine.history.summary()


@app.post("/ingest/ble", dependencies=[Depends(_require_token_strict)])
def ingest_ble(payload: Union[List[Any], Dict[str, Any]] = Body(...)):
    """Ingest a BLE scan from a remote sensor node.

    Body: ``{"node_id": "bag-pi", "devices": [{"address", "name", "rssi"},
    ...]}`` or a bare device list. The scan runs through the same enrichment,
    rules, and correlation as on-device Bluetooth. Requires the bearer token;
    disabled (403) when no token is configured.
    """
    if not _manager:
        raise HTTPException(status_code=503, detail="Sensor manager not running")
    return _manager.detection_engine.ingest_ble(payload)


@app.post("/ingest/suricata", dependencies=[Depends(_require_token_strict)])
def ingest_suricata(payload: Union[List[Any], Dict[str, Any]] = Body(...)):
    """Ingest Suricata EVE alert(s) from a router/gateway sensor.

    Accepts a single EVE record or a list; only ``alert`` records are
    converted (flow/dns/stats records are counted as rejected). Accepted
    alerts become ``network`` detections and flow through the forensic log,
    alert channels, and correlation engine like any on-device detection.
    Requires the same bearer token as the data endpoints.
    """
    if not _manager:
        raise HTTPException(status_code=503, detail="Sensor manager not running")
    return _manager.detection_engine.ingest_network(payload)


@app.get("/events", dependencies=[Depends(_require_token)])
def events(
    limit: int = 50,
    event_type: Optional[str] = None,
    min_severity: Optional[int] = None,
    sensor_type: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    q: Optional[str] = None,
):
    """Query the durable event store (persists across restarts).

    Unlike ``/detections`` (recent, in-memory), this reads from SQLite and
    supports ``event_type``, ``min_severity``, ``sensor_type``, ISO ``since`` /
    ``until`` bounds, and a ``q`` substring match on the description. Returns
    ``[]`` when persistence is disabled.
    """
    if not _manager:
        return []
    return _manager.detection_engine.event_store.recent(
        limit=limit, event_type=event_type, min_severity=min_severity,
        sensor_type=sensor_type, since=since, until=until, text=q,
    )


@app.get("/events/summary", dependencies=[Depends(_require_token)])
def events_summary(since: Optional[str] = None, until: Optional[str] = None):
    """Counts of persisted events by severity, type, and sensor over a window."""
    if not _manager:
        return {"total": 0, "by_severity": {}, "by_type": {}, "by_sensor_type": {}}
    return _manager.detection_engine.event_store.summary(since=since, until=until)


@app.get("/analytics", dependencies=[Depends(_require_token)])
def analytics(
    bucket: str = "day",
    event_type: str = "detection",
    since: Optional[str] = None,
    until: Optional[str] = None,
):
    """Time-bucketed event counts (``hour``/``day``/``month``) + top descriptions."""
    if not _manager:
        return {"bucket": bucket, "counts": [], "top_descriptions": []}
    return _manager.detection_engine.event_store.analytics(
        bucket=bucket, event_type=event_type, since=since, until=until,
    )


def _ssl_options(secure: bool, server: Dict[str, Any]) -> Dict[str, Any]:
    """Build uvicorn TLS/mTLS keyword arguments.

    When ``secure`` is set, generate (or reuse) the CA and server certificate
    via :class:`SecureChannel` and serve the dashboard over mutual TLS. The
    already-hardened context from ``SecureChannel.get_ssl_context`` (TLS 1.3
    minimum, no session tickets, no compression, client certificate required)
    is passed through uvicorn's ``ssl_context_factory`` so uvicorn uses it
    verbatim instead of rebuilding a weaker context from the certificate files.
    Returns an empty dict when ``secure`` is false (plain HTTP).
    """
    if not secure:
        return {}

    from src.security.secure_communication import SecureChannel

    channel = SecureChannel(cert_dir=server.get("cert_dir", "certs"))

    def ssl_context_factory(*_args: Any):
        # uvicorn invokes this as factory(config, default_factory); ignore both
        # and hand back SecureChannel's hardened, client-cert-requiring context.
        return channel.get_ssl_context("server")

    return {"ssl_context_factory": ssl_context_factory}


def _enforce_validation(config: Dict[str, Any], secure: bool) -> None:
    """Ensure the detector is validated before use (NIJ validate-before-use).

    When the latest validation record is missing, failed, or from a different
    version:

    * without ``--secure`` the operator is warned but startup proceeds;
    * with ``--secure`` the self-test is run inline — if it passes the record
      is written and startup continues, but if it fails (or cannot run) startup
      is refused via :class:`SystemExit`, so a secure deployment never serves an
      unvalidated or broken detector.
    """
    validation_dir = config.get("app", {}).get("validation_dir", "data/validation")
    try:
        from src.core.selftest import needs_revalidation, run_selftest
    except Exception as e:  # selftest deps unavailable
        if secure:
            raise SystemExit(f"Refusing to start in --secure mode: {e}") from e
        logger.debug(f"Revalidation check skipped: {e}")
        return

    if not needs_revalidation(validation_dir):
        return

    if not secure:
        logger.warning(
            "No current passing self-validation found in %s; run "
            "`python scripts/selftest.py` to validate this version before "
            "relying on detections.",
            validation_dir,
        )
        return

    logger.info("No current passing self-validation; running self-test before secure startup.")
    try:
        report = run_selftest(record_dir=validation_dir)
    except Exception as e:
        raise SystemExit(f"Refusing to start in --secure mode: self-test errored: {e}") from e
    if not report["ok"]:
        failed = ", ".join(c["name"] for c in report["checks"] if not c["passed"])
        raise SystemExit(
            "Refusing to start in --secure mode: self-validation failed "
            f"({failed}). Investigate before relying on detections."
        )
    logger.info("Self-validation passed; continuing secure startup.")


def main():
    """CLI entry point: parse flags, build the manager, and run the server."""
    global _manager, _api_token

    parser = argparse.ArgumentParser()
    parser.add_argument("--dummy",  action="store_true", help="Use synthetic sensors")
    parser.add_argument("--train",  action="store_true", help="Training mode")
    parser.add_argument(
        "--secure",
        action="store_true",
        help="Enable runtime integrity monitoring and serve the dashboard over mutual TLS",
    )
    args = parser.parse_args()

    _manager = SensorManager(dummy=args.dummy, training=args.train)

    _enforce_validation(_manager.config, args.secure)

    if args.secure:
        from src.security.secure_boot import start_runtime_protection
        start_runtime_protection(_manager.config)

    server = _manager.config.get("server", {})
    _api_token = server.get("api_token") or os.environ.get("TIGRESS_API_TOKEN")

    ssl_options = _ssl_options(args.secure, server)
    if ssl_options:
        logger.info("Serving dashboard over mutual TLS (client certificate required)")
    if _api_token:
        logger.info("Dashboard data endpoints require a bearer token")
    elif not ssl_options:
        logger.warning(
            "Dashboard is serving detection data without authentication; set "
            "server.api_token / TIGRESS_API_TOKEN or run with --secure (mTLS)."
        )

    uvicorn.run(
        app,
        host=server.get("host", "127.0.0.1"),
        port=int(server.get("port", 8080)),
        log_level="info",
        **ssl_options,
    )


if __name__ == "__main__":
    main()
