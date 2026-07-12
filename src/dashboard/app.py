"""FastAPI dashboard exposing sensor status and health endpoints."""

import argparse
import hmac
import os
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
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
):
    """Return recent detections, newest first, with optional filters.

    Query params: ``limit`` (max results), ``min_severity`` (1-5), and
    ``sensor_type`` (e.g. ``wifi`` or ``phone``).
    """
    if not _manager:
        return []
    return _manager.detection_engine.history.recent(
        limit=limit, min_severity=min_severity, sensor_type=sensor_type
    )


@app.get("/detections/summary", dependencies=[Depends(_require_token)])
def detections_summary():
    """Return counts of recent detections by severity and sensor type."""
    if not _manager:
        return {"total": 0, "by_severity": {}, "by_sensor_type": {}}
    return _manager.detection_engine.history.summary()


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


def _warn_if_revalidation_needed(config: Dict[str, Any]) -> None:
    """Log a warning when the detector has no current passing validation.

    Follows the NIJ practice of validating a forensic tool before use and after
    every update: if the latest validation record is missing, failed, or from a
    different version, nudge the operator to run ``scripts/selftest.py``.
    """
    validation_dir = config.get("app", {}).get("validation_dir", "data/validation")
    try:
        from src.core.selftest import needs_revalidation
        if needs_revalidation(validation_dir):
            logger.warning(
                "No current passing self-validation found in %s; run "
                "`python scripts/selftest.py` to validate this version before "
                "relying on detections.",
                validation_dir,
            )
    except Exception as e:  # never block startup on the validation check
        logger.debug(f"Revalidation check skipped: {e}")


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

    _warn_if_revalidation_needed(_manager.config)

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
