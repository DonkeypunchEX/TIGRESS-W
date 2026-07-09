"""FastAPI dashboard exposing sensor status and health endpoints."""

import argparse
from contextlib import asynccontextmanager
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from src.core.sensor_manager import SensorManager
from src.utils.logger import get_logger

logger = get_logger(__name__)

_manager: SensorManager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start sensors on app startup and stop them on shutdown."""
    _manager.start_all()
    yield
    _manager.stop_all()


app = FastAPI(title="TIGRESS", lifespan=lifespan)


@app.get("/")
def root():
    """Root endpoint: overall status and sensor list."""
    return {"status": "running", "sensors": _manager.list_sensors() if _manager else []}


@app.get("/sensors")
def sensors():
    """Return per-sensor status."""
    return JSONResponse(_manager.list_sensors())


@app.get("/health")
def health():
    """Liveness probe reporting whether sensors are running."""
    return {"ok": True, "sensors_running": _manager.is_running if _manager else False}


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


def main():
    """CLI entry point: parse flags, build the manager, and run the server."""
    global _manager

    parser = argparse.ArgumentParser()
    parser.add_argument("--dummy",  action="store_true", help="Use synthetic sensors")
    parser.add_argument("--train",  action="store_true", help="Training mode")
    parser.add_argument(
        "--secure",
        action="store_true",
        help="Enable runtime integrity monitoring and serve the dashboard over mutual TLS",
    )
    args = parser.parse_args()

    if args.secure:
        from src.security.secure_boot import start_runtime_protection
        start_runtime_protection()

    _manager = SensorManager(dummy=args.dummy, training=args.train)
    server = _manager.config.get("server", {})
    ssl_options = _ssl_options(args.secure, server)
    if ssl_options:
        logger.info("Serving dashboard over mutual TLS (client certificate required)")

    uvicorn.run(
        app,
        host=server.get("host", "127.0.0.1"),
        port=int(server.get("port", 8080)),
        log_level="info",
        **ssl_options,
    )


if __name__ == "__main__":
    main()
