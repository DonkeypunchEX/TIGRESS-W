import argparse
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from src.core.sensor_manager import SensorManager
from src.utils.logger import get_logger

logger = get_logger(__name__)

_manager: SensorManager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    _manager.start_all()
    yield
    _manager.stop_all()


app = FastAPI(title="TIGRESS", lifespan=lifespan)


@app.get("/")
def root():
    return {"status": "running", "sensors": _manager.list_sensors() if _manager else []}


@app.get("/sensors")
def sensors():
    return JSONResponse(_manager.list_sensors())


@app.get("/health")
def health():
    return {"ok": True, "sensors_running": _manager.is_running if _manager else False}


def main():
    global _manager

    parser = argparse.ArgumentParser()
    parser.add_argument("--dummy",  action="store_true", help="Use synthetic sensors")
    parser.add_argument("--train",  action="store_true", help="Training mode")
    parser.add_argument("--secure", action="store_true", help="Enable runtime integrity monitoring")
    args = parser.parse_args()

    if args.secure:
        from src.security.secure_boot import start_runtime_protection
        start_runtime_protection()

    _manager = SensorManager(dummy=args.dummy, training=args.train)
    uvicorn.run(app, host="127.0.0.1", port=8080, log_level="info")


if __name__ == "__main__":
    main()
