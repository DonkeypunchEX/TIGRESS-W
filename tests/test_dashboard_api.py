from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")

from src.core.detection_store import DetectionStore
from src.dashboard import app


@pytest.fixture
def manager_with_detections(monkeypatch):
    store = DetectionStore()
    store.add({"id": "a", "severity": 2, "sensor_type": "wifi"})
    store.add({"id": "b", "severity": 5, "sensor_type": "wifi"})
    store.add({"id": "c", "severity": 5, "sensor_type": "phone"})
    fake = SimpleNamespace(detection_engine=SimpleNamespace(history=store))
    monkeypatch.setattr(app, "_manager", fake)
    return store


def test_detections_endpoint_newest_first(manager_with_detections):
    result = app.detections()
    assert [d["id"] for d in result] == ["c", "b", "a"]


def test_detections_endpoint_filters(manager_with_detections):
    high_wifi = app.detections(min_severity=4, sensor_type="wifi")
    assert [d["id"] for d in high_wifi] == ["b"]

    limited = app.detections(limit=1)
    assert [d["id"] for d in limited] == ["c"]


def test_detections_summary_endpoint(manager_with_detections):
    summary = app.detections_summary()
    assert summary["total"] == 3
    assert summary["by_severity"] == {"2": 1, "5": 2}
    assert summary["by_sensor_type"] == {"wifi": 2, "phone": 1}


def test_endpoints_safe_without_manager(monkeypatch):
    monkeypatch.setattr(app, "_manager", None)
    assert app.detections() == []
    assert app.detections_summary()["total"] == 0
