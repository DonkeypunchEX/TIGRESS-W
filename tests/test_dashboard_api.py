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


def test_detections_pyramid_level_filter(monkeypatch):
    store = DetectionStore()
    store.add({"id": "a", "severity": 3, "sensor_type": "wifi",
               "features": {"pyramid_level": "address"}})
    store.add({"id": "b", "severity": 4, "sensor_type": "correlation",
               "features": {"pyramid_level": "ttp"}})
    fake = SimpleNamespace(detection_engine=SimpleNamespace(history=store))
    monkeypatch.setattr(app, "_manager", fake)

    assert [d["id"] for d in app.detections(pyramid_level="ttp")] == ["b"]
    assert [d["id"] for d in app.detections(pyramid_level="address")] == ["a"]
    summary = app.detections_summary()
    assert summary["by_pyramid_level"] == {"address": 1, "ttp": 1}


def test_strict_token_dependency_refuses_when_unconfigured(monkeypatch):
    import pytest
    from fastapi import HTTPException

    monkeypatch.setattr(app, "_api_token", None)
    with pytest.raises(HTTPException) as exc:
        app._require_token_strict(authorization=None)
    assert exc.value.status_code == 403

    monkeypatch.setattr(app, "_api_token", "s3cr3t")
    app._require_token_strict(authorization="Bearer s3cr3t")  # must not raise
    with pytest.raises(HTTPException) as exc:
        app._require_token_strict(authorization="Bearer nope")
    assert exc.value.status_code == 401
