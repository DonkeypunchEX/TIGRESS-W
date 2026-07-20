from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from src.core.detection_store import DetectionStore
from src.dashboard import app as appmod


@pytest.fixture
def client(monkeypatch):
    store = DetectionStore()
    store.add({"id": "a", "severity": 5, "sensor_type": "wifi"})
    manager = SimpleNamespace(
        detection_engine=SimpleNamespace(
            history=store,
            ingest_network=lambda payload: {"accepted": 1, "rejected": 0},
            ingest_ble=lambda payload: {"devices": 1, "rejected": 0,
                                        "new_devices": 0, "detections": 0},
        ),
        list_sensors=lambda: [],
        is_running=True,
    )
    monkeypatch.setattr(appmod, "_manager", manager)
    return TestClient(appmod.app)


def test_open_when_no_token(client, monkeypatch):
    monkeypatch.setattr(appmod, "_api_token", None)
    assert client.get("/detections").status_code == 200
    assert client.get("/").status_code == 200


def test_protected_endpoints_require_token(client, monkeypatch):
    monkeypatch.setattr(appmod, "_api_token", "s3cr3t")
    for path in ("/", "/sensors", "/detections", "/detections/summary"):
        assert client.get(path).status_code == 401, path


def test_valid_token_grants_access(client, monkeypatch):
    monkeypatch.setattr(appmod, "_api_token", "s3cr3t")
    r = client.get("/detections", headers={"Authorization": "Bearer s3cr3t"})
    assert r.status_code == 200
    assert r.json()[0]["id"] == "a"


def test_wrong_token_rejected(client, monkeypatch):
    monkeypatch.setattr(appmod, "_api_token", "s3cr3t")
    r = client.get("/detections", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_health_is_always_open(client, monkeypatch):
    monkeypatch.setattr(appmod, "_api_token", "s3cr3t")
    assert client.get("/health").status_code == 200


def test_ingest_disabled_without_configured_token(client, monkeypatch):
    # The read endpoints fall open without a token; write endpoints must not.
    monkeypatch.setattr(appmod, "_api_token", None)
    r = client.post("/ingest/suricata", json={"event_type": "alert", "alert": {}})
    assert r.status_code == 403
    r = client.post("/ingest/ble", json={"node_id": "n", "devices": []})
    assert r.status_code == 403


def test_ble_ingest_accepts_valid_token(client, monkeypatch):
    monkeypatch.setattr(appmod, "_api_token", "s3cr3t")
    r = client.post(
        "/ingest/ble",
        json={"node_id": "bag-pi",
              "devices": [{"address": "aa:bb:cc:dd:ee:01", "rssi": -60}]},
        headers={"Authorization": "Bearer s3cr3t"},
    )
    assert r.status_code == 200
    assert r.json()["devices"] == 1


def test_ingest_rejects_wrong_token(client, monkeypatch):
    monkeypatch.setattr(appmod, "_api_token", "s3cr3t")
    r = client.post(
        "/ingest/suricata",
        json={"event_type": "alert", "alert": {}},
        headers={"Authorization": "Bearer nope"},
    )
    assert r.status_code == 401


def test_ingest_accepts_valid_token(client, monkeypatch):
    monkeypatch.setattr(appmod, "_api_token", "s3cr3t")
    r = client.post(
        "/ingest/suricata",
        json={"event_type": "alert", "alert": {"signature": "x", "severity": 1}},
        headers={"Authorization": "Bearer s3cr3t"},
    )
    assert r.status_code == 200
    assert r.json() == {"accepted": 1, "rejected": 0}
