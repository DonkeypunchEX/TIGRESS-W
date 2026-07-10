from src.core.detection_store import DetectionStore


def _det(severity, sensor_type="wifi", did="x"):
    return {"id": did, "severity": severity, "sensor_type": sensor_type}


def test_recent_returns_newest_first():
    store = DetectionStore()
    store.add(_det(1, did="a"))
    store.add(_det(2, did="b"))
    ids = [d["id"] for d in store.recent()]
    assert ids == ["b", "a"]


def test_recent_respects_limit_and_zero():
    store = DetectionStore()
    for i in range(5):
        store.add(_det(3, did=str(i)))
    assert len(store.recent(limit=2)) == 2
    assert store.recent(limit=0) == []


def test_recent_filters_by_severity_and_type():
    store = DetectionStore()
    store.add(_det(2, "wifi", "low"))
    store.add(_det(5, "wifi", "high"))
    store.add(_det(5, "phone", "phonehigh"))

    high = store.recent(min_severity=4)
    assert {d["id"] for d in high} == {"high", "phonehigh"}

    wifi_high = store.recent(min_severity=4, sensor_type="wifi")
    assert [d["id"] for d in wifi_high] == ["high"]


def test_store_is_bounded():
    store = DetectionStore(max_size=3)
    for i in range(10):
        store.add(_det(1, did=str(i)))
    assert len(store) == 3
    assert [d["id"] for d in store.recent()] == ["9", "8", "7"]


def test_summary_counts():
    store = DetectionStore()
    store.add(_det(5, "wifi"))
    store.add(_det(5, "phone"))
    store.add(_det(3, "wifi"))
    summary = store.summary()
    assert summary["total"] == 3
    assert summary["by_severity"] == {"3": 1, "5": 2}
    assert summary["by_sensor_type"] == {"wifi": 2, "phone": 1}


def test_add_copies_input():
    store = DetectionStore()
    d = _det(4)
    store.add(d)
    d["severity"] = 1  # mutating the caller's dict must not change the store
    assert store.recent()[0]["severity"] == 4


def test_add_deep_copies_nested_objects():
    store = DetectionStore()
    d = {"id": "x", "severity": 4, "sensor_type": "wifi", "features": {"score": 0.9}}
    store.add(d)
    d["features"]["score"] = 0.1  # nested mutation must not reach the store
    assert store.recent()[0]["features"]["score"] == 0.9


def test_recent_returns_isolated_copies():
    store = DetectionStore()
    store.add({"id": "x", "severity": 4, "sensor_type": "wifi", "features": {"score": 0.9}})
    returned = store.recent()[0]
    returned["features"]["score"] = 0.0  # mutating the result must not corrupt the store
    assert store.recent()[0]["features"]["score"] == 0.9


def test_clear_empties_store():
    store = DetectionStore()
    store.add(_det(1))
    store.add(_det(2))
    store.clear()
    assert len(store) == 0
    assert store.recent() == []
