from src.core.correlation_engine import CorrelationEngine
from src.core.movement import MovementTracker


def _det(address="de:ad:be:ef:00:01"):
    return {
        "id": "d1",
        "sensor_type": "bluetooth",
        "confidence": 0.8,
        "severity": 3,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "sensor_id": "bluetooth_sensor",
        "description": "test",
        "features": {"address": address},
    }


def _corr(movement, **persistence):
    return CorrelationEngine(
        {
            "enabled": True,
            "window_seconds": 600,
            "cooldown_seconds": 300,
            "rules": {
                "entity_persistence": {
                    "enabled": True, "min_hits": 2, "min_span_seconds": 10,
                    "severity": 4, **persistence,
                },
                "cross_sensor": {"enabled": False},
                "burst": {"enabled": False},
            },
        },
        movement=movement,
    )


# --------------------------------------------------------------------------- #
# MovementTracker
# --------------------------------------------------------------------------- #

def test_stationary_magnitudes_are_not_motion():
    t = MovementTracker({"delta_threshold": 1.5})
    for at in (0, 10, 20):
        t.record(9.8, now=at)
    assert t.has_data()
    assert t.moved_between(0, 20) is False


def test_acceleration_deviation_is_motion():
    t = MovementTracker({"delta_threshold": 1.5})
    t.record(9.8, now=0)
    t.record(13.0, now=10)   # walking/vehicle
    t.record(9.8, now=20)
    assert t.moved_between(0, 20) is True
    assert t.moved_between(15, 20) is False  # motion was before this span


def test_samples_expire_and_bad_input_tolerated():
    t = MovementTracker({"delta_threshold": 1.5, "retention_seconds": 100})
    t.record(13.0, now=0)
    t.record(9.8, now=200)  # prunes the motion sample at t=0
    assert t.moved_between(0, 200) is False
    t.record(None, now=201)
    t.record("garbage", now=202)  # neither raises nor records


def test_disabled_tracker_records_nothing():
    t = MovementTracker({"enabled": False})
    t.record(13.0, now=0)
    assert t.has_data() is False


# --------------------------------------------------------------------------- #
# persistence + movement integration
# --------------------------------------------------------------------------- #

def test_persistence_escalates_when_device_moved_during_span():
    movement = MovementTracker({"delta_threshold": 1.5, "escalate_severity": 1})
    movement.record(13.0, now=50)  # motion inside the sighting span
    eng = _corr(movement)
    eng.observe([_det()], now=0)
    meta = eng.observe([_det()], now=100)
    assert len(meta) == 1
    assert meta[0]["severity"] == 5  # 4 + escalate
    assert meta[0]["features"]["moved_during_span"] is True
    assert "IN MOTION" in meta[0]["description"]


def test_persistence_not_escalated_when_stationary():
    movement = MovementTracker({"delta_threshold": 1.5})
    movement.record(9.8, now=50)  # context exists, but no motion
    eng = _corr(movement)
    eng.observe([_det()], now=0)
    meta = eng.observe([_det()], now=100)
    assert len(meta) == 1
    assert meta[0]["severity"] == 4
    assert meta[0]["features"]["moved_during_span"] is False


def test_require_movement_suppresses_stationary_recurrence():
    movement = MovementTracker({"delta_threshold": 1.5, "require_movement": True})
    movement.record(9.8, now=50)
    eng = _corr(movement)
    eng.observe([_det()], now=0)
    assert eng.observe([_det()], now=100) == []
    # The suppressed finding must not have consumed the cooldown: once the
    # device moves, the very next evaluation fires.
    movement.record(13.0, now=150)
    meta = eng.observe([_det()], now=200)
    assert len(meta) == 1
    assert meta[0]["features"]["moved_during_span"] is True


def test_no_movement_context_behaves_as_before():
    eng = _corr(movement=None)
    eng.observe([_det()], now=0)
    meta = eng.observe([_det()], now=100)
    assert len(meta) == 1
    assert meta[0]["severity"] == 4
    assert meta[0]["features"]["moved_during_span"] is None


def test_engine_feeds_movement_from_phone_readings(engine):
    engine.analyze_phone([{
        "magnitude": 13.0, "tamper_suspect": False,
        "timestamp": "2026-01-01T00:00:00", "sensor_id": "phone_sensor",
    }])
    assert engine.movement.has_data()
    now = engine.movement._samples[-1][0]
    assert engine.movement.moved_between(now - 1, now + 1) is True
