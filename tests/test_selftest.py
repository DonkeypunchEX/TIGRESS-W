import json

from src.core import selftest
from src.version import __version__


def test_run_selftest_passes_on_golden_dataset():
    report = selftest.run_selftest()
    assert report["ok"] is True
    assert report["version"] == __version__
    assert report["dataset_sha256"] == selftest.dataset_hash()
    assert {c["name"] for c in report["checks"]} == {
        "wifi_ssid_spoof", "ble_tracker", "ble_proximity",
    }
    assert all(c["passed"] for c in report["checks"])


def test_run_selftest_writes_versioned_record(tmp_path):
    report = selftest.run_selftest(record_dir=str(tmp_path))
    record_path = tmp_path / report["record_path"].split("/")[-1]
    assert record_path.exists()
    assert __version__ in record_path.name
    on_disk = json.loads(record_path.read_text())
    assert on_disk["ok"] is True


def test_needs_revalidation_true_when_no_record(tmp_path):
    assert selftest.needs_revalidation(str(tmp_path)) is True


def test_needs_revalidation_false_after_passing_current_version(tmp_path):
    selftest.run_selftest(record_dir=str(tmp_path))
    assert selftest.needs_revalidation(str(tmp_path)) is False


def test_needs_revalidation_true_for_stale_version(tmp_path):
    (tmp_path / "validation_0.0.1_20200101T000000Z.json").write_text(
        json.dumps({"ok": True, "version": "0.0.1"})
    )
    assert selftest.needs_revalidation(str(tmp_path)) is True
