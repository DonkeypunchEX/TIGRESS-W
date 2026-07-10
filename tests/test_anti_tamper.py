import pytest

pytest.importorskip("psutil")

from src.security.anti_tamper import RuntimeProtection


def _rp(tmp_path, **kwargs):
    return RuntimeProtection(set(), **kwargs)


def test_verify_files_detects_modification(tmp_path):
    f = tmp_path / "critical.py"
    f.write_text("original")
    rp = RuntimeProtection({f})
    assert rp.verify_files() is True

    f.write_text("tampered")
    assert rp.verify_files() is False
    assert any("File modified" in v for v in rp.violations)


def test_verify_files_detects_missing(tmp_path):
    f = tmp_path / "critical.py"
    f.write_text("data")
    rp = RuntimeProtection({f})
    f.unlink()
    assert rp.verify_files() is False
    assert any("File missing" in v for v in rp.violations)


def test_process_whitelist_merges_extra_names(tmp_path):
    rp = _rp(tmp_path, process_whitelist=["myapp", "helper"])
    assert "myapp" in rp.process_whitelist
    assert "python" in rp.process_whitelist  # built-in defaults retained


def test_verify_processes_baseline_then_new(tmp_path, monkeypatch):
    rp = _rp(tmp_path, monitor_processes=True)
    seq = [
        {"python", "bash", "sshd"},          # baseline
        {"python", "bash", "sshd"},          # unchanged
        {"python", "bash", "sshd", "nc"},    # new, non-whitelisted process appears
    ]
    calls = iter(seq)
    monkeypatch.setattr(rp, "_current_process_names", lambda: next(calls))

    assert rp.verify_processes() is True          # establishes baseline, no alarm
    assert rp.verify_processes() is True           # nothing new
    assert rp.verify_processes() is False          # "nc" appeared
    assert any("nc" in v for v in rp.violations)


def test_verify_processes_ignores_whitelisted_newcomers(tmp_path, monkeypatch):
    rp = _rp(tmp_path, process_whitelist=["helper"], monitor_processes=True)
    seq = [
        {"python"},              # baseline
        {"python", "helper"},    # newcomer, but whitelisted
    ]
    calls = iter(seq)
    monkeypatch.setattr(rp, "_current_process_names", lambda: next(calls))

    assert rp.verify_processes() is True
    assert rp.verify_processes() is True
    assert rp.violations == []


def test_verify_processes_reports_new_only_once(tmp_path, monkeypatch):
    rp = _rp(tmp_path, monitor_processes=True)
    seq = [
        {"python"},           # baseline
        {"python", "evil"},   # evil appears -> alarm
        {"python", "evil"},   # evil still there -> already known, no new alarm
    ]
    calls = iter(seq)
    monkeypatch.setattr(rp, "_current_process_names", lambda: next(calls))

    rp.verify_processes()
    assert rp.verify_processes() is False
    assert rp.verify_processes() is True


def test_verify_processes_no_false_alarm_when_enumeration_empty(tmp_path, monkeypatch):
    rp = _rp(tmp_path, monitor_processes=True)
    monkeypatch.setattr(rp, "_current_process_names", set)
    assert rp.verify_processes() is True


def test_process_alarm_message_lists_names_without_redundant_prefix(tmp_path, monkeypatch):
    rp = _rp(tmp_path, monitor_processes=True)
    seq = iter([{"python"}, {"python", "nc"}])
    monkeypatch.setattr(rp, "_current_process_names", lambda: next(seq))

    alarms = []
    monkeypatch.setattr(rp, "_alarm", lambda reason: alarms.append(reason))

    rp._check_processes()  # establishes baseline, no alarm
    rp._check_processes()  # "nc" appears
    assert alarms == ["Unexpected process(es): nc"]
