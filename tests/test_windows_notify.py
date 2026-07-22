"""Windows toast notifier: PowerShell invocation and escaping (hermetic)."""

from src.utils.win_notify import WindowsNotifier, _ps_escape


def test_send_invokes_powershell_and_reports_success(monkeypatch):
    captured = {}

    class _Result:
        returncode = 0

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return _Result()

    monkeypatch.setattr("src.utils.win_notify.shutil.which", lambda _c: "powershell")
    monkeypatch.setattr("src.utils.win_notify.subprocess.run", _fake_run)

    notifier = WindowsNotifier()
    assert notifier.send("Tracker seen", "AirTag nearby") is True
    # The toast script is passed to PowerShell with the title/content embedded.
    script = captured["cmd"][-1]
    assert "Tracker seen" in script
    assert "AirTag nearby" in script


def test_send_returns_false_when_powershell_missing(monkeypatch):
    monkeypatch.setattr("src.utils.win_notify.shutil.which", lambda _c: None)
    assert WindowsNotifier().send("t", "c") is False


def test_send_returns_false_on_nonzero_exit(monkeypatch):
    class _Result:
        returncode = 1

    monkeypatch.setattr("src.utils.win_notify.shutil.which", lambda _c: "powershell")
    monkeypatch.setattr("src.utils.win_notify.subprocess.run", lambda *a, **k: _Result())
    assert WindowsNotifier().send("t", "c") is False


def test_ps_escape_neutralizes_single_quotes():
    # A single quote in notification text must not break out of the literal.
    assert _ps_escape("it's a trap'") == "it''s a trap''"
