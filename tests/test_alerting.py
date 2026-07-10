from src.utils.alerting import (
    AlertChannel,
    AlertDispatcher,
    EmailChannel,
    TermuxChannel,
    WebhookChannel,
)


class _RecordingChannel(AlertChannel):
    name = "recording"

    def __init__(self, min_severity=1, ok=True):
        super().__init__(min_severity)
        self.calls = []
        self._ok = ok

    def send(self, title, content, severity):
        self.calls.append((title, content, severity))
        return self._ok


# --------------------------------------------------------------------------- #
# AlertDispatcher
# --------------------------------------------------------------------------- #

def test_from_config_defaults_to_termux_when_no_channels():
    disp = AlertDispatcher.from_config({})
    assert disp.channel_names == ["termux"]


def test_from_config_builds_only_enabled_channels():
    disp = AlertDispatcher.from_config({
        "channels": {
            "termux": {"enabled": True},
            "webhook": {"enabled": True, "url": "https://x", "min_severity": 3},
            "email": {"enabled": False},
            "bogus": {"enabled": True},  # unknown -> ignored
        }
    })
    assert disp.channel_names == ["termux", "webhook"]
    webhook = disp.channels[1]
    assert webhook.min_severity == 3


def test_dispatch_respects_min_severity():
    high = _RecordingChannel(min_severity=4)
    low = _RecordingChannel(min_severity=1)
    disp = AlertDispatcher([high, low])
    disp.dispatch("t", "c", severity=2)
    assert low.calls and not high.calls


def test_dispatch_disambiguates_duplicate_channel_names():
    a = _RecordingChannel()
    b = _RecordingChannel()
    disp = AlertDispatcher([a, b])  # both named "recording"
    results = disp.dispatch("t", "c", severity=5)
    assert set(results) == {"recording[0]", "recording[1]"}
    assert a.calls and b.calls


def test_dispatch_isolates_failing_channels():
    class _Boom(AlertChannel):
        name = "boom"

        def send(self, title, content, severity):
            raise RuntimeError("down")

    good = _RecordingChannel()
    disp = AlertDispatcher([_Boom(), good])
    results = disp.dispatch("t", "c", severity=5)
    assert results == {"boom": False, "recording": True}
    assert good.calls  # the good channel still fired


# --------------------------------------------------------------------------- #
# TermuxChannel
# --------------------------------------------------------------------------- #

class _FakeNotifier:
    def __init__(self):
        self.kwargs = None

    def send(self, **kwargs):
        self.kwargs = kwargs
        return True


def test_termux_channel_maps_severity_to_priority():
    fake = _FakeNotifier()
    ch = TermuxChannel(notifier=fake)
    assert ch.send("t", "c", severity=5) is True
    assert fake.kwargs["priority"] == "max"
    assert fake.kwargs["ongoing"] is True

    ch.send("t", "c", severity=4)
    assert fake.kwargs["priority"] == "high"

    ch.send("t", "c", severity=2)
    assert fake.kwargs["priority"] == "default"
    assert fake.kwargs["vibrate"] is False


# --------------------------------------------------------------------------- #
# WebhookChannel
# --------------------------------------------------------------------------- #

class _FakeResp:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_webhook_channel_posts_and_reports_success(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = req.data
        return _FakeResp(200)

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    ch = WebhookChannel("https://hook.example/alert")
    assert ch.send("Title", "Body", severity=4) is True
    assert captured["url"] == "https://hook.example/alert"
    assert b"Title" in captured["body"]


def test_webhook_channel_reports_failure(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert WebhookChannel("https://hook").send("t", "c", 3) is False


def test_webhook_channel_without_url_is_noop():
    assert WebhookChannel("").send("t", "c", 5) is False


def test_webhook_channel_rejects_non_http_scheme(monkeypatch):
    called = []
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: called.append(1))
    assert WebhookChannel("file:///etc/passwd").send("t", "c", 5) is False
    assert not called  # urlopen must never be reached for a non-http scheme


# --------------------------------------------------------------------------- #
# EmailChannel
# --------------------------------------------------------------------------- #

class _FakeSMTP:
    sent = []

    def __init__(self, host, port, timeout=None):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        pass

    def login(self, user, password):
        pass

    def send_message(self, msg):
        _FakeSMTP.sent.append(msg)


def test_email_channel_sends(monkeypatch):
    _FakeSMTP.sent.clear()
    monkeypatch.setattr("smtplib.SMTP", _FakeSMTP)
    ch = EmailChannel(smtp_host="smtp.x", recipients=["soc@x"], username="u", password="p")
    assert ch.send("Alert", "Body", severity=5) is True
    assert len(_FakeSMTP.sent) == 1
    assert _FakeSMTP.sent[0]["To"] == "soc@x"
    assert _FakeSMTP.sent[0]["Subject"] == "[TIGRESS] Alert"


def test_email_channel_requires_host_and_recipients():
    assert EmailChannel(smtp_host="", recipients=["a@b"]).send("t", "c", 5) is False
    assert EmailChannel(smtp_host="smtp.x", recipients=[]).send("t", "c", 5) is False


def test_email_password_falls_back_to_env(monkeypatch):
    monkeypatch.setenv("TIGRESS_SMTP_PASSWORD", "from-env")
    ch = EmailChannel(smtp_host="smtp.x", recipients=["a@b"])  # no password arg
    assert ch.password == "from-env"
    # an explicit password still wins over the env var
    ch2 = EmailChannel(smtp_host="smtp.x", recipients=["a@b"], password="explicit")
    assert ch2.password == "explicit"
