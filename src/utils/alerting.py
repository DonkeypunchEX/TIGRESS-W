"""Pluggable alert channels.

An :class:`AlertDispatcher` fans a single alert out to any number of configured
channels — Termux push, an HTTP webhook, and email — each with its own minimum
severity. All channels are standard-library only (no extra dependencies) and
failures in one channel never block the others. The dispatcher can optionally
deliver alerts on background worker threads so slow channels (a hung webhook or
SMTP server) never stall the detection pipeline.
"""

import atexit
import json
import logging
import os
import queue
import smtplib
import ssl
import threading
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

from src.utils.termux_notify import notifier as _default_notifier

logger = logging.getLogger(__name__)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow redirects.

    Following a redirect from an allow-listed host to an arbitrary location
    would defeat the webhook egress allowlist (an SSRF vector), so 3xx
    responses are surfaced as errors instead of transparently chased.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return None so urllib treats the 3xx as a terminal HTTPError."""
        return None


#: Opener that never follows redirects, used for all outbound webhook POSTs.
_no_redirect_opener = urllib.request.build_opener(_NoRedirect())


class AlertChannel(ABC):
    """Base class for an alert delivery channel."""

    name = "channel"

    def __init__(self, min_severity: int = 1):
        self.min_severity = int(min_severity)

    @abstractmethod
    def send(self, title: str, content: str, severity: int) -> bool:
        """Deliver one alert. Return True on success, False otherwise."""


class TermuxChannel(AlertChannel):
    """Deliver via ``termux-notification`` (on-device push)."""

    name = "termux"

    def __init__(self, min_severity: int = 1, notifier=None):
        super().__init__(min_severity)
        self._notifier = notifier or _default_notifier

    def send(self, title: str, content: str, severity: int) -> bool:
        """Deliver via termux-notification, mapping severity to priority."""
        priority = "max" if severity >= 5 else "high" if severity >= 4 else "default"
        return self._notifier.send(
            title=title,
            content=content,
            priority=priority,
            vibrate=severity >= 3,
            ongoing=severity >= 5,
        )


class WebhookChannel(AlertChannel):
    """POST a JSON alert to a configured URL.

    When ``allowed_hosts`` is set, the target host must appear in it or the
    POST is refused — an egress allowlist that bounds where alerts (and any
    attacker who can influence the configured URL) can send traffic. Redirects
    are never followed, so an allow-listed host cannot bounce the request
    elsewhere.
    """

    name = "webhook"

    def __init__(
        self,
        url: str,
        min_severity: int = 1,
        timeout: float = 5,
        allowed_hosts: Optional[List[str]] = None,
    ):
        super().__init__(min_severity)
        self.url = url
        self.timeout = timeout
        # Normalise to a lowercase set; None/empty means "no restriction".
        self.allowed_hosts = (
            {h.strip().lower() for h in allowed_hosts if h and h.strip()}
            if allowed_hosts else set()
        )

    def send(self, title: str, content: str, severity: int) -> bool:
        """POST the alert as JSON to the configured webhook URL."""
        if not self.url:
            logger.warning("Webhook channel enabled but no url configured")
            return False
        if not self.url.startswith(("http://", "https://")):
            logger.warning(f"Webhook url must use http/https, got: {self.url}")
            return False
        host = (urllib.parse.urlparse(self.url).hostname or "").lower()
        if self.allowed_hosts and host not in self.allowed_hosts:
            logger.warning(
                "Webhook host %r not in egress allowlist %s; refusing to send",
                host, sorted(self.allowed_hosts),
            )
            return False
        payload = json.dumps({
            "source": "TIGRESS",
            "title": title,
            "content": content,
            "severity": severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }).encode()
        req = urllib.request.Request(
            self.url, data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            # Scheme is validated above and redirects are disabled, so this is
            # not the unrestricted url-open bandit warns about.
            with _no_redirect_opener.open(req, timeout=self.timeout) as resp:  # nosec B310
                return 200 <= resp.status < 300
        except Exception as e:
            logger.warning(f"Webhook alert failed: {e}")
            return False


class EmailChannel(AlertChannel):
    """Send an alert email over SMTP (optionally STARTTLS + auth)."""

    name = "email"

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        username: Optional[str] = None,
        password: Optional[str] = None,
        sender: Optional[str] = None,
        recipients: Optional[List[str]] = None,
        use_tls: bool = True,
        timeout: float = 10,
        min_severity: int = 1,
    ):
        super().__init__(min_severity)
        self.smtp_host = smtp_host
        self.smtp_port = int(smtp_port)
        self.username = username
        # Prefer an env var so the password need not live in the config file.
        self.password = password or os.environ.get("TIGRESS_SMTP_PASSWORD")
        self.sender = sender or username or "tigress@localhost"
        self.recipients = list(recipients or [])
        self.use_tls = use_tls
        self.timeout = timeout

    def send(self, title: str, content: str, severity: int) -> bool:
        """Send the alert as an email over SMTP."""
        if not self.smtp_host or not self.recipients:
            logger.warning("Email channel enabled but smtp_host/recipients missing")
            return False
        msg = EmailMessage()
        msg["Subject"] = f"[TIGRESS] {title}"
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(f"{content}\n\nSeverity: {severity}/5")
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout) as smtp:
                if self.use_tls:
                    smtp.starttls(context=ssl.create_default_context())
                if self.username:
                    smtp.login(self.username, self.password or "")
                smtp.send_message(msg)
            return True
        except Exception as e:
            logger.warning(f"Email alert failed: {e}")
            return False


class AlertDispatcher:
    """Fan an alert out to every configured channel that clears its severity.

    Delivery is synchronous by default (:meth:`dispatch` returns a per-channel
    result map). Passing ``async_workers > 0`` starts that many background
    daemon threads; callers then use :meth:`submit` for fire-and-forget
    delivery that never blocks on a slow channel.
    """

    def __init__(
        self,
        channels: Optional[List[AlertChannel]] = None,
        async_workers: int = 0,
        queue_size: int = 256,
    ):
        self.channels: List[AlertChannel] = list(channels or [])
        self._queue: Optional["queue.Queue"] = None
        self._workers: List[threading.Thread] = []
        if async_workers > 0:
            self._start_workers(async_workers, queue_size)

    def _start_workers(self, count: int, queue_size: int) -> None:
        """Spin up background delivery threads reading from a bounded queue."""
        self._queue = queue.Queue(maxsize=max(1, queue_size))
        for i in range(count):
            t = threading.Thread(
                target=self._worker_loop, name=f"alert-worker-{i}", daemon=True,
            )
            t.start()
            self._workers.append(t)
        atexit.register(self.shutdown)

    def _worker_loop(self) -> None:
        """Deliver queued alerts until a ``None`` sentinel is received."""
        # Bind the queue locally so a concurrent shutdown() that clears
        # self._queue can never turn the next get() into an AttributeError.
        q = self._queue
        assert q is not None
        while True:
            item = q.get()
            try:
                if item is None:  # shutdown sentinel
                    return
                title, content, severity = item
                self.dispatch(title, content, severity)
            except Exception as e:  # a bad alert must not kill the worker
                logger.error(f"Alert worker error: {e}")
            finally:
                q.task_done()

    def submit(self, title: str, content: str, severity: int = 3) -> None:
        """Fire-and-forget delivery.

        Enqueues the alert when async workers are running (returning at once),
        otherwise dispatches synchronously in the caller's thread. On a full
        queue the alert is dropped with a warning so alerting can never block
        or unboundedly grow the detection pipeline.
        """
        if self._queue is not None:
            try:
                self._queue.put_nowait((title, content, severity))
            except queue.Full:
                logger.warning(
                    "Alert queue full (%d); dropping alert: %s",
                    self._queue.maxsize, title,
                )
            return
        self.dispatch(title, content, severity)

    def shutdown(self, timeout: float = 5) -> None:
        """Drain queued alerts and stop the background workers.

        Idempotent and safe to call when running synchronously (no-op). Sentinel
        puts never block indefinitely: workers drain the queue, so on a full
        queue we wait at most ``timeout`` for room. Workers hold their own queue
        reference, so clearing ``self._queue`` here cannot crash a straggler.
        """
        q = self._queue
        if q is None:
            return
        for _ in self._workers:
            try:
                q.put_nowait(None)
            except queue.Full:
                # Workers are consuming; wait briefly for space, then give up
                # (they are daemon threads and are reaped at process exit).
                try:
                    q.put(None, timeout=timeout)
                except queue.Full:
                    break
        for t in self._workers:
            t.join(timeout=timeout)
        self._workers = []
        self._queue = None

    @classmethod
    def from_config(cls, alerting_cfg: Dict[str, Any]) -> "AlertDispatcher":
        """Build a dispatcher from the ``alerting`` config section.

        When no ``channels`` block is present, defaults to Termux only (the
        previous behaviour). Otherwise builds each channel whose ``enabled`` is
        true. ``async_dispatch: true`` delivers alerts on background threads
        (see ``async_workers`` and ``queue_size``).
        """
        alerting_cfg = alerting_cfg or {}
        async_workers = (
            int(alerting_cfg.get("async_workers", 2))
            if alerting_cfg.get("async_dispatch") else 0
        )
        queue_size = int(alerting_cfg.get("queue_size", 256))

        channels_cfg = alerting_cfg.get("channels")
        if channels_cfg is None:
            return cls(
                [TermuxChannel()], async_workers=async_workers, queue_size=queue_size,
            )

        channels: List[AlertChannel] = []
        for name, cfg in channels_cfg.items():
            cfg = cfg or {}
            if not cfg.get("enabled"):
                continue
            ms = cfg.get("min_severity", 1)
            if name == "termux":
                channels.append(TermuxChannel(min_severity=ms))
            elif name == "webhook":
                channels.append(WebhookChannel(
                    cfg.get("url", ""), min_severity=ms, timeout=cfg.get("timeout", 5),
                    allowed_hosts=cfg.get("allowed_hosts"),
                ))
            elif name == "email":
                channels.append(EmailChannel(
                    smtp_host=cfg.get("smtp_host", ""),
                    smtp_port=cfg.get("smtp_port", 587),
                    username=cfg.get("username"),
                    password=cfg.get("password"),
                    sender=cfg.get("from"),
                    recipients=cfg.get("to"),
                    use_tls=cfg.get("use_tls", True),
                    timeout=cfg.get("timeout", 10),
                    min_severity=ms,
                ))
            else:
                logger.warning(f"Unknown alert channel '{name}' — ignored")
        return cls(channels, async_workers=async_workers, queue_size=queue_size)

    def dispatch(self, title: str, content: str, severity: int = 3) -> Dict[str, bool]:
        """Send to every channel with ``min_severity <= severity``.

        Returns a per-channel success map. A channel that raises is recorded as
        a failure and does not prevent other channels from firing.
        """
        results: Dict[str, bool] = {}
        seen: Dict[str, int] = {}
        for channel in self.channels:
            if severity < channel.min_severity:
                continue
            # Disambiguate duplicate channel names so results never overwrite.
            if sum(1 for c in self.channels if c.name == channel.name) > 1:
                idx = seen.get(channel.name, 0)
                seen[channel.name] = idx + 1
                key = f"{channel.name}[{idx}]"
            else:
                key = channel.name
            try:
                results[key] = channel.send(title, content, severity)
            except Exception as e:
                logger.error(f"Alert channel '{channel.name}' raised: {e}")
                results[key] = False
        return results

    @property
    def channel_names(self) -> List[str]:
        """Names of the configured channels, in order."""
        return [c.name for c in self.channels]
