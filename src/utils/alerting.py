"""Pluggable alert channels.

An :class:`AlertDispatcher` fans a single alert out to any number of configured
channels — Termux push, an HTTP webhook, and email — each with its own minimum
severity. All channels are standard-library only (no extra dependencies) and
failures in one channel never block the others.
"""

import json
import logging
import os
import smtplib
import ssl
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Dict, List, Optional

from src.utils.termux_notify import notifier as _default_notifier

logger = logging.getLogger(__name__)


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
    """POST a JSON alert to a configured URL."""

    name = "webhook"

    def __init__(self, url: str, min_severity: int = 1, timeout: float = 5):
        super().__init__(min_severity)
        self.url = url
        self.timeout = timeout

    def send(self, title: str, content: str, severity: int) -> bool:
        """POST the alert as JSON to the configured webhook URL."""
        if not self.url:
            logger.warning("Webhook channel enabled but no url configured")
            return False
        if not self.url.startswith(("http://", "https://")):
            logger.warning(f"Webhook url must use http/https, got: {self.url}")
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
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
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
    """Fan an alert out to every configured channel that clears its severity."""

    def __init__(self, channels: Optional[List[AlertChannel]] = None):
        self.channels: List[AlertChannel] = list(channels or [])

    @classmethod
    def from_config(cls, alerting_cfg: Dict[str, Any]) -> "AlertDispatcher":
        """Build a dispatcher from the ``alerting`` config section.

        When no ``channels`` block is present, defaults to Termux only (the
        previous behaviour). Otherwise builds each channel whose ``enabled`` is
        true.
        """
        channels_cfg = (alerting_cfg or {}).get("channels")
        if channels_cfg is None:
            return cls([TermuxChannel()])

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
        return cls(channels)

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
