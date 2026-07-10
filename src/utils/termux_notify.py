"""Thin wrapper around termux-notification for on-device push."""

import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


class TermuxNotifier:
    """Thin wrapper around termux-notification."""

    def __init__(self, default_id: str = "tigress_alert"):
        self.default_id = default_id

    def send(
        self,
        title: str,
        content: str,
        *,
        nid: Optional[str] = None,
        priority: str = "high",
        sound: bool = False,
        vibrate: bool = True,
        ongoing: bool = False,
    ) -> bool:
        """Send a notification; return True if termux-notification succeeded."""
        cmd = [
            "termux-notification",
            "--title", title,
            "--content", content,
            "--id", nid or self.default_id,
            "--priority", priority,
        ]
        if sound:
            cmd.append("--sound")
        if vibrate:
            cmd.append("--vibrate")
        if ongoing:
            cmd.append("--ongoing")

        try:
            subprocess.run(cmd, check=True, timeout=6, capture_output=True)
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.debug(f"Notification failed (termux-api installed?): {e}")
            return False


notifier = TermuxNotifier()
