"""Thin wrapper around Windows toast notifications via PowerShell.

The Windows counterpart of :mod:`src.utils.termux_notify`. It raises a native
toast using the WinRT ``ToastNotificationManager`` driven by PowerShell, which
ships with Windows — so, like the Termux notifier shelling out to
``termux-notification``, it adds no Python runtime dependency. ``send`` mirrors
the :class:`~src.utils.termux_notify.TermuxNotifier` interface so the alert
dispatcher can treat both interchangeably.
"""

import logging
import shutil
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)

# WinRT toast raised from PowerShell. {title}/{content} are injected as
# single-quoted, escaped literals so notification text cannot break out of the
# script or inject XML.
_TOAST_SCRIPT = """
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$texts = $template.GetElementsByTagName('text')
$texts.Item(0).AppendChild($template.CreateTextNode('{title}')) | Out-Null
$texts.Item(1).AppendChild($template.CreateTextNode('{content}')) | Out-Null
$toast = [Windows.UI.Notifications.ToastNotification]::new($template)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{app_id}').Show($toast)
"""


def _ps_escape(value: str) -> str:
    """Escape a string for embedding inside a single-quoted PowerShell literal."""
    return str(value).replace("'", "''")


class WindowsNotifier:
    """Raise Windows toast notifications through PowerShell."""

    def __init__(self, app_id: str = "TIGRESS"):
        self.app_id = app_id

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
        """Show a toast; return True if PowerShell reported success.

        Accepts the same keyword arguments as
        :meth:`src.utils.termux_notify.TermuxNotifier.send` for a drop-in
        interface; ``nid``/``priority``/``sound``/``vibrate``/``ongoing`` have
        no toast equivalent and are ignored.
        """
        shell = shutil.which("powershell") or shutil.which("pwsh")
        if not shell:
            logger.debug("Toast notification skipped: PowerShell not found")
            return False
        script = _TOAST_SCRIPT.format(
            title=_ps_escape(title),
            content=_ps_escape(content),
            app_id=_ps_escape(self.app_id),
        )
        try:
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-Command", script],
                timeout=8,
                capture_output=True,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.debug(f"Toast notification failed: {e}")
            return False


notifier = WindowsNotifier()
