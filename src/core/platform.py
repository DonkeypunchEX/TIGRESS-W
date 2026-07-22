"""Host-platform detection used to pick platform-specific backends.

TIGRESS is a single cross-platform codebase: the detection/correlation/
dashboard pipeline is portable Python, and only the *edges* — the sensors that
shell out to OS scanning tools and the notifier that raises OS notifications —
have per-platform implementations. These helpers let the sensor registry and
the alert dispatcher choose the right backend at runtime without scattering
``sys.platform`` checks through the code.
"""

import os
import sys
from pathlib import Path


def is_windows() -> bool:
    """Return True when running on Windows."""
    return sys.platform.startswith("win")


def is_termux() -> bool:
    """Return True when running under Termux on Android.

    Termux reports ``sys.platform == 'linux'``, so it is detected by its
    ``TERMUX_VERSION`` environment variable or its well-known prefix path
    rather than by ``sys.platform``.
    """
    if os.environ.get("TERMUX_VERSION"):
        return True
    return Path("/data/data/com.termux/files/usr").exists()


def current_platform() -> str:
    """Return a coarse platform label: ``windows``, ``termux``, or ``posix``."""
    if is_windows():
        return "windows"
    if is_termux():
        return "termux"
    return "posix"
