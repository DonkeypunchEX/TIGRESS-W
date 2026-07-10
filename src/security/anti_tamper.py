"""Runtime integrity monitoring: file hashes, process whitelist, debugger detection."""

import hashlib
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

import psutil

from src.utils.termux_notify import notifier

logger = logging.getLogger(__name__)


class RuntimeProtection:
    """Monitor critical files and processes for tampering at runtime."""

    PROCESS_WHITELIST = {
        "python", "python3", "bash", "sh",
        "termux-wake-lock", "termux-sensor", "termux-wifi-scaninfo",
        "sshd", "logcat", "uvicorn",
    }

    def __init__(
        self,
        critical_files: Set[Path],
        process_whitelist: Optional[Iterable[str]] = None,
        monitor_processes: bool = False,
    ):
        self.critical_files = critical_files
        self._baseline_hashes: Dict[Path, str] = self._hash_files()
        self._thread = None
        self._running = False
        self.violations: List[str] = []

        # Process monitoring: alarm only on processes that appear *after* a
        # baseline is established and are not on the whitelist.
        self.process_whitelist: Set[str] = set(self.PROCESS_WHITELIST) | set(
            process_whitelist or []
        )
        self._monitor_processes = monitor_processes
        self._known_processes: Set[str] = set()
        self._process_baseline_ready = False

    def _hash_files(self) -> Dict[Path, str]:
        return {p: hashlib.sha512(p.read_bytes()).hexdigest() for p in self.critical_files if p.exists()}

    def verify_files(self) -> bool:
        current = self._hash_files()
        for path, original in self._baseline_hashes.items():
            if path not in current:
                self.violations.append(f"File missing: {path}")
                return False
            if current[path] != original:
                self.violations.append(f"File modified: {path}")
                return False
        return True

    def verify_no_debugger(self) -> bool:
        try:
            status = Path(f"/proc/{os.getpid()}/status").read_text()
            for line in status.splitlines():
                if line.startswith("TracerPid:"):
                    tracer_pid = int(line.split(":")[1].strip())
                    if tracer_pid != 0:
                        self.violations.append(f"Debugger attached (PID {tracer_pid})")
                        return False
        except OSError:
            pass
        return True

    def _current_process_names(self) -> Set[str]:
        """Return the set of currently-running process names."""
        try:
            return {
                p.info["name"]
                for p in psutil.process_iter(["name"])
                if p.info.get("name")
            }
        except Exception as e:  # psutil unavailable or permission denied
            logger.debug(f"Process enumeration failed: {e}")
            return set()

    def verify_processes(self) -> bool:
        """Detect newly-appeared, non-whitelisted processes.

        The first call establishes a baseline (everything currently running,
        plus the whitelist) and returns ``True``. Subsequent calls flag process
        names that were not in the baseline and are not whitelisted — each is
        reported once, then folded into the baseline so it does not re-alarm.
        Returns ``True`` when no new unexpected process appeared.
        """
        current = self._current_process_names()
        if not current:
            return True  # couldn't enumerate; do not raise a false alarm

        if not self._process_baseline_ready:
            self._known_processes = set(current) | self.process_whitelist
            self._process_baseline_ready = True
            logger.info(
                f"Process baseline established ({len(self._known_processes)} names)"
            )
            return True

        new = current - self._known_processes
        self._known_processes |= current
        for name in sorted(new):
            self.violations.append(f"Unexpected process appeared: {name}")
        return not new

    def start_monitoring(self, interval: int = 30):
        self._running = True
        self._thread = threading.Thread(target=self._loop, args=(interval,), daemon=True)
        self._thread.start()
        logger.info("Runtime protection active")

    def stop_monitoring(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self, interval: int):
        while self._running:
            self.violations.clear()
            if not self.verify_files():
                self._alarm("File integrity violation")
            if not self.verify_no_debugger():
                self._alarm("Debugger detected")
            if self._monitor_processes:
                self._check_processes()
            time.sleep(interval)

    def _check_processes(self):
        """Run the process check and alarm (once) on any new process names."""
        before = len(self.violations)
        if not self.verify_processes():
            # verify_processes records "Unexpected process appeared: <name>";
            # extract just the names so the alarm text isn't doubled up.
            names = [v.split(": ", 1)[-1] for v in self.violations[before:]]
            self._alarm("Unexpected process(es): " + ", ".join(names))

    def _alarm(self, reason: str):
        logger.critical(f"TAMPER ALARM: {reason}")
        alert_log = Path("data/alerts/tamper.log")
        alert_log.parent.mkdir(exist_ok=True, parents=True)
        with open(alert_log, "a") as f:
            f.write(f"{time.time():.0f}: {reason}\n")
        notifier.send(
            title="🚨 TIGRESS — Tamper Detected",
            content=reason,
            priority="max",
            vibrate=True,
            ongoing=True,
        )
