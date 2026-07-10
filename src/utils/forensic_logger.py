"""Append-only forensic JSONL logging."""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


class ForensicLogger:
    """Append-only JSONL forensic log. Each write is fsynced."""

    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(exist_ok=True, parents=True)

    def log(self, event_type: str, data: Dict[str, Any]):
        """Append one fsynced JSONL record for an event."""
        entry = json.dumps({"type": event_type, "data": data})
        try:
            with open(self.log_path, "a") as f:
                f.write(entry + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            logger.error(f"Forensic log write failed: {e}")
