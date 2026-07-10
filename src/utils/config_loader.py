"""YAML configuration loading."""

from pathlib import Path
from typing import Any, Dict

import yaml


class ConfigLoader:
    """Loads YAML configuration files into plain dicts."""

    @staticmethod
    def load_config(path: str) -> Dict[str, Any]:
        """Load the main application config."""
        return ConfigLoader.load_yaml(path)

    @staticmethod
    def load_yaml(path: str) -> Dict[str, Any]:
        """Load and parse a YAML file; raise FileNotFoundError if missing."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(p) as f:
            return yaml.safe_load(f) or {}
