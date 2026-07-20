"""Rule audit: enforce single-behaviour detection signals (Josh Liburdi).

Liburdi's loosely-coupled model holds that each rule should describe *one*
behaviour of interest — a "detection signal" — and that signals are recombined
into higher-order alerts by the correlation engine, not by stacking behaviours
inside a single rule. Multi-behaviour rules couple detection to a specific
scenario and are harder to reuse for hunting, intel, and IR.

This module audits a rules mapping and reports rules that combine multiple
behaviours (more than one match condition). It is intentionally advisory:
splitting a rule can change detection coverage, so the decision is left to the
operator. :func:`audit_rules` is pure so it is trivially testable;
``scripts/audit_rules.py`` wraps it for the command line.
"""

from pathlib import Path
from typing import Any, Dict, List

import yaml

# Rule sections understood by the detection engine.
RULE_SECTIONS = ("wifi_rules", "bluetooth_rules")


def audit_rules(rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return one finding per multi-behaviour rule in ``rules``.

    Each finding: ``{section, rule_id, condition_count, fields, recommendation}``.
    An empty list means every rule is a single-behaviour signal.
    """
    findings: List[Dict[str, Any]] = []
    for section in RULE_SECTIONS:
        for rule in rules.get(section) or []:
            if not isinstance(rule, dict):
                continue
            conditions = rule.get("conditions")
            if not isinstance(conditions, list) or len(conditions) <= 1:
                continue
            fields = [c.get("field") for c in conditions if isinstance(c, dict)]
            findings.append({
                "section": section,
                "rule_id": rule.get("id", "<unnamed>"),
                "condition_count": len(conditions),
                "fields": fields,
                "recommendation": (
                    "Combines multiple behaviours; consider splitting into "
                    "single-behaviour signals recombined by the correlation "
                    "engine (behavioural progression / cross-sensor)."
                ),
            })
    return findings


def audit_rules_file(path: str) -> List[Dict[str, Any]]:
    """Load a YAML rules file and audit it. Missing file yields no findings."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    data = yaml.safe_load(text) or {}
    return audit_rules(data)
