import yaml

from src.core.rule_audit import audit_rules, audit_rules_file


def test_single_behaviour_rules_yield_no_findings():
    rules = {
        "wifi_rules": [
            {"id": "ssid", "conditions": [{"field": "SSID", "op": "eq", "value": "x"}]},
        ],
        "bluetooth_rules": [
            {"id": "prox", "conditions": [{"field": "rssi", "op": "gt", "value": "-50"}]},
        ],
    }
    assert audit_rules(rules) == []


def test_multi_behaviour_rule_is_flagged():
    rules = {
        "bluetooth_rules": [
            {"id": "combo", "conditions": [
                {"field": "mac_randomized", "op": "eq", "value": True},
                {"field": "rssi", "op": "gt", "value": "-60"},
            ]},
        ],
    }
    findings = audit_rules(rules)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "combo"
    assert findings[0]["condition_count"] == 2
    assert findings[0]["fields"] == ["mac_randomized", "rssi"]
    assert "split" in findings[0]["recommendation"].lower()


def test_rule_with_no_conditions_is_not_flagged():
    rules = {"wifi_rules": [{"id": "always", "conditions": []}]}
    assert audit_rules(rules) == []


def test_malformed_conditions_do_not_crash():
    # A hand-edited rules file could set `conditions: true`; len() on a bool
    # would raise TypeError, so non-list conditions must be treated as empty.
    rules = {"wifi_rules": [
        {"id": "bad_bool", "conditions": True},
        {"id": "bad_int", "conditions": 3},
        {"id": "missing"},
    ]}
    assert audit_rules(rules) == []


def test_missing_file_yields_no_findings(tmp_path):
    assert audit_rules_file(str(tmp_path / "nope.yaml")) == []


def test_audit_rules_file_reads_yaml(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump({
        "wifi_rules": [{"id": "multi", "conditions": [
            {"field": "a", "op": "eq", "value": 1},
            {"field": "b", "op": "eq", "value": 2},
        ]}],
    }))
    findings = audit_rules_file(str(path))
    assert [f["rule_id"] for f in findings] == ["multi"]


def test_shipped_rules_file_audits_cleanly_except_documented_rule():
    # The repo's real rules file keeps exactly one intentional multi-behaviour
    # rule (ble_randomized_mac_close); the audit must surface it and nothing else.
    findings = audit_rules_file("config/rules.yaml")
    assert [f["rule_id"] for f in findings] == ["ble_randomized_mac_close"]
