import json
from pathlib import Path

import pytest

from nsg_automation.nsg.serializer import export_config, load_config, parse_config
from nsg_automation.utils.errors import ConfigError, ValidationError

from conftest import make_rule

EXAMPLE = Path(__file__).resolve().parent.parent / "config" / "example-nsg.json"


def test_example_config_parses():
    config, warnings = load_config(EXAMPLE)
    assert config.resource_group == "network-rg" and config.nsg == "web-nsg"
    assert len(config.rules) == 6
    assert warnings == []


def test_spec_example_format():
    config, _ = parse_config({
        "resourceGroup": "network-rg", "nsg": "web-nsg",
        "rules": [{"name": "Allow-HTTPS", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                   "source": "*", "sourcePort": "*", "destination": "*", "destinationPort": "443",
                   "priority": 100, "description": "Allow HTTPS"}]})
    assert config.rules[0] == make_rule(description="Allow HTTPS")


def test_invalid_json_reports_line(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text('{"resourceGroup": "rg",\n "nsg": }', encoding="utf-8")
    with pytest.raises(ConfigError, match="line 2"):
        load_config(p)


def test_missing_file():
    with pytest.raises(ConfigError, match="not found"):
        load_config("does-not-exist.json")


def test_errors_from_all_rules_are_collected():
    data = {"resourceGroup": "rg", "nsg": "nsg", "extra": 1, "rules": [
        {"name": "a", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
         "destinationPort": "443", "priority": 5},
        {"name": "b", "direction": "Sideways", "access": "Allow", "protocol": "Tcp",
         "destinationPort": "443", "priority": 200},
        "not-an-object",
    ]}
    with pytest.raises(ValidationError) as exc:
        parse_config(data)
    messages = [i.message for i in exc.value.issues]
    assert any("unknown top-level key 'extra'" in m for m in messages)
    assert any(m.startswith("rules[0]") and "priority" in m for m in messages)
    assert any(m.startswith("rules[1]") and "direction" in m for m in messages)
    assert any("rules[2] must be an object" in m for m in messages)


def test_missing_required_top_level_keys():
    with pytest.raises(ValidationError) as exc:
        parse_config({"rules": []})
    assert len(exc.value.issues) == 2


def test_top_level_must_be_object():
    with pytest.raises(ConfigError):
        parse_config([1, 2])


def test_export_then_import_round_trip(tmp_path):
    rules = [make_rule("B", priority=200, source=("10.0.0.0/24", "10.0.1.0/24")),
             make_rule("A", priority=100),
             make_rule("Out", direction="Outbound", priority=100, destination=("Sql",))]
    data = export_config("rg", "nsg", rules, location="eastus")
    assert [r["name"] for r in data["rules"]] == ["A", "B", "Out"]   # sorted by direction/priority
    p = tmp_path / "export.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    config, _ = load_config(p)
    assert set(config.rules) == set(rules)
    assert config.location == "eastus"
