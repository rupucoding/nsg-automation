"""Read/write the JSON desired-state format.

    {
      "subscriptionId": "optional - env/flag preferred",
      "resourceGroup": "network-rg",
      "nsg": "web-nsg",
      "location": "optional - only used if the NSG has to be created",
      "tags": {"optional": "used only on creation"},
      "rules": [ { "name": "Allow-HTTPS", "direction": "Inbound", ... } ]
    }

Rule fields: name, direction, access, protocol, priority, source, sourcePort,
destination, destinationPort, description, sourceAsgs, destinationAsgs. Address
and port fields accept a string ("443", "80,443") or a list.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from nsg_automation.models.config import NsgConfig
from nsg_automation.models.rule import NsgRule
from nsg_automation.utils.errors import ConfigError, ValidationError
from nsg_automation.validation.issues import Issue, Severity
from nsg_automation.validation.validators import build_rule

TOP_LEVEL_KEYS = {"$schema", "subscriptionId", "resourceGroup", "nsg", "location", "tags",
                  "rules", "description"}


def load_config(path: str | Path) -> tuple[NsgConfig, list[Issue]]:
    """Load and validate a configuration file (all rule errors reported at once)."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"Configuration file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{p} is not valid JSON: line {exc.lineno}, column {exc.colno}: {exc.msg}") from None
    except OSError as exc:
        raise ConfigError(f"Cannot read {p}: {exc}") from None
    return parse_config(data, source=str(p))


def parse_config(data: Any, source: str = "<config>") -> tuple[NsgConfig, list[Issue]]:
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: top level must be a JSON object")

    problems: list[Issue] = []
    unknown = set(data) - TOP_LEVEL_KEYS
    for key in sorted(unknown):
        problems.append(Issue(Severity.ERROR, "UNKNOWN_KEY",
                              f"unknown top-level key {key!r} (allowed: {', '.join(sorted(TOP_LEVEL_KEYS))})"))
    for key in ("resourceGroup", "nsg"):
        if not isinstance(data.get(key), str) or not data.get(key, "").strip():
            problems.append(Issue(Severity.ERROR, "MISSING_KEY", f"{key!r} is required and must be a string"))

    tags = data.get("tags") or {}
    if not isinstance(tags, dict) or not all(isinstance(v, str) for v in tags.values()):
        problems.append(Issue(Severity.ERROR, "INVALID_TAGS", "'tags' must be an object of string values"))
        tags = {}

    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        problems.append(Issue(Severity.ERROR, "MISSING_KEY", "'rules' is required and must be a list"))
        raw_rules = []

    rules: list[NsgRule] = []
    warnings: list[Issue] = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            problems.append(Issue(Severity.ERROR, "INVALID_RULE", f"rules[{index}] must be an object"))
            continue
        try:
            rule, notes = build_rule(raw)
            rules.append(rule)
            warnings.extend(notes)
        except ValidationError as exc:
            problems.extend(
                Issue(i.severity, i.code, f"rules[{index}]: {i.message}", i.rule, i.hint) for i in exc.issues)

    if problems:
        raise ValidationError(f"{source} contains {len(problems)} error(s)", issues=problems)

    config = NsgConfig(
        resource_group=data["resourceGroup"].strip(),
        nsg=data["nsg"].strip(),
        rules=tuple(rules),
        subscription_id=(data.get("subscriptionId") or None),
        location=(data.get("location") or None),
        tags=dict(tags),
    )
    return config, warnings


def export_config(resource_group: str, nsg: str, rules: Iterable[NsgRule],
                  location: str | None = None, tags: dict[str, str] | None = None) -> dict[str, Any]:
    """Build a config document that ``import``/``apply`` can consume unchanged."""
    return NsgConfig(resource_group=resource_group, nsg=nsg, rules=tuple(rules),
                     location=location, tags=dict(tags or {})).to_dict()


def dump_json(data: Any, path: str | Path | None = None) -> str:
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return text
