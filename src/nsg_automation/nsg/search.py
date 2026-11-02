"""Search / filter NSG rules (offline, on rules already fetched from Azure)."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Iterable

from nsg_automation.models.rule import NsgRule
from nsg_automation.validation.addressing import addresses_overlap, port_in
from nsg_automation.validation.validators import (
    normalize_access, normalize_addresses, normalize_direction, normalize_protocol,
)


@dataclass(frozen=True)
class RuleFilter:
    name: str | None = None            # substring or glob (e.g. "Allow-*")
    direction: str | None = None
    access: str | None = None
    protocol: str | None = None        # rules with protocol '*' also match
    port: int | None = None            # destination port contained in the rule
    source: str | None = None          # IP/CIDR/tag the rule's source matches
    destination: str | None = None     # IP/CIDR/tag the rule's destination matches
    min_priority: int | None = None
    max_priority: int | None = None
    text: str | None = None            # free text in name or description

    def normalized(self) -> "RuleFilter":
        """Validate user-supplied filter values (raises FieldError)."""
        return RuleFilter(
            name=self.name,
            direction=normalize_direction(self.direction) if self.direction else None,
            access=normalize_access(self.access) if self.access else None,
            protocol=normalize_protocol(self.protocol) if self.protocol else None,
            port=self.port,
            source=normalize_addresses(self.source, "source")[0][0] if self.source else None,
            destination=(normalize_addresses(self.destination, "destination")[0][0]
                         if self.destination else None),
            min_priority=self.min_priority, max_priority=self.max_priority, text=self.text,
        )


def matches(rule: NsgRule, f: RuleFilter) -> bool:
    if f.name:
        pattern = f.name.lower()
        name = rule.name.lower()
        if any(ch in pattern for ch in "*?[") and not fnmatch.fnmatch(name, pattern):
            return False
        if not any(ch in pattern for ch in "*?[") and pattern not in name:
            return False
    if f.direction and rule.direction != f.direction:
        return False
    if f.access and rule.access != f.access:
        return False
    if f.protocol and rule.protocol not in (f.protocol, "*"):
        return False
    if f.port is not None and not port_in(f.port, rule.destination_ports):
        return False
    if f.source and addresses_overlap(rule.source, [f.source]) is not True:
        return False
    if f.destination and addresses_overlap(rule.destination, [f.destination]) is not True:
        return False
    if f.min_priority is not None and rule.priority < f.min_priority:
        return False
    if f.max_priority is not None and rule.priority > f.max_priority:
        return False
    if f.text:
        needle = f.text.lower()
        if needle not in rule.name.lower() and needle not in (rule.description or "").lower():
            return False
    return True


def filter_rules(rules: Iterable[NsgRule], f: RuleFilter) -> list[NsgRule]:
    return sorted((r for r in rules if matches(r, f)), key=lambda r: (r.direction, r.priority))
