"""Compare desired rules (JSON) with the rules currently in Azure.

Rules are matched by name (case-insensitive, like Azure). The resulting plan
lists, Terraform-style:

    + create     rule in config, not in Azure
    ~ update     rule in both, at least one property differs
    - delete     rule in Azure, not in config   (unless keep_unmanaged=True)
    = unchanged  rule identical in both
    . unmanaged  rule only in Azure, kept because keep_unmanaged=True
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from nsg_automation.models.config import NsgConfig
from nsg_automation.models.rule import NsgRule

CREATE, UPDATE, DELETE, UNCHANGED, UNMANAGED = "create", "update", "delete", "unchanged", "unmanaged"
SYMBOLS = {CREATE: "+", UPDATE: "~", DELETE: "-", UNCHANGED: "=", UNMANAGED: "."}


@dataclass(frozen=True)
class RuleChange:
    action: str
    name: str
    current: NsgRule | None = None
    desired: NsgRule | None = None
    diff: dict[str, tuple[Any, Any]] = field(default_factory=dict)

    @property
    def symbol(self) -> str:
        return SYMBOLS[self.action]

    @property
    def effective(self) -> NsgRule | None:
        """The rule as it will exist after apply (None when deleted)."""
        if self.action == DELETE:
            return None
        return self.desired or self.current


@dataclass
class Plan:
    resource_group: str
    nsg: str
    nsg_exists: bool
    changes: list[RuleChange]
    keep_unmanaged: bool = False
    location: str | None = None

    def of(self, action: str) -> list[RuleChange]:
        return [c for c in self.changes if c.action == action]

    @property
    def has_changes(self) -> bool:
        return not self.nsg_exists or any(c.action in (CREATE, UPDATE, DELETE) for c in self.changes)

    @property
    def changed_names(self) -> set[str]:
        return {c.name.lower() for c in self.changes if c.action in (CREATE, UPDATE)}

    def final_rules(self) -> list[NsgRule]:
        return [c.effective for c in self.changes if c.effective is not None]

    def summary(self) -> dict[str, int]:
        return {a: len(self.of(a)) for a in (CREATE, UPDATE, DELETE, UNCHANGED, UNMANAGED)}


def build_plan(config: NsgConfig, current: Iterable[NsgRule], *, nsg_exists: bool = True,
               keep_unmanaged: bool = False, location: str | None = None) -> Plan:
    current_by_key = {r.key: r for r in current}
    changes: list[RuleChange] = []

    for desired in config.rules:
        existing = current_by_key.pop(desired.key, None)
        if existing is None:
            changes.append(RuleChange(CREATE, desired.name, desired=desired))
            continue
        diff = existing.diff(desired)
        action = UPDATE if diff else UNCHANGED
        changes.append(RuleChange(action, desired.name, current=existing, desired=desired, diff=diff))

    for leftover in current_by_key.values():
        action = UNMANAGED if keep_unmanaged else DELETE
        changes.append(RuleChange(action, leftover.name, current=leftover))

    order = {DELETE: 0, UPDATE: 1, CREATE: 2, UNCHANGED: 3, UNMANAGED: 4}
    changes.sort(key=lambda c: (order[c.action], (c.desired or c.current).direction,
                                (c.desired or c.current).priority))
    return Plan(config.resource_group, config.nsg, nsg_exists, changes, keep_unmanaged,
                location or config.location)
