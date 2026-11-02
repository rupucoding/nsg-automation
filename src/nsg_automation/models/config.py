"""Desired-state configuration for one NSG (loaded from JSON)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nsg_automation.models.rule import NsgRule


@dataclass(frozen=True)
class NsgConfig:
    resource_group: str
    nsg: str
    rules: tuple[NsgRule, ...]
    subscription_id: str | None = None
    location: str | None = None          # used only when the NSG must be created
    tags: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"resourceGroup": self.resource_group, "nsg": self.nsg}
        if self.subscription_id:
            data["subscriptionId"] = self.subscription_id
        if self.location:
            data["location"] = self.location
        if self.tags:
            data["tags"] = dict(self.tags)
        data["rules"] = [r.to_dict() for r in sorted(self.rules, key=_sort_key)]
        return data


def _sort_key(rule: NsgRule) -> tuple[int, int]:
    return (0 if rule.direction == "Inbound" else 1, rule.priority)
