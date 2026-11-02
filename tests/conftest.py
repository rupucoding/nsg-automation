"""Shared fixtures. No test talks to real Azure: ``FakeNsgClient`` is an
in-memory stand-in with the same interface as ``AzureNsgClient``."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nsg_automation.models.rule import NsgRule
from nsg_automation.nsg.manager import NsgManager
from nsg_automation.utils.audit import AuditLogger
from nsg_automation.utils.errors import NsgNotFoundError, ResourceGroupNotFoundError, RuleNotFoundError

SUB = "00000000-0000-0000-0000-000000000000"
WRITE_OPS = {"create_or_update_rule", "delete_rule", "create_nsg", "replace_rules"}


def make_rule(name="Allow-HTTPS", direction="Inbound", access="Allow", protocol="Tcp",
              priority=100, source=("*",), source_ports=("*",), destination=("*",),
              destination_ports=("443",), description="", **kw) -> NsgRule:
    return NsgRule(name=name, direction=direction, access=access, protocol=protocol,
                   priority=priority, source=tuple(source), source_ports=tuple(source_ports),
                   destination=tuple(destination), destination_ports=tuple(destination_ports),
                   description=description, **kw)


class FakeNsgClient:
    def __init__(self, nsgs=None, locations=None, subscription_id=SUB):
        self.subscription_id = subscription_id
        self.nsgs: dict[tuple[str, str], list[NsgRule]] = {k: list(v) for k, v in (nsgs or {}).items()}
        self.locations = locations or {"rg": "eastus"}
        self.calls: list[tuple] = []

    @property
    def writes(self) -> list[tuple]:
        return [c for c in self.calls if c[0] in WRITE_OPS]

    def _rules(self, rg, nsg):
        if rg not in self.locations:
            raise ResourceGroupNotFoundError(f"Resource group {rg!r} was not found.")
        if (rg, nsg) not in self.nsgs:
            raise NsgNotFoundError(f"Network security group {nsg!r} was not found.")
        return self.nsgs[(rg, nsg)]

    def resource_group_location(self, rg):
        self.calls.append(("resource_group_location", rg))
        if rg not in self.locations:
            raise ResourceGroupNotFoundError(f"Resource group {rg!r} was not found.")
        return self.locations[rg]

    def get_nsg(self, rg, nsg):
        self.calls.append(("get_nsg", rg, nsg))
        rules = self._rules(rg, nsg)
        return SimpleNamespace(location=self.locations[rg], security_rules=rules)

    def nsg_exists(self, rg, nsg):
        try:
            self._rules(rg, nsg)
            return True
        except NsgNotFoundError:
            return False

    def list_rules(self, rg, nsg):
        self.calls.append(("list_rules", rg, nsg))
        return list(self._rules(rg, nsg))

    def list_default_rules(self, rg, nsg):
        self._rules(rg, nsg)
        return [make_rule("DenyAllInBound", access="Deny", protocol="*", priority=65500,
                          destination_ports=("*",))]

    def get_rule(self, rg, nsg, name):
        for r in self._rules(rg, nsg):
            if r.key == name.lower():
                return r
        raise RuleNotFoundError(f"Rule {name!r} was not found.")

    def create_or_update_rule(self, rg, nsg, rule):
        self.calls.append(("create_or_update_rule", rg, nsg, rule))
        rules = [r for r in self._rules(rg, nsg) if r.key != rule.key]
        self.nsgs[(rg, nsg)] = rules + [rule]
        return rule

    def delete_rule(self, rg, nsg, name):
        self.calls.append(("delete_rule", rg, nsg, name))
        self.get_rule(rg, nsg, name)
        self.nsgs[(rg, nsg)] = [r for r in self._rules(rg, nsg) if r.key != name.lower()]

    def create_nsg(self, rg, nsg, location, tags=None, rules=()):
        self.calls.append(("create_nsg", rg, nsg, location, tags, tuple(rules)))
        self.nsgs[(rg, nsg)] = list(rules)

    def replace_rules(self, rg, nsg, rules):
        rules = list(rules)
        self.calls.append(("replace_rules", rg, nsg, tuple(rules)))
        self._rules(rg, nsg)
        self.nsgs[(rg, nsg)] = rules
        return rules

    def rule_resource_id(self, rg, nsg, rule=None):
        rid = (f"/subscriptions/{self.subscription_id}/resourceGroups/{rg}"
               f"/providers/Microsoft.Network/networkSecurityGroups/{nsg}")
        return f"{rid}/securityRules/{rule}" if rule else rid


@pytest.fixture
def audit_path(tmp_path) -> Path:
    return tmp_path / "audit.log"


@pytest.fixture
def fake_client() -> FakeNsgClient:
    return FakeNsgClient({("rg", "nsg"): [
        make_rule("Allow-HTTPS", priority=100),
        make_rule("Allow-SSH-Admin", priority=200, source=("203.0.113.0/28",), destination_ports=("22",)),
        make_rule("Allow-DNS-Out", direction="Outbound", protocol="Udp", priority=100,
                  destination=("10.0.0.4",), destination_ports=("53",)),
    ]})


@pytest.fixture
def manager(fake_client, audit_path) -> NsgManager:
    return NsgManager(fake_client, AuditLogger(audit_path, user_resolver=lambda: "tester@contoso.com"))


def read_audit(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
