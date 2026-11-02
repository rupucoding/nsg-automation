"""Thin wrapper around the Azure management SDK for NSG operations.

All Azure calls go through this class so that:
  * SDK exceptions are translated into friendly errors in one place,
  * the rest of the tool works with ``NsgRule`` instead of SDK models,
  * tests can swap in an in-memory fake with the same interface.

Long-running operations (PUT/DELETE) return an ``LROPoller``; we block on
``.result()`` so the CLI reports the final provisioning outcome.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, TypeVar

from azure.core.exceptions import AzureError
from azure.mgmt.network import NetworkManagementClient

from nsg_automation.azure.errors import translate_azure_error
from nsg_automation.models.rule import NsgRule
from nsg_automation.utils.logging_setup import get_logger

try:  # azure-mgmt-resource >= 24 moved the client into a sub-package
    from azure.mgmt.resource.resources import ResourceManagementClient
except ImportError:  # pragma: no cover - older SDKs
    from azure.mgmt.resource import ResourceManagementClient

T = TypeVar("T")
LRO_TIMEOUT_SECONDS = 600
_log = get_logger("azure")


class AzureNsgClient:
    """Operations on NSGs and their security rules in one subscription."""

    def __init__(self, credential: Any, subscription_id: str,
                 network_client: Any | None = None, resource_client: Any | None = None) -> None:
        self.subscription_id = subscription_id
        self._credential = credential
        self._network = network_client
        self._resources = resource_client

    # --------------------------------------------------------------- clients
    @property
    def network(self) -> NetworkManagementClient:
        if self._network is None:
            # The SDK's default retry policy already retries 429/5xx with
            # exponential back-off and honours Retry-After.
            self._network = NetworkManagementClient(self._credential, self.subscription_id)
        return self._network

    @property
    def resources(self) -> ResourceManagementClient:
        if self._resources is None:
            self._resources = ResourceManagementClient(self._credential, self.subscription_id)
        return self._resources

    def _call(self, fn: Callable[[], T], *, op: str, resource_group: str | None = None,
              nsg: str | None = None, rule: str | None = None) -> T:
        _log.debug("azure call", extra={"fields": {
            "operation": op, "resource_group": resource_group, "nsg": nsg, "rule": rule}})
        try:
            return fn()
        except AzureError as exc:
            err = translate_azure_error(exc, subscription=self.subscription_id,
                                        resource_group=resource_group, nsg=nsg, rule=rule)
            _log.warning("azure call failed", extra={"fields": {
                "operation": op, "error_type": type(err).__name__, "error": err.message,
                "code": getattr(err, "code", None)}})
            raise err from exc

    # ----------------------------------------------------- resource groups
    def resource_group_location(self, resource_group: str) -> str:
        rg = self._call(lambda: self.resources.resource_groups.get(resource_group),
                        op="ResourceGroups.get", resource_group=resource_group)
        return rg.location

    # ----------------------------------------------------------------- NSGs
    def get_nsg(self, resource_group: str, nsg: str) -> Any:
        return self._call(lambda: self.network.network_security_groups.get(resource_group, nsg),
                          op="NetworkSecurityGroups.get", resource_group=resource_group, nsg=nsg)

    def nsg_exists(self, resource_group: str, nsg: str) -> bool:
        from nsg_automation.utils.errors import NsgNotFoundError
        try:
            self.get_nsg(resource_group, nsg)
            return True
        except NsgNotFoundError:
            return False

    def create_nsg(self, resource_group: str, nsg: str, location: str,
                   tags: dict[str, str] | None = None, rules: Iterable[NsgRule] = ()) -> Any:
        from azure.mgmt.network.models import NetworkSecurityGroup

        params = NetworkSecurityGroup(location=location, tags=tags or None,
                                      security_rules=[r.to_azure() for r in rules])
        return self._call(
            lambda: self.network.network_security_groups.begin_create_or_update(
                resource_group, nsg, params).result(timeout=LRO_TIMEOUT_SECONDS),
            op="NetworkSecurityGroups.begin_create_or_update", resource_group=resource_group, nsg=nsg)

    # ---------------------------------------------------------------- rules
    def list_rules(self, resource_group: str, nsg: str) -> list[NsgRule]:
        group = self.get_nsg(resource_group, nsg)
        return [NsgRule.from_azure(r) for r in (group.security_rules or [])]

    def list_default_rules(self, resource_group: str, nsg: str) -> list[NsgRule]:
        group = self.get_nsg(resource_group, nsg)
        return [NsgRule.from_azure(r) for r in (group.default_security_rules or [])]

    def get_rule(self, resource_group: str, nsg: str, name: str) -> NsgRule:
        sr = self._call(lambda: self.network.security_rules.get(resource_group, nsg, name),
                        op="SecurityRules.get", resource_group=resource_group, nsg=nsg, rule=name)
        return NsgRule.from_azure(sr)

    def create_or_update_rule(self, resource_group: str, nsg: str, rule: NsgRule) -> NsgRule:
        result = self._call(
            lambda: self.network.security_rules.begin_create_or_update(
                resource_group, nsg, rule.name, rule.to_azure()).result(timeout=LRO_TIMEOUT_SECONDS),
            op="SecurityRules.begin_create_or_update", resource_group=resource_group, nsg=nsg,
            rule=rule.name)
        return NsgRule.from_azure(result)

    def delete_rule(self, resource_group: str, nsg: str, name: str) -> None:
        self._call(
            lambda: self.network.security_rules.begin_delete(
                resource_group, nsg, name).result(timeout=LRO_TIMEOUT_SECONDS),
            op="SecurityRules.begin_delete", resource_group=resource_group, nsg=nsg, rule=name)

    def replace_rules(self, resource_group: str, nsg: str, rules: Iterable[NsgRule]) -> list[NsgRule]:
        """Atomically set the NSG's complete custom rule set with a single PUT.

        The NSG is read first so that every other property (location, tags,
        flush-connection setting ...) is sent back unchanged. Default rules are
        read-only and unaffected.
        """
        group = self.get_nsg(resource_group, nsg)
        group.security_rules = [r.to_azure() for r in rules]
        result = self._call(
            lambda: self.network.network_security_groups.begin_create_or_update(
                resource_group, nsg, group).result(timeout=LRO_TIMEOUT_SECONDS),
            op="NetworkSecurityGroups.begin_create_or_update", resource_group=resource_group, nsg=nsg)
        return [NsgRule.from_azure(r) for r in (result.security_rules or [])]

    # ------------------------------------------------------------- display
    def rule_resource_id(self, resource_group: str, nsg: str, rule: str | None = None) -> str:
        rid = (f"/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}"
               f"/providers/Microsoft.Network/networkSecurityGroups/{nsg}")
        return f"{rid}/securityRules/{rule}" if rule else rid
