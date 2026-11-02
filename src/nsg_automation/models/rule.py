"""Domain model for an NSG security rule.

``NsgRule`` is the tool's single, normalised representation of a rule. It is
immutable and independent of the Azure SDK so that validation, diffing and
tests never need network access.

Address and port fields are always tuples. Azure's API has separate
singular/plural properties (``sourceAddressPrefix`` vs ``sourceAddressPrefixes``,
``sourcePortRange`` vs ``sourcePortRanges``); the conversion helpers below pick
the right one automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from typing import Any

INBOUND = "Inbound"
OUTBOUND = "Outbound"
ALLOW = "Allow"
DENY = "Deny"
ANY = "*"

# Fields compared when deciding whether two rules are "the same" (plan/diff).
COMPARED_FIELDS = (
    "direction", "access", "protocol", "priority",
    "source", "source_ports", "destination", "destination_ports",
    "source_asgs", "destination_asgs", "description",
)

# Fields where order is irrelevant (compared as sets).
_SET_FIELDS = {"source", "source_ports", "destination", "destination_ports",
               "source_asgs", "destination_asgs"}


@dataclass(frozen=True)
class NsgRule:
    name: str
    direction: str
    access: str
    protocol: str
    priority: int
    source: tuple[str, ...] = (ANY,)
    source_ports: tuple[str, ...] = (ANY,)
    destination: tuple[str, ...] = (ANY,)
    destination_ports: tuple[str, ...] = (ANY,)
    description: str = ""
    # Application Security Group resource IDs (alternative to address prefixes).
    source_asgs: tuple[str, ...] = ()
    destination_asgs: tuple[str, ...] = ()

    # ------------------------------------------------------------------ helpers
    @property
    def key(self) -> str:
        """Case-insensitive identity (Azure resource names are case-insensitive)."""
        return self.name.lower()

    def with_changes(self, **changes: Any) -> "NsgRule":
        return replace(self, **changes)

    def _comparable(self, field_name: str) -> Any:
        value = getattr(self, field_name)
        if field_name in _SET_FIELDS:
            return frozenset(v.lower() for v in value)
        if field_name == "description":
            return (value or "").strip()
        return value

    def diff(self, other: "NsgRule") -> dict[str, tuple[Any, Any]]:
        """Return {field: (self_value, other_value)} for every differing field."""
        return {
            name: (getattr(self, name), getattr(other, name))
            for name in COMPARED_FIELDS
            if self._comparable(name) != other._comparable(name)
        }

    def same_traffic_as(self, other: "NsgRule") -> bool:
        """True when both rules match exactly the same packets with the same action."""
        ignored = {"priority", "description"}
        return all(self._comparable(f) == other._comparable(f)
                   for f in COMPARED_FIELDS if f not in ignored)

    # ------------------------------------------------------------ JSON format
    def to_dict(self) -> dict[str, Any]:
        """Serialise to the tool's JSON configuration format (camelCase)."""
        data: dict[str, Any] = {
            "name": self.name,
            "direction": self.direction,
            "access": self.access,
            "protocol": self.protocol,
            "priority": self.priority,
            "source": _collapse(self.source),
            "sourcePort": _collapse(self.source_ports),
            "destination": _collapse(self.destination),
            "destinationPort": _collapse(self.destination_ports),
            "description": self.description,
        }
        if self.source_asgs:
            data["sourceAsgs"] = list(self.source_asgs)
        if self.destination_asgs:
            data["destinationAsgs"] = list(self.destination_asgs)
        if not self.source:
            data.pop("source")
        if not self.destination:
            data.pop("destination")
        return data

    # ------------------------------------------------------- Azure SDK format
    def to_azure(self):
        """Build an ``azure.mgmt.network.models.SecurityRule``."""
        from azure.mgmt.network.models import ApplicationSecurityGroup, SecurityRule

        kwargs: dict[str, Any] = {
            "name": self.name,
            "direction": self.direction,
            "access": self.access,
            "protocol": self.protocol,
            "priority": self.priority,
            "description": self.description or None,
        }
        kwargs.update(_split("source_address_prefix", self.source))
        kwargs.update(_split("destination_address_prefix", self.destination))
        kwargs.update(_split("source_port_range", self.source_ports))
        kwargs.update(_split("destination_port_range", self.destination_ports))
        if self.source_asgs:
            kwargs["source_application_security_groups"] = [
                ApplicationSecurityGroup(id=i) for i in self.source_asgs]
        if self.destination_asgs:
            kwargs["destination_application_security_groups"] = [
                ApplicationSecurityGroup(id=i) for i in self.destination_asgs]
        return SecurityRule(**{k: v for k, v in kwargs.items() if v is not None})

    @classmethod
    def from_azure(cls, sr: Any) -> "NsgRule":
        """Create from an SDK ``SecurityRule`` (singular/plural fields merged)."""
        return cls(
            name=sr.name,
            direction=_enum_value(sr.direction),
            access=_enum_value(sr.access),
            protocol=_enum_value(sr.protocol),
            priority=int(sr.priority),
            source=_merge(sr.source_address_prefix, sr.source_address_prefixes),
            source_ports=_merge(sr.source_port_range, sr.source_port_ranges),
            destination=_merge(sr.destination_address_prefix, sr.destination_address_prefixes),
            destination_ports=_merge(sr.destination_port_range, sr.destination_port_ranges),
            description=sr.description or "",
            source_asgs=_asg_ids(sr.source_application_security_groups),
            destination_asgs=_asg_ids(sr.destination_application_security_groups),
        )


def rule_field_names() -> list[str]:
    return [f.name for f in fields(NsgRule)]


def _collapse(values: tuple[str, ...]) -> str | list[str]:
    return values[0] if len(values) == 1 else list(values)


def _split(singular: str, values: tuple[str, ...]) -> dict[str, Any]:
    """Map a tuple onto Azure's singular (1 value) or plural (>1) property."""
    if not values:
        return {}
    if len(values) == 1:
        return {singular: values[0]}
    plural = singular + "es" if singular.endswith("prefix") else singular + "s"
    return {plural: list(values)}


def _merge(single: str | None, many: list[str] | None) -> tuple[str, ...]:
    if many:
        return tuple(many)
    if single:
        return (single,)
    return ()


def _enum_value(value: Any) -> str:
    """SDK models may return plain strings or str-enums (e.g. SecurityRuleDirection.INBOUND)."""
    return str(getattr(value, "value", value))


def _asg_ids(groups: Any) -> tuple[str, ...]:
    if not groups:
        return ()
    ids = []
    for g in groups:
        gid = getattr(g, "id", None) or (g.get("id") if isinstance(g, dict) else None)
        if gid:
            ids.append(gid)
    return tuple(ids)
