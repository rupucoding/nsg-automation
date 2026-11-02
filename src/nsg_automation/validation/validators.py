"""Field-level validation and normalisation of NSG rule input.

``build_rule`` is the single entry point used by both the CLI flags and the JSON
loader: it turns loosely-typed user input into a canonical ``NsgRule`` or raises
``ValidationError`` listing *every* problem found (not just the first).

Azure limits enforced here (Microsoft.Network/networkSecurityGroups/securityRules):
  * priority: integer 100-4096, unique per direction within an NSG
  * name: 1-80 chars, starts with alphanumeric, ends with alphanumeric or '_',
    may contain alphanumerics, '_', '.', '-'
  * description: max 140 characters
  * protocol: Tcp, Udp, Icmp, Esp, Ah or * (Any)
  * ports: '*', a single port or a 'start-end' range within 0-65535
  * addresses: '*', IPv4/IPv6 address or CIDR, or a service tag; service tags
    and '*' cannot be combined with other values in the same rule field
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Mapping

from nsg_automation.models.rule import ANY, NsgRule
from nsg_automation.utils.errors import ValidationError
from nsg_automation.validation.addressing import (
    KNOWN_SERVICE_TAGS, MAX_PORT, MIN_PORT, SERVICE_TAG_PATTERN,
)
from nsg_automation.validation.issues import Issue, Severity

MIN_PRIORITY, MAX_PRIORITY = 100, 4096
MAX_DESCRIPTION = 140
RULE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.\-]{0,78}[A-Za-z0-9_])?$")
ASG_ID_PATTERN = re.compile(
    r"^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/"
    r"applicationSecurityGroups/[^/]+$", re.IGNORECASE)

PROTOCOLS = {"tcp": "Tcp", "udp": "Udp", "icmp": "Icmp", "esp": "Esp", "ah": "Ah",
             "*": "*", "any": "*"}
DIRECTIONS = {"inbound": "Inbound", "in": "Inbound", "outbound": "Outbound", "out": "Outbound"}
ACCESS = {"allow": "Allow", "deny": "Deny"}

# Accepted JSON keys -> internal field. Azure-style property names are accepted
# as aliases so output from `az network nsg rule list` can be adapted easily.
FIELD_ALIASES = {
    "name": "name", "direction": "direction", "access": "access", "protocol": "protocol",
    "priority": "priority", "description": "description",
    "source": "source", "sourceAddressPrefix": "source", "sourceAddressPrefixes": "source",
    "destination": "destination", "destinationAddressPrefix": "destination",
    "destinationAddressPrefixes": "destination",
    "sourcePort": "source_ports", "sourcePortRange": "source_ports",
    "sourcePortRanges": "source_ports",
    "destinationPort": "destination_ports", "destinationPortRange": "destination_ports",
    "destinationPortRanges": "destination_ports",
    "sourceAsgs": "source_asgs", "destinationAsgs": "destination_asgs",
}
REQUIRED_FIELDS = ("name", "direction", "access", "protocol", "priority", "destination_ports")


class FieldError(ValueError):
    """A single invalid field value."""


# ------------------------------------------------------------- scalar fields
def normalize_direction(value: Any) -> str:
    return _lookup(value, DIRECTIONS, "direction", "Inbound or Outbound")


def normalize_access(value: Any) -> str:
    return _lookup(value, ACCESS, "access", "Allow or Deny")


def normalize_protocol(value: Any) -> str:
    return _lookup(value, PROTOCOLS, "protocol", "Tcp, Udp, Icmp, Esp, Ah or * (Any)")


def validate_priority(value: Any) -> int:
    if isinstance(value, bool):
        raise FieldError(f"priority must be an integer, got {value!r}")
    try:
        priority = int(str(value).strip())
    except (TypeError, ValueError):
        raise FieldError(f"priority must be an integer, got {value!r}") from None
    if not MIN_PRIORITY <= priority <= MAX_PRIORITY:
        raise FieldError(
            f"priority {priority} is out of range; Azure allows {MIN_PRIORITY}-{MAX_PRIORITY} "
            "(lower number = evaluated first)")
    return priority


def validate_rule_name(value: Any) -> str:
    name = str(value or "").strip()
    if not name:
        raise FieldError("rule name is required")
    if not RULE_NAME_PATTERN.match(name):
        raise FieldError(
            f"invalid rule name {name!r}: 1-80 characters, must start with a letter/number, "
            "end with a letter/number/underscore, and contain only letters, numbers, '_', '.', '-'")
    return name


def validate_description(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    if len(text) > MAX_DESCRIPTION:
        raise FieldError(f"description is {len(text)} characters; Azure allows at most {MAX_DESCRIPTION}")
    return text


# ----------------------------------------------------------- list fields
def split_values(value: Any) -> list[str]:
    """Accept '443', 443, '80,443', ['80', 443] -> ['80', '443']."""
    if value is None:
        return []
    raw_items = value if isinstance(value, (list, tuple, set)) else [value]
    items = [part for v in raw_items for part in str(v).split(",")]
    return [i.strip() for i in items if i.strip()]


def normalize_ports(value: Any, field: str = "port") -> tuple[str, ...]:
    items = split_values(value)
    if not items:
        raise FieldError(f"{field} is required (use '*' for any port)")
    result: list[str] = []
    for item in items:
        if item.lower() in ("*", "any"):
            result.append(ANY)
            continue
        m = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", item)
        if not m:
            raise FieldError(f"{field} {item!r} is not a valid port or range (e.g. 443, 8000-8080, *)")
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) is not None else lo
        for p in (lo, hi):
            if not MIN_PORT <= p <= MAX_PORT:
                raise FieldError(f"{field} {item!r}: port {p} is outside {MIN_PORT}-{MAX_PORT}")
        if lo > hi:
            raise FieldError(f"{field} {item!r}: range start {lo} is greater than end {hi}")
        result.append(str(lo) if lo == hi else f"{lo}-{hi}")
    if ANY in result and len(result) > 1:
        raise FieldError(f"{field}: '*' (any) cannot be combined with other ports")
    if len(set(result)) != len(result):
        raise FieldError(f"{field}: duplicate values in {items}")
    return tuple(result)


def normalize_addresses(value: Any, field: str = "address") -> tuple[tuple[str, ...], list[str]]:
    """Return (normalised values, warnings)."""
    items = split_values(value)
    if not items:
        raise FieldError(f"{field} is required (use '*' for any)")
    result: list[str] = []
    warnings: list[str] = []
    tags: list[str] = []
    for item in items:
        if item.lower() in ("*", "any"):
            result.append(ANY)
            continue
        if _looks_like_ip(item):
            result.append(_validate_ip_or_cidr(item, field))
            continue
        if SERVICE_TAG_PATTERN.match(item):
            base = item.split(".", 1)[0].lower()
            canonical_base = KNOWN_SERVICE_TAGS.get(base)
            if canonical_base:
                suffix = item[len(base):]
                item = canonical_base + suffix
            else:
                warnings.append(f"{field} {item!r} is not a known Azure service tag; "
                                "Azure will reject it if the tag does not exist")
            result.append(item)
            tags.append(item)
            continue
        raise FieldError(f"{field} {item!r} is not a valid IP address, CIDR, service tag or '*'")

    if len(result) > 1:
        if ANY in result:
            raise FieldError(f"{field}: '*' (any) cannot be combined with other addresses")
        if tags:
            raise FieldError(f"{field}: service tag(s) {tags} cannot be combined with other "
                             "addresses in one rule; create a separate rule per service tag")
    if len({r.lower() for r in result}) != len(result):
        raise FieldError(f"{field}: duplicate values in {items}")
    return tuple(result), warnings


def normalize_asgs(value: Any, field: str) -> tuple[str, ...]:
    ids = split_values(value)
    for i in ids:
        if not ASG_ID_PATTERN.match(i):
            raise FieldError(f"{field} {i!r} is not an Application Security Group resource ID")
    return tuple(ids)


def _looks_like_ip(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9.]+(/\d+)?", value)) or (":" in value)


def _validate_ip_or_cidr(value: str, field: str) -> str:
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            if str(net) != _canonical_cidr(value):
                raise FieldError(
                    f"{field} {value!r} has host bits set; the network address is {net} "
                    f"(did you mean {net}?)")
            return str(net)
        return str(ipaddress.ip_address(value))
    except FieldError:
        raise
    except ValueError:
        raise FieldError(f"{field} {value!r} is not valid CIDR notation "
                         "(expected e.g. 10.0.0.0/24, 192.168.1.10, 2001:db8::/32)") from None


def _canonical_cidr(value: str) -> str:
    addr, _, length = value.partition("/")
    try:
        return f"{ipaddress.ip_address(addr)}/{int(length)}"
    except ValueError:
        raise FieldError(f"{value!r} is not valid CIDR notation") from None


def _lookup(value: Any, table: dict[str, str], field: str, allowed: str) -> str:
    key = str(value or "").strip().lower()
    if key not in table:
        raise FieldError(f"invalid {field} {value!r}; expected {allowed}")
    return table[key]


# ------------------------------------------------------------- whole rule
def build_rule(raw: Mapping[str, Any]) -> tuple[NsgRule, list[Issue]]:
    """Validate raw input and build a canonical ``NsgRule``.

    Returns the rule plus non-blocking warnings. Raises ``ValidationError`` with
    one ``Issue`` per problem when anything is invalid.
    """
    rule_label = str(raw.get("name") or "<unnamed>")
    problems: list[Issue] = []
    warnings: list[Issue] = []

    def err(message: str) -> None:
        problems.append(Issue(Severity.ERROR, "INVALID_FIELD", message, rule_label))

    values: dict[str, Any] = {}
    for key, value in raw.items():
        target = FIELD_ALIASES.get(key)
        if target is None:
            err(f"unknown field {key!r} (allowed: {', '.join(sorted(FIELD_ALIASES))})")
            continue
        if target in values and value is not None:
            err(f"field {target!r} given more than once (via {key!r})")
            continue
        if value is not None:
            values[target] = value

    for required in REQUIRED_FIELDS:
        if required not in values:
            err(f"missing required field {_json_name(required)!r}")

    out: dict[str, Any] = {}
    checks = {
        "name": validate_rule_name, "direction": normalize_direction,
        "access": normalize_access, "protocol": normalize_protocol,
        "priority": validate_priority, "description": validate_description,
    }
    for field, fn in checks.items():
        if field in values:
            try:
                out[field] = fn(values[field])
            except FieldError as exc:
                err(str(exc))

    for field, label in (("source_ports", "sourcePort"), ("destination_ports", "destinationPort")):
        try:
            out[field] = normalize_ports(values.get(field, ANY), label)
        except FieldError as exc:
            err(str(exc))

    for field, label in (("source_asgs", "sourceAsgs"), ("destination_asgs", "destinationAsgs")):
        try:
            out[field] = normalize_asgs(values.get(field), label)
        except FieldError as exc:
            err(str(exc))

    for field, asg_field, label in (("source", "source_asgs", "source"),
                                    ("destination", "destination_asgs", "destination")):
        has_asg = bool(out.get(asg_field))
        if field in values and has_asg:
            err(f"{label}: specify either address prefixes or Application Security Groups, not both")
            continue
        if has_asg:
            out[field] = ()
            continue
        try:
            addresses, notes = normalize_addresses(values.get(field, ANY), label)
            out[field] = addresses
            warnings.extend(Issue(Severity.WARNING, "UNKNOWN_SERVICE_TAG", n, rule_label) for n in notes)
        except FieldError as exc:
            err(str(exc))

    if problems:
        raise ValidationError(f"Rule {rule_label!r} is invalid", issues=problems)

    if out["protocol"] in ("Icmp", "Esp", "Ah") and (
            out["source_ports"] != (ANY,) or out["destination_ports"] != (ANY,)):
        warnings.append(Issue(
            Severity.WARNING, "PORTS_IGNORED",
            f"{out['protocol']} has no ports; port values other than '*' are not meaningful",
            rule_label, hint="Use '*' for source and destination ports"))

    return NsgRule(**out), warnings


def _json_name(field: str) -> str:
    return {"source_ports": "sourcePort", "destination_ports": "destinationPort",
            "source_asgs": "sourceAsgs", "destination_asgs": "destinationAsgs"}.get(field, field)
