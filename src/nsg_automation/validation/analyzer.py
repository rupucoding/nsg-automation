"""Rule-set analysis: security risks, duplicates, conflicts and shadowing.

How Azure evaluates NSG rules (and what this module models):

* Inbound and outbound rules are evaluated independently.
* Within a direction, rules are processed in ascending priority order
  (100 first, 4096 last). The *first* rule that matches a flow decides
  Allow/Deny and processing stops.
* A rule matches when protocol, source address, source port, destination
  address and destination port all match.
* Default rules (65000-65500) always exist: AllowVnetInBound,
  AllowAzureLoadBalancerInBound, DenyAllInBound, AllowVnetOutBound,
  AllowInternetOutBound, DenyAllOutBound.

Consequences checked here:

* Two rules with the same priority in the same direction  -> ERROR (Azure rejects).
* Duplicate rule names                                    -> ERROR.
* A later rule fully covered by an earlier rule           -> it never matches
  (REDUNDANT if same action, SHADOWED if opposite action).
* Rules that partially overlap with opposite actions      -> CONFLICT (earlier wins).
  (A later, broader rule that fully contains an earlier exception - e.g. a
  final Deny-All - is the intended pattern and is not reported.)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from nsg_automation.models.rule import ALLOW, ANY, DENY, INBOUND, OUTBOUND, NsgRule
from nsg_automation.validation.addressing import (
    ALL_PORTS, ASG_PREFIX, INTERNET_EQUIVALENT, Tri, addresses_cover, addresses_overlap,
    port_count, port_in, ports_cover, ports_overlap, protocol_covers, protocol_overlaps,
    tri_and,
)
from nsg_automation.validation.issues import Issue, Severity, sort_issues

# Ports that should never be reachable from the Internet.
SENSITIVE_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 135: "MS-RPC", 137: "NetBIOS",
    139: "NetBIOS", 445: "SMB", 1433: "MS SQL", 1521: "Oracle DB", 2375: "Docker API",
    2379: "etcd", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 5986: "WinRM-HTTPS", 6379: "Redis", 9200: "Elasticsearch",
    10250: "Kubelet", 11211: "Memcached", 27017: "MongoDB",
}
WIDE_PORT_RANGE = 1000


# ------------------------------------------------------------------ helpers
def _endpoints(prefixes: tuple[str, ...], asgs: tuple[str, ...]) -> list[str]:
    return list(prefixes) + [ASG_PREFIX + a for a in asgs]


def _is_open(prefixes: tuple[str, ...], asgs: tuple[str, ...]) -> bool:
    """Address field allows any Internet address (*, 0.0.0.0/0, ::/0, Internet)."""
    return not asgs and any(p.lower() in INTERNET_EQUIVALENT for p in prefixes)


def _is_any(prefixes: tuple[str, ...], asgs: tuple[str, ...]) -> bool:
    return not asgs and any(p.lower() in ("*", "0.0.0.0/0", "::/0") for p in prefixes)


def _all_ports(ports: tuple[str, ...]) -> bool:
    return port_count(ports) == ALL_PORTS[1] - ALL_PORTS[0] + 1


def rule_covers(a: NsgRule, b: NsgRule) -> Tri:
    """Does ``a`` match every packet that ``b`` matches?"""
    return tri_and(
        protocol_covers(a.protocol, b.protocol),
        addresses_cover(_endpoints(a.source, a.source_asgs), _endpoints(b.source, b.source_asgs)),
        ports_cover(a.source_ports, b.source_ports),
        addresses_cover(_endpoints(a.destination, a.destination_asgs),
                        _endpoints(b.destination, b.destination_asgs)),
        ports_cover(a.destination_ports, b.destination_ports),
    )


def rules_overlap(a: NsgRule, b: NsgRule) -> Tri:
    """Is there at least one packet both rules match?"""
    return tri_and(
        protocol_overlaps(a.protocol, b.protocol),
        addresses_overlap(_endpoints(a.source, a.source_asgs), _endpoints(b.source, b.source_asgs)),
        ports_overlap(a.source_ports, b.source_ports),
        addresses_overlap(_endpoints(a.destination, a.destination_asgs),
                          _endpoints(b.destination, b.destination_asgs)),
        ports_overlap(a.destination_ports, b.destination_ports),
    )


# ----------------------------------------------------------- per-rule risk
def security_issues(rule: NsgRule) -> list[Issue]:
    """Security findings for a single rule (only Allow rules are risky)."""
    if rule.access != ALLOW:
        return []
    issues: list[Issue] = []
    name = rule.name
    open_src = _is_open(rule.source, rule.source_asgs)
    any_src = _is_any(rule.source, rule.source_asgs)
    any_dst = _is_any(rule.destination, rule.destination_asgs)
    all_ports = _all_ports(rule.destination_ports)
    any_proto = rule.protocol == ANY

    if any_src and any_dst and all_ports and any_proto:
        sev = Severity.CRITICAL if rule.direction == INBOUND else Severity.HIGH
        issues.append(Issue(
            sev, "ANY_ANY_ALLOW",
            f"{rule.direction} rule allows ALL traffic: source {', '.join(rule.source)} -> "
            f"destination {', '.join(rule.destination)}, any port, any protocol "
            f"({'Any/Any inbound' if rule.direction == INBOUND else 'unrestricted egress'})",
            name, hint="Restrict source CIDRs, destination, ports and protocol to what is required"))
        return issues

    if rule.direction == INBOUND and open_src:
        if all_ports:
            issues.append(Issue(
                Severity.CRITICAL, "ALL_PORTS_FROM_INTERNET",
                f"exposes ALL ports{'' if any_proto else ' (' + rule.protocol + ')'} to the Internet "
                f"(source {', '.join(rule.source)})",
                name, hint="Limit destination ports and source address ranges"))
            return issues
        exposed = sorted(p for p in SENSITIVE_PORTS
                         if port_in(p, rule.destination_ports) and rule.protocol != "Icmp")
        if exposed:
            labels = ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in exposed)
            issues.append(Issue(
                Severity.HIGH, "MANAGEMENT_PORT_EXPOSED",
                f"exposes sensitive port(s) {labels} to the Internet (source {', '.join(rule.source)})",
                name, hint="Use Azure Bastion, Just-In-Time VM access, a VPN, or restrict the source to "
                           "known admin IP ranges"))
        count = port_count(rule.destination_ports)
        if count > WIDE_PORT_RANGE:
            issues.append(Issue(
                Severity.MEDIUM, "WIDE_PORT_RANGE_FROM_INTERNET",
                f"opens {count} destination ports to the Internet", name,
                hint="Open only the specific ports the workload needs"))
        if not exposed and count <= WIDE_PORT_RANGE:
            issues.append(Issue(
                Severity.MEDIUM, "OPEN_TO_INTERNET",
                f"allows inbound traffic from the entire Internet (source {', '.join(rule.source)}) "
                f"on port(s) {', '.join(rule.destination_ports)}",
                name, hint="Expected for public endpoints (e.g. HTTPS); otherwise restrict the source"))
    elif rule.direction == OUTBOUND and _is_open(rule.destination, rule.destination_asgs) and all_ports \
            and any_proto:
        issues.append(Issue(
            Severity.MEDIUM, "UNRESTRICTED_EGRESS",
            "allows outbound traffic to the Internet on any port/protocol", name,
            hint="Restrict egress to required destinations/ports where possible"))
    return issues


# --------------------------------------------------------- whole rule set
def analyze_rules(rules: Iterable[NsgRule], include_security: bool = True) -> list[Issue]:
    """Analyse a complete rule set as Azure would evaluate it."""
    rules = list(rules)
    issues: list[Issue] = []

    # Names must be unique (case-insensitive) across the NSG.
    by_name: dict[str, list[NsgRule]] = defaultdict(list)
    for r in rules:
        by_name[r.key].append(r)
    for group in by_name.values():
        if len(group) > 1:
            issues.append(Issue(Severity.ERROR, "DUPLICATE_NAME",
                                f"rule name {group[0].name!r} is used {len(group)} times",
                                group[0].name))

    for direction in (INBOUND, OUTBOUND):
        ordered = sorted((r for r in rules if r.direction == direction), key=lambda r: (r.priority, r.key))
        issues.extend(_priority_conflicts(ordered, direction))
        issues.extend(_pairwise(ordered))
        if direction == INBOUND:
            issues.extend(_default_rule_overrides(ordered))

    if include_security:
        for r in rules:
            issues.extend(security_issues(r))
    return sort_issues(issues)


def _priority_conflicts(ordered: list[NsgRule], direction: str) -> list[Issue]:
    by_priority: dict[int, list[NsgRule]] = defaultdict(list)
    for r in ordered:
        by_priority[r.priority].append(r)
    return [
        Issue(Severity.ERROR, "PRIORITY_CONFLICT",
              f"{direction} priority {p} is used by multiple rules: "
              f"{', '.join(repr(r.name) for r in group)}",
              group[-1].name, hint="Each rule in the same direction needs a unique priority")
        for p, group in by_priority.items() if len(group) > 1
    ]


def _pairwise(ordered: list[NsgRule]) -> list[Issue]:
    """Compare each rule with every rule evaluated before it."""
    issues: list[Issue] = []
    for i, later in enumerate(ordered):
        for earlier in ordered[:i]:
            if earlier.priority == later.priority:
                continue  # already reported as PRIORITY_CONFLICT
            if earlier.same_traffic_as(later):
                issues.append(Issue(
                    Severity.WARNING, "DUPLICATE_RULE",
                    f"duplicates {earlier.name!r} (priority {earlier.priority}): same traffic and "
                    f"action; this rule (priority {later.priority}) is never evaluated",
                    later.name, hint=f"Remove {later.name!r} or change its match criteria"))
                break
            covered = rule_covers(earlier, later)
            if covered is True:
                if earlier.access == later.access:
                    issues.append(Issue(
                        Severity.WARNING, "REDUNDANT_RULE",
                        f"fully covered by {earlier.name!r} (priority {earlier.priority}, "
                        f"{earlier.access}); it can never match", later.name))
                else:
                    issues.append(Issue(
                        Severity.WARNING, "SHADOWED_RULE",
                        f"{later.access} rule is completely shadowed by {earlier.name!r} "
                        f"(priority {earlier.priority}, {earlier.access}); it will never take effect",
                        later.name,
                        hint=f"Give {later.name!r} a lower priority number than {earlier.priority} "
                             "if it should take precedence"))
                break
            # A broader later rule containing the earlier one is the normal
            # "specific exception first, general rule after" pattern - not a conflict.
            if (earlier.access != later.access and rules_overlap(earlier, later) is True
                    and rule_covers(later, earlier) is not True):
                issues.append(Issue(
                    Severity.WARNING, "CONFLICTING_RULES",
                    f"overlaps with {earlier.name!r} (priority {earlier.priority}) but has the "
                    f"opposite action; for overlapping traffic {earlier.name!r} "
                    f"({earlier.access}) wins", later.name))
    return issues


def _default_rule_overrides(inbound: list[NsgRule]) -> list[Issue]:
    """Warn when a deny-all rule overrides AllowAzureLoadBalancerInBound/AllowVnetInBound."""
    issues = []
    for idx, r in enumerate(inbound):
        if r.access != DENY or r.protocol != ANY or not _all_ports(r.destination_ports):
            continue
        if not _is_any(r.source, r.source_asgs) or not _is_any(r.destination, r.destination_asgs):
            continue
        lb_allowed = any(
            e.access == ALLOW and any(s.lower() == "azureloadbalancer" for s in e.source)
            for e in inbound[:idx])
        if not lb_allowed:
            issues.append(Issue(
                Severity.WARNING, "OVERRIDES_DEFAULT_RULES",
                f"deny-all at priority {r.priority} overrides the default rules AllowVnetInBound "
                "and AllowAzureLoadBalancerInBound: Azure Load Balancer health probes and "
                "intra-VNet traffic will be blocked",
                r.name, hint="Add an Allow rule for source 'AzureLoadBalancer' (and 'VirtualNetwork' "
                             "if needed) with a lower priority number"))
    return issues


def check_change(rule: NsgRule, existing: Iterable[NsgRule], replacing: str | None = None) -> list[Issue]:
    """Analyse adding/updating ``rule`` in an NSG that currently has ``existing`` rules.

    Only findings involving ``rule`` are returned (pre-existing problems between
    other rules are not this change's fault).
    """
    others = [r for r in existing if r.key != (replacing or rule.name).lower()]
    combined = others + [rule]
    return [i for i in analyze_rules(combined)
            if i.rule is not None and (i.rule.lower() == rule.key or repr(rule.name) in i.message)]
