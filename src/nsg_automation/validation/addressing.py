"""Address-prefix, port-range and protocol set logic used by the analyzer.

Overlap/coverage questions are answered with *three-valued logic*:
``True`` (definitely), ``False`` (definitely not) or ``None`` (cannot be
determined offline, e.g. a service tag compared with a CIDR, because the IP
ranges behind service tags change and are not known locally). The analyzer only
reports findings that are definitely true, so it never produces false alarms
from guesses.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, Optional

Tri = Optional[bool]

MIN_PORT, MAX_PORT = 0, 65535
ALL_PORTS = (MIN_PORT, MAX_PORT)

# Address values that mean "the whole Internet / anything".
ANY_ADDRESS_VALUES = {"*", "0.0.0.0/0", "::/0", "any"}
INTERNET_EQUIVALENT = ANY_ADDRESS_VALUES | {"internet"}

# Commonly used Azure service tags (case-insensitive lookup -> canonical case).
# Regional variants such as "Storage.WestEurope" are accepted via their base tag.
KNOWN_SERVICE_TAGS = {t.lower(): t for t in [
    "Internet", "VirtualNetwork", "AzureLoadBalancer", "AzureCloud", "AzureTrafficManager",
    "Storage", "StorageSyncService", "Sql", "SqlManagement", "AzureCosmosDB", "AzureKeyVault",
    "EventHub", "ServiceBus", "AzureMonitor", "AzureActiveDirectory",
    "AzureActiveDirectoryDomainServices", "AzureFrontDoor", "GatewayManager", "ApiManagement",
    "AppService", "AppServiceManagement", "AzureBackup", "AzureContainerRegistry",
    "AzureDevOps", "AzureMachineLearning", "AzureBotService", "AzureDataLake",
    "AzureSiteRecovery", "AzureCognitiveSearch", "BatchNodeManagement",
    "CognitiveServicesManagement", "DataFactory", "DataFactoryManagement",
    "GuestAndHybridManagement", "HDInsight", "MicrosoftContainerRegistry", "PowerBI",
    "AzureUpdateDelivery", "AzureArcInfrastructure", "AzureResourceManager",
    "AzurePlatformDNS", "AzurePlatformIMDS", "AzurePlatformLKM", "ActionGroup",
    "AzureDatabricks", "AzureEventGrid", "AzureSignalR", "LogicApps", "LogicAppsManagement",
    "AzureConnectors", "AzureDigitalTwins", "AzureIoTHub", "AzureSpringCloud", "AzureStack",
    "AzureOpenDatasets", "AzurePortal", "MicrosoftCloudAppSecurity", "OneDsCollector",
    "PowerPlatformInfra", "PowerQueryOnline", "WindowsAdminCenter", "WindowsVirtualDesktop",
    "AzureCloudAppSecurity", "AzureSecurityCenter", "AzureSentinel", "ServiceFabric",
    "AzureKubernetesService", "AzureAttestation", "AzureManagedGrafana",
]}

SERVICE_TAG_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)*$")
ASG_PREFIX = "asg:"  # internal marker so ASG endpoints can be compared like tags


@dataclass(frozen=True)
class Endpoint:
    """One parsed address value: any, cidr, tag or asg."""

    raw: str
    kind: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None

    @property
    def is_any(self) -> bool:
        return self.kind == "any"


def parse_endpoint(value: str) -> Endpoint:
    """Parse an already-validated address value."""
    v = value.strip()
    low = v.lower()
    if low in ("*", "any"):
        return Endpoint(v, "any")
    if low.startswith(ASG_PREFIX):
        return Endpoint(v, "asg")
    try:
        return Endpoint(v, "cidr", ipaddress.ip_network(v, strict=False))
    except ValueError:
        return Endpoint(v, "tag")


def endpoint_covers(a: Endpoint, b: Endpoint) -> Tri:
    """Does ``a`` include every address in ``b``?"""
    if a.is_any:
        return True
    if b.is_any:
        return False
    if a.kind == "cidr" and b.kind == "cidr":
        if a.network.version != b.network.version:
            return False
        return b.network.subnet_of(a.network)
    if a.kind == b.kind and a.raw.lower() == b.raw.lower():
        return True
    return None


def endpoint_overlaps(a: Endpoint, b: Endpoint) -> Tri:
    if a.is_any or b.is_any:
        return True
    if a.kind == "cidr" and b.kind == "cidr":
        if a.network.version != b.network.version:
            return False
        return a.network.overlaps(b.network)
    if a.kind == b.kind and a.raw.lower() == b.raw.lower():
        return True
    return None


def addresses_cover(a: Iterable[str], b: Iterable[str]) -> Tri:
    """Every value in ``b`` is covered by at least one value of ``a``."""
    a_eps = [parse_endpoint(x) for x in a]
    results = []
    for eb in (parse_endpoint(x) for x in b):
        per = [endpoint_covers(ea, eb) for ea in a_eps]
        if True in per:
            results.append(True)
        elif all(r is False for r in per):
            results.append(False)
        else:
            results.append(None)
    return _all(results)


def addresses_overlap(a: Iterable[str], b: Iterable[str]) -> Tri:
    a_eps = [parse_endpoint(x) for x in a]
    results = [endpoint_overlaps(ea, parse_endpoint(x)) for x in b for ea in a_eps]
    return _any(results)


# --------------------------------------------------------------------- ports
def parse_port_range(value: str) -> tuple[int, int]:
    """Parse an already-validated port value ('*', '443', '1000-2000')."""
    v = value.strip()
    if v == "*":
        return ALL_PORTS
    if "-" in v:
        lo, hi = v.split("-", 1)
        return int(lo), int(hi)
    return int(v), int(v)


def ports_cover(a: Iterable[str], b: Iterable[str]) -> bool:
    """Every port of ``b`` is inside the union of ``a``'s ranges."""
    merged = _merge_ranges(parse_port_range(x) for x in a)
    return all(any(lo >= mlo and hi <= mhi for mlo, mhi in merged)
               for lo, hi in (parse_port_range(x) for x in b))


def ports_overlap(a: Iterable[str], b: Iterable[str]) -> bool:
    ra = [parse_port_range(x) for x in a]
    return any(lo1 <= hi2 and lo2 <= hi1 for lo1, hi1 in ra for lo2, hi2 in (parse_port_range(x) for x in b))


def port_count(values: Iterable[str]) -> int:
    return sum(hi - lo + 1 for lo, hi in _merge_ranges(parse_port_range(x) for x in values))


def port_in(port: int, values: Iterable[str]) -> bool:
    return any(lo <= port <= hi for lo, hi in (parse_port_range(x) for x in values))


def _merge_ranges(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


# ----------------------------------------------------------------- protocols
def protocol_covers(a: str, b: str) -> bool:
    return a == "*" or a == b


def protocol_overlaps(a: str, b: str) -> bool:
    return a == "*" or b == "*" or a == b


# ------------------------------------------------------------- tri-state ops
def _all(values: list[Tri]) -> Tri:
    if any(v is False for v in values):
        return False
    if all(v is True for v in values):
        return True
    return None


def _any(values: list[Tri]) -> Tri:
    if any(v is True for v in values):
        return True
    if all(v is False for v in values):
        return False
    return None


def tri_and(*values: Tri) -> Tri:
    return _all(list(values))
