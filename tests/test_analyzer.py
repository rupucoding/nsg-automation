from nsg_automation.validation.addressing import (
    addresses_cover, addresses_overlap, port_count, ports_cover, ports_overlap,
)
from nsg_automation.validation.analyzer import analyze_rules, check_change, security_issues
from nsg_automation.validation.issues import Severity

from conftest import make_rule


def codes(issues):
    return {i.code for i in issues}


# ---------------------------------------------------------- set logic
def test_address_cover_and_overlap():
    assert addresses_cover(["10.0.0.0/8"], ["10.1.2.0/24"]) is True
    assert addresses_cover(["10.1.2.0/24"], ["10.0.0.0/8"]) is False
    assert addresses_cover(["*"], ["Internet"]) is True
    assert addresses_cover(["Internet"], ["10.0.0.0/8"]) is None       # unknown offline
    assert addresses_overlap(["10.0.0.0/8"], ["10.200.0.0/16"]) is True
    assert addresses_overlap(["10.0.0.0/8"], ["192.168.0.0/16"]) is False
    assert addresses_overlap(["10.0.0.0/8"], ["2001:db8::/32"]) is False


def test_port_logic():
    assert ports_cover(["1-100", "101-200"], ["50-150"]) is True      # union of adjacent ranges
    assert ports_cover(["80"], ["80-81"]) is False
    assert ports_overlap(["1000-2000"], ["1500"]) is True
    assert ports_overlap(["80"], ["443"]) is False
    assert port_count(["*"]) == 65536
    assert port_count(["80", "80-81"]) == 2


# ------------------------------------------------------ priority / names
def test_priority_conflict_same_direction_is_error():
    issues = analyze_rules([make_rule("A", priority=100), make_rule("B", priority=100, destination_ports=("80",))])
    assert "PRIORITY_CONFLICT" in codes(issues)
    assert any(i.severity is Severity.ERROR for i in issues)


def test_same_priority_different_direction_is_fine():
    issues = analyze_rules([make_rule("A", priority=100),
                            make_rule("B", direction="Outbound", priority=100)])
    assert "PRIORITY_CONFLICT" not in codes(issues)


def test_duplicate_names_case_insensitive():
    issues = analyze_rules([make_rule("Allow-Web", priority=100), make_rule("allow-web", priority=110)])
    assert "DUPLICATE_NAME" in codes(issues)


# -------------------------------------------- duplicates / conflicts
def test_duplicate_rule_detected():
    issues = analyze_rules([make_rule("A", priority=100), make_rule("B", priority=200)])
    dup = [i for i in issues if i.code == "DUPLICATE_RULE"]
    assert dup and dup[0].rule == "B"


def test_duplicate_detection_ignores_value_order():
    a = make_rule("A", priority=100, destination_ports=("80", "443"))
    b = make_rule("B", priority=200, destination_ports=("443", "80"))
    assert "DUPLICATE_RULE" in codes(analyze_rules([a, b]))


def test_redundant_rule_fully_covered_same_action():
    broad = make_rule("Web", priority=100, destination_ports=("80-443",))
    narrow = make_rule("Https", priority=200, destination_ports=("443",), source=("10.0.0.0/24",))
    assert "REDUNDANT_RULE" in codes(analyze_rules([broad, narrow]))


def test_shadowed_rule_opposite_action():
    allow = make_rule("Allow-10", priority=100, source=("10.0.0.0/8",), destination_ports=("*",), protocol="*")
    deny = make_rule("Deny-Host", access="Deny", priority=200, source=("10.1.1.1",), destination_ports=("22",))
    issues = analyze_rules([allow, deny])
    shadowed = [i for i in issues if i.code == "SHADOWED_RULE"]
    assert shadowed and shadowed[0].rule == "Deny-Host"


def test_partial_overlap_opposite_action_is_conflict():
    allow = make_rule("Allow-Range", priority=100, destination_ports=("1000-2000",))
    deny = make_rule("Deny-Range", access="Deny", priority=200, destination_ports=("1500-2500",))
    issues = analyze_rules([allow, deny])
    conflict = [i for i in issues if i.code == "CONFLICTING_RULES"]
    assert conflict and "'Allow-Range' (Allow) wins" in conflict[0].message


def test_exception_then_catch_all_is_not_a_conflict():
    rules = [make_rule("Allow-HTTPS", priority=100),
             make_rule("Allow-LB", priority=200, source=("AzureLoadBalancer",), protocol="*",
                       destination_ports=("*",)),
             make_rule("Deny-All", access="Deny", protocol="*", priority=4096, destination_ports=("*",))]
    found = codes(analyze_rules(rules, include_security=False))
    assert "CONFLICTING_RULES" not in found
    assert "OVERRIDES_DEFAULT_RULES" not in found


def test_non_overlapping_rules_produce_no_findings():
    rules = [make_rule("A", priority=100, source=("10.0.0.0/24",), destination_ports=("443",)),
             make_rule("B", access="Deny", priority=200, source=("10.0.1.0/24",), destination_ports=("443",))]
    assert analyze_rules(rules) == []


def test_deny_all_without_lb_allow_warns():
    deny_all = make_rule("Deny-All", access="Deny", protocol="*", priority=4096, destination_ports=("*",))
    assert "OVERRIDES_DEFAULT_RULES" in codes(analyze_rules([deny_all]))


# ------------------------------------------------------------- security
def test_any_any_inbound_allow_is_critical():
    rule = make_rule("Open", protocol="*", source=("0.0.0.0/0",), destination_ports=("*",))
    issues = security_issues(rule)
    assert issues[0].code == "ANY_ANY_ALLOW" and issues[0].severity is Severity.CRITICAL


def test_any_any_outbound_allow_is_high():
    rule = make_rule("Open-Out", direction="Outbound", protocol="*", destination_ports=("*",))
    assert security_issues(rule)[0].severity is Severity.HIGH


def test_all_ports_from_internet_is_critical():
    rule = make_rule("Tcp-All", source=("Internet",), destination=("10.0.0.0/24",), destination_ports=("*",))
    assert security_issues(rule)[0].code == "ALL_PORTS_FROM_INTERNET"


def test_ssh_and_rdp_from_internet_is_high():
    rule = make_rule("Mgmt", destination_ports=("22", "3389"))
    issue = security_issues(rule)[0]
    assert issue.code == "MANAGEMENT_PORT_EXPOSED" and issue.severity is Severity.HIGH
    assert "22/SSH" in issue.message and "3389/RDP" in issue.message


def test_port_range_containing_ssh_is_flagged():
    rule = make_rule("Range", destination_ports=("20-30",))
    assert "MANAGEMENT_PORT_EXPOSED" in codes(security_issues(rule))


def test_https_from_internet_is_medium_only():
    issues = security_issues(make_rule("Web"))
    assert [i.code for i in issues] == ["OPEN_TO_INTERNET"]
    assert issues[0].severity is Severity.MEDIUM


def test_ssh_from_known_range_is_not_flagged():
    assert security_issues(make_rule("Ssh", source=("203.0.113.0/28",), destination_ports=("22",))) == []


def test_deny_rules_are_never_security_risks():
    assert security_issues(make_rule("Deny", access="Deny", protocol="*", destination_ports=("*",))) == []


def test_check_change_only_reports_new_rule_findings():
    existing = [make_rule("Old-A", priority=100), make_rule("Old-B", priority=200)]  # pre-existing duplicate
    new = make_rule("New", priority=100, destination_ports=("8443",), source=("10.0.0.0/8",))
    found = check_change(new, existing)
    assert "PRIORITY_CONFLICT" in codes(found)
    assert "DUPLICATE_RULE" not in codes(found)  # Old-B vs Old-A is not this change's problem


def test_check_change_update_replaces_self():
    existing = [make_rule("A", priority=100)]
    updated = make_rule("A", priority=100, destination_ports=("8443",), source=("10.0.0.0/8",))
    assert check_change(updated, existing, replacing="A") == []
