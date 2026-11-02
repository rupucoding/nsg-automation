import pytest

from nsg_automation.utils.errors import ValidationError
from nsg_automation.validation.validators import (
    FieldError, build_rule, normalize_addresses, normalize_ports, normalize_protocol,
    validate_description, validate_priority, validate_rule_name,
)


# ------------------------------------------------------------------- CIDR
@pytest.mark.parametrize("value, expected", [
    ("10.0.0.0/24", "10.0.0.0/24"),
    ("192.168.1.10", "192.168.1.10"),
    ("10.1.2.3/32", "10.1.2.3/32"),
    ("0.0.0.0/0", "0.0.0.0/0"),
    ("2001:DB8::/32", "2001:db8::/32"),
    ("*", "*"),
    ("any", "*"),
    ("internet", "Internet"),
    ("virtualnetwork", "VirtualNetwork"),
    ("AzureLoadBalancer", "AzureLoadBalancer"),
    ("storage.westeurope", "Storage.westeurope"),
])
def test_valid_addresses(value, expected):
    values, warnings = normalize_addresses(value, "source")
    assert values == (expected,)
    assert warnings == []


@pytest.mark.parametrize("value, fragment", [
    ("10.0.0.5/24", "host bits"),
    ("10.0.0.0/33", "not valid CIDR"),
    ("256.1.1.1", "not valid CIDR"),
    ("10.0.0/24", "not valid CIDR"),
    ("10.0.0.0/abc", "not a valid"),
    ("bad tag!", "not a valid"),
])
def test_invalid_cidr(value, fragment):
    with pytest.raises(FieldError, match=fragment):
        normalize_addresses(value, "source")


def test_multiple_prefixes_and_list_input():
    values, _ = normalize_addresses(["10.0.0.0/24", "10.1.0.0/16"], "source")
    assert values == ("10.0.0.0/24", "10.1.0.0/16")
    values, _ = normalize_addresses("10.0.0.0/24, 10.1.0.0/16", "source")
    assert values == ("10.0.0.0/24", "10.1.0.0/16")


def test_any_cannot_be_combined():
    with pytest.raises(FieldError, match="cannot be combined"):
        normalize_addresses("*,10.0.0.0/8", "source")


def test_service_tag_cannot_be_combined():
    with pytest.raises(FieldError, match="service tag"):
        normalize_addresses("Internet,10.0.0.0/8", "source")


def test_unknown_service_tag_is_a_warning():
    values, warnings = normalize_addresses("MadeUpTag", "source")
    assert values == ("MadeUpTag",)
    assert "not a known Azure service tag" in warnings[0]


def test_duplicate_addresses_rejected():
    with pytest.raises(FieldError, match="duplicate"):
        normalize_addresses("10.0.0.0/8,10.0.0.0/8", "source")


# ------------------------------------------------------------------ ports
@pytest.mark.parametrize("value, expected", [
    ("443", ("443",)), (443, ("443",)), ("*", ("*",)), ("any", ("*",)),
    ("8000-8080", ("8000-8080",)), ("80,443", ("80", "443")), ([80, "443"], ("80", "443")),
    ("0", ("0",)), ("65535", ("65535",)), ("22-22", ("22",)), (" 1000 - 2000 ", ("1000-2000",)),
])
def test_valid_ports(value, expected):
    assert normalize_ports(value) == expected


@pytest.mark.parametrize("value, fragment", [
    ("65536", "outside"), ("-1", "not a valid"), ("2000-1000", "greater than"),
    ("abc", "not a valid"), ("80,*", "cannot be combined"), ("", "required"),
    ("1-70000", "outside"), ("80,80", "duplicate"),
])
def test_invalid_ports(value, fragment):
    with pytest.raises(FieldError, match=fragment):
        normalize_ports(value)


# --------------------------------------------------------------- priority
@pytest.mark.parametrize("value", [100, 4096, "250", 1000])
def test_valid_priority(value):
    assert validate_priority(value) == int(value)


@pytest.mark.parametrize("value", [99, 4097, 0, -5, 65000, "abc", None, True, 1.5])
def test_invalid_priority(value):
    with pytest.raises(FieldError):
        validate_priority(value)


# ------------------------------------------------------------ other fields
def test_protocol_normalisation():
    assert normalize_protocol("TCP") == "Tcp"
    assert normalize_protocol("any") == "*"
    with pytest.raises(FieldError):
        normalize_protocol("http")


@pytest.mark.parametrize("name", ["Allow-HTTPS", "a", "rule_1", "x.y-z_", "A" * 80])
def test_valid_rule_names(name):
    assert validate_rule_name(name) == name


@pytest.mark.parametrize("name", ["", "-start", "end-", "has space", "A" * 81, "bad/char"])
def test_invalid_rule_names(name):
    with pytest.raises(FieldError):
        validate_rule_name(name)


def test_description_length():
    assert validate_description("x" * 140) == "x" * 140
    with pytest.raises(FieldError):
        validate_description("x" * 141)


# -------------------------------------------------------------- build_rule
def _raw(**overrides):
    raw = {"name": "Allow-HTTPS", "direction": "inbound", "access": "allow", "protocol": "tcp",
           "destinationPort": "443", "priority": 100}
    raw.update(overrides)
    return raw


def test_build_rule_defaults_and_normalisation():
    rule, warnings = build_rule(_raw())
    assert rule.direction == "Inbound" and rule.access == "Allow" and rule.protocol == "Tcp"
    assert rule.source == ("*",) and rule.source_ports == ("*",) and rule.destination == ("*",)
    assert warnings == []


def test_build_rule_reports_all_errors_at_once():
    with pytest.raises(ValidationError) as exc:
        build_rule(_raw(priority=50, protocol="http", source="10.0.0.1/8", destinationPort="99999"))
    messages = " | ".join(i.message for i in exc.value.issues)
    assert "priority" in messages and "protocol" in messages
    assert "host bits" in messages and "outside" in messages
    assert len(exc.value.issues) == 4


def test_build_rule_missing_and_unknown_fields():
    with pytest.raises(ValidationError) as exc:
        build_rule({"name": "x", "prioritty": 100})
    messages = " | ".join(i.message for i in exc.value.issues)
    assert "unknown field 'prioritty'" in messages
    assert "missing required field 'priority'" in messages
    assert "missing required field 'destinationPort'" in messages


def test_build_rule_accepts_azure_property_names():
    raw = _raw(sourceAddressPrefixes=["10.0.0.0/24", "10.0.1.0/24"], destinationPortRanges=["80", "443"])
    del raw["destinationPort"]
    rule, _ = build_rule(raw)
    assert rule.source == ("10.0.0.0/24", "10.0.1.0/24")
    assert rule.destination_ports == ("80", "443")


def test_same_field_twice_via_alias_is_rejected():
    with pytest.raises(ValidationError, match="invalid"):
        build_rule(_raw(destinationPortRange="443"))


def test_build_rule_asg_and_prefix_conflict():
    asg = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/web"
    rule, _ = build_rule(_raw(destinationAsgs=[asg]))
    assert rule.destination == () and rule.destination_asgs == (asg,)
    with pytest.raises(ValidationError, match="invalid"):
        build_rule(_raw(destination="10.0.0.0/24", destinationAsgs=[asg]))


def test_icmp_ports_warning():
    _, warnings = build_rule(_raw(protocol="icmp", destinationPort="80"))
    assert warnings[0].code == "PORTS_IGNORED"
