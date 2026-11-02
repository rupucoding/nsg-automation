from azure.mgmt.network.models import SecurityRule

from nsg_automation.models.config import NsgConfig
from nsg_automation.models.rule import NsgRule
from nsg_automation.nsg.planner import CREATE, DELETE, UNCHANGED, UNMANAGED, UPDATE, build_plan

from conftest import make_rule


# ------------------------------------------------------------ rule model
def test_to_azure_uses_singular_properties_for_one_value():
    sr = make_rule().to_azure()
    assert sr.destination_port_range == "443" and sr.destination_port_ranges is None
    assert sr.source_address_prefix == "*"
    body = sr.as_dict()
    assert body["properties"]["destinationPortRange"] == "443"
    assert body["properties"]["priority"] == 100


def test_to_azure_uses_plural_properties_for_many_values():
    sr = make_rule(source=("10.0.0.0/24", "10.0.1.0/24"), destination_ports=("80", "443")).to_azure()
    assert sr.source_address_prefixes == ["10.0.0.0/24", "10.0.1.0/24"]
    assert sr.source_address_prefix is None
    assert sr.destination_port_ranges == ["80", "443"]


def test_from_azure_round_trip():
    original = make_rule(source=("10.0.0.0/24", "10.0.1.0/24"), destination_ports=("80", "8000-8080"),
                         description="web")
    assert NsgRule.from_azure(original.to_azure()) == original


def test_from_azure_rest_payload_with_asgs():
    asg = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/web"
    sr = SecurityRule({"name": "r", "properties": {
        "protocol": "Tcp", "access": "Allow", "direction": "Inbound", "priority": 300,
        "sourceAddressPrefix": "VirtualNetwork", "sourcePortRange": "*",
        "destinationApplicationSecurityGroups": [{"id": asg}], "destinationPortRange": "443"}})
    rule = NsgRule.from_azure(sr)
    assert rule.destination == () and rule.destination_asgs == (asg,)
    assert rule.to_azure().destination_application_security_groups[0].id == asg


def test_diff_ignores_order_and_reports_changes():
    a = make_rule(destination_ports=("80", "443"))
    b = make_rule(destination_ports=("443", "80"))
    assert a.diff(b) == {}
    c = make_rule(destination_ports=("8443",), priority=150)
    assert set(a.diff(c)) == {"destination_ports", "priority"}


def test_to_dict_collapses_single_values():
    d = make_rule(source=("10.0.0.0/24", "10.0.1.0/24")).to_dict()
    assert d["destinationPort"] == "443"
    assert d["source"] == ["10.0.0.0/24", "10.0.1.0/24"]


# --------------------------------------------------------------- planner
def _config(*rules):
    return NsgConfig(resource_group="rg", nsg="nsg", rules=tuple(rules))


def test_plan_create_update_delete_unchanged():
    current = [make_rule("Same", priority=100),
               make_rule("Changed", priority=110, destination_ports=("80",)),
               make_rule("Gone", priority=120, destination_ports=("8080",))]
    desired = _config(make_rule("Same", priority=100),
                      make_rule("Changed", priority=110, destination_ports=("8443",)),
                      make_rule("New", priority=130, destination_ports=("22",), source=("10.0.0.0/8",)))
    plan = build_plan(desired, current)
    actions = {c.name: c.action for c in plan.changes}
    assert actions == {"Same": UNCHANGED, "Changed": UPDATE, "Gone": DELETE, "New": CREATE}
    changed = next(c for c in plan.changes if c.name == "Changed")
    assert changed.diff == {"destination_ports": (("80",), ("8443",))}
    assert plan.has_changes
    assert {r.name for r in plan.final_rules()} == {"Same", "Changed", "New"}
    assert plan.summary() == {CREATE: 1, UPDATE: 1, DELETE: 1, UNCHANGED: 1, UNMANAGED: 0}


def test_plan_keep_unmanaged_does_not_delete():
    plan = build_plan(_config(make_rule("A")), [make_rule("A"), make_rule("Manual", priority=500)],
                      keep_unmanaged=True)
    assert [c.action for c in plan.changes if c.name == "Manual"] == [UNMANAGED]
    assert not plan.has_changes
    assert {r.name for r in plan.final_rules()} == {"A", "Manual"}


def test_plan_matches_names_case_insensitively():
    plan = build_plan(_config(make_rule("allow-https")), [make_rule("Allow-HTTPS")])
    assert [c.action for c in plan.changes] == [UNCHANGED]


def test_plan_for_missing_nsg():
    plan = build_plan(_config(make_rule("A")), [], nsg_exists=False, location="westeurope")
    assert plan.has_changes and plan.location == "westeurope"
    assert plan.of(CREATE)[0].name == "A"
