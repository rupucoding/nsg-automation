import pytest

from nsg_automation.models.config import NsgConfig
from nsg_automation.nsg.manager import NsgManager
from nsg_automation.utils.audit import AuditLogger
from nsg_automation.utils.errors import NsgToolError, RuleNotFoundError, ValidationError

from conftest import FakeNsgClient, make_rule, read_audit


# ---------------------------------------------------------- dry run / add
def test_prepare_add_is_read_only(manager, fake_client):
    rule = make_rule("Allow-8443", priority=300, destination_ports=("8443",), source=("10.0.0.0/8",))
    preview = manager.prepare_add("rg", "nsg", rule)
    assert fake_client.writes == []
    assert not preview.blocked
    call = preview.api_calls[0]
    assert call.sdk_method == "SecurityRules.begin_create_or_update" and call.http_method == "PUT"
    assert call.resource_id.endswith("/networkSecurityGroups/nsg/securityRules/Allow-8443")
    assert call.body["properties"]["destinationPortRange"] == "8443"
    assert [r.name for r in preview.existing_rules] == ["Allow-HTTPS", "Allow-SSH-Admin", "Allow-DNS-Out"]


def test_dry_run_is_audited_without_changes(manager, fake_client, audit_path):
    preview = manager.prepare_add("rg", "nsg", make_rule("New", priority=300, destination_ports=("8443",)))
    manager.record_dry_run(preview)
    assert fake_client.writes == []
    entry = read_audit(audit_path)[-1]
    assert entry["dry_run"] is True and entry["result"] == "dry-run"
    assert entry["user"] == "tester@contoso.com" and entry["rule"] == "New"


def test_execute_add_writes_and_audits(manager, fake_client, audit_path):
    rule = make_rule("New", priority=300, destination_ports=("8443",), source=("10.0.0.0/8",))
    manager.execute(manager.prepare_add("rg", "nsg", rule))
    assert fake_client.writes[0][0] == "create_or_update_rule"
    entry = read_audit(audit_path)[-1]
    assert entry["action"] == "add_rule" and entry["result"] == "success"
    assert entry["subscription"] and entry["resource_group"] == "rg" and entry["nsg"] == "nsg"
    assert entry["operation"] == "SecurityRules.begin_create_or_update"


def test_add_existing_name_is_blocked(manager):
    preview = manager.prepare_add("rg", "nsg", make_rule("allow-https", priority=300))
    assert preview.blocked
    assert "RULE_EXISTS" in {i.code for i in preview.issues}
    with pytest.raises(NsgToolError):
        manager.execute(preview)


def test_add_duplicate_priority_is_blocked(manager, fake_client):
    preview = manager.prepare_add("rg", "nsg", make_rule("Other", priority=200, destination_ports=("8080",)))
    assert preview.blocked and "PRIORITY_CONFLICT" in {i.code for i in preview.issues}
    assert fake_client.writes == []


def test_dangerous_rule_requires_confirmation(manager):
    preview = manager.prepare_add("rg", "nsg", make_rule("Open", priority=300, protocol="*",
                                                         destination_ports=("*",)))
    assert not preview.blocked
    assert [i.code for i in preview.confirmation_issues] == ["ANY_ANY_ALLOW"]


# --------------------------------------------------------------- update
def test_update_merges_only_given_fields(manager):
    preview = manager.prepare_update("rg", "nsg", "Allow-SSH-Admin", {"priority": 250})
    assert preview.proposed.source == ("203.0.113.0/28",)
    assert preview.diff == {"priority": (200, 250)}
    assert not preview.blocked


def test_update_with_same_values_is_noop(manager):
    preview = manager.prepare_update("rg", "nsg", "Allow-HTTPS", {"destinationPort": "443"})
    assert preview.is_noop


def test_update_invalid_value_raises(manager):
    with pytest.raises(ValidationError):
        manager.prepare_update("rg", "nsg", "Allow-HTTPS", {"source": "10.0.0.1/8"})


def test_update_switch_prefix_to_asg(manager):
    asg = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/applicationSecurityGroups/web"
    preview = manager.prepare_update("rg", "nsg", "Allow-HTTPS", {"destinationAsgs": [asg]})
    assert preview.proposed.destination == () and preview.proposed.destination_asgs == (asg,)


def test_update_missing_rule(manager):
    with pytest.raises(RuleNotFoundError):
        manager.prepare_update("rg", "nsg", "Nope", {"priority": 300})


# --------------------------------------------------------------- delete
def test_delete_is_destructive_and_executes(manager, fake_client, audit_path):
    preview = manager.prepare_delete("rg", "nsg", "allow-ssh-admin")
    assert preview.is_destructive and preview.api_calls[0].http_method == "DELETE"
    assert fake_client.writes == []
    manager.execute(preview)
    assert fake_client.writes == [("delete_rule", "rg", "nsg", "Allow-SSH-Admin")]
    assert read_audit(audit_path)[-1]["details"]["deleted_rule"]["name"] == "Allow-SSH-Admin"


def test_failed_execute_is_audited(manager, fake_client, audit_path):
    preview = manager.prepare_delete("rg", "nsg", "Allow-SSH-Admin")
    fake_client.nsgs[("rg", "nsg")] = []           # deleted by someone else meanwhile
    with pytest.raises(RuleNotFoundError):
        manager.execute(preview)
    entry = read_audit(audit_path)[-1]
    assert entry["result"] == "failure" and "not found" in entry["error"]


# ---------------------------------------------------------- apply/import
def _config(*rules, **kw):
    return NsgConfig(resource_group="rg", nsg="nsg", rules=tuple(rules), **kw)


def test_apply_replaces_rules_atomically(manager, fake_client):
    desired = _config(make_rule("Allow-HTTPS", priority=100),
                      make_rule("Allow-HTTP", priority=110, destination_ports=("80",)))
    preview = manager.prepare_apply(desired)
    assert preview.is_destructive                 # SSH + DNS rules would be deleted
    assert fake_client.writes == []
    manager.execute(preview)
    assert [w[0] for w in fake_client.writes] == ["replace_rules"]
    assert {r.name for r in fake_client.nsgs[("rg", "nsg")]} == {"Allow-HTTPS", "Allow-HTTP"}


def test_import_keeps_unmanaged_rules(manager, fake_client):
    preview = manager.prepare_apply(_config(make_rule("Allow-HTTP", priority=110, destination_ports=("80",))),
                                    keep_unmanaged=True, action="import")
    assert not preview.is_destructive
    manager.execute(preview)
    assert len(fake_client.nsgs[("rg", "nsg")]) == 4


def test_apply_creates_missing_nsg_in_resource_group_location(audit_path):
    client = FakeNsgClient({}, locations={"rg": "westeurope"})
    mgr = NsgManager(client, AuditLogger(audit_path))
    preview = mgr.prepare_apply(_config(make_rule("A")))
    assert not preview.plan.nsg_exists and preview.location == "westeurope"
    mgr.execute(preview)
    assert client.writes[0][0] == "create_nsg" and client.writes[0][3] == "westeurope"


def test_apply_no_changes_is_noop(manager, fake_client):
    preview = manager.prepare_apply(_config(*fake_client.nsgs[("rg", "nsg")]))
    assert preview.is_noop


def test_apply_confirmation_ignores_untouched_risky_rules(fake_client, audit_path):
    fake_client.nsgs[("rg", "nsg")].append(make_rule("Legacy-RDP", priority=900, destination_ports=("3389",)))
    mgr = NsgManager(fake_client, AuditLogger(audit_path))
    preview = mgr.prepare_apply(_config(make_rule("Allow-HTTP", priority=110, destination_ports=("80",))),
                                keep_unmanaged=True)
    assert "MANAGEMENT_PORT_EXPOSED" in {i.code for i in preview.issues}   # still displayed
    assert preview.confirmation_issues == []                               # but not re-confirmed


def test_apply_blocks_priority_collision_with_unmanaged_rule(manager):
    preview = manager.prepare_apply(_config(make_rule("New", priority=200, destination_ports=("8080",))),
                                    keep_unmanaged=True)
    assert preview.blocked
