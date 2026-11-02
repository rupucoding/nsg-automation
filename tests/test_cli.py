"""End-to-end CLI tests against the in-memory fake Azure client."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nsg_automation.cli.app import AppContext, cli
from nsg_automation.cli.output import make_console
from nsg_automation.nsg.manager import NsgManager
from nsg_automation.utils.audit import AuditLogger
from nsg_automation.utils.settings import Settings

from conftest import SUB, read_audit

EXAMPLE = str(Path(__file__).resolve().parent.parent / "config" / "example-nsg.json")
BASE = ["-g", "rg", "--nsg", "nsg"]
ADD_8443 = ["add", *BASE, "--name", "Allow-8443", "--direction", "inbound", "--access", "allow",
            "--protocol", "tcp", "--source", "10.0.0.0/8", "--destination-port", "8443",
            "--priority", "300"]


@pytest.fixture
def run(fake_client, audit_path, tmp_path):
    settings = Settings(subscription_id=SUB, log_dir=tmp_path, log_level="INFO", audit_log_file=audit_path)

    def _run(*args, input=None):
        app = AppContext(settings=settings, console=make_console(), subscription_flag=SUB,
                         manager_factory=lambda sub: NsgManager(fake_client, AuditLogger(audit_path)))
        return CliRunner().invoke(cli, list(args), obj=app, input=input)
    return _run


def test_list_json(run):
    result = run("list", *BASE, "-o", "json")
    assert result.exit_code == 0
    assert [r["name"] for r in json.loads(result.output)][:2] == ["Allow-HTTPS", "Allow-SSH-Admin"]


def test_search_by_port_and_source(run):
    result = run("search", *BASE, "--port", "22", "--source", "203.0.113.5", "-o", "json")
    assert result.exit_code == 0
    assert [r["name"] for r in json.loads(result.output)] == ["Allow-SSH-Admin"]


def test_add_dry_run_changes_nothing(run, fake_client, audit_path):
    result = run(*ADD_8443, "--dry-run")
    assert result.exit_code == 0, result.output
    for text in ("Existing configuration", "Proposed change", "Azure API operation",
                 "SecurityRules.begin_create_or_update", "DRY RUN"):
        assert text in result.output
    assert fake_client.writes == []
    assert read_audit(audit_path)[-1]["dry_run"] is True


def test_add_executes(run, fake_client):
    result = run(*ADD_8443)
    assert result.exit_code == 0, result.output
    assert "Success" in result.output
    assert fake_client.writes[0][3].name == "Allow-8443"


def test_invalid_input_gives_friendly_error(run, fake_client):
    result = run("add", *BASE, "--name", "Bad", "--direction", "inbound", "--access", "allow",
                 "--protocol", "tcp", "--source", "10.0.0.300/24", "--destination-port", "70000",
                 "--priority", "50")
    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert "not valid CIDR" in result.output and "outside" in result.output and "priority 50" in result.output
    assert fake_client.writes == []


def test_dangerous_rule_aborts_without_confirmation(run, fake_client, audit_path):
    args = ["add", *BASE, "--name", "Open", "--direction", "inbound", "--access", "allow",
            "--protocol", "*", "--source", "0.0.0.0/0", "--destination-port", "*", "--priority", "300"]
    result = run(*args)                      # CliRunner stdin is not a TTY
    assert result.exit_code == 3
    assert "SECURITY WARNING" in result.output and "--force" in result.output
    assert fake_client.writes == []
    assert read_audit(audit_path)[-1]["result"] == "aborted"

    result = run(*args, "--force")
    assert result.exit_code == 0, result.output
    assert len(fake_client.writes) == 1


def test_delete_requires_force_when_not_interactive(run, fake_client):
    result = run("delete", *BASE, "--name", "Allow-SSH-Admin")
    assert result.exit_code == 3 and fake_client.writes == []
    result = run("delete", *BASE, "--name", "Allow-SSH-Admin", "--force")
    assert result.exit_code == 0 and fake_client.writes[0][0] == "delete_rule"


def test_update_rule(run, fake_client):
    result = run("update", *BASE, "--name", "Allow-HTTPS", "--destination-port", "443,8443")
    assert result.exit_code == 0, result.output
    assert fake_client.writes[0][3].destination_ports == ("443", "8443")


def test_update_without_changes_is_usage_error(run):
    assert run("update", *BASE, "--name", "Allow-HTTPS").exit_code == 2


def test_rule_not_found(run):
    result = run("delete", *BASE, "--name", "Nope", "--force")
    assert result.exit_code == 4 and "was not found" in result.output


def test_validate_example(run):
    result = run("validate", EXAMPLE)
    assert result.exit_code == 0 and "Valid" in result.output


def test_plan_and_apply_workflow(run, fake_client, tmp_path):
    config = {"resourceGroup": "rg", "nsg": "nsg", "rules": [
        {"name": "Allow-HTTPS", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
         "destinationPort": "443,8443", "priority": 100},
        {"name": "Allow-HTTP", "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
         "source": "10.0.0.0/8", "destinationPort": "80", "priority": 110}]}
    path = tmp_path / "desired.json"
    path.write_text(json.dumps(config), encoding="utf-8")

    plan = run("plan", str(path), "-o", "json")
    assert plan.exit_code == 0
    assert json.loads(plan.output)["summary"] == {
        "create": 1, "update": 1, "delete": 2, "unchanged": 0, "unmanaged": 0}
    assert fake_client.writes == []

    text_plan = run("plan", str(path))
    assert "+ Allow-HTTP" in text_plan.output and "~ Allow-HTTPS" in text_plan.output
    assert "- Allow-SSH-Admin" in text_plan.output

    assert run("apply", str(path), "--dry-run").exit_code == 0 and fake_client.writes == []
    assert run("apply", str(path)).exit_code == 3 and fake_client.writes == []   # needs confirmation
    result = run("apply", str(path), "--force")
    assert result.exit_code == 0, result.output
    assert {r.name for r in fake_client.nsgs[("rg", "nsg")]} == {"Allow-HTTPS", "Allow-HTTP"}


def test_export_and_import(run, fake_client, tmp_path):
    out = tmp_path / "export.json"
    assert run("export", *BASE, "-f", str(out)).exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert len(data["rules"]) == 3 and data["location"] == "eastus"

    data["rules"].append({"name": "Allow-HTTP", "direction": "Inbound", "access": "Allow",
                          "protocol": "Tcp", "source": "10.0.0.0/8", "destinationPort": "80",
                          "priority": 110})
    data["rules"] = [r for r in data["rules"] if r["name"] != "Allow-DNS-Out"]
    out.write_text(json.dumps(data), encoding="utf-8")
    result = run("import", str(out), "--force")
    assert result.exit_code == 0, result.output
    # import never deletes: Allow-DNS-Out (missing from the file) is kept
    assert len(fake_client.nsgs[("rg", "nsg")]) == 4
