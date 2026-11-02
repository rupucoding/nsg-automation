import json
import logging

from nsg_automation.utils.audit import AuditLogger
from nsg_automation.utils.logging_setup import REDACTED, JsonFormatter, redact


def test_redacts_sensitive_keys_and_values():
    data = {"client_secret": "abc", "nested": {"accessToken": "x", "ok": "fine"},
            "msg": "Authorization: Bearer abc.def.ghi", "list": ["password=hunter2"]}
    out = redact(data)
    assert out["client_secret"] == REDACTED and out["nested"]["accessToken"] == REDACTED
    assert out["nested"]["ok"] == "fine"
    assert "abc.def" not in out["msg"] and "hunter2" not in out["list"][0]


def test_jwt_in_message_is_redacted():
    jwt = "eyJhbGciOi.eyJzdWIiOiIx.c2lnbmF0dXJl"
    record = logging.LogRecord("t", logging.INFO, __file__, 1, f"token {jwt}", None, None)
    assert jwt not in JsonFormatter().format(record)


def test_audit_entry_fields(tmp_path):
    audit = AuditLogger(tmp_path / "a.log", user_resolver=lambda: "alice@contoso.com")
    audit.record(action="add_rule", result="success", subscription="sub", resource_group="rg",
                 nsg="nsg", rule="r", operation="op", details={"secret": "s"})
    entry = json.loads((tmp_path / "a.log").read_text(encoding="utf-8"))
    for key in ("timestamp", "user", "action", "subscription", "resource_group", "nsg", "rule",
                "operation", "result", "error", "dry_run"):
        assert key in entry
    assert entry["user"] == "alice@contoso.com" and entry["details"]["secret"] == REDACTED


def test_audit_user_falls_back_when_identity_lookup_fails(tmp_path):
    def boom():
        raise RuntimeError("no token")
    audit = AuditLogger(tmp_path / "a.log", user_resolver=boom)
    assert audit.user.startswith("local:")
