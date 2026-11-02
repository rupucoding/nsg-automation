"""NSG operations: prepare (read-only preview) and execute (write to Azure).

Every write follows the same two-step flow so dry-run is *exactly* the same
code path as a real run, minus the final API call:

    preview = manager.prepare_add(...)      # reads Azure, validates, analyses
    ...show preview, ask for confirmation...
    manager.execute(preview)                # performs the API call(s) + audit log

``prepare_*`` never modifies Azure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from nsg_automation.models.config import NsgConfig
from nsg_automation.models.rule import DENY, NsgRule
from nsg_automation.nsg.planner import CREATE, DELETE, UPDATE, Plan, build_plan
from nsg_automation.utils.audit import AuditLogger
from nsg_automation.utils.errors import NsgNotFoundError, NsgToolError, RuleNotFoundError
from nsg_automation.validation.analyzer import analyze_rules, check_change
from nsg_automation.validation.issues import Issue, Severity, dangerous, errors, sort_issues
from nsg_automation.validation.validators import build_rule

ADD_RULE, UPDATE_RULE, DELETE_RULE = "add_rule", "update_rule", "delete_rule"
CREATE_NSG, APPLY, IMPORT = "create_nsg", "apply", "import"


@dataclass(frozen=True)
class ApiCall:
    """Description of an Azure API call that would be / was made."""

    sdk_method: str
    http_method: str
    resource_id: str
    body: dict[str, Any] | None = None


@dataclass
class ChangePreview:
    action: str
    resource_group: str
    nsg: str
    current: NsgRule | None = None
    proposed: NsgRule | None = None
    diff: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    issues: list[Issue] = field(default_factory=list)
    api_calls: list[ApiCall] = field(default_factory=list)
    existing_rules: list[NsgRule] = field(default_factory=list)
    plan: Plan | None = None
    location: str | None = None
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return bool(errors(self.issues))

    @property
    def is_noop(self) -> bool:
        if self.plan is not None:
            return not self.plan.has_changes
        return self.action == UPDATE_RULE and not self.diff

    @property
    def confirmation_issues(self) -> list[Issue]:
        """Dangerous findings that require explicit confirmation.

        For apply/import only rules that are actually being created or changed
        count; an existing risky rule that is left untouched should not force a
        prompt on every run (it is still displayed).
        """
        found = dangerous(self.issues)
        if self.plan is not None:
            changed = self.plan.changed_names
            found = [i for i in found if i.rule and i.rule.lower() in changed]
        return found

    @property
    def is_destructive(self) -> bool:
        if self.action == DELETE_RULE:
            return True
        return bool(self.plan and self.plan.of(DELETE))

    @property
    def rule_name(self) -> str | None:
        rule = self.proposed or self.current
        return rule.name if rule else None


class NsgManager:
    def __init__(self, client: Any, audit: AuditLogger) -> None:
        self.client = client
        self.audit = audit

    @property
    def subscription_id(self) -> str:
        return self.client.subscription_id

    # ------------------------------------------------------------ reads
    def list_rules(self, resource_group: str, nsg: str, include_defaults: bool = False) -> list[NsgRule]:
        rules = self.client.list_rules(resource_group, nsg)
        if include_defaults:
            rules += self.client.list_default_rules(resource_group, nsg)
        return sorted(rules, key=lambda r: (r.direction, r.priority))

    # ---------------------------------------------------------- prepare
    def prepare_create_nsg(self, resource_group: str, nsg: str, location: str | None,
                           tags: dict[str, str] | None = None) -> ChangePreview:
        preview = ChangePreview(CREATE_NSG, resource_group, nsg, tags=dict(tags or {}))
        if self.client.nsg_exists(resource_group, nsg):
            preview.issues.append(Issue(Severity.ERROR, "NSG_EXISTS",
                                        f"NSG {nsg!r} already exists in {resource_group!r}"))
            return preview
        preview.location = location or self.client.resource_group_location(resource_group)
        from azure.mgmt.network.models import NetworkSecurityGroup
        body = NetworkSecurityGroup(location=preview.location, tags=preview.tags or None).as_dict()
        preview.api_calls.append(ApiCall("NetworkSecurityGroups.begin_create_or_update", "PUT",
                                         self.client.rule_resource_id(resource_group, nsg), body))
        return preview

    def prepare_add(self, resource_group: str, nsg: str, rule: NsgRule,
                    warnings: Iterable[Issue] = ()) -> ChangePreview:
        existing = self.client.list_rules(resource_group, nsg)
        preview = ChangePreview(ADD_RULE, resource_group, nsg, proposed=rule,
                                existing_rules=existing, issues=list(warnings))
        clash = next((r for r in existing if r.key == rule.key), None)
        if clash:
            preview.current = clash
            preview.issues.append(Issue(
                Severity.ERROR, "RULE_EXISTS", f"rule {clash.name!r} already exists in {nsg!r}",
                rule.name, hint="Use 'nsg-tool update' to modify it"))
        preview.issues.extend(check_change(rule, existing))
        preview.issues = sort_issues(preview.issues)
        preview.api_calls.append(self._rule_put(resource_group, nsg, rule))
        return preview

    def prepare_update(self, resource_group: str, nsg: str, name: str,
                       changes: dict[str, Any]) -> ChangePreview:
        """``changes`` uses JSON field names (e.g. {"priority": 120, "destinationPort": "443,8443"})."""
        existing = self.client.list_rules(resource_group, nsg)
        current = self._find(existing, name, nsg)
        if "name" in changes and str(changes["name"]).lower() != current.key:
            raise NsgToolError("Renaming a rule is not supported by Azure",
                               hint="Add a new rule with the new name and delete the old one")
        merged = current.to_dict()
        merged.update({k: v for k, v in changes.items() if v is not None})
        # Switching between address prefixes and ASGs: drop the other form.
        if "sourceAsgs" in changes:
            merged.pop("source", None)
        if "source" in changes:
            merged.pop("sourceAsgs", None)
        if "destinationAsgs" in changes:
            merged.pop("destination", None)
        if "destination" in changes:
            merged.pop("destinationAsgs", None)
        merged["name"] = current.name
        proposed, warnings = build_rule(merged)

        preview = ChangePreview(UPDATE_RULE, resource_group, nsg, current=current, proposed=proposed,
                                diff=current.diff(proposed), existing_rules=existing,
                                issues=list(warnings))
        preview.issues.extend(check_change(proposed, existing, replacing=current.name))
        preview.issues = sort_issues(preview.issues)
        preview.api_calls.append(self._rule_put(resource_group, nsg, proposed))
        return preview

    def prepare_delete(self, resource_group: str, nsg: str, name: str) -> ChangePreview:
        existing = self.client.list_rules(resource_group, nsg)
        current = self._find(existing, name, nsg)
        preview = ChangePreview(DELETE_RULE, resource_group, nsg, current=current,
                                existing_rules=existing)
        if current.access == DENY:
            preview.issues.append(Issue(
                Severity.WARNING, "REMOVING_DENY",
                f"removing Deny rule {current.name!r} may expose traffic it currently blocks "
                "(lower-precedence Allow rules will start matching)", current.name))
        preview.api_calls.append(ApiCall(
            "SecurityRules.begin_delete", "DELETE",
            self.client.rule_resource_id(resource_group, nsg, current.name)))
        return preview

    def prepare_apply(self, config: NsgConfig, *, keep_unmanaged: bool = False,
                      warnings: Iterable[Issue] = (), action: str = APPLY) -> ChangePreview:
        rg, nsg = config.resource_group, config.nsg
        try:
            current = self.client.list_rules(rg, nsg)
            exists = True
        except NsgNotFoundError:
            current, exists = [], False

        location = config.location
        if not exists and not location:
            location = self.client.resource_group_location(rg)

        plan = build_plan(config, current, nsg_exists=exists, keep_unmanaged=keep_unmanaged,
                          location=location)
        preview = ChangePreview(action, rg, nsg, existing_rules=current, plan=plan,
                                location=location, tags=dict(config.tags),
                                issues=list(warnings))
        preview.issues.extend(analyze_rules(plan.final_rules()))
        preview.issues = sort_issues(preview.issues)

        from azure.mgmt.network.models import NetworkSecurityGroup
        body = NetworkSecurityGroup(
            location=location, tags=(config.tags or None) if not exists else None,
            security_rules=[r.to_azure() for r in plan.final_rules()]).as_dict()
        if exists:
            body.pop("location", None)  # existing properties are re-sent unchanged
        preview.api_calls.append(ApiCall(
            "NetworkSecurityGroups.begin_create_or_update", "PUT",
            self.client.rule_resource_id(rg, nsg), body))
        return preview

    # ---------------------------------------------------------- execute
    def execute(self, preview: ChangePreview) -> Any:
        """Perform the change described by ``preview`` and audit it."""
        if preview.blocked:
            raise NsgToolError("Refusing to execute a change that has validation errors")
        operation = preview.api_calls[0].sdk_method if preview.api_calls else None
        try:
            result = self._dispatch(preview)
        except NsgToolError as exc:
            self._audit(preview, "failure", operation, error=exc.message)
            raise
        except Exception as exc:  # unexpected: still audit, then re-raise
            self._audit(preview, "failure", operation, error=f"{type(exc).__name__}: {exc}")
            raise
        self._audit(preview, "success", operation)
        return result

    def record_dry_run(self, preview: ChangePreview) -> None:
        operation = preview.api_calls[0].sdk_method if preview.api_calls else None
        self._audit(preview, "blocked" if preview.blocked else "dry-run", operation, dry_run=True)

    def record_aborted(self, preview: ChangePreview, reason: str) -> None:
        operation = preview.api_calls[0].sdk_method if preview.api_calls else None
        self._audit(preview, "aborted", operation, error=reason)

    def _dispatch(self, preview: ChangePreview) -> Any:
        c, rg, nsg = self.client, preview.resource_group, preview.nsg
        if preview.action == CREATE_NSG:
            return c.create_nsg(rg, nsg, preview.location, preview.tags)
        if preview.action in (ADD_RULE, UPDATE_RULE):
            return c.create_or_update_rule(rg, nsg, preview.proposed)
        if preview.action == DELETE_RULE:
            return c.delete_rule(rg, nsg, preview.current.name)
        if preview.action in (APPLY, IMPORT):
            plan = preview.plan
            if not plan.has_changes:
                return plan.final_rules()
            if not plan.nsg_exists:
                c.create_nsg(rg, nsg, plan.location, preview.tags, rules=plan.final_rules())
                return plan.final_rules()
            return c.replace_rules(rg, nsg, plan.final_rules())
        raise NsgToolError(f"Unknown action {preview.action!r}")

    # ---------------------------------------------------------- helpers
    def _audit(self, preview: ChangePreview, result: str, operation: str | None,
               error: str | None = None, dry_run: bool = False) -> None:
        details: dict[str, Any] = {}
        if preview.plan is not None:
            details["summary"] = preview.plan.summary()
            details["changes"] = [
                {"action": ch.action, "rule": ch.name,
                 "diff": {k: [_plain(v[0]), _plain(v[1])] for k, v in ch.diff.items()}}
                for ch in preview.plan.changes if ch.action in (CREATE, UPDATE, DELETE)]
            if not preview.plan.nsg_exists:
                details["nsg_created"] = True
        if preview.diff:
            details["diff"] = {k: [_plain(v[0]), _plain(v[1])] for k, v in preview.diff.items()}
        if preview.proposed and preview.action == ADD_RULE:
            details["rule"] = preview.proposed.to_dict()
        if preview.current and preview.action == DELETE_RULE:
            details["deleted_rule"] = preview.current.to_dict()
        if preview.location and preview.action == CREATE_NSG:
            details["location"] = preview.location
        flagged = [i.code for i in preview.issues if i.severity is not Severity.INFO]
        if flagged:
            details["findings"] = flagged
        self.audit.record(
            action=preview.action, result=result, subscription=self.subscription_id,
            resource_group=preview.resource_group, nsg=preview.nsg, rule=preview.rule_name,
            operation=operation, dry_run=dry_run, error=error, details=details)

    def _rule_put(self, rg: str, nsg: str, rule: NsgRule) -> ApiCall:
        return ApiCall("SecurityRules.begin_create_or_update", "PUT",
                       self.client.rule_resource_id(rg, nsg, rule.name), rule.to_azure().as_dict())

    @staticmethod
    def _find(rules: list[NsgRule], name: str, nsg: str) -> NsgRule:
        match = next((r for r in rules if r.key == name.lower()), None)
        if match is None:
            raise RuleNotFoundError(f"Rule {name!r} was not found in NSG {nsg!r}.",
                                    hint="List rules with: nsg-tool list -g <rg> --nsg <nsg>")
        return match


def _plain(value: Any) -> Any:
    return list(value) if isinstance(value, tuple) else value
