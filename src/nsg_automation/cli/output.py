"""Terminal rendering (rich) for rules, issues, previews and plans."""

from __future__ import annotations

import json
from typing import Any, Iterable

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from nsg_automation.models.rule import ALLOW, NsgRule
from nsg_automation.nsg.manager import ADD_RULE, CREATE_NSG, DELETE_RULE, UPDATE_RULE, ChangePreview
from nsg_automation.nsg.planner import CREATE, DELETE, UNCHANGED, UNMANAGED, UPDATE, Plan
from nsg_automation.validation.issues import DANGEROUS, Issue, Severity, sort_issues

SEVERITY_STYLE = {
    Severity.ERROR: "bold red", Severity.CRITICAL: "bold white on red", Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow", Severity.WARNING: "yellow", Severity.INFO: "cyan",
}
ACTION_STYLE = {CREATE: "green", UPDATE: "yellow", DELETE: "red", UNCHANGED: "dim", UNMANAGED: "dim cyan"}
FIELD_LABELS = {
    "direction": "Direction", "access": "Access", "protocol": "Protocol", "priority": "Priority",
    "source": "Source", "source_ports": "Source ports", "destination": "Destination",
    "destination_ports": "Destination ports", "description": "Description",
    "source_asgs": "Source ASGs", "destination_asgs": "Destination ASGs",
}


def make_console() -> Console:
    # Rich assumes 80 columns when output is not a terminal (pipes, CI logs);
    # rule tables need more room to stay readable.
    console = Console(highlight=False, soft_wrap=False)
    if not console.is_terminal:
        console.width = max(console.width, 160)
    return console


def fmt(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "-"
    if value in (None, ""):
        return "-"
    return str(value)


def _source(rule: NsgRule) -> str:
    return fmt(rule.source) if rule.source else "ASG: " + fmt([a.rsplit("/", 1)[-1] for a in rule.source_asgs])


def _destination(rule: NsgRule) -> str:
    return (fmt(rule.destination) if rule.destination
            else "ASG: " + fmt([a.rsplit("/", 1)[-1] for a in rule.destination_asgs]))


# ------------------------------------------------------------------ rules
def rules_table(rules: Iterable[NsgRule], title: str | None = None) -> Table:
    table = Table(title=title, show_lines=False, header_style="bold")
    for col in ("Priority", "Name", "Dir", "Access", "Proto", "Source", "Src Port",
                "Destination", "Dst Port", "Description"):
        table.add_column(col, overflow="fold")
    for r in rules:
        access = Text(r.access, style="green" if r.access == ALLOW else "red")
        table.add_row(str(r.priority), r.name, r.direction[:3] if r.direction == "Inbound" else "Out",
                      access, r.protocol, _source(r), fmt(r.source_ports), _destination(r),
                      fmt(r.destination_ports), r.description or "")
    return table


def rule_detail(rule: NsgRule, title: str | None = None) -> Table:
    table = Table(title=title, show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Name", rule.name)
    for field, label in FIELD_LABELS.items():
        value = getattr(rule, field)
        if field.endswith("asgs") and not value:
            continue
        table.add_row(label, fmt(value))
    return table


# ----------------------------------------------------------------- issues
def render_issues(console: Console, issues: Iterable[Issue]) -> None:
    issues = sort_issues(issues)
    if not issues:
        return
    danger = [i for i in issues if i.severity in DANGEROUS]
    others = [i for i in issues if i.severity not in DANGEROUS]
    if danger:
        lines = []
        for i in danger:
            lines.append(Text.assemble((f"[{i.severity.value.upper()}] ", "bold"),
                                       (f"{i.rule}: " if i.rule else "", "bold"), i.message))
            if i.hint:
                lines.append(Text(f"    -> {i.hint}", style="italic"))
        console.print(Panel(Group(*lines), title="!!  SECURITY WARNING  !!", border_style="bold red",
                            style="red", padding=(1, 2)))
    for i in others:
        line = Text.assemble((f"  {i.severity.value.upper():<8}", SEVERITY_STYLE[i.severity]),
                             (f"{i.rule}: " if i.rule else "", "bold"), i.message)
        console.print(line)
        if i.hint:
            console.print(Text(f"            hint: {i.hint}", style="dim"))


# ---------------------------------------------------------------- preview
def render_preview(console: Console, preview: ChangePreview, subscription: str,
                   dry_run: bool = False) -> None:
    title = {ADD_RULE: "Add rule", UPDATE_RULE: "Update rule", DELETE_RULE: "Delete rule",
             CREATE_NSG: "Create NSG"}.get(preview.action, preview.action)
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold")
    header.add_column()
    header.add_row("Operation", title + ("   [DRY RUN]" if dry_run else ""))
    header.add_row("Subscription", subscription)
    header.add_row("Resource group", preview.resource_group)
    header.add_row("NSG", preview.nsg)
    if preview.location:
        header.add_row("Location", preview.location)
    console.print(Panel(header, title="NSG change", border_style="cyan"))

    # Existing configuration
    console.rule("[bold]Existing configuration")
    if preview.action == CREATE_NSG:
        console.print("  NSG does not exist yet." if not preview.blocked else "  NSG already exists.")
    elif preview.current is not None:
        console.print(rule_detail(preview.current))
    elif preview.proposed is not None:
        same_dir = [r for r in preview.existing_rules if r.direction == preview.proposed.direction]
        if same_dir:
            console.print(rules_table(same_dir, title=f"Current {preview.proposed.direction.lower()} rules"))
        else:
            console.print(f"  No custom {preview.proposed.direction.lower()} rules exist in this NSG.")

    # Proposed change
    console.rule("[bold]Proposed change")
    if preview.action == ADD_RULE and preview.proposed:
        console.print(rule_detail(preview.proposed, title="[green]+ new rule"))
    elif preview.action == UPDATE_RULE:
        if not preview.diff:
            console.print("  [dim]No differences - the rule already has these values.[/dim]")
        else:
            console.print(diff_table(preview.diff))
    elif preview.action == DELETE_RULE and preview.current:
        console.print(f"  [red]- rule {preview.current.name!r} will be permanently deleted[/red]")
    elif preview.action == CREATE_NSG:
        console.print(f"  [green]+ NSG {preview.nsg!r} in {preview.location}[/green]"
                      + (f" with tags {preview.tags}" if preview.tags else ""))

    if preview.issues:
        console.rule("[bold]Validation & security analysis")
        render_issues(console, preview.issues)
    render_api_calls(console, preview)


def diff_table(diff: dict[str, tuple[Any, Any]]) -> Table:
    table = Table(header_style="bold")
    table.add_column("Property")
    table.add_column("Current", style="red")
    table.add_column("Proposed", style="green")
    for field, (old, new) in diff.items():
        table.add_row(FIELD_LABELS.get(field, field), fmt(old), fmt(new))
    return table


def render_api_calls(console: Console, preview: ChangePreview) -> None:
    if not preview.api_calls:
        return
    console.rule("[bold]Azure API operation")
    for call in preview.api_calls:
        console.print(f"  SDK    : [bold]{call.sdk_method}[/bold]")
        console.print(f"  HTTP   : {call.http_method} https://management.azure.com{call.resource_id}")
        if call.body is not None:
            console.print("  Body   :")
            console.print(Syntax(json.dumps(call.body, indent=2), "json", theme="ansi_dark",
                                 background_color="default"))


# ------------------------------------------------------------------- plan
def render_plan(console: Console, plan: Plan, show_unchanged: bool = True) -> None:
    console.rule(f"[bold]Plan for {plan.resource_group}/{plan.nsg}")
    if not plan.nsg_exists:
        console.print(f"[green]+ NSG {plan.nsg!r} will be created in {plan.location}[/green]")
    for ch in plan.changes:
        if ch.action in (UNCHANGED, UNMANAGED) and not show_unchanged:
            continue
        rule = ch.desired or ch.current
        style = ACTION_STYLE[ch.action]
        label = {UNMANAGED: "unmanaged (kept)"}.get(ch.action, ch.action)
        console.print(Text.assemble(
            (f"  {ch.symbol} ", f"bold {style}"),
            (f"{ch.name:<32}", style),
            (f" {rule.direction:<8} {rule.priority:>4}  {rule.access:<5} ", style),
            (f"{label}", style)))
        if ch.action == UPDATE:
            for field, (old, new) in ch.diff.items():
                console.print(Text(f"        {FIELD_LABELS.get(field, field)}: {fmt(old)}  ->  {fmt(new)}",
                                   style="yellow"))
    s = plan.summary()
    console.print()
    console.print(
        f"[bold]Plan:[/bold] [green]{s[CREATE]} to create[/green], [yellow]{s[UPDATE]} to update[/yellow], "
        f"[red]{s[DELETE]} to delete[/red], {s[UNCHANGED]} unchanged"
        + (f", {s[UNMANAGED]} unmanaged kept" if plan.keep_unmanaged else "") + ".")
    if not plan.has_changes:
        console.print("[green]No changes. Azure already matches the configuration.[/green]")


def plan_to_dict(plan: Plan) -> dict[str, Any]:
    return {
        "resourceGroup": plan.resource_group, "nsg": plan.nsg, "nsgExists": plan.nsg_exists,
        "summary": plan.summary(),
        "changes": [{
            "action": c.action, "rule": c.name,
            "current": c.current.to_dict() if c.current else None,
            "desired": c.desired.to_dict() if c.desired else None,
            "diff": {k: {"current": _plain(v[0]), "desired": _plain(v[1])} for k, v in c.diff.items()},
        } for c in plan.changes],
    }


def _plain(value: Any) -> Any:
    return list(value) if isinstance(value, tuple) else value
