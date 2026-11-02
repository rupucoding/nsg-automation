"""Interactive (prompt-driven) mode: ``nsg-tool interactive``."""

from __future__ import annotations

from typing import Any, Callable

import click

from nsg_automation.cli import output
from nsg_automation.nsg.serializer import dump_json, export_config
from nsg_automation.utils.errors import NsgToolError, ValidationError
from nsg_automation.validation.validators import build_rule

MENU = """
[bold]What would you like to do?[/bold]
  1) List rules          4) Delete a rule
  2) Add a rule          5) Export rules to JSON
  3) Update a rule       6) Switch NSG
  q) Quit
"""


def run_interactive(app: Any, run_change: Callable) -> None:
    console = app.console
    mgr = app.manager()
    console.print(f"[bold cyan]NSG tool - interactive mode[/bold cyan] (subscription {mgr.subscription_id})")
    rg, nsg = _ask_target()

    while True:
        console.print(MENU)
        choice = click.prompt("Choice", type=click.Choice(["1", "2", "3", "4", "5", "6", "q"]),
                              show_choices=False)
        try:
            if choice == "q":
                return
            if choice == "6":
                rg, nsg = _ask_target()
            elif choice == "1":
                rules = mgr.list_rules(rg, nsg)
                console.print(output.rules_table(rules, title=f"{rg}/{nsg}") if rules else "No rules.")
            elif choice == "2":
                rule, warnings = build_rule(_ask_rule())
                dry = click.confirm("Dry run only?", default=True)
                run_change(app, mgr, mgr.prepare_add(rg, nsg, rule, warnings), dry, False)
            elif choice == "3":
                name = click.prompt("Rule name to update")
                current = next((r for r in mgr.list_rules(rg, nsg) if r.key == name.lower()), None)
                if current is None:
                    console.print(f"[red]Rule {name!r} not found.[/red]")
                    continue
                console.print(output.rule_detail(current, title="Current values"))
                changes = _ask_rule(current.to_dict(), include_name=False)
                dry = click.confirm("Dry run only?", default=True)
                run_change(app, mgr, mgr.prepare_update(rg, nsg, name, changes), dry, False)
            elif choice == "4":
                name = click.prompt("Rule name to delete")
                dry = click.confirm("Dry run only?", default=True)
                run_change(app, mgr, mgr.prepare_delete(rg, nsg, name), dry, False)
            elif choice == "5":
                path = click.prompt("Output file", default=f"{nsg}-export.json")
                dump_json(export_config(rg, nsg, mgr.list_rules(rg, nsg)), path)
                console.print(f"[green]Exported to {path}[/green]")
        except ValidationError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc.message}")
            output.render_issues(console, exc.issues)
        except NsgToolError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc.message}")
            if exc.hint:
                console.print(f"[yellow]Hint:[/yellow] {exc.hint}")
        except click.Abort:
            console.print("\nCancelled.")


def _ask_target() -> tuple[str, str]:
    return click.prompt("Resource group"), click.prompt("NSG name")


def _ask_rule(defaults: dict[str, Any] | None = None, include_name: bool = True) -> dict[str, Any]:
    d = defaults or {}

    def ask(label: str, key: str, default: Any, **kw: Any) -> Any:
        value = d.get(key, default)
        if isinstance(value, list):
            value = ",".join(str(v) for v in value)
        return click.prompt(label, default=value, **kw)

    raw: dict[str, Any] = {}
    if include_name:
        raw["name"] = click.prompt("Rule name")
    raw["direction"] = ask("Direction (Inbound/Outbound)", "direction", "Inbound")
    raw["access"] = ask("Access (Allow/Deny)", "access", "Allow")
    raw["protocol"] = ask("Protocol (Tcp/Udp/Icmp/*)", "protocol", "Tcp")
    raw["priority"] = ask("Priority (100-4096)", "priority", None, type=int)
    raw["source"] = ask("Source (CIDR, IP, service tag or *)", "source", "*")
    raw["sourcePort"] = ask("Source port(s)", "sourcePort", "*")
    raw["destination"] = ask("Destination (CIDR, IP, service tag or *)", "destination", "*")
    raw["destinationPort"] = ask("Destination port(s) (e.g. 443 or 80,443 or 8000-8080)",
                                 "destinationPort", None)
    raw["description"] = ask("Description", "description", "", show_default=False)
    return raw
