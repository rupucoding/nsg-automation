"""``nsg-tool`` command-line interface."""

from __future__ import annotations

import json
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import click
from rich.console import Console

from nsg_automation import __version__
from nsg_automation.cli import output
from nsg_automation.cli.prompts import confirm_change
from nsg_automation.nsg.manager import IMPORT, ChangePreview, NsgManager
from nsg_automation.nsg.search import RuleFilter, filter_rules
from nsg_automation.nsg.serializer import dump_json, export_config, load_config
from nsg_automation.utils.errors import NsgToolError, ValidationError
from nsg_automation.utils.logging_setup import configure_logging, get_logger
from nsg_automation.utils.settings import Settings, resolve_subscription_id
from nsg_automation.validation.analyzer import analyze_rules
from nsg_automation.validation.issues import Severity, errors
from nsg_automation.validation.validators import FieldError, build_rule

_log = get_logger("cli")

DIRECTIONS = click.Choice(["inbound", "outbound"], case_sensitive=False)
ACCESSES = click.Choice(["allow", "deny"], case_sensitive=False)
PROTOCOLS = click.Choice(["tcp", "udp", "icmp", "esp", "ah", "*", "any"], case_sensitive=False)


# ------------------------------------------------------------- app context
@dataclass
class AppContext:
    settings: Settings
    console: Console
    subscription_flag: str | None = None
    debug: bool = False
    manager_factory: Callable[[str], NsgManager] | None = None
    _managers: dict[str, NsgManager] = field(default_factory=dict)

    def manager(self, config_subscription: str | None = None) -> NsgManager:
        sub = resolve_subscription_id(self.subscription_flag, self.settings.subscription_id,
                                      config_subscription)
        if sub not in self._managers:
            factory = self.manager_factory or self._default_manager
            self._managers[sub] = factory(sub)
        return self._managers[sub]

    def _default_manager(self, subscription_id: str) -> NsgManager:
        from nsg_automation.azure.auth import create_credential, describe_identity
        from nsg_automation.azure.client import AzureNsgClient
        from nsg_automation.utils.audit import AuditLogger

        credential = create_credential()
        audit = AuditLogger(self.settings.audit_log_file,
                            user_resolver=lambda: describe_identity(credential)["identity"])
        return NsgManager(AzureNsgClient(credential, subscription_id), audit)


class SafeGroup(click.Group):
    """Turn expected errors into friendly messages instead of stack traces."""

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except NsgToolError as exc:
            app: AppContext | None = ctx.find_object(AppContext)
            console = app.console if app else output.make_console()
            _print_error(console, exc)
            _log.error("command failed", extra={"fields": {
                "error_type": type(exc).__name__, "error": exc.message}})
            if app and app.debug:
                console.print(traceback.format_exc(), style="dim")
            ctx.exit(exc.exit_code)
        except (click.ClickException, click.exceptions.Exit, click.exceptions.Abort):
            raise
        except KeyboardInterrupt:
            click.echo("\nInterrupted. No further changes were made.", err=True)
            ctx.exit(130)
        except Exception as exc:  # unexpected bug: log full details, show a short message
            app = ctx.find_object(AppContext)
            _log.exception("unexpected error")
            if app and app.debug:
                raise
            click.secho(f"Unexpected error: {type(exc).__name__}: {exc}", fg="red", err=True)
            click.echo("Re-run with --debug for details (also written to logs/nsg-tool.log).", err=True)
            ctx.exit(1)


def _print_error(console: Console, exc: NsgToolError) -> None:
    console.print(f"[bold red]Error:[/bold red] {exc.message}")
    if isinstance(exc, ValidationError) and exc.issues:
        output.render_issues(console, exc.issues)
    if exc.hint:
        console.print(f"[yellow]Hint:[/yellow] {exc.hint}")


# ---------------------------------------------------------------- root
@click.group(cls=SafeGroup, context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="nsg-tool")
@click.option("-s", "--subscription", envvar=None, help="Azure subscription ID (default: "
              "AZURE_SUBSCRIPTION_ID, then the config file, then `az account show`).")
@click.option("--env-file", type=click.Path(dir_okay=False), default=None,
              help="Load settings from this .env file (default: ./.env if present).")
@click.option("--debug", is_flag=True, help="Show stack traces and Azure SDK HTTP logging.")
@click.pass_context
def cli(ctx: click.Context, subscription: str | None, env_file: str | None, debug: bool) -> None:
    """Azure NSG automation: manage Network Security Group rules safely.

    \b
    Authentication uses DefaultAzureCredential (az login, managed identity,
    service principal environment variables, VS Code ...).
    """
    if isinstance(ctx.obj, AppContext):   # injected (tests / embedding)
        return
    settings = Settings.load(env_file)
    configure_logging(settings.log_dir, settings.log_level, verbose=debug)
    ctx.obj = AppContext(settings=settings, console=output.make_console(),
                         subscription_flag=subscription, debug=debug)


def nsg_options(fn: Callable) -> Callable:
    fn = click.option("--nsg", "nsg", required=True, help="Network security group name.")(fn)
    fn = click.option("-g", "--resource-group", required=True, help="Resource group name.")(fn)
    return fn


def _app(ctx: click.Context) -> AppContext:
    return ctx.obj


# ------------------------------------------------------------- whoami
@cli.command()
@click.pass_context
def whoami(ctx: click.Context) -> None:
    """Test authentication and show the identity/subscription in use."""
    from nsg_automation.azure.auth import create_credential, describe_identity

    app = _app(ctx)
    sub = resolve_subscription_id(app.subscription_flag, app.settings.subscription_id)
    info = describe_identity(create_credential())
    app.console.print("[green]Authenticated to Azure.[/green]")
    for key, value in [("Identity", info["identity"]), ("Type", info["type"]),
                       ("Object ID", info["object_id"]), ("Tenant ID", info["tenant_id"]),
                       ("Subscription", sub)]:
        app.console.print(f"  [bold]{key:<13}[/bold] {value or '-'}")


# ---------------------------------------------------------------- reads
@cli.command("list")
@nsg_options
@click.option("--direction", type=DIRECTIONS, help="Only inbound or outbound rules.")
@click.option("--include-defaults", is_flag=True, help="Also show Azure's default rules (65000+).")
@click.option("-o", "--output", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def list_cmd(ctx, resource_group, nsg, direction, include_defaults, fmt):
    """List the rules of an NSG."""
    app = _app(ctx)
    rules = app.manager().list_rules(resource_group, nsg, include_defaults=include_defaults)
    if direction:
        rules = [r for r in rules if r.direction.lower() == direction.lower()]
    _show_rules(app, rules, fmt, f"{resource_group}/{nsg}")


@cli.command()
@nsg_options
@click.option("--name", "name_filter", help="Rule name substring or glob (e.g. 'Allow-*').")
@click.option("--direction", type=DIRECTIONS)
@click.option("--access", type=ACCESSES)
@click.option("--protocol", type=PROTOCOLS, help="Rules using this protocol (or Any).")
@click.option("--port", type=click.IntRange(0, 65535), help="Rules whose destination ports include this port.")
@click.option("--source", help="Rules whose source matches this IP/CIDR/service tag.")
@click.option("--destination", help="Rules whose destination matches this IP/CIDR/service tag.")
@click.option("--min-priority", type=int)
@click.option("--max-priority", type=int)
@click.option("--text", help="Free text searched in name and description.")
@click.option("-o", "--output", "fmt", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def search(ctx, resource_group, nsg, name_filter, direction, access, protocol, port, source,
           destination, min_priority, max_priority, text, fmt):
    """Search/filter rules by port, address, name, access, protocol or priority.

    Example: which rules match port 22 from 10.0.0.5?
    nsg-tool search -g RG --nsg NSG --port 22 --source 10.0.0.5
    """
    app = _app(ctx)
    try:
        flt = RuleFilter(name_filter, direction, access, protocol, port, source, destination,
                         min_priority, max_priority, text).normalized()
    except FieldError as exc:
        raise click.BadParameter(str(exc)) from None
    rules = filter_rules(app.manager().list_rules(resource_group, nsg), flt)
    _show_rules(app, rules, fmt, f"{resource_group}/{nsg} - {len(rules)} matching rule(s)")


def _show_rules(app: AppContext, rules, fmt: str, title: str) -> None:
    if fmt == "json":
        click.echo(dump_json([r.to_dict() for r in rules]), nl=False)
        return
    if not rules:
        app.console.print("No rules found.")
        return
    app.console.print(output.rules_table(rules, title=title))


# ---------------------------------------------------------- NSG create
@cli.command("create-nsg")
@nsg_options
@click.option("-l", "--location", help="Azure region (default: the resource group's region).")
@click.option("--tag", "tags", multiple=True, metavar="KEY=VALUE", help="Tag (repeatable).")
@click.option("--dry-run", is_flag=True, help="Show what would happen without changing Azure.")
@click.pass_context
def create_nsg(ctx, resource_group, nsg, location, tags, dry_run):
    """Create a new (empty) network security group."""
    app = _app(ctx)
    parsed = {}
    for item in tags:
        if "=" not in item:
            raise click.BadParameter(f"tag {item!r} must be KEY=VALUE", param_hint="--tag")
        k, v = item.split("=", 1)
        parsed[k.strip()] = v.strip()
    mgr = app.manager()
    _run_change(app, mgr, mgr.prepare_create_nsg(resource_group, nsg, location, parsed),
                dry_run=dry_run, force=False)


# --------------------------------------------------------- rule writes
def rule_options(required: bool) -> Callable:
    def decorate(fn: Callable) -> Callable:
        opts = [
            click.option("--description", default=None, help="Free-text description (max 140)."),
            click.option("--destination-asg", "destination_asgs", multiple=True,
                         help="Destination Application Security Group resource ID (repeatable)."),
            click.option("--source-asg", "source_asgs", multiple=True,
                         help="Source Application Security Group resource ID (repeatable)."),
            click.option("--priority", type=int, required=required,
                         help="100-4096; lower number = higher precedence; unique per direction."),
            click.option("--destination-port", "destination_ports", multiple=True, required=required,
                         help="Port, range or '*'. Comma-separated or repeatable: 443 | 8000-8080 | 80,443."),
            click.option("--destination", multiple=True,
                         help="Destination IP/CIDR/service tag/'*'. Comma-separated or repeatable."
                         + ("" if not required else " [default: *]")),
            click.option("--source-port", "source_ports", multiple=True,
                         help="Source port, range or '*'." + ("" if not required else " [default: *]")),
            click.option("--source", multiple=True,
                         help="Source IP/CIDR/service tag (Internet, VirtualNetwork, "
                              "AzureLoadBalancer...)/'*'. Comma-separated or repeatable."
                         + ("" if not required else " [default: *]")),
            click.option("--protocol", type=PROTOCOLS, required=required),
            click.option("--access", type=ACCESSES, required=required),
            click.option("--direction", type=DIRECTIONS, required=required),
            click.option("--name", required=True, help="Security rule name."),
        ]
        for opt in opts:
            fn = opt(fn)
        return fn
    return decorate


def write_flags(fn: Callable) -> Callable:
    fn = click.option("--force", is_flag=True,
                      help="Skip confirmation prompts (including dangerous-rule warnings).")(fn)
    fn = click.option("--dry-run", is_flag=True,
                      help="Show existing config, proposed change, warnings and the API call; change nothing.")(fn)
    return fn


def _raw_rule(name, direction, access, protocol, source, source_ports, destination,
              destination_ports, priority, description, source_asgs, destination_asgs,
              fill_defaults: bool) -> dict[str, Any]:
    raw: dict[str, Any] = {"name": name}
    pairs = {
        "direction": direction, "access": access, "protocol": protocol, "priority": priority,
        "description": description,
        "source": list(source) or None, "sourcePort": list(source_ports) or None,
        "destination": list(destination) or None, "destinationPort": list(destination_ports) or None,
        "sourceAsgs": list(source_asgs) or None, "destinationAsgs": list(destination_asgs) or None,
    }
    for key, value in pairs.items():
        if value is not None:
            raw[key] = value
    if fill_defaults:
        if "sourceAsgs" not in raw:
            raw.setdefault("source", "*")
        if "destinationAsgs" not in raw:
            raw.setdefault("destination", "*")
        raw.setdefault("sourcePort", "*")
    return raw


@cli.command()
@nsg_options
@rule_options(required=True)
@write_flags
@click.pass_context
def add(ctx, resource_group, nsg, name, direction, access, protocol, source, source_ports,
        destination, destination_ports, priority, description, source_asgs, destination_asgs,
        dry_run, force):
    """Add an inbound or outbound security rule."""
    app = _app(ctx)
    rule, warnings = build_rule(_raw_rule(
        name, direction, access, protocol, source, source_ports, destination, destination_ports,
        priority, description, source_asgs, destination_asgs, fill_defaults=True))
    mgr = app.manager()
    _run_change(app, mgr, mgr.prepare_add(resource_group, nsg, rule, warnings), dry_run, force)


@cli.command()
@nsg_options
@rule_options(required=False)
@write_flags
@click.pass_context
def update(ctx, resource_group, nsg, name, direction, access, protocol, source, source_ports,
           destination, destination_ports, priority, description, source_asgs, destination_asgs,
           dry_run, force):
    """Update properties of an existing rule (only the options you pass change)."""
    app = _app(ctx)
    changes = _raw_rule(name, direction, access, protocol, source, source_ports, destination,
                        destination_ports, priority, description, source_asgs, destination_asgs,
                        fill_defaults=False)
    changes.pop("name")
    if not changes:
        raise click.UsageError("Nothing to update: pass at least one property option "
                               "(e.g. --priority, --destination-port, --source).")
    mgr = app.manager()
    _run_change(app, mgr, mgr.prepare_update(resource_group, nsg, name, changes), dry_run, force)


@cli.command()
@nsg_options
@click.option("--name", required=True, help="Security rule name.")
@write_flags
@click.pass_context
def delete(ctx, resource_group, nsg, name, dry_run, force):
    """Delete a security rule (asks for confirmation)."""
    app = _app(ctx)
    mgr = app.manager()
    _run_change(app, mgr, mgr.prepare_delete(resource_group, nsg, name), dry_run, force)


def _run_change(app: AppContext, mgr: NsgManager, preview: ChangePreview, dry_run: bool,
                force: bool) -> None:
    """Shared flow: show preview -> stop if blocked/dry-run -> confirm -> execute."""
    console = app.console
    if preview.plan is not None:
        output.render_plan(console, preview.plan)
        if preview.issues:
            console.rule("[bold]Validation & security analysis")
            output.render_issues(console, preview.issues)
        if dry_run:
            output.render_api_calls(console, preview)
    else:
        output.render_preview(console, preview, mgr.subscription_id, dry_run=dry_run)

    if preview.blocked:
        mgr.record_dry_run(preview) if dry_run else mgr.record_aborted(preview, "validation errors")
        raise ValidationError("The change was blocked by validation errors. Nothing was changed.",
                              hint="Fix the errors listed above and try again.")
    if dry_run:
        mgr.record_dry_run(preview)
        console.print("\n[bold cyan]DRY RUN:[/bold cyan] no changes were made to Azure.")
        return
    if preview.is_noop:
        console.print("[green]Nothing to do.[/green]")
        return
    try:
        confirm_change(console, preview, force)
    except NsgToolError as exc:
        mgr.record_aborted(preview, exc.message)
        raise
    with console.status("Applying change in Azure..."):
        mgr.execute(preview)
    console.print(f"[bold green]Success:[/bold green] {_success_message(preview)}")


def _success_message(preview: ChangePreview) -> str:
    if preview.plan is not None:
        s = preview.plan.summary()
        created = "" if preview.plan.nsg_exists else f"NSG {preview.nsg!r} created; "
        return (f"{created}{s['create']} created, {s['update']} updated, {s['delete']} deleted "
                f"in {preview.resource_group}/{preview.nsg}.")
    return {
        "create_nsg": f"NSG {preview.nsg!r} created in {preview.location}.",
        "add_rule": f"rule {preview.rule_name!r} added to {preview.nsg!r}.",
        "update_rule": f"rule {preview.rule_name!r} updated in {preview.nsg!r}.",
        "delete_rule": f"rule {preview.rule_name!r} deleted from {preview.nsg!r}.",
    }.get(preview.action, "done.")


# ---------------------------------------------------- JSON workflows
@cli.command()
@nsg_options
@click.option("-f", "--file", "out_file", type=click.Path(dir_okay=False),
              help="Write to this file instead of stdout.")
@click.pass_context
def export(ctx, resource_group, nsg, out_file):
    """Export an NSG's custom rules to JSON (importable with `import`/`apply`)."""
    app = _app(ctx)
    mgr = app.manager()
    group = mgr.client.get_nsg(resource_group, nsg)
    rules = mgr.list_rules(resource_group, nsg)
    data = export_config(resource_group, nsg, rules, location=getattr(group, "location", None))
    text = dump_json(data, out_file)
    if out_file:
        app.console.print(f"[green]Exported {len(rules)} rule(s) to {out_file}[/green]")
    else:
        click.echo(text, nl=False)


@cli.command()
@click.argument("config_file", type=click.Path(dir_okay=False))
@click.pass_context
def validate(ctx, config_file):
    """Validate a JSON config offline (syntax, CIDRs, ports, priorities, conflicts, security)."""
    app = _app(ctx)
    config, warnings = load_config(config_file)
    issues = warnings + analyze_rules(config.rules)
    app.console.print(output.rules_table(
        sorted(config.rules, key=lambda r: (r.direction, r.priority)),
        title=f"{config_file}: {config.resource_group}/{config.nsg}"))
    if issues:
        output.render_issues(app.console, issues)
    if errors(issues):
        raise ValidationError(f"{config_file} has {len(errors(issues))} error(s).")
    n_warn = len([i for i in issues if i.severity is not Severity.INFO])
    app.console.print(f"[bold green]Valid:[/bold green] {len(config.rules)} rule(s), {n_warn} warning(s).")


@cli.command()
@click.argument("config_file", type=click.Path(dir_okay=False))
@click.option("--keep-unmanaged", is_flag=True,
              help="Do not delete rules that exist in Azure but not in the file.")
@click.option("-o", "--output", "fmt", type=click.Choice(["text", "json"]), default="text")
@click.pass_context
def plan(ctx, config_file, keep_unmanaged, fmt):
    """Show what `apply` would change (never modifies Azure)."""
    app = _app(ctx)
    config, warnings = load_config(config_file)
    mgr = app.manager(config.subscription_id)
    preview = mgr.prepare_apply(config, keep_unmanaged=keep_unmanaged, warnings=warnings)
    if fmt == "json":
        data = output.plan_to_dict(preview.plan)
        data["issues"] = [i.to_dict() for i in preview.issues]
        click.echo(json.dumps(data, indent=2))
        return
    output.render_plan(app.console, preview.plan)
    if preview.issues:
        app.console.rule("[bold]Validation & security analysis")
        output.render_issues(app.console, preview.issues)
    if preview.blocked:
        raise ValidationError("The plan contains errors; `apply` would be refused.")


@cli.command()
@click.argument("config_file", type=click.Path(dir_okay=False))
@click.option("--keep-unmanaged", is_flag=True,
              help="Do not delete rules that exist in Azure but not in the file.")
@write_flags
@click.pass_context
def apply(ctx, config_file, keep_unmanaged, dry_run, force):
    """Make the NSG match the JSON config exactly (creates/updates/deletes, one atomic PUT)."""
    app = _app(ctx)
    config, warnings = load_config(config_file)
    mgr = app.manager(config.subscription_id)
    _run_change(app, mgr, mgr.prepare_apply(config, keep_unmanaged=keep_unmanaged,
                                            warnings=warnings), dry_run, force)


@cli.command("import")
@click.argument("config_file", type=click.Path(dir_okay=False))
@write_flags
@click.pass_context
def import_cmd(ctx, config_file, dry_run, force):
    """Import rules from JSON: create/update them, never delete other rules."""
    app = _app(ctx)
    config, warnings = load_config(config_file)
    mgr = app.manager(config.subscription_id)
    _run_change(app, mgr, mgr.prepare_apply(config, keep_unmanaged=True, warnings=warnings,
                                            action=IMPORT), dry_run, force)


# ------------------------------------------------------- interactive
@cli.command()
@click.pass_context
def interactive(ctx):
    """Menu-driven mode that prompts for every value."""
    from nsg_automation.cli.interactive import run_interactive
    run_interactive(_app(ctx), _run_change)
