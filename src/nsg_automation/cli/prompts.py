"""Confirmation rules for writes.

* Dangerous rules (CRITICAL/HIGH findings)  -> user must type 'yes' (or pass --force)
* Destructive operations (delete, apply with deletions) -> user must confirm (or --force)
* apply / import                          -> confirm after showing the plan (or --force)
* Non-interactive session without --force -> aborted (never silently proceed)
"""

from __future__ import annotations

import sys

import click
from rich.console import Console

from nsg_automation.nsg.manager import APPLY, IMPORT, ChangePreview
from nsg_automation.utils.errors import OperationAborted


def is_interactive() -> bool:
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def confirm_change(console: Console, preview: ChangePreview, force: bool) -> None:
    """Raise ``OperationAborted`` unless the change is confirmed."""
    danger = preview.confirmation_issues
    needs_confirm = bool(danger) or preview.is_destructive or preview.action in (APPLY, IMPORT)
    if not needs_confirm:
        return
    if force:
        reason = "dangerous rule" if danger else "destructive change" if preview.is_destructive else "apply"
        console.print(f"[yellow]--force given: skipping confirmation ({reason}).[/yellow]")
        return
    if not is_interactive():
        raise OperationAborted(
            "Confirmation required but the session is not interactive.",
            hint="Review the output above (or use --dry-run) and re-run with --force to proceed.")

    if danger:
        console.print("[bold red]This change creates a rule flagged as a security risk.[/bold red]")
        answer = click.prompt("Type 'yes' to create it anyway", default="", show_default=False)
        if answer.strip().lower() != "yes":
            raise OperationAborted("Aborted: dangerous rule not confirmed. No changes were made.")
        if not preview.is_destructive and preview.action not in (APPLY, IMPORT):
            return

    if preview.is_destructive:
        question = "This will permanently DELETE rule(s) from Azure. Continue?"
    else:
        question = "Apply these changes to Azure?"
    if not click.confirm(question, default=False):
        raise OperationAborted("Aborted by user. No changes were made.")
