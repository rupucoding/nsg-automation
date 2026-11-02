"""Append-only audit trail of every change (and attempted change) to Azure.

Each line of the audit file is a JSON object:

    {"timestamp": "...", "user": "alice@contoso.com", "action": "add_rule",
     "subscription": "...", "resource_group": "...", "nsg": "...", "rule": "...",
     "operation": "SecurityRules.begin_create_or_update", "dry_run": false,
     "result": "success", "error": null, "details": {...}}

Credentials, tokens and secrets are never written (values pass through
``redact``).
"""

from __future__ import annotations

import getpass
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from nsg_automation.utils.logging_setup import get_logger, redact

_log = get_logger("audit")


class AuditLogger:
    def __init__(self, path: Path, user_resolver: Callable[[], str | None] | None = None) -> None:
        self.path = Path(path)
        self._user_resolver = user_resolver
        self._user: str | None = None
        self._lock = threading.Lock()

    @property
    def user(self) -> str:
        if self._user is None:
            resolved = None
            if self._user_resolver:
                try:
                    resolved = self._user_resolver()
                except Exception:  # identity lookup must never break auditing
                    resolved = None
            self._user = resolved or f"local:{_local_user()}"
        return self._user

    def record(self, *, action: str, result: str, subscription: str | None = None,
               resource_group: str | None = None, nsg: str | None = None,
               rule: str | None = None, operation: str | None = None,
               dry_run: bool = False, error: str | None = None,
               details: dict[str, Any] | None = None) -> dict[str, Any]:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": self.user,
            "action": action,
            "subscription": subscription,
            "resource_group": resource_group,
            "nsg": nsg,
            "rule": rule,
            "operation": operation,
            "dry_run": dry_run,
            "result": result,
            "error": error,
            "details": details or {},
        }
        entry = redact(entry)
        line = json.dumps(entry, default=str)
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                _log.error("Could not write audit log", extra={"fields": {"error": str(exc)}})
        _log.info("audit", extra={"fields": entry})
        return entry


def _local_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
