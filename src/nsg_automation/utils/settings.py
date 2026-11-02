"""Runtime settings loaded from environment variables (and an optional .env file).

Nothing here is a secret: credentials are handled entirely by
``DefaultAzureCredential``, which reads its own environment variables
(AZURE_CLIENT_ID, AZURE_TENANT_ID, ...) directly. We never copy those values
into our own objects or logs.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from nsg_automation.utils.errors import SettingsError


@dataclass(frozen=True)
class Settings:
    subscription_id: str | None
    log_dir: Path
    log_level: str
    audit_log_file: Path

    @classmethod
    def load(cls, env_file: str | os.PathLike | None = None) -> "Settings":
        # override=False: real environment variables always win over .env values.
        load_dotenv(dotenv_path=env_file, override=False)
        log_dir = Path(os.getenv("NSG_TOOL_LOG_DIR", "logs"))
        return cls(
            subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID") or None,
            log_dir=log_dir,
            log_level=os.getenv("NSG_TOOL_LOG_LEVEL", "INFO").upper(),
            audit_log_file=Path(os.getenv("NSG_TOOL_AUDIT_LOG", str(log_dir / "audit.log"))),
        )


def resolve_subscription_id(*candidates: str | None) -> str:
    """Return the first non-empty candidate, falling back to the Azure CLI default.

    Order used by the CLI: --subscription flag, AZURE_SUBSCRIPTION_ID, the
    ``subscriptionId`` field of a JSON config, then ``az account show``.
    """
    for value in candidates:
        if value and value.strip():
            return value.strip()

    from_cli = _subscription_from_azure_cli()
    if from_cli:
        return from_cli

    raise SettingsError(
        "No Azure subscription ID configured.",
        hint="Pass --subscription <ID>, set AZURE_SUBSCRIPTION_ID (e.g. in .env), "
             "or run: az account set --subscription \"<SUBSCRIPTION_ID>\"",
    )


def _subscription_from_azure_cli() -> str | None:
    az = shutil.which("az")
    if not az:
        return None
    try:
        result = subprocess.run(
            [az, "account", "show", "--query", "id", "--output", "tsv"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value if result.returncode == 0 and value else None
