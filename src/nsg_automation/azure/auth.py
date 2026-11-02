"""Authentication via ``DefaultAzureCredential``.

DefaultAzureCredential tries these sources in order and uses the first that works:

  1. EnvironmentCredential      AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET
                                (or AZURE_CLIENT_CERTIFICATE_PATH) - service principals / CI
  2. WorkloadIdentityCredential AKS / GitHub Actions federated identity
  3. ManagedIdentityCredential  Azure VMs, App Service, Functions, Container Apps ...
  4. SharedTokenCacheCredential (Windows) Microsoft developer token cache
  5. VisualStudioCodeCredential Azure Resources extension sign-in in VS Code
  6. AzureCliCredential         `az login`
  7. AzurePowerShellCredential  `Connect-AzAccount`
  8. AzureDeveloperCliCredential `azd auth login`

Tokens are obtained and refreshed by the SDK. This module never stores, prints
or logs a token; ``describe_identity`` only reads non-secret claims (user
principal name, object ID, tenant ID) so the audit log can record *who* made a
change.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential

from nsg_automation.utils.errors import AuthenticationError

ARM_SCOPE = "https://management.azure.com/.default"


def create_credential() -> DefaultAzureCredential:
    # Interactive browser login is excluded (the default) so the tool never
    # pops up a browser unexpectedly in scripts or CI.
    return DefaultAzureCredential(exclude_interactive_browser_credential=True)


def describe_identity(credential: Any) -> dict[str, str | None]:
    """Return non-secret information about the signed-in identity."""
    try:
        token = credential.get_token(ARM_SCOPE).token
    except ClientAuthenticationError as exc:
        raise AuthenticationError(
            "Could not obtain an Azure access token from any credential source.",
            hint="Run: az login   (then: az account set --subscription \"<SUBSCRIPTION_ID>\"). "
                 "Details: " + str(exc).splitlines()[0][:300]) from exc

    claims = _jwt_claims(token)
    del token  # make sure the raw token does not linger in this scope
    user = claims.get("upn") or claims.get("unique_name") or claims.get("preferred_username")
    app_id = claims.get("appid") or claims.get("azp")
    kind = "user" if user else ("managed identity / service principal" if app_id else "unknown")
    return {
        "identity": user or app_id or claims.get("oid"),
        "type": kind,
        "object_id": claims.get("oid"),
        "tenant_id": claims.get("tid"),
        "app_id": app_id,
    }


def _jwt_claims(token: str) -> dict[str, Any]:
    """Decode (without verifying) the payload segment of a JWT."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode()))
    except (IndexError, ValueError):
        return {}
