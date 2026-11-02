"""Translate Azure SDK exceptions into friendly ``NsgToolError`` subclasses.

Azure Resource Manager returns an error ``code`` alongside the HTTP status; the
code is far more specific (e.g. ``ResourceGroupNotFound`` vs ``ResourceNotFound``)
so we map on it first and fall back to the status.
"""

from __future__ import annotations

from azure.core.exceptions import (
    AzureError, ClientAuthenticationError, HttpResponseError, ServiceRequestError,
    ServiceResponseError,
)

from nsg_automation.utils import errors as e

_RBAC_HINT = ("Your identity needs 'Network Contributor' (or a custom role with "
              "Microsoft.Network/networkSecurityGroups/* permissions) on the NSG, its resource "
              "group or the subscription. Read-only commands need only 'Reader'.")
_LOGIN_HINT = ("Sign in with: az login   then select the subscription with: "
               "az account set --subscription \"<SUBSCRIPTION_ID>\". "
               "For service principals set AZURE_TENANT_ID, AZURE_CLIENT_ID and "
               "AZURE_CLIENT_SECRET (or a certificate) in the environment.")


def _error_code(exc: HttpResponseError) -> str | None:
    err = getattr(exc, "error", None)
    code = getattr(err, "code", None)
    if code:
        return str(code)
    # Some responses only carry the code inside the message ("(Code) message").
    msg = getattr(exc, "message", "") or ""
    if msg.startswith("(") and ")" in msg:
        return msg[1:msg.index(")")]
    return None


def _error_message(exc: AzureError) -> str:
    err = getattr(exc, "error", None)
    msg = getattr(err, "message", None) or getattr(exc, "message", None) or str(exc)
    msg = str(msg).strip().splitlines()[0] if msg else exc.__class__.__name__
    return msg[:500]


def translate_azure_error(exc: Exception, *, subscription: str | None = None,
                          resource_group: str | None = None, nsg: str | None = None,
                          rule: str | None = None) -> e.NsgToolError:
    """Return the ``NsgToolError`` that best describes ``exc``."""
    if isinstance(exc, e.NsgToolError):
        return exc

    # Credential problems (includes azure.identity.CredentialUnavailableError).
    if isinstance(exc, ClientAuthenticationError) and not getattr(exc, "status_code", None):
        return e.AuthenticationError(
            "Could not authenticate to Azure: no usable credential was found or the sign-in failed.",
            hint=_LOGIN_HINT)

    if isinstance(exc, (ServiceRequestError, ServiceResponseError)):
        return e.AzureNetworkError(
            f"Could not reach Azure Resource Manager: {_error_message(exc)}",
            hint="Check network connectivity, proxy settings (HTTPS_PROXY) and DNS, then retry.")

    if not isinstance(exc, HttpResponseError):
        if isinstance(exc, AzureError):
            return e.AzureOperationError(f"Azure SDK error: {_error_message(exc)}")
        return e.AzureOperationError(f"Unexpected error talking to Azure: {exc}")

    code = _error_code(exc) or ""
    status = getattr(exc, "status_code", None)
    message = _error_message(exc)
    lc = code.lower()
    kw = {"code": code or None, "status": status}

    if lc in ("subscriptionnotfound", "invalidsubscriptionid") or (
            "subscription" in lc and "notfound" in lc):
        return e.SubscriptionNotFoundError(
            f"Subscription {subscription!r} was not found or is not accessible.",
            hint="Check the ID with: az account list --output table", **kw)
    if lc == "missingsubscriptionregistration":
        return e.AzureOperationError(
            f"The Microsoft.Network resource provider is not registered: {message}",
            hint="Run: az provider register --namespace Microsoft.Network", **kw)
    if lc in ("authorizationfailed", "linkedauthorizationfailed") or status == 403:
        return e.AuthorizationError(
            f"Access denied by Azure RBAC: {message}", hint=_RBAC_HINT, **kw)
    if status == 401 or "authenticationtoken" in lc or lc == "invalidauthenticationtokentenant":
        return e.AuthenticationError(f"Azure rejected the credentials: {message}",
                                     hint=_LOGIN_HINT, **kw)
    if lc == "resourcegroupnotfound":
        return e.ResourceGroupNotFoundError(
            f"Resource group {resource_group!r} was not found.",
            hint="List resource groups with: az group list --output table", **kw)
    if status == 404 or lc in ("resourcenotfound", "notfound"):
        lower_msg = message.lower()
        if rule and ("securityrules" in lower_msg or "security rule" in lower_msg):
            return e.RuleNotFoundError(
                f"Rule {rule!r} was not found in NSG {nsg!r}.",
                hint="List rules with: nsg-tool list -g <rg> --nsg <nsg>", **kw)
        return e.NsgNotFoundError(
            f"Network security group {nsg!r} was not found in resource group {resource_group!r}.",
            hint="Create it with: nsg-tool create-nsg -g <rg> --nsg <nsg> --location <region>", **kw)
    if status == 429 or lc in ("toomanyrequests", "subscriptionrequeststhrottled"):
        retry = None
        response = getattr(exc, "response", None)
        if response is not None and getattr(response, "headers", None):
            retry = response.headers.get("Retry-After")
        return e.RateLimitedError(
            "Azure Resource Manager is throttling requests (HTTP 429).",
            hint=f"Wait {retry + ' seconds' if retry else 'a minute'} and retry; "
                 "avoid running many tool instances in parallel.", **kw)
    if lc == "securityruleconflict" or ("priority" in message.lower() and "same" in message.lower()):
        return e.PriorityConflictError(
            f"Azure rejected the rule because of a conflict: {message}",
            hint="Each rule in the same direction needs a unique priority.", **kw)
    if lc in ("anotheroperationinprogress", "retryableerror") or status == 409:
        return e.AzureOperationError(
            f"Azure reported a conflicting operation in progress: {message}",
            hint="Another change is being applied to this NSG; retry in a few seconds.", **kw)
    if status == 400 or lc.startswith("securityrule") or lc in ("invalidparameter", "invalidrequestformat"):
        return e.AzureOperationError(f"Azure rejected the request ({code or status}): {message}",
                                     hint="Fix the parameter mentioned above and retry.", **kw)
    if status and status >= 500:
        return e.AzureOperationError(
            f"Azure service error ({status}): {message}",
            hint="This is usually transient; retry shortly. Check https://status.azure.com", **kw)
    return e.AzureOperationError(f"Azure API error ({code or status}): {message}", **kw)
