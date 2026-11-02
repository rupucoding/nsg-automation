"""Exception hierarchy for the NSG tool.

Every error raised intentionally by the tool derives from ``NsgToolError`` and
carries a human-friendly ``message`` plus an optional ``hint`` describing how to
fix the problem. The CLI prints these without stack traces; anything else is
treated as an unexpected bug.
"""

from __future__ import annotations


class NsgToolError(Exception):
    """Base class for all expected, user-facing errors."""

    exit_code = 1

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint


# --- Input / configuration -------------------------------------------------

class ValidationError(NsgToolError):
    """Rule or configuration input failed validation."""

    exit_code = 2

    def __init__(self, message: str, issues: list | None = None, hint: str | None = None) -> None:
        super().__init__(message, hint)
        self.issues = issues or []


class ConfigError(NsgToolError):
    """Problem reading or parsing a JSON configuration file."""

    exit_code = 2


class SettingsError(NsgToolError):
    """Missing or invalid tool settings (e.g. no subscription ID)."""

    exit_code = 2


class OperationAborted(NsgToolError):
    """The user declined a confirmation prompt."""

    exit_code = 3


# --- Azure-side errors -----------------------------------------------------

class AzureOperationError(NsgToolError):
    """Generic Azure API failure."""

    exit_code = 4

    def __init__(self, message: str, hint: str | None = None, code: str | None = None,
                 status: int | None = None) -> None:
        super().__init__(message, hint)
        self.code = code
        self.status = status


class AuthenticationError(AzureOperationError):
    """No usable credential, or the credential was rejected."""


class AuthorizationError(AzureOperationError):
    """Authenticated, but RBAC does not permit the operation."""


class SubscriptionNotFoundError(AzureOperationError):
    """Subscription does not exist or is not visible to the identity."""


class ResourceGroupNotFoundError(AzureOperationError):
    """Resource group does not exist."""


class NsgNotFoundError(AzureOperationError):
    """Network security group does not exist."""


class RuleNotFoundError(AzureOperationError):
    """Security rule does not exist in the NSG."""


class RuleAlreadyExistsError(AzureOperationError):
    """A rule with the requested name already exists."""


class PriorityConflictError(AzureOperationError):
    """Another rule in the same direction already uses this priority."""


class RateLimitedError(AzureOperationError):
    """Azure Resource Manager throttled the request (HTTP 429)."""


class AzureNetworkError(AzureOperationError):
    """Could not reach Azure (DNS, proxy, timeout, TLS ...)."""
