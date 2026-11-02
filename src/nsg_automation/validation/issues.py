"""Validation / analysis findings."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class Severity(str, Enum):
    ERROR = "error"          # invalid: the change is blocked
    CRITICAL = "critical"    # security: requires explicit confirmation (or --force)
    HIGH = "high"            # security: requires explicit confirmation (or --force)
    MEDIUM = "medium"        # security: shown prominently, not blocking
    WARNING = "warning"      # logic problem (duplicate, shadowed, conflicting ...)
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Severity.ERROR: 0, Severity.CRITICAL: 1, Severity.HIGH: 2,
         Severity.MEDIUM: 3, Severity.WARNING: 4, Severity.INFO: 5}

DANGEROUS = frozenset({Severity.CRITICAL, Severity.HIGH})


@dataclass(frozen=True)
class Issue:
    severity: Severity
    code: str
    message: str
    rule: str | None = None
    hint: str | None = None

    def to_dict(self) -> dict:
        return {"severity": self.severity.value, "code": self.code, "rule": self.rule,
                "message": self.message, "hint": self.hint}


def errors(issues: Iterable[Issue]) -> list[Issue]:
    return [i for i in issues if i.severity is Severity.ERROR]


def dangerous(issues: Iterable[Issue]) -> list[Issue]:
    return [i for i in issues if i.severity in DANGEROUS]


def sort_issues(issues: Iterable[Issue]) -> list[Issue]:
    return sorted(issues, key=lambda i: (i.severity.rank, i.rule or "", i.code))
