"""Structured (JSON-lines) application logging with secret redaction."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

LOGGER_NAME = "nsg_automation"

# Keys whose values must never be written to a log.
_SENSITIVE_KEYS = re.compile(
    r"(token|secret|password|passwd|authorization|client_?secret|access_?key|"
    r"certificate|assertion|credential|sas|signature)", re.IGNORECASE)

# Values that look like secrets regardless of the key they are stored under.
_SENSITIVE_VALUES = [
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),  # JWT
    re.compile(r"(?i)(client_secret|password|sig|AccountKey)=([^&;\s]+)"),
]

REDACTED = "***REDACTED***"

# Library best practice: stay silent until configure_logging() is called.
logging.getLogger(LOGGER_NAME).addHandler(logging.NullHandler())


def redact(value):
    """Recursively redact sensitive keys/values from dicts, lists and strings."""
    if isinstance(value, dict):
        return {k: (REDACTED if _SENSITIVE_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        for pattern in _SENSITIVE_VALUES:
            value = pattern.sub(REDACTED, value)
        return value
    return value


class JsonFormatter(logging.Formatter):
    """Render each record as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            payload.update(redact(extra))
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(log_dir: Path, level: str = "INFO", verbose: bool = False) -> logging.Logger:
    """Configure the tool logger. Safe to call more than once."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "nsg-tool.log", encoding="utf-8")
        file_handler.setLevel(getattr(logging, level, logging.INFO))
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)
    except OSError:
        # Logging must never stop the tool from working (e.g. read-only FS).
        pass

    if verbose:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(JsonFormatter())
        logger.addHandler(console)

    # Azure SDK logs (credential chain diagnostics, HTTP details) go to the same
    # handlers: the log file always, the console only with --debug. Without
    # this, Python's last-resort handler would dump them on stderr. The SDK's
    # HttpLoggingPolicy already redacts Authorization headers.
    azure_logger = logging.getLogger("azure")
    azure_logger.setLevel(logging.DEBUG if verbose else logging.WARNING)
    azure_logger.propagate = False
    azure_logger.handlers = list(logger.handlers) or [logging.NullHandler()]
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)
