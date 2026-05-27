# Copyright (c) 2025 Carlos Rocha
# SPDX-License-Identifier: MIT

"""Structured logging for MemMark pipeline stages.

Provides lightweight structured log records with
correlation IDs and pipeline context.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from typing import Any


class StructuredFormatter(logging.Formatter):
    """JSON-structured log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "ctx"):
            log_entry["ctx"] = record.ctx
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry, default=str)


_LOG = logging.getLogger("memmark")
_LOG_HANDLER: logging.Handler | None = None


def configure_logging(
    level: str = "WARNING",
    *,
    json_format: bool = True,
) -> None:
    """Configure MemMark's structured logger.

    Args:
        level: Log level name (DEBUG, INFO, WARNING, ERROR).
        json_format: If True (default), output JSON-structured logs.
    """
    global _LOG_HANDLER  # noqa: PLW0603
    _LOG.setLevel(getattr(logging, level.upper(), logging.WARNING))

    if _LOG_HANDLER:
        _LOG.removeHandler(_LOG_HANDLER)

    handler = logging.StreamHandler(sys.stderr)
    if json_format:
        handler.setFormatter(StructuredFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(levelname)s  %(message)s"))
    _LOG.addHandler(handler)
    _LOG_HANDLER = handler


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a MemMark child logger.

    Args:
        name: Optional child logger name.

    Returns:
        A :class:`logging.Logger` instance.
    """
    return _LOG.getChild(name) if name else _LOG


def correlation_id() -> str:
    """Generate a short correlation ID for pipeline tracing.

    Returns:
        8-character hex correlation ID.
    """
    return uuid.uuid4().hex[:8]
