"""Dependency-neutral expansion of environment references in config values.

This module deliberately has no CLI or gateway imports.  Both configuration
surfaces use it so a canonical ``config.yaml`` has one expansion meaning
without either loader depending on the other's command surface.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Match

logger = logging.getLogger(__name__)


def _env_expand_match(match: Match[str]) -> str:
    """Expand one ``${VAR}`` or ``${env:VAR}`` reference."""
    raw = match.group(0)
    inner = match.group(1).strip()
    if inner.startswith("env:"):
        name = inner[len("env:") :].strip()
        if not name:
            return raw
        value = os.environ.get(name)
        if value is not None:
            return value
        logger.warning(
            "Config ref %r: %s is not set (check ~/.hermes/.env); "
            "keeping the literal placeholder",
            raw,
            name,
        )
        return raw
    if ":" in inner and re.match(r"^[a-z][a-z0-9_-]*:", inner):
        logger.warning(
            "Config ref %r uses source %r which is not resolvable in "
            "config.yaml — external secret sources inject env vars at "
            "startup, so reference the variable as ${env:NAME} instead",
            raw,
            inner.split(":", 1)[0],
        )
        return raw
    return os.environ.get(inner, raw)


def expand_env_vars(obj: Any) -> Any:
    """Recursively expand environment references in config values.

    Only string values are processed. Unresolved references remain literal so
    callers can detect them, matching the historical canonical-loader contract.
    """
    if isinstance(obj, str):
        return re.sub(r"\${([^}]+)}", _env_expand_match, obj)
    if isinstance(obj, dict):
        return {key: expand_env_vars(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [expand_env_vars(value) for value in obj]
    return obj
