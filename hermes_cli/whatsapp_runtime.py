"""Canonical non-secret WhatsApp enablement and session resolution.

All Python consumers use this module so explicit config.yaml state wins over
the legacy ``WHATSAPP_ENABLED`` compatibility carrier.  The installer probe is
also exposed as a tiny module entry point; it prints only bounded booleans and
never reads credential contents.
"""

from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
from typing import Any, Callable

from hermes_constants import get_hermes_dir, get_hermes_home


_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


def _coerce_explicit_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _TRUE:
            return True
        if token in _FALSE:
            return False
    return bool(value)


def _explicit_yaml_value(config: object) -> tuple[bool, object]:
    if isinstance(config, Mapping):
        platforms = config.get("platforms")
        if isinstance(platforms, Mapping):
            whatsapp = platforms.get("whatsapp")
            if isinstance(whatsapp, Mapping) and "enabled" in whatsapp:
                return True, whatsapp["enabled"]
        gateway = config.get("gateway")
        if isinstance(gateway, Mapping):
            gateway_platforms = gateway.get("platforms")
            if isinstance(gateway_platforms, Mapping):
                whatsapp = gateway_platforms.get("whatsapp")
                if isinstance(whatsapp, Mapping) and "enabled" in whatsapp:
                    return True, whatsapp["enabled"]
    try:
        from gateway.config import Platform

        platform_config = getattr(config, "platforms", {}).get(Platform.WHATSAPP)
    except Exception:
        platform_config = None
    extra = getattr(platform_config, "extra", {}) if platform_config is not None else {}
    if isinstance(extra, Mapping) and extra.get("_enabled_explicit") is True:
        return True, getattr(platform_config, "enabled", False)
    return False, None


def resolve_whatsapp_enabled(
    config: object | None = None,
    *,
    legacy_value: str | None = None,
    getenv: Callable[[str], str | None] | None = None,
    default: bool = False,
) -> bool:
    """Resolve YAML-first enablement with legacy env fallback only if absent."""
    if config is None:
        try:
            from hermes_cli.config import load_config_readonly

            config = load_config_readonly()
        except Exception:
            config = {}
    explicit, value = _explicit_yaml_value(config)
    if explicit:
        return _coerce_explicit_bool(value)
    if legacy_value is None:
        reader = getenv or os.getenv
        legacy_value = reader("WHATSAPP_ENABLED")
    token = str(legacy_value or "").strip().lower()
    if token in _TRUE:
        return True
    if token in _FALSE:
        return False
    return bool(default)


def resolve_whatsapp_session_dir(*, home: Path | None = None) -> Path:
    """Mirror runtime legacy-before-canonical populated-path precedence."""
    selected_home = home or get_hermes_home()
    return get_hermes_dir(
        "platforms/whatsapp/session",
        "whatsapp/session",
        home=selected_home,
    )


def installer_probe(*, home: Path | None = None) -> tuple[bool, bool]:
    """Return enablement/readiness without parsing any credential content."""
    selected_home = home or get_hermes_home()
    try:
        import yaml

        raw = yaml.safe_load((selected_home / "config.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, ValueError, TypeError):
        raw = {}
    try:
        from hermes_cli.config import get_env_value

        legacy_value = get_env_value("WHATSAPP_ENABLED")
    except Exception:
        legacy_value = os.getenv("WHATSAPP_ENABLED")
    enabled = resolve_whatsapp_enabled(raw, legacy_value=legacy_value)
    ready = (resolve_whatsapp_session_dir(home=selected_home) / "creds.json").is_file()
    return enabled, ready


def _main() -> int:
    enabled, ready = installer_probe()
    print(f"enabled={str(enabled).lower()};ready={str(ready).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "installer_probe",
    "resolve_whatsapp_enabled",
    "resolve_whatsapp_session_dir",
]
