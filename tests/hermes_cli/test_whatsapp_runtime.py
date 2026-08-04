from __future__ import annotations

from pathlib import Path

import pytest

from hermes_cli.whatsapp_runtime import (
    installer_probe,
    resolve_whatsapp_enabled,
    resolve_whatsapp_session_dir,
)


def test_explicit_yaml_enablement_is_authoritative_over_legacy_false() -> None:
    config = {"platforms": {"whatsapp": {"enabled": True}}}
    assert resolve_whatsapp_enabled(config, legacy_value="false") is True


def test_legacy_enablement_applies_only_when_canonical_yaml_is_absent() -> None:
    assert resolve_whatsapp_enabled({}, legacy_value="true") is True
    assert resolve_whatsapp_enabled({}, legacy_value="false") is False
    assert resolve_whatsapp_enabled(
        {"platforms": {"whatsapp": {"enabled": False}}},
        legacy_value="true",
    ) is False


@pytest.mark.parametrize("profile_name", ["default", "named"])
@pytest.mark.parametrize(
    ("legacy", "canonical", "expected"),
    [
        (True, False, "whatsapp/session"),
        (False, True, "platforms/whatsapp/session"),
        (True, True, "whatsapp/session"),
        (False, False, "platforms/whatsapp/session"),
    ],
)
def test_runtime_and_installer_share_profile_legacy_precedence(
    tmp_path: Path,
    profile_name: str,
    legacy: bool,
    canonical: bool,
    expected: str,
) -> None:
    home = tmp_path / profile_name
    home.mkdir(mode=0o700)
    if legacy:
        target = home / "whatsapp" / "session"
        target.mkdir(parents=True)
        (target / "creds.json").write_text("fixture", encoding="utf-8")
    if canonical:
        target = home / "platforms" / "whatsapp" / "session"
        target.mkdir(parents=True)
        (target / "creds.json").write_text("fixture", encoding="utf-8")
    resolved = resolve_whatsapp_session_dir(home=home)
    assert resolved == home / expected

    (home / "config.yaml").write_text(
        "platforms:\n  whatsapp:\n    enabled: true\n",
        encoding="utf-8",
    )
    enabled, ready = installer_probe(home=home)
    assert enabled is True
    assert ready is (legacy or canonical)


def test_dump_and_tools_consumers_use_canonical_resolver(monkeypatch) -> None:
    config = {"platforms": {"whatsapp": {"enabled": True}}}
    monkeypatch.setenv("WHATSAPP_ENABLED", "false")

    from hermes_cli import dump, tools_config

    monkeypatch.setattr(tools_config, "load_config", lambda: config)
    monkeypatch.setattr(tools_config, "get_env_value", lambda _name: "false")
    assert "whatsapp" in dump._configured_platforms(config)
    assert "whatsapp" in tools_config._get_enabled_platforms()
