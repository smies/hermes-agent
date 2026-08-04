from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from hermes_cli.whatsapp_runtime import (
    installer_probe,
    resolve_whatsapp_enabled,
    resolve_whatsapp_session_dir,
)
from hermes_constants import reset_hermes_home_override, set_hermes_home_override


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


def test_probe_and_runtime_expand_canonical_yaml_before_boolean_coercion(
    tmp_path: Path,
    monkeypatch,
) -> None:
    home = tmp_path / "expanded"
    home.mkdir(mode=0o700)
    (home / "config.yaml").write_text(
        "platforms:\n  whatsapp:\n    enabled: ${WA_ENABLED}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("WA_ENABLED", "false")
    monkeypatch.setenv("WHATSAPP_ENABLED", "true")

    assert installer_probe(home=home) == (False, False)
    token = set_hermes_home_override(home)
    try:
        assert resolve_whatsapp_enabled() is False
    finally:
        reset_hermes_home_override(token)


def test_probe_uses_legacy_env_only_when_canonical_key_is_absent(
    tmp_path: Path,
) -> None:
    canonical = tmp_path / "canonical"
    canonical.mkdir(mode=0o700)
    (canonical / "config.yaml").write_text(
        "platforms:\n  whatsapp:\n    enabled: false\n",
        encoding="utf-8",
    )
    (canonical / ".env").write_text("WHATSAPP_ENABLED=true\n", encoding="utf-8")
    assert installer_probe(home=canonical) == (False, False)

    legacy = tmp_path / "legacy"
    legacy.mkdir(mode=0o700)
    (legacy / "config.yaml").write_text("{}\n", encoding="utf-8")
    (legacy / ".env").write_text("WHATSAPP_ENABLED=true\n", encoding="utf-8")
    assert installer_probe(home=legacy) == (True, False)


@pytest.mark.parametrize(
    ("selection", "export_selected_home"),
    [
        ("default", False),
        ("custom", False),
        ("named-profile", True),
    ],
)
def test_installer_probe_receives_selected_home_even_when_shell_variable_is_unexported(
    tmp_path: Path,
    selection: str,
    export_selected_home: bool,
) -> None:
    shell_home = tmp_path / "shell-home"
    shell_home.mkdir(mode=0o700)
    selected_home = shell_home / ".hermes" if selection == "default" else tmp_path / selection
    selected_home.mkdir(mode=0o700)
    probe = tmp_path / "probe"
    probe.write_text("#!/bin/sh\nprintf '%s\\n' \"${HERMES_HOME-unset}\"\n", encoding="utf-8")
    probe.chmod(0o700)
    export_line = "export HERMES_HOME" if export_selected_home else ":"
    shell = f"""
set -eu
HOME={str(shell_home)!r}
HERMES_HOME={str(selected_home)!r}
{export_line}
WHATSAPP_PROBE_PY={str(probe)!r}
WHATSAPP_STATE=$(cd {str(tmp_path)!r} && HERMES_HOME="$HERMES_HOME" "$WHATSAPP_PROBE_PY" -m hermes_cli.whatsapp_runtime)
printf '%s\\n' "$WHATSAPP_STATE"
"""
    env = os.environ.copy()
    env.pop("HERMES_HOME", None)
    result = subprocess.run(
        ["bash", "-c", shell],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.stdout.strip() == str(selected_home)
