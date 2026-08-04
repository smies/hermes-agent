from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_shipped_ordinary_whatsapp_surfaces_do_not_restore_qr_instructions() -> None:
    paths = (
        ROOT / "website/docs/user-guide/messaging/whatsapp.md",
        ROOT / "website/docs/user-guide/messaging/whatsapp-cloud.md",
        ROOT / "website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/user-guide/messaging/whatsapp.md",
        ROOT / "website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/reference/cli-commands.md",
        ROOT / "website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/guides/migrate-from-openclaw.md",
        ROOT / "apps/desktop/src/i18n/zh.ts",
        ROOT / "optional-skills/migration/openclaw-migration/scripts/openclaw_to_hermes.py",
    )
    forbidden = (
        re.compile(r"(?is)whatsapp.{0,160}(?:scan|scanning).{0,80}qr"),
        re.compile(r"(?is)(?:scan|scanning).{0,80}qr.{0,160}whatsapp"),
        re.compile(r"(?is)whatsapp.{0,160}qr[- ]code pairing"),
        re.compile(r"WhatsApp.{0,160}扫描二维码", re.S),
        re.compile(r"扫描二维码.{0,160}WhatsApp", re.S),
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            assert pattern.search(text) is None, (path, pattern.pattern)


def test_cloud_api_guide_remains_a_distinct_integration() -> None:
    cloud = (ROOT / "website/docs/user-guide/messaging/whatsapp-cloud.md").read_text(
        encoding="utf-8"
    )
    ordinary = (ROOT / "website/docs/user-guide/messaging/whatsapp.md").read_text(
        encoding="utf-8"
    )
    assert "official" in cloud.lower()
    assert "Cloud API" in cloud
    assert "hermes whatsapp provision --role ordinary" in ordinary
    assert "There is no QR fallback" in ordinary


def test_shell_and_powershell_installers_use_the_same_profile_safe_session() -> None:
    shell = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    powershell = (ROOT / "scripts/install.ps1").read_text(encoding="utf-8")
    assert "-m hermes_cli.whatsapp_runtime" in shell
    assert "-m hermes_cli.whatsapp_runtime" in powershell
    assert "whatsapp provision --role ordinary" not in powershell
    assert 'WHATSAPP_STATE" = "enabled=true;ready=false"' in shell
    assert 'HERMES_HOME="$HERMES_HOME" "$WHATSAPP_PROBE_PY" -m hermes_cli.whatsapp_runtime' in shell
    assert '$whatsappState -eq "enabled=true;ready=false"' in powershell

    # The shared probe owns legacy/canonical precedence; neither installer
    # grows a second hard-coded session resolver.
    assert "resolve_whatsapp_session_dir" not in shell
    assert "resolve_whatsapp_session_dir" not in powershell
