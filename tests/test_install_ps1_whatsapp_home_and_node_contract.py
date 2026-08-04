import os
from pathlib import Path
import re
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = (ROOT / "scripts" / "install.ps1").read_text(encoding="utf-8")


def test_windows_node_contract_matches_root_engine_and_download_major() -> None:
    manifest = (ROOT / "package.json").read_text(encoding="utf-8")
    assert '"node": ">=22.22.0"' in manifest
    assert '$NodeVersion = "22"' in INSTALLER
    assert "Hermes requires Node >=22.22.0" in INSTALLER
    assert "Hermes requires Node >=26" not in INSTALLER
    assert "Node >=26" not in INSTALLER


def test_standalone_gateway_stage_scopes_probe_to_exact_hermes_home() -> None:
    body = re.search(
        r"function Start-GatewayIfConfigured \{(?P<body>[\s\S]*?)\nfunction Write-Completion",
        INSTALLER,
    )
    assert body is not None
    source = body.group("body")
    assign = source.index("$env:HERMES_HOME = $HermesHome")
    probe = source.index("-m hermes_cli.whatsapp_runtime")
    restore = source.index("$env:HERMES_HOME = $previousProcessHermesHome")
    assert assign < probe < restore
    assert "Remove-Item Env:HERMES_HOME" in source


@pytest.mark.parametrize(
    ("selection", "enabled"),
    [("default", True), ("custom", False)],
)
def test_gateway_probe_child_observes_selected_default_or_custom_home(
    tmp_path: Path,
    selection: str,
    enabled: bool,
) -> None:
    stale = tmp_path / "stale"
    selected = tmp_path / selection
    stale.mkdir(mode=0o700)
    selected.mkdir(mode=0o700)
    (stale / "config.yaml").write_text(
        f"platforms:\n  whatsapp:\n    enabled: {str(not enabled).lower()}\n",
        encoding="utf-8",
    )
    (selected / "config.yaml").write_text(
        f"platforms:\n  whatsapp:\n    enabled: {str(enabled).lower()}\n",
        encoding="utf-8",
    )
    def probe(home: Path) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["HERMES_HOME"] = str(home)
        return subprocess.run(
            [sys.executable, "-m", "hermes_cli.whatsapp_runtime"],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )

    assert probe(stale).stdout.strip().startswith(
        f"enabled={str(not enabled).lower()};"
    )
    result = probe(selected)
    assert result.stdout.strip().startswith(f"enabled={str(enabled).lower()};")


def test_simplified_chinese_windows_contract_is_current_and_fail_closed() -> None:
    windows = (
        ROOT
        / "website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/user-guide/windows-native.md"
    ).read_text(encoding="utf-8")
    whatsapp = (
        ROOT
        / "website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/user-guide/messaging/whatsapp.md"
    ).read_text(encoding="utf-8")
    contributing = (
        ROOT
        / "website/i18n/zh-Hans/docusaurus-plugin-content-docs/current/developer-guide/contributing.md"
    ).read_text(encoding="utf-8")
    assert "Node.js 22.22+" in windows
    assert "Node.js 22.22+" in whatsapp
    assert "Node.js 22.22+" in contributing
    assert "原生 Windows 不支持 Baileys 离线预配" in windows
    assert "不会创建会话或显示二维码" in windows
