"""Regression tests for #48130: Windows npm lifecycle scripts need node on PATH.

The desktop installer can resolve ``npm.cmd`` while postinstall hooks fail with
``'node' is not recognized`` because child ``cmd.exe`` processes do not inherit
a PATH that includes ``node.exe``'s directory.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_PS1 = REPO_ROOT / "scripts" / "install.ps1"


def _install_ps1() -> str:
    return INSTALL_PS1.read_text(encoding="utf-8")


def test_install_ps1_defines_ensure_node_exe_on_path_helper() -> None:
    text = _install_ps1()
    assert "function Ensure-NodeExeOnPath" in text
    assert re.search(
        r"\$env:Path\s*=\s*\"\$nodeExeDir;\$env:Path\"",
        text,
    ), "Ensure-NodeExeOnPath must prepend node.exe's directory to PATH"


def test_test_node_prepends_node_dir_before_success() -> None:
    text = _install_ps1()
    assert re.search(
        r"if \(Test-NodeVersionOk \$version\) \{[\s\S]{0,200}?Ensure-NodeExeOnPath",
        text,
    ), "Test-Node must call Ensure-NodeExeOnPath when a system Node passes the version floor"


def test_install_node_deps_prepends_node_dir_before_npm() -> None:
    text = _install_ps1()
    assert re.search(
        r"function Install-NodeDeps \{[\s\S]{0,900}?Ensure-NodeExeOnPath[\s\S]{0,900}?Resolve npm explicitly",
        text,
    ), "Install-NodeDeps must call Ensure-NodeExeOnPath before invoking npm"


def test_winget_fallback_revalidates_exact_resolved_node_before_success() -> None:
    text = _install_ps1()
    branch = re.search(
        r"# Fallback: try winget(?P<body>[\s\S]*?)\n\s*Write-Info \"Install manually:",
        text,
    )
    assert branch is not None
    body = branch.group("body")
    assert "Get-Command node -CommandType Application" in body
    assert "& $resolvedNode.Source --version" in body
    assert re.search(
        r"if \(Test-NodeVersionOk \$version\) \{[\s\S]*?\$script:HasNode = \$true",
        body,
    )
    assert "PATH still resolves unsupported Node.js" in body


def test_winget_cannot_set_has_node_true_after_presence_only() -> None:
    text = _install_ps1()
    branch = re.search(
        r"# Fallback: try winget(?P<body>[\s\S]*?)\n\s*Write-Info \"Install manually:",
        text,
    )
    assert branch is not None
    body = branch.group("body")
    presence = body.index("if ($resolvedNode)")
    version_gate = body.index("if (Test-NodeVersionOk $version)", presence)
    success = body.index("$script:HasNode = $true", presence)
    assert presence < version_gate < success
    assert body.count("$script:HasNode = $true") == 1


def test_node_version_contract_rejects_stale_and_accepts_22_22_plus() -> None:
    text = _install_ps1()
    function = re.search(
        r"function Test-NodeVersionOk \{(?P<body>[\s\S]*?)\n\}", text
    )
    assert function is not None
    body = function.group("body")
    assert "if ($v.Major -eq 22) { return ($v.Minor -ge 22) }" in body
    assert "return ($v.Major -gt 22)" in body
    # These are the boundary examples the PowerShell clauses above encode.
    def version_ok(major: int, minor: int) -> bool:
        return minor >= 22 if major == 22 else major > 22

    assert version_ok(20, 99) is False
    assert version_ok(22, 21) is False
    assert version_ok(22, 22) is True
    assert version_ok(23, 0) is True
