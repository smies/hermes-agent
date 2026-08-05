#!/usr/bin/env python3
"""Run the Juno cross-runtime vertical from private copied Node trees.

This runner never installs into or symlinks dependencies from the worktree.
Both Node packages are copied to a mode-0700 temporary tree and installed from
their committed lockfiles before pytest receives the exact copied paths.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def _assert_no_symlinks(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("isolated Node tree contains a symlink")


def _assert_symlinks_stay_private(root: Path, private: Path) -> None:
    private_resolved = private.resolve()
    for path in root.rglob("*"):
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(private_resolved):
                raise RuntimeError("isolated Node dependency symlink escapes private tree")


def _install(package: Path, cache: Path, private: Path, *, offline: bool) -> None:
    offline_args = ["--offline"] if offline else []
    subprocess.run(
        [
            "npm", "ci", "--ignore-scripts",
            "--no-audit", "--no-fund", "--cache", str(cache),
            *offline_args,
        ],
        check=True,
        cwd=package,
        env={**os.environ, "HOME": str(cache.parent)},
        timeout=300,
    )
    _assert_symlinks_stay_private(package, private)


def _seed_locked_cache(source: Path, destination: Path, locks: tuple[Path, ...]) -> None:
    """Copy only indexed metadata and lockfile-addressed npm content."""
    cacache = source / "_cacache"
    shutil.copytree(cacache / "index-v5", destination / "_cacache" / "index-v5")
    for lock_path in locks:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        for package in lock.get("packages", {}).values():
            integrity = package.get("integrity") if type(package) is dict else None
            if not integrity:
                continue
            algorithm, encoded = integrity.split("-", 1)
            digest = base64.b64decode(encoded, validate=True).hex()
            relative = Path("content-v2") / algorithm / digest[:2] / digest[2:4] / digest[4:]
            source_file = cacache / relative
            if not source_file.is_file():
                if package.get("optional") is True:
                    continue
                raise RuntimeError("required lockfile artifact is absent from cache seed")
            destination_file = destination / "_cacache" / relative
            destination_file.parent.mkdir(parents=True, exist_ok=True)
            if not destination_file.exists():
                shutil.copy2(source_file, destination_file)


def _run_node_suite(package: Path, private: Path) -> None:
    tests = sorted(str(path.resolve()) for path in package.glob("*.test.mjs"))
    subprocess.run(
        ["node", "--test", "--test-concurrency=1", *tests],
        check=True, cwd=package, env={**os.environ, "HOME": str(private / "home")},
        timeout=300,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="juno-private-vertical-") as raw:
        private = Path(raw)
        private.chmod(0o700)
        scripts = private / "scripts"
        fixtures = private / "tests" / "fixtures"
        scripts.mkdir(parents=True)
        fixtures.mkdir(parents=True)
        ordinary = scripts / "whatsapp-bridge"
        sensitive = scripts / "whatsapp-sensitive-bridge"
        ignore_installed = shutil.ignore_patterns("node_modules")
        shutil.copytree(
            ROOT / "scripts/whatsapp-bridge", ordinary, ignore=ignore_installed,
        )
        shutil.copytree(
            ROOT / "scripts/whatsapp-sensitive-bridge", sensitive,
            ignore=ignore_installed,
        )
        shutil.copy2(
            ROOT / "tests/fixtures/juno_sensitive_http_harness.mjs",
            fixtures / "juno_sensitive_http_harness.mjs",
        )
        shutil.copy2(
            ROOT / "tests/fixtures/juno_ordinary_bridge_harness.mjs",
            fixtures / "juno_ordinary_bridge_harness.mjs",
        )
        shutil.copy2(
            ROOT / "tests/fixtures/juno_sensitive_core_boundary_loader.mjs",
            fixtures / "juno_sensitive_core_boundary_loader.mjs",
        )
        shutil.copy2(ROOT / ".npmrc", private / ".npmrc")
        _assert_no_symlinks(private)
        cache = private / "npm-cache"
        cache.mkdir(mode=0o700)
        seed_value = os.environ.get("JUNO_NPM_CACHE_SEED")
        if seed_value:
            seed = Path(seed_value).resolve(strict=True)
            _seed_locked_cache(
                seed, cache,
                (ordinary / "package-lock.json", sensitive / "package-lock.json"),
            )
        _install(ordinary, cache, private, offline=bool(seed_value))
        _install(sensitive, cache, private, offline=bool(seed_value))
        sabotaged_ordinary = scripts / "whatsapp-bridge-registration-sabotage"
        shutil.copytree(ordinary, sabotaged_ordinary, symlinks=True)
        sabotaged_bridge = sabotaged_ordinary / "bridge.js"
        live_call = (
            "registerProductionInboundMessageHandler({ "
            "connectionSocket, isActiveSocket });"
        )
        source = sabotaged_bridge.read_text(encoding="utf-8")
        if source.count(live_call) != 1:
            raise RuntimeError("actual startSocket registration call is not unique")
        sabotaged_bridge.write_text(
            source.replace(
                live_call,
                "registerProductionInboundMessageHandler({ connectionSocket, "
                "isActiveSocket: () => false });",
            ),
            encoding="utf-8",
        )
        _assert_symlinks_stay_private(sabotaged_ordinary, private)
        isolated_home = private / "home"
        isolated_hermes = private / "hermes-home"
        isolated_home.mkdir(mode=0o700)
        isolated_hermes.mkdir(mode=0o700)
        _run_node_suite(ordinary, private)
        _run_node_suite(sensitive, private)
        env = {
            **os.environ,
            "HOME": str(isolated_home),
            "HERMES_HOME": str(isolated_hermes),
            "XDG_CACHE_HOME": str(private / "cache"),
            "PYTHONPYCACHEPREFIX": str(private / "pycache"),
            "JUNO_ISOLATED_BRIDGE_MODULE": str(ordinary / "bridge.js"),
            "JUNO_ISOLATED_SABOTAGED_BRIDGE_MODULE": str(
                sabotaged_ordinary / "bridge.js"
            ),
            "JUNO_ISOLATED_ORDINARY_HARNESS": str(
                fixtures / "juno_ordinary_bridge_harness.mjs"
            ),
            "JUNO_ISOLATED_SENSITIVE_HARNESS": str(
                fixtures / "juno_sensitive_http_harness.mjs"
            ),
            "JUNO_ISOLATED_SENSITIVE_BOUNDARY_LOADER": str(
                fixtures / "juno_sensitive_core_boundary_loader.mjs"
            ),
            "JUNO_ISOLATED_SENSITIVE_PACKAGE": str(sensitive),
        }
        completed = subprocess.run(
            [
                sys.executable, "-m", "pytest", "-q",
                "-rs",
                "tests/gateway/test_juno_private_read_mvp_remediation.py",
                "-k", (
                    "actual_start_socket_route_adapter_dispatch or "
                    "actual_start_socket_registration_mutation_blocks_dispatch or "
                    "sensitive_launcher_mutation_rejects_before_core_import or "
                    "offline_cross_runtime_producer_to_private_delivery_vertical or "
                    "no_socket_vertical_preserves_producer_adapter_and_replay_contract"
                ),
            ],
            cwd=ROOT,
            env=env,
            timeout=180,
        )
        return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
