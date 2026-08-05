"""Production resolver coverage for reviewed WhatsApp bridge mirrors."""

import multiprocessing
import os
from pathlib import Path
import shutil

import pytest

from gateway.platforms import whatsapp_common


_REVIEWED_BRIDGE = (
    Path(__file__).resolve().parents[2] / "scripts" / "whatsapp-bridge"
)


def _seed_reviewed_install_tree(install_bridge: Path) -> None:
    install_bridge.mkdir(parents=True)
    for name in whatsapp_common._ORDINARY_MIRROR_FILES:
        shutil.copy2(_REVIEWED_BRIDGE / name, install_bridge / name)


@pytest.fixture
def resolver_tree(tmp_path: Path, monkeypatch):
    install_root = tmp_path / "install"
    install_bridge = install_root / "scripts" / "whatsapp-bridge"
    _seed_reviewed_install_tree(install_bridge)
    hermes_home = tmp_path / "hermes-home"
    hermes_home.mkdir(mode=0o700)
    monkeypatch.setattr(
        whatsapp_common, "__file__",
        str(install_root / "gateway" / "platforms" / "whatsapp_common.py"),
    )
    monkeypatch.setattr("hermes_constants.get_hermes_home", lambda: hermes_home)
    return install_bridge, hermes_home


def _force_read_only(monkeypatch, install_bridge: Path) -> None:
    real_mkstemp = whatsapp_common.tempfile.mkstemp

    def denied(*args, **kwargs):
        if Path(kwargs.get("dir")) == install_bridge:
            raise PermissionError("read-only reviewed install")
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr(whatsapp_common.tempfile, "mkstemp", denied)


def _expected_mirror(hermes_home: Path) -> Path:
    return (
        hermes_home / "scripts" / ".whatsapp-bridge-mirrors"
        / whatsapp_common._reviewed_bridge_identity()
    )


def _resolve_in_child(results) -> None:
    try:
        results.put(("ok", str(whatsapp_common.resolve_whatsapp_bridge_dir())))
    except BaseException as exc:
        results.put(("error", type(exc).__name__))


def test_writable_reviewed_install_is_preserved(resolver_tree):
    install_bridge, _ = resolver_tree
    assert whatsapp_common.resolve_whatsapp_bridge_dir() == install_bridge


def test_readonly_install_without_mirror_is_atomically_mirrored(
    resolver_tree, monkeypatch,
):
    install_bridge, hermes_home = resolver_tree
    _force_read_only(monkeypatch, install_bridge)
    resolved = whatsapp_common.resolve_whatsapp_bridge_dir()
    assert resolved == _expected_mirror(hermes_home)
    assert stat_mode(resolved) == 0o700
    assert set(whatsapp_common._ORDINARY_MIRROR_FILES) <= {
        item.name for item in resolved.iterdir()
    }
    whatsapp_common._reviewed_bridge_files(resolved)


def test_stale_static_mirror_is_never_selected(resolver_tree, monkeypatch):
    install_bridge, hermes_home = resolver_tree
    _force_read_only(monkeypatch, install_bridge)
    stale = hermes_home / "scripts" / "whatsapp-bridge"
    stale.mkdir(parents=True)
    (stale / "launcher.js").write_text("// stale pre-cycle-3 launcher\n")
    resolved = whatsapp_common.resolve_whatsapp_bridge_dir()
    assert resolved == _expected_mirror(hermes_home)
    assert resolved != stale
    assert (stale / "launcher.js").read_text() == "// stale pre-cycle-3 launcher\n"


def test_current_complete_mirror_is_reused_with_dependency_tree(
    resolver_tree, monkeypatch,
):
    install_bridge, _ = resolver_tree
    _force_read_only(monkeypatch, install_bridge)
    first = whatsapp_common.resolve_whatsapp_bridge_dir()
    dependency = first / "node_modules" / "synthetic-dependency"
    dependency.mkdir(parents=True)
    (dependency / "package.json").write_text('{"name":"synthetic"}\n')
    second = whatsapp_common.resolve_whatsapp_bridge_dir()
    assert second == first
    assert (dependency / "package.json").is_file()


@pytest.mark.parametrize("damage", ["partial", "corrupt", "symlink"])
def test_partial_or_corrupt_content_addressed_mirror_is_replaced(
    resolver_tree, monkeypatch, damage: str,
):
    install_bridge, hermes_home = resolver_tree
    _force_read_only(monkeypatch, install_bridge)
    destination = _expected_mirror(hermes_home)
    destination.parent.mkdir(parents=True, mode=0o700)
    if damage == "symlink":
        target = hermes_home / "attacker-tree"
        target.mkdir()
        destination.symlink_to(target, target_is_directory=True)
    else:
        destination.mkdir(mode=0o700)
        (destination / "launcher.js").write_text(
            "// partial\n" if damage == "partial" else "// corrupt\n"
        )
    resolved = whatsapp_common.resolve_whatsapp_bridge_dir()
    assert resolved == destination
    assert not resolved.is_symlink()
    whatsapp_common._reviewed_bridge_files(resolved)


def test_concurrent_readonly_resolution_converges_on_one_complete_mirror(
    resolver_tree, monkeypatch,
):
    install_bridge, hermes_home = resolver_tree
    _force_read_only(monkeypatch, install_bridge)
    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    processes = [context.Process(target=_resolve_in_child, args=(queue,)) for _ in range(12)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
    outcomes = [queue.get(timeout=2) for _ in processes]
    expected = _expected_mirror(hermes_home)
    assert all(process.exitcode == 0 for process in processes)
    assert set(outcomes) == {("ok", str(expected))}
    whatsapp_common._reviewed_bridge_files(expected)
    assert not list(expected.parent.glob(".*.stage-*"))


def test_sync_failure_never_falls_back_to_static_or_readonly_source(
    resolver_tree, monkeypatch,
):
    install_bridge, hermes_home = resolver_tree
    _force_read_only(monkeypatch, install_bridge)
    stale = hermes_home / "scripts" / "whatsapp-bridge"
    stale.mkdir(parents=True)
    (stale / "launcher.js").write_text("// stale\n")
    monkeypatch.setattr(
        whatsapp_common, "_write_staged_bridge",
        lambda *_args: (_ for _ in ()).throw(OSError("synthetic sync failure")),
    )
    with pytest.raises(OSError, match="synthetic sync failure"):
        whatsapp_common.resolve_whatsapp_bridge_dir()


def test_launcher_anchor_accepts_candidate_and_rejects_old_bytes(tmp_path: Path):
    candidate = _REVIEWED_BRIDGE / "launcher.js"
    assert whatsapp_common.verify_ordinary_launcher(candidate)
    old = tmp_path / "launcher.js"
    old.write_bytes(b"// pre-cycle-3 launcher bytes\n")
    old.chmod(0o700)
    assert not whatsapp_common.verify_ordinary_launcher(old)


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
