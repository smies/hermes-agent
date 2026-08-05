"""Tests for ``hermes update --eject`` (hermes_cli/update_cmd.py::cmd_update_eject).

Uses real git repos (not mocks) per the repo's E2E-validation preference:
a local "origin" plus a depth-1 clone reproduce exactly what a bundled
desktop payload checkout looks like.
"""

import subprocess

import pytest

from hermes_cli.install_manifest import (
    CHANNEL_MAIN,
    CHANNEL_STABLE,
    MODE_BUNDLED,
    MODE_SOURCE,
    read_install_manifest,
    write_install_manifest,
)
from hermes_cli.update_cmd import cmd_update_eject


def _git(cwd, *args):
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True, text=True, encoding="utf-8",
    )
    assert result.returncode == 0, f"git {args} failed: {result.stderr}"
    return result.stdout.strip()


@pytest.fixture
def bundled_checkout(tmp_path):
    """A depth-1 clone of a local origin, manifest-marked as bundled."""
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-b", "main")
    _git(origin, "config", "user.email", "test@example.com")
    _git(origin, "config", "user.name", "test")
    for i in range(3):
        (origin / f"f{i}.txt").write_text(f"content {i}\n")
        _git(origin, "add", ".")
        _git(origin, "commit", "-m", f"commit {i}")
    _git(origin, "tag", "v0.1.0")

    checkout = tmp_path / "checkout"
    subprocess.run(
        ["git", "clone", "--depth", "1", f"file://{origin}", str(checkout)],
        capture_output=True, text=True, check=True,
    )
    write_install_manifest(
        {"installMode": MODE_BUNDLED, "channel": CHANNEL_STABLE, "pinnedTag": "v0.1.0"},
        checkout,
    )
    return checkout


class _Args:
    def __init__(self, channel=None):
        self.eject = True
        self.channel = channel


def _patch_project_root(monkeypatch, root):
    import hermes_cli.main as hermes_main

    monkeypatch.setattr(hermes_main, "PROJECT_ROOT", root)


class TestEjectBundled:
    def test_eject_unshallows_and_flips_mode(self, bundled_checkout, monkeypatch, capsys):
        _patch_project_root(monkeypatch, bundled_checkout)
        assert _git(bundled_checkout, "rev-parse", "--is-shallow-repository") == "true"

        rc = cmd_update_eject(_Args())

        assert rc == 0
        assert _git(bundled_checkout, "rev-parse", "--is-shallow-repository") == "false"
        manifest = read_install_manifest(bundled_checkout)
        assert manifest["installMode"] == MODE_SOURCE
        assert manifest["channel"] == CHANNEL_MAIN  # default eject channel
        # Provenance pin survives for forensics.
        assert manifest["pinnedTag"] == "v0.1.0"
        # Full history + tags are now available.
        assert _git(bundled_checkout, "rev-list", "--count", "HEAD") == "3"
        assert "v0.1.0" in _git(bundled_checkout, "tag", "--list")
        assert "Ejected" in capsys.readouterr().out

    def test_eject_with_stable_channel(self, bundled_checkout, monkeypatch):
        _patch_project_root(monkeypatch, bundled_checkout)
        rc = cmd_update_eject(_Args(channel="stable"))
        assert rc == 0
        assert read_install_manifest(bundled_checkout)["channel"] == CHANNEL_STABLE

    def test_failed_fetch_leaves_manifest_untouched(self, bundled_checkout, monkeypatch, capsys):
        """Eject must be atomic-ish: no mode flip if git fetch fails."""
        _patch_project_root(monkeypatch, bundled_checkout)
        _git(bundled_checkout, "remote", "set-url", "origin", "file:///nonexistent/repo")

        rc = cmd_update_eject(_Args())

        assert rc == 1
        manifest = read_install_manifest(bundled_checkout)
        assert manifest["installMode"] == MODE_BUNDLED
        assert "aborted" in capsys.readouterr().out

    def test_missing_git_dir_refuses(self, tmp_path, monkeypatch, capsys):
        root = tmp_path / "nogit"
        root.mkdir()
        write_install_manifest(
            {"installMode": MODE_BUNDLED, "channel": CHANNEL_STABLE}, root
        )
        _patch_project_root(monkeypatch, root)

        rc = cmd_update_eject(_Args())

        assert rc == 1
        assert read_install_manifest(root)["installMode"] == MODE_BUNDLED
        assert "not a git repository" in capsys.readouterr().out


class TestEjectOnSourceInstalls:
    def test_noop_without_channel(self, tmp_path, monkeypatch, capsys):
        root = tmp_path / "src"
        root.mkdir()
        _patch_project_root(monkeypatch, root)

        rc = cmd_update_eject(_Args())

        assert rc == 0
        assert "already source-managed" in capsys.readouterr().out
        # No manifest is created by a pure no-op eject... actually one may be
        # absent entirely; reading it must still say source/main.
        manifest = read_install_manifest(root)
        assert manifest["installMode"] == MODE_SOURCE

    def test_channel_switch_shorthand(self, tmp_path, monkeypatch):
        """--eject --channel stable on a source install just sets the channel."""
        root = tmp_path / "src"
        root.mkdir()
        _patch_project_root(monkeypatch, root)

        rc = cmd_update_eject(_Args(channel="stable"))

        assert rc == 0
        manifest = read_install_manifest(root)
        assert manifest["installMode"] == MODE_SOURCE
        assert manifest["channel"] == CHANNEL_STABLE
