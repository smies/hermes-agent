from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from unittest.mock import patch

import pytest

from hermes_cli.whatsapp_provisioning import (
    _acquire_provisioning_lock,
    _minimal_node_environment,
    _PAIRING_CODE_ALPHABET,
    _PAIRING_CODE_RE,
    _provisioner_script,
    WhatsAppProvisioningError,
    command,
    resolve_provisioning_roots,
    run_whatsapp_provisioning,
)


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_python_pairing_validator_uses_exact_rc14_alphabet() -> None:
    assert _PAIRING_CODE_ALPHABET == "123456789ABCDEFGHJKLMNPQRSTVWXYZ"
    assert _PAIRING_CODE_RE.fullmatch("WXYZ1234") is not None
    for impossible in ("00000000", "ABCDI234", "ABCDO234", "ABCDU234"):
        assert _PAIRING_CODE_RE.fullmatch(impossible) is None


def test_sensitive_provision_launcher_is_bound_by_host_source_identity() -> None:
    assert _provisioner_script().name == "provision_launcher.js"
    with patch.object(Path, "read_bytes", return_value=b"synthetic-tampering"):
        with pytest.raises(WhatsAppProvisioningError, match="identity mismatch"):
            _provisioner_script()


class _Process:
    def __init__(self, output: str, returncode: int = 0, operator_event: str = ""):
        self.output = output
        self.returncode = returncode
        self.pid = 123
        self.kwargs = None
        self.request = None
        self.stdin = self._Input(self)
        self.stderr = io.StringIO(operator_event)

    class _Input:
        def __init__(self, owner):
            self.owner = owner

        def write(self, request: str):
            self.owner.request = request

        def close(self):
            return None

    def communicate(self, timeout: float):
        return self.output, None

    def poll(self):
        return self.returncode


def test_valid_existing_session_returns_ready_without_pairing_code(tmp_path: Path) -> None:
    process = _Process(
        json.dumps(
            {
                "event": "complete",
                "state": "ready_for_production",
                "lid_ready": True,
                "account_namespace": "fixture-namespace",
            }
        )
        + "\n"
    )
    operator = io.StringIO()
    machine = io.StringIO()
    roots = (tmp_path / "ordinary", tmp_path / "sensitive")
    with (
        patch("hermes_cli.whatsapp_provisioning.find_node_executable", return_value="/bin/node"),
        patch("hermes_cli.whatsapp_provisioning.resolve_provisioning_roots", return_value=roots),
        patch("hermes_cli.whatsapp_provisioning._provisioner_script", return_value=tmp_path / "offline.js"),
        patch("hermes_cli.whatsapp_provisioning._ensure_provisioner_dependencies"),
        patch("hermes_cli.whatsapp_provisioning.subprocess.Popen", return_value=process) as popen,
    ):
        result = run_whatsapp_provisioning(
            "ordinary",
            phone=None,
            operator=operator,
            machine_output=machine,
            validate_only=True,
        )
    assert result["state"] == "ready_for_production"
    assert "pairing code" not in operator.getvalue().lower()
    args, kwargs = popen.call_args
    assert args[0] == ["/bin/node", str(tmp_path / "offline.js")]
    assert "phone" not in args[0]
    assert set(kwargs["env"]) <= {"PATH", "LANG", "LC_ALL", "TZ", "NODE_PATH"}
    request = json.loads(process.request)
    assert request["action"] == "validate"
    assert "phone" not in request
    assert not (tmp_path / ".hermes-whatsapp-provision.lock").exists()


def test_pairing_code_is_only_written_to_explicit_operator_channel(tmp_path: Path) -> None:
    code = "ABCD3FGH"
    process = _Process(
        json.dumps(
            {"event": "complete", "state": "ready_for_production", "lid_ready": True}
        )
        + "\n",
        operator_event=json.dumps({"event": "pairing_code", "code": code}) + "\n",
    )
    operator = _TTY()
    machine = io.StringIO()
    roots = (tmp_path / "ordinary", tmp_path / "sensitive")
    with (
        patch("hermes_cli.whatsapp_provisioning.find_node_executable", return_value="/bin/node"),
            patch("hermes_cli.whatsapp_provisioning.resolve_provisioning_roots", return_value=roots),
            patch("hermes_cli.whatsapp_provisioning._provisioner_script", return_value=tmp_path / "offline.js"),
            patch("hermes_cli.whatsapp_provisioning._ensure_provisioner_dependencies"),
            patch("hermes_cli.whatsapp_provisioning.subprocess.Popen", return_value=process),
        ):
        run_whatsapp_provisioning(
            "sensitive",
            phone="+15551234567",
            operator=operator,
            machine_output=machine,
        )
    assert code in operator.getvalue()
    assert code not in machine.getvalue()
    assert code not in repr(process.request)
    assert json.loads(process.request)["phone"] == "+15551234567"
    assert process.kwargs is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX Node operator-channel contract")
def test_real_node_boundary_surfaces_allowlisted_pre_code_failure_without_mutation(
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    fixture = tmp_path / "provisioner-fixture.mjs"
    fixture.write_text(
        """
let request = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { request += chunk; });
process.stdin.on('end', () => {
  JSON.parse(request);
  process.stderr.write(JSON.stringify({
    event: 'pairing_failure', reason: 'pairing_request_failed',
  }) + '\\n');
  process.stdout.write(JSON.stringify({
    event: 'complete', state: 'needs_provisioning',
  }) + '\\n');
  process.exitCode = 1;
});
""",
        encoding="utf-8",
    )
    ordinary = tmp_path / "ordinary"
    sensitive = tmp_path / "sensitive"
    operator = _TTY()
    machine = io.StringIO()
    with (
        patch(
            "hermes_cli.whatsapp_provisioning.find_node_executable",
            return_value=node,
        ),
        patch(
            "hermes_cli.whatsapp_provisioning.resolve_provisioning_roots",
            return_value=(ordinary, sensitive),
        ),
        patch(
            "hermes_cli.whatsapp_provisioning._provisioner_script",
            return_value=fixture,
        ),
        patch("hermes_cli.whatsapp_provisioning._ensure_provisioner_dependencies"),
        pytest.raises(
            WhatsAppProvisioningError,
            match="pairing-code request failed before a code was issued",
        ),
    ):
        run_whatsapp_provisioning(
            "sensitive",
            phone="+15551234567",
            operator=operator,
            machine_output=machine,
        )
    assert operator.getvalue() == ""
    assert machine.getvalue() == ""
    assert not ordinary.exists()
    assert not sensitive.exists()


def test_noninteractive_operator_is_rejected_before_spawn() -> None:
    with pytest.raises(WhatsAppProvisioningError, match="interactive operator"):
        run_whatsapp_provisioning(
            "ordinary",
            phone=None,
            operator=io.StringIO(),
            machine_output=io.StringIO(),
            validate_only=False,
        )


def test_profile_roots_are_canonical_owner_only_and_not_created_by_validation(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o700)
    ordinary = profile / "ordinary" / "session"
    sensitive = profile / "sensitive-delivery" / "whatsapp" / "session"
    with (
        patch(
            "hermes_cli.whatsapp_provisioning.get_hermes_dir",
            return_value=ordinary,
        ),
        patch(
            "hermes_cli.whatsapp_provisioning.get_hermes_home",
            return_value=profile,
        ),
    ):
        assert resolve_provisioning_roots() == (ordinary, sensitive)
    assert not ordinary.exists()
    assert not sensitive.exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX advisory-lock contract")
@pytest.mark.live_system_guard_bypass
def test_provisioning_lock_releases_on_owner_death_and_serializes_roles(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o700)
    ordinary = tmp_path / "ordinary"
    sensitive = tmp_path / "sensitive"
    child_code = """
import sys, time
from pathlib import Path
from hermes_cli.whatsapp_provisioning import _acquire_provisioning_lock
fd = _acquire_provisioning_lock(Path(sys.argv[1]), Path(sys.argv[2]))
print('locked', flush=True)
time.sleep(60)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", child_code, str(ordinary), str(sensitive)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        cwd=str(Path(__file__).resolve().parents[2]),
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "locked"
        with pytest.raises(WhatsAppProvisioningError, match="another .* active"):
            _acquire_provisioning_lock(ordinary, sensitive)
        child.terminate()
        child.wait(timeout=5)
        descriptor = _acquire_provisioning_lock(ordinary, sensitive)
        os.close(descriptor)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


@pytest.mark.parametrize("unsafe", ["mode", "symlink"])
def test_profile_root_mode_and_symlink_attacks_are_rejected(
    tmp_path: Path, unsafe: str
) -> None:
    profile = tmp_path / "profile"
    profile.mkdir(mode=0o700)
    target = profile / "target"
    target.mkdir(mode=0o700)
    ordinary = profile / "ordinary"
    if unsafe == "symlink":
        ordinary.symlink_to(target, target_is_directory=True)
    else:
        ordinary.mkdir(mode=0o700)
        ordinary.chmod(0o755)
    sensitive = profile / "sensitive-delivery" / "whatsapp" / "session"
    with (
        patch(
            "hermes_cli.whatsapp_provisioning.get_hermes_dir",
            return_value=ordinary,
        ),
        patch(
            "hermes_cli.whatsapp_provisioning.get_hermes_home",
            return_value=profile,
        ),
        pytest.raises(WhatsAppProvisioningError),
    ):
        resolve_provisioning_roots()


def test_native_windows_is_rejected_before_setup_or_spawn(tmp_path: Path) -> None:
    with (
        patch("hermes_cli.whatsapp_provisioning._is_windows", return_value=True),
        patch("hermes_cli.whatsapp_provisioning.find_node_executable") as find_node,
        patch("hermes_cli.whatsapp_provisioning.resolve_provisioning_roots") as roots,
        patch("hermes_cli.whatsapp_provisioning._ensure_provisioner_dependencies") as deps,
        patch("hermes_cli.whatsapp_provisioning.subprocess.Popen") as popen,
        pytest.raises(WhatsAppProvisioningError, match="native Windows.*unsupported"),
    ):
        run_whatsapp_provisioning(
            "ordinary",
            phone="15550001111",
            operator=_TTY(),
            machine_output=io.StringIO(),
        )
    find_node.assert_not_called()
    roots.assert_not_called()
    deps.assert_not_called()
    popen.assert_not_called()


def test_native_windows_command_rejects_before_phone_or_config() -> None:
    args = type("Args", (), {
        "role": "ordinary",
        "validate_only": False,
        "reprovision": True,
    })()
    with (
        patch("hermes_cli.whatsapp_provisioning._is_windows", return_value=True),
        patch("hermes_cli.whatsapp_provisioning.run_whatsapp_provisioning") as run,
        patch("cli.save_config_value") as save,
        patch("hermes_cli.whatsapp_provisioning.sys.stdin", _TTY("15550001111\n")),
        pytest.raises(WhatsAppProvisioningError, match="native Windows.*unsupported"),
    ):
        command(args)
    run.assert_not_called()
    save.assert_not_called()


def test_minimal_child_environment_preserves_windows_runtime_requirements(
    monkeypatch,
) -> None:
    required = {
        "SYSTEMROOT": r"C:\\Windows",
        "WINDIR": r"C:\\Windows",
        "COMSPEC": r"C:\\Windows\\System32\\cmd.exe",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "USERPROFILE": r"C:\\Users\\fixture",
        "LOCALAPPDATA": r"C:\\Users\\fixture\\AppData\\Local",
        "APPDATA": r"C:\\Users\\fixture\\AppData\\Roaming",
        "PROGRAMDATA": r"C:\\ProgramData",
        "TEMP": r"C:\\Temp",
        "TMP": r"C:\\Temp",
    }
    for name, value in required.items():
        monkeypatch.setenv(name, value)

    environment = _minimal_node_environment("/bin/node")

    assert {name: environment[name] for name in required} == required


@pytest.mark.parametrize(
    ("role", "validate_only", "saved"),
    [
        ("ordinary", False, [("platforms.whatsapp.enabled", True)]),
        ("sensitive", False, []),
        ("ordinary", True, []),
    ],
)
def test_canonical_config_enablement_is_role_and_action_scoped(
    role: str,
    validate_only: bool,
    saved: list[tuple[str, bool]],
) -> None:
    args = type("Args", (), {
        "role": role,
        "validate_only": validate_only,
        "reprovision": not validate_only,
    })()
    observed = []
    ready = {"state": "ready_for_production", "lid_ready": True}
    with (
        patch("hermes_cli.whatsapp_provisioning.run_whatsapp_provisioning", return_value=ready),
        patch("hermes_cli.whatsapp_provisioning.sys.stdin", _TTY("15550001111\n")),
        patch("hermes_cli.whatsapp_provisioning.sys.stderr", _TTY()),
        patch("cli.save_config_value", side_effect=lambda key, value: observed.append((key, value)) or True),
    ):
        assert command(args) == 0
    assert observed == saved


def test_ready_ordinary_reuse_enables_canonical_config_without_reprovision() -> None:
    args = type("Args", (), {
        "role": "ordinary",
        "validate_only": False,
        "reprovision": False,
    })()
    observed = []
    ready = {"state": "ready_for_production", "lid_ready": True}
    with (
        patch(
            "hermes_cli.whatsapp_provisioning.run_whatsapp_provisioning",
            return_value=ready,
        ) as run,
        patch("hermes_cli.whatsapp_provisioning.sys.stdin", _TTY()),
        patch("hermes_cli.whatsapp_provisioning.sys.stderr", _TTY()),
        patch(
            "cli.save_config_value",
            side_effect=lambda key, value: observed.append((key, value)) or True,
        ),
    ):
        assert command(args) == 0
    assert run.call_count == 1
    assert run.call_args.kwargs["validate_only"] is True
    assert observed == [("platforms.whatsapp.enabled", True)]


def test_failed_atomic_config_write_does_not_report_success() -> None:
    args = type("Args", (), {
        "role": "ordinary",
        "validate_only": False,
        "reprovision": True,
    })()
    ready = {"state": "ready_for_production", "lid_ready": True}
    with (
        patch("hermes_cli.whatsapp_provisioning.run_whatsapp_provisioning", return_value=ready),
        patch("hermes_cli.whatsapp_provisioning.sys.stdin", _TTY("15550001111\n")),
        patch("hermes_cli.whatsapp_provisioning.sys.stderr", _TTY()),
        patch("cli.save_config_value", return_value=False),
        pytest.raises(WhatsAppProvisioningError, match="configuration was not enabled"),
    ):
        command(args)


def test_interrupted_atomic_config_write_preserves_existing_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    hermes_home = tmp_path / "hermes"
    hermes_home.mkdir(mode=0o700)
    config = hermes_home / "config.yaml"
    original = b"platforms:\n  whatsapp:\n    enabled: false\n"
    config.write_bytes(original)
    config.chmod(0o600)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    args = type("Args", (), {
        "role": "ordinary",
        "validate_only": False,
        "reprovision": True,
    })()
    ready = {"state": "ready_for_production", "lid_ready": True}
    with (
        patch("hermes_cli.whatsapp_provisioning.run_whatsapp_provisioning", return_value=ready),
        patch("hermes_cli.whatsapp_provisioning.sys.stdin", _TTY("15550001111\n")),
        patch("hermes_cli.whatsapp_provisioning.sys.stderr", _TTY()),
        patch(
            "utils.atomic_roundtrip_yaml_update",
            side_effect=KeyboardInterrupt,
        ),
        pytest.raises(KeyboardInterrupt),
    ):
        command(args)
    assert config.read_bytes() == original


def test_posix_timeout_terminates_reaps_and_releases_lock(
    tmp_path: Path,
) -> None:
    class TimedOutProcess(_Process):
        def __init__(self):
            super().__init__("")
            self.running = True
            self.terminated = 0
            self.killed = 0
            self.waited = 0

        def communicate(self, timeout: float):
            raise __import__("subprocess").TimeoutExpired(["node"], timeout)

        def poll(self):
            return None if self.running else self.returncode

        def wait(self, timeout: float):
            self.waited += 1
            return self.returncode

    process = TimedOutProcess()
    roots = (tmp_path / "ordinary", tmp_path / "sensitive")
    with (
        patch("hermes_cli.whatsapp_provisioning.find_node_executable", return_value="/bin/node"),
        patch("hermes_cli.whatsapp_provisioning.resolve_provisioning_roots", return_value=roots),
        patch("hermes_cli.whatsapp_provisioning._provisioner_script", return_value=tmp_path / "offline.js"),
        patch("hermes_cli.whatsapp_provisioning._ensure_provisioner_dependencies"),
        patch("hermes_cli.whatsapp_provisioning.subprocess.Popen", return_value=process),
        patch(
            "hermes_cli.whatsapp_provisioning.os.killpg",
            side_effect=lambda *_args: setattr(process, "running", False),
        ) as killpg,
        pytest.raises(__import__("subprocess").TimeoutExpired),
    ):
        run_whatsapp_provisioning(
            "ordinary",
            phone="15550001111",
            operator=_TTY(),
            machine_output=io.StringIO(),
            timeout_seconds=0.1,
        )
    assert killpg.call_count == 1
    assert process.waited == 1
