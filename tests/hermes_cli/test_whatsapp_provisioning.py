from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from hermes_cli.whatsapp_provisioning import (
    WhatsAppProvisioningError,
    command,
    resolve_provisioning_roots,
    run_whatsapp_provisioning,
)


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


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


def test_pairing_code_is_only_written_to_explicit_operator_channel(tmp_path: Path) -> None:
    code = "ABCD-EFGH"
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
            phone="+" + "0" * 11,
            operator=operator,
            machine_output=machine,
        )
    assert code in operator.getvalue()
    assert code not in machine.getvalue()
    assert code not in repr(process.request)
    assert process.kwargs is None


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


def test_simulated_windows_uses_bounded_stdio_without_posix_handles(tmp_path: Path) -> None:
    code = "W1ND-0WS1"
    process = _Process(
        json.dumps({"event": "complete", "state": "ready_for_production", "lid_ready": True}) + "\n",
        operator_event=json.dumps({"event": "pairing_code", "code": code}) + "\n",
    )
    captured = {}

    def popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return process

    roots = (tmp_path / "ordinary", tmp_path / "sensitive")
    with (
        patch("hermes_cli.whatsapp_provisioning.find_node_executable", return_value="C:/node/node.exe"),
        patch("hermes_cli.whatsapp_provisioning.resolve_provisioning_roots", return_value=roots),
        patch("hermes_cli.whatsapp_provisioning._provisioner_script", return_value=tmp_path / "offline.js"),
        patch("hermes_cli.whatsapp_provisioning._ensure_provisioner_dependencies"),
        patch("hermes_cli.whatsapp_provisioning._is_windows", return_value=True),
        patch("hermes_cli.whatsapp_provisioning.subprocess.CREATE_NEW_PROCESS_GROUP", 512, create=True),
        patch("hermes_cli.whatsapp_provisioning.subprocess.Popen", side_effect=popen),
    ):
        operator = _TTY()
        machine = io.StringIO()
        result = run_whatsapp_provisioning(
            "ordinary",
            phone="15550001111",
            operator=operator,
            machine_output=machine,
        )
    assert result["state"] == "ready_for_production"
    assert captured["args"] == ["C:/node/node.exe", str(tmp_path / "offline.js"), "--operator-stdio"]
    assert captured["kwargs"]["creationflags"] == 512
    assert "pass_fds" not in captured["kwargs"]
    assert "start_new_session" not in captured["kwargs"]
    assert captured["kwargs"]["stderr"] is not None
    assert code in operator.getvalue()
    assert code not in machine.getvalue()
    assert "15550001111" not in repr(captured)


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


def test_simulated_windows_timeout_terminates_and_reaps_exact_child(
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

        def terminate(self):
            self.terminated += 1
            self.running = False

        def kill(self):
            self.killed += 1
            self.running = False

        def wait(self, timeout: float):
            self.waited += 1
            return self.returncode

    process = TimedOutProcess()
    roots = (tmp_path / "ordinary", tmp_path / "sensitive")
    with (
        patch("hermes_cli.whatsapp_provisioning.find_node_executable", return_value="C:/node/node.exe"),
        patch("hermes_cli.whatsapp_provisioning.resolve_provisioning_roots", return_value=roots),
        patch("hermes_cli.whatsapp_provisioning._provisioner_script", return_value=tmp_path / "offline.js"),
        patch("hermes_cli.whatsapp_provisioning._ensure_provisioner_dependencies"),
        patch("hermes_cli.whatsapp_provisioning._is_windows", return_value=True),
        patch("hermes_cli.whatsapp_provisioning.subprocess.Popen", return_value=process),
        pytest.raises(__import__("subprocess").TimeoutExpired),
    ):
        run_whatsapp_provisioning(
            "ordinary",
            phone="15550001111",
            operator=_TTY(),
            machine_output=io.StringIO(),
            timeout_seconds=0.1,
        )
    assert process.terminated == 1
    assert process.killed == 0
    assert process.waited == 1
