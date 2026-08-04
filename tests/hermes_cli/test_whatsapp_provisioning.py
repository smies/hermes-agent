from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from hermes_cli.whatsapp_provisioning import (
    WhatsAppProvisioningError,
    resolve_provisioning_roots,
    run_whatsapp_provisioning,
)


class _TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


class _Process:
    def __init__(self, output: str, returncode: int = 0):
        self.output = output
        self.returncode = returncode
        self.pid = 123
        self.kwargs = None
        self.request = None
        self.stdin = self._Input(self)

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
        + "\n"
    )
    operator = _TTY()
    machine = io.StringIO()
    roots = (tmp_path / "ordinary", tmp_path / "sensitive")
    with (
        patch("hermes_cli.whatsapp_provisioning.find_node_executable", return_value="/bin/node"),
        patch("hermes_cli.whatsapp_provisioning.resolve_provisioning_roots", return_value=roots),
        patch("hermes_cli.whatsapp_provisioning._provisioner_script", return_value=tmp_path / "offline.js"),
        patch("hermes_cli.whatsapp_provisioning.subprocess.Popen", return_value=process),
        patch("hermes_cli.whatsapp_provisioning.os.pipe", return_value=(90, 91)),
        patch("hermes_cli.whatsapp_provisioning.os.set_inheritable"),
        patch("hermes_cli.whatsapp_provisioning.os.close"),
        patch("hermes_cli.whatsapp_provisioning.select.select", return_value=([90], [], [])),
        patch(
            "hermes_cli.whatsapp_provisioning.os.read",
            return_value=(json.dumps({"event": "pairing_code", "code": code}) + "\n").encode(),
        ),
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
