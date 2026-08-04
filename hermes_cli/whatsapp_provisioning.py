"""Explicit offline WhatsApp account provisioning.

The phone number and session identities cross the child boundary only in one
bounded stdin frame.  The child has no production bridge mode and the
production bridges have no provisioning mode.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import select
import re
import time
from typing import IO

from hermes_constants import find_node_executable, get_hermes_dir, get_hermes_home


_MAX_EVENT_BYTES = 4096
_ROLES = frozenset({"ordinary", "sensitive"})
_PAIRING_CODE_RE = re.compile(r"^[A-Z0-9-]{4,32}$")


class WhatsAppProvisioningError(RuntimeError):
    """Content-free provisioning failure safe for an operator boundary."""


def _canonical_owner_directory(path: Path, *, require_existing: bool) -> Path:
    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise WhatsAppProvisioningError("unsafe provisioning session path")
    cursor = path
    missing: list[Path] = []
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    for item in tuple(cursor.parents)[::-1] + (cursor,):
        info = item.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise WhatsAppProvisioningError("unsafe provisioning session path")
        if hasattr(os, "getuid") and info.st_uid not in {0, os.getuid()}:
            raise WhatsAppProvisioningError("unsafe provisioning session path")
        if mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX):
            raise WhatsAppProvisioningError("unsafe provisioning session path")
    if missing and require_existing:
        raise WhatsAppProvisioningError("provisioning session path is unavailable")
    prospective = cursor.resolve(strict=True).joinpath(*reversed([p.name for p in missing]))
    if prospective != path:
        raise WhatsAppProvisioningError("unsafe provisioning session path")
    if missing:
        return path
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise WhatsAppProvisioningError("provisioning session path must be owner-only")
    return path


def resolve_provisioning_roots() -> tuple[Path, Path]:
    ordinary = Path(
        get_hermes_dir("platforms/whatsapp/session", "whatsapp/session")
    )
    sensitive = (
        get_hermes_home() / "sensitive-delivery" / "whatsapp" / "session"
    )
    _canonical_owner_directory(ordinary, require_existing=False)
    _canonical_owner_directory(sensitive, require_existing=False)
    try:
        ordinary.relative_to(sensitive)
        overlap = True
    except ValueError:
        try:
            sensitive.relative_to(ordinary)
            overlap = True
        except ValueError:
            overlap = False
    same = ordinary.exists() and sensitive.exists() and ordinary.samefile(sensitive)
    if overlap or same:
        raise WhatsAppProvisioningError("ordinary and sensitive sessions must be separate")
    return ordinary, sensitive


def _provisioner_script() -> Path:
    script = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "whatsapp-sensitive-bridge"
        / "offline_provision.js"
    )
    if not script.is_file():
        raise WhatsAppProvisioningError("offline provisioner is unavailable")
    return script


def _minimal_node_environment(node: str) -> dict[str, str]:
    environment = {"PATH": str(Path(node).resolve().parent)}
    for name in ("LANG", "LC_ALL", "TZ", "NODE_PATH"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def run_whatsapp_provisioning(
    role: str,
    *,
    phone: str | None,
    operator: IO[str],
    machine_output: IO[str],
    timeout_seconds: float = 150.0,
    validate_only: bool = False,
) -> dict[str, object]:
    """Run the separate provisioner and return its non-sensitive final state."""
    if role not in _ROLES:
        raise WhatsAppProvisioningError("provisioning role is invalid")
    if not validate_only and not operator.isatty():
        raise WhatsAppProvisioningError("an interactive operator channel is required")
    node = find_node_executable("node")
    if not node:
        raise WhatsAppProvisioningError("Node.js is unavailable")
    script = _provisioner_script()
    ordinary, sensitive = resolve_provisioning_roots()
    request_value: dict[str, object] = {
        "version": 1,
        "action": "validate" if validate_only else "provision",
        "role": role,
        "ordinary_session": str(ordinary),
        "sensitive_session": str(sensitive),
    }
    if not validate_only:
        if type(phone) is not str:
            raise WhatsAppProvisioningError("phone input is required")
        request_value["phone"] = phone
    request = json.dumps(
        request_value,
        separators=(",", ":"),
        sort_keys=True,
    ) + "\n"
    phone = None
    ordinary = None
    sensitive = None
    operator_read_fd = operator_write_fd = None
    child_args = [node, str(script)]
    pass_fds: tuple[int, ...] = ()
    try:
        if not validate_only:
            operator_read_fd, operator_write_fd = os.pipe()
            os.set_inheritable(operator_write_fd, True)
            child_args.extend(("--operator-fd", str(operator_write_fd)))
            pass_fds = (operator_write_fd,)
        process = subprocess.Popen(
            child_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            env=_minimal_node_environment(node),
            start_new_session=True,
            pass_fds=pass_fds,
        )
    except BaseException:
        request = ""
        request_value.clear()
        phone = None
        ordinary = None
        sensitive = None
        for descriptor in (operator_read_fd, operator_write_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise WhatsAppProvisioningError("provisioner could not start") from None
    if operator_write_fd is not None:
        os.close(operator_write_fd)
        operator_write_fd = None
    final: dict[str, object] | None = None
    code = None
    code_event = None
    code_frame = b""
    try:
        started = time.monotonic()
        if process.stdin is None:
            raise WhatsAppProvisioningError("provisioner input is unavailable")
        process.stdin.write(request)
        process.stdin.close()
        process.stdin = None
        if operator_read_fd is not None:
            ready, _, _ = select.select(
                [operator_read_fd], [], [], timeout_seconds
            )
            if not ready:
                raise subprocess.TimeoutExpired(child_args, timeout_seconds)
            code_frame = os.read(operator_read_fd, 256)
            if code_frame and (len(code_frame) > 128 or not code_frame.endswith(b"\n")):
                raise WhatsAppProvisioningError("provisioner returned an invalid code")
            if code_frame:
                try:
                    code_event = json.loads(code_frame.decode("ascii", "strict"))
                except (ValueError, UnicodeError) as exc:
                    raise WhatsAppProvisioningError(
                        "provisioner returned an invalid code"
                    ) from exc
                code = code_event.get("code") if type(code_event) is dict else None
                if (
                    code_event.get("event") != "pairing_code"
                    or type(code) is not str
                    or _PAIRING_CODE_RE.fullmatch(code) is None
                ):
                    raise WhatsAppProvisioningError("provisioner returned an invalid code")
                operator.write(f"WhatsApp pairing code: {code}\n")
                operator.flush()
        remaining = max(0.1, timeout_seconds - (time.monotonic() - started))
        stdout, _ = process.communicate(timeout=remaining)
        if len(stdout.encode("utf-8")) > _MAX_EVENT_BYTES:
            raise WhatsAppProvisioningError("provisioner output exceeded its bound")
        for line in stdout.splitlines():
            event = json.loads(line)
            if type(event) is not dict:
                raise WhatsAppProvisioningError("provisioner returned an invalid event")
            if event.get("event") == "complete":
                final = {
                    "state": event.get("state"),
                    "role": role,
                    "lid_ready": bool(event.get("lid_ready", False)),
                }
        if final is None or final["state"] not in {
            "ready_for_production",
            "needs_provisioning",
        }:
            raise WhatsAppProvisioningError("provisioner did not return readiness")
        if final["state"] == "ready_for_production" and process.returncode != 0:
            raise WhatsAppProvisioningError("provisioner readiness was inconsistent")
        if final["state"] == "needs_provisioning" and process.returncode not in {0, 1}:
            raise WhatsAppProvisioningError("provisioner readiness was inconsistent")
        machine_output.write(json.dumps(final, sort_keys=True) + "\n")
        machine_output.flush()
        return final
    except BaseException:
        if process.poll() is None:
            try:
                os.killpg(process.pid, 15)
                process.wait(timeout=3)
            except BaseException:
                try:
                    os.killpg(process.pid, 9)
                    process.wait(timeout=3)
                except BaseException:
                    pass
        raise
    finally:
        for descriptor in (operator_read_fd, operator_write_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        request = ""
        request_value.clear()
        phone = None
        ordinary = None
        sensitive = None
        code = None
        code_event = None
        code_frame = b""


def command(args) -> int:
    role = str(getattr(args, "role", "") or "")
    validate_only = getattr(args, "validate_only", False) is True
    reprovision = getattr(args, "reprovision", False) is True
    if validate_only:
        final = run_whatsapp_provisioning(
            role,
            phone=None,
            operator=sys.stderr,
            machine_output=sys.stdout,
            validate_only=True,
        )
        return 0 if final["state"] == "ready_for_production" else 1
    phone = None
    try:
        operator = open("/dev/tty", "w", encoding="utf-8", buffering=1)
    except OSError as exc:
        raise WhatsAppProvisioningError(
            "an interactive operator channel is required"
        ) from exc
    try:
        if not reprovision:
            validated = run_whatsapp_provisioning(
                role,
                phone=None,
                operator=operator,
                machine_output=sys.stdout,
                validate_only=True,
            )
            if validated["state"] == "ready_for_production":
                return 0
        try:
            phone = input("WhatsApp phone number (international format): ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise WhatsAppProvisioningError("provisioning cancelled") from exc
        final = run_whatsapp_provisioning(
            role, phone=phone, operator=operator, machine_output=sys.stdout
        )
        return 0 if final["state"] == "ready_for_production" else 1
    finally:
        phone = None
        operator.close()


__all__ = [
    "WhatsAppProvisioningError",
    "command",
    "resolve_provisioning_roots",
    "run_whatsapp_provisioning",
]
