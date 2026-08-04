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
import re
import threading
import time
from typing import IO

from hermes_constants import find_node_executable, get_hermes_dir, get_hermes_home


_MAX_EVENT_BYTES = 4096
_ROLES = frozenset({"ordinary", "sensitive"})
_PAIRING_CODE_RE = re.compile(r"^[A-Z0-9-]{4,32}$")


class WhatsAppProvisioningError(RuntimeError):
    """Content-free provisioning failure safe for an operator boundary."""


def _is_windows() -> bool:
    return os.name == "nt"


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


def _ensure_provisioner_dependencies(node: str, script: Path) -> None:
    """Install and verify the provisioner's exact lockfile dependency tree."""
    root = script.parent
    package_file = root / "package.json"
    lock_file = root / "package-lock.json"
    try:
        package = json.loads(package_file.read_text(encoding="utf-8"))
        lock = json.loads(lock_file.read_text(encoding="utf-8"))
        requested = package["dependencies"]["@whiskeysockets/baileys"]
        locked_requested = lock["packages"][""]["dependencies"]["@whiskeysockets/baileys"]
        locked = lock["packages"]["node_modules/@whiskeysockets/baileys"]
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise WhatsAppProvisioningError(
            "provisioner dependency metadata is invalid"
        ) from exc
    commit = "01047debd81beb20da7b7779b08edcb06aa03770"
    if (
        type(requested) is not str
        or not requested.endswith("#" + commit)
        or locked_requested != requested
        or type(locked.get("resolved")) is not str
        or not locked["resolved"].endswith("#" + commit)
        or type(locked.get("integrity")) is not str
        or not locked["integrity"].startswith("sha512-")
    ):
        raise WhatsAppProvisioningError(
            "provisioner dependency metadata is invalid"
        )
    installed_file = root / "node_modules" / "@whiskeysockets" / "baileys" / "package.json"
    if not installed_file.is_file():
        npm = find_node_executable("npm")
        if not npm:
            raise WhatsAppProvisioningError("provisioner dependencies are unavailable")
        try:
            installed = subprocess.run(
                [npm, "ci", "--no-fund", "--no-audit", "--progress=false"],
                cwd=str(root),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=_minimal_node_environment(node),
                timeout=300,
                check=False,
            )
        except BaseException:
            raise WhatsAppProvisioningError(
                "provisioner dependency installation failed"
            ) from None
        if installed.returncode != 0:
            raise WhatsAppProvisioningError(
                "provisioner dependency installation failed"
            )
    try:
        installed_package = json.loads(installed_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WhatsAppProvisioningError("provisioner dependencies are invalid") from exc
    if (
        installed_package.get("name") not in {"baileys", "@whiskeysockets/baileys"}
        or installed_package.get("version") != locked.get("version")
    ):
        raise WhatsAppProvisioningError("provisioner dependencies are invalid")
    # Exercise the same exact package/lock/source/installed-tree identity code
    # used by the sensitive transport before launching the provisioner.  This
    # both catches an incomplete clean install (including ERR_MODULE_NOT_FOUND)
    # and binds launch to the pinned commit and installed tree digest.
    identity_script = (
        "import('./transport_identity.js')"
        ".then(m=>m.computeTransportIdentity(process.cwd()))"
        ".catch(()=>process.exitCode=1)"
    )
    try:
        verified = subprocess.run(
            [node, "--input-type=module", "--eval", identity_script],
            cwd=str(root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_minimal_node_environment(node),
            timeout=60,
            check=False,
        )
    except BaseException:
        raise WhatsAppProvisioningError(
            "provisioner dependency identity verification failed"
        ) from None
    if verified.returncode != 0:
        raise WhatsAppProvisioningError(
            "provisioner dependency identity verification failed"
        )


def _minimal_node_environment(node: str) -> dict[str, str]:
    executable_paths = [str(Path(node).resolve().parent), *os.defpath.split(os.pathsep)]
    environment = {"PATH": os.pathsep.join(dict.fromkeys(executable_paths))}
    for name in ("LANG", "LC_ALL", "TZ"):
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
    reprovision: bool = False,
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
    _ensure_provisioner_dependencies(node, script)
    ordinary, sensitive = resolve_provisioning_roots()
    request_value: dict[str, object] = {
        "version": 1,
        "action": "validate" if validate_only else "provision",
        "role": role,
        "ordinary_session": str(ordinary),
        "sensitive_session": str(sensitive),
        "reprovision": bool(reprovision),
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
    child_args = [node, str(script)]
    if not validate_only:
        child_args.append("--operator-stdio")
    try:
        popen_kwargs: dict[str, object] = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE if not validate_only else subprocess.DEVNULL,
            "text": True,
            "encoding": "utf-8",
            "errors": "strict",
            "env": _minimal_node_environment(node),
        }
        if _is_windows():
            popen_kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        else:
            popen_kwargs["start_new_session"] = True
        process = subprocess.Popen(
            child_args,
            **popen_kwargs,
        )
    except BaseException:
        request = ""
        request_value.clear()
        phone = None
        ordinary = None
        sensitive = None
        raise WhatsAppProvisioningError("provisioner could not start") from None
    operator_stream = process.stderr if not validate_only else None
    # ``communicate`` must not compete with the dedicated operator reader for
    # the same pipe.  Retain sole ownership locally and detach it from Popen's
    # communicate set before either reader starts.
    if not validate_only:
        process.stderr = None
    final: dict[str, object] | None = None
    code = None
    code_event = None
    code_frame = ""
    operator_failure: list[BaseException] = []

    def _forward_operator_event() -> None:
        nonlocal code, code_event, code_frame
        try:
            if operator_stream is None:
                raise WhatsAppProvisioningError("operator channel is unavailable")
            code_frame = operator_stream.readline(257)
            if not code_frame or len(code_frame.encode("utf-8")) > 256 or not code_frame.endswith("\n"):
                raise WhatsAppProvisioningError("provisioner returned an invalid code")
            code_event = json.loads(code_frame)
            code = code_event.get("code") if type(code_event) is dict else None
            if (
                code_event.get("event") != "pairing_code"
                or type(code) is not str
                or _PAIRING_CODE_RE.fullmatch(code) is None
            ):
                raise WhatsAppProvisioningError("provisioner returned an invalid code")
            operator.write(f"WhatsApp pairing code: {code}\n")
            operator.flush()
        except BaseException as exc:
            operator_failure.append(exc)

    operator_thread = None
    try:
        started = time.monotonic()
        if process.stdin is None:
            raise WhatsAppProvisioningError("provisioner input is unavailable")
        process.stdin.write(request)
        process.stdin.close()
        process.stdin = None
        if not validate_only:
            operator_thread = threading.Thread(
                target=_forward_operator_event,
                name="whatsapp-provision-operator",
                daemon=True,
            )
            operator_thread.start()
        remaining = max(0.1, timeout_seconds - (time.monotonic() - started))
        stdout, _ = process.communicate(timeout=remaining)
        if operator_thread is not None:
            operator_thread.join(timeout=max(0.1, remaining))
            if operator_thread.is_alive():
                raise subprocess.TimeoutExpired(child_args, timeout_seconds)
            if operator_failure:
                raise WhatsAppProvisioningError(
                    "provisioner returned an invalid code"
                ) from None
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
                if not _is_windows():
                    os.killpg(process.pid, 15)
                else:
                    process.terminate()
                process.wait(timeout=3)
            except BaseException:
                try:
                    if not _is_windows():
                        os.killpg(process.pid, 9)
                    else:
                        process.kill()
                    process.wait(timeout=3)
                except BaseException:
                    pass
        raise
    finally:
        if operator_thread is not None and operator_thread.is_alive():
            try:
                if operator_stream is not None:
                    operator_stream.close()
            except BaseException:
                pass
            operator_thread.join(timeout=3)
        elif operator_stream is not None:
            try:
                operator_stream.close()
            except BaseException:
                pass
        request = ""
        request_value.clear()
        phone = None
        ordinary = None
        sensitive = None
        code = None
        code_event = None
        code_frame = ""
        operator_failure.clear()


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
            reprovision=False,
        )
        return 0 if final["state"] == "ready_for_production" else 1
    phone = None
    operator = sys.stderr
    if not operator.isatty() or not sys.stdin.isatty():
        raise WhatsAppProvisioningError(
            "an interactive operator channel is required"
        )
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
            operator.write("WhatsApp phone number (international format): ")
            operator.flush()
            phone = sys.stdin.readline(64)
            if not phone or not phone.endswith("\n"):
                raise EOFError
            phone = phone.rstrip("\r\n")
        except (EOFError, KeyboardInterrupt) as exc:
            raise WhatsAppProvisioningError("provisioning cancelled") from exc
        final = run_whatsapp_provisioning(
            role,
            phone=phone,
            operator=operator,
            machine_output=sys.stdout,
            reprovision=reprovision,
        )
        if role == "ordinary" and final["state"] == "ready_for_production":
            from cli import save_config_value

            if save_config_value("platforms.whatsapp.enabled", True) is not True:
                raise WhatsAppProvisioningError(
                    "ordinary provisioning completed but configuration was not enabled"
                )
        return 0 if final["state"] == "ready_for_production" else 1
    finally:
        phone = None


__all__ = [
    "WhatsAppProvisioningError",
    "command",
    "resolve_provisioning_roots",
    "run_whatsapp_provisioning",
]
