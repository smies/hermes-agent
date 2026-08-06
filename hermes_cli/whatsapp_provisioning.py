"""Explicit offline WhatsApp account provisioning.

The phone number and session identities cross the child boundary only in one
bounded stdin frame.  The child has no production bridge mode and the
production bridges have no provisioning mode.
"""

from __future__ import annotations

import json
import hashlib
import hmac
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
_PAIRING_CODE_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTVWXYZ"
_PAIRING_CODE_RE = re.compile(rf"^[{_PAIRING_CODE_ALPHABET}]{{8}}$")
_SENSITIVE_PROVISION_LAUNCHER_SHA256 = "b812665a229f8947c9b4da2fda1ec3fa5a2ace2002dea49b31662f01500a5b31"


class WhatsAppProvisioningError(RuntimeError):
    """Content-free provisioning failure safe for an operator boundary."""


def _is_windows() -> bool:
    return os.name == "nt"


def _canonical_owner_directory(
    path: Path,
    *,
    require_existing: bool,
    allow_legacy_target: bool = False,
) -> Path:
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
        or (
            stat.S_IMODE(info.st_mode) != 0o700
            and not (
                allow_legacy_target
                and stat.S_IMODE(info.st_mode) & 0o022 == 0
            )
        )
    ):
        raise WhatsAppProvisioningError("provisioning session path must be owner-only")
    return path


def resolve_provisioning_roots(
    *,
    role: str | None = None,
    reprovision: bool = False,
) -> tuple[Path, Path]:
    ordinary = Path(
        get_hermes_dir("platforms/whatsapp/session", "whatsapp/session")
    )
    sensitive = (
        get_hermes_home() / "sensitive-delivery" / "whatsapp" / "session"
    )
    _canonical_owner_directory(
        ordinary,
        require_existing=False,
        allow_legacy_target=bool(reprovision and role == "ordinary"),
    )
    _canonical_owner_directory(
        sensitive,
        require_existing=False,
        allow_legacy_target=bool(reprovision and role == "sensitive"),
    )
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
        / "provision_launcher.js"
    )
    if not script.is_file():
        raise WhatsAppProvisioningError("offline provisioner is unavailable")
    try:
        observed = hashlib.sha256(script.read_bytes()).hexdigest()
    except OSError as exc:
        raise WhatsAppProvisioningError("offline provisioner is unavailable") from exc
    if not hmac.compare_digest(observed, _SENSITIVE_PROVISION_LAUNCHER_SHA256):
        raise WhatsAppProvisioningError("offline provisioner identity mismatch")
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
    version = "7.0.0-rc14"
    resolved = (
        "https://registry.npmjs.org/@whiskeysockets/baileys/"
        "-/baileys-7.0.0-rc14.tgz"
    )
    integrity = (
        "sha512-WK+X8ju8TPGxvWIsP8hrY6JB6FltYuFe+vsqKfjOYX25JObij9qLf2c3ZGdl1Q+"
        "vhFwbnT+AZmWAB5pTvzmSiQ=="
    )
    if (
        requested != version
        or locked_requested != requested
        or lock.get("lockfileVersion") != 3
        or locked.get("version") != version
        or locked.get("resolved") != resolved
        or locked.get("integrity") != integrity
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
        installed_package.get("name") != "@whiskeysockets/baileys"
        or installed_package.get("version") != version
    ):
        raise WhatsAppProvisioningError("provisioner dependencies are invalid")
    # Exercise the same exact package/lock/source/installed-tree identity code
    # used by the sensitive transport before launching the provisioner.  This
    # both catches an incomplete clean install (including ERR_MODULE_NOT_FOUND)
    # and binds launch to the pinned commit and installed tree digest.
    try:
        verified = subprocess.run(
            [node, str(script), "--verify-only"],
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
    for name in (
        "LANG", "LC_ALL", "TZ",
        "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE",
        "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "TEMP", "TMP",
    ):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _acquire_provisioning_lock(ordinary: Path, sensitive: Path) -> int:
    """Acquire one owner-checked advisory lock covering both account roles."""
    if _is_windows():
        raise WhatsAppProvisioningError(
            "native Windows offline provisioning is unsupported; use a pre-provisioned session from a supported POSIX host or WhatsApp Cloud"
        )
    import fcntl

    owner_root = Path(os.path.commonpath((str(ordinary), str(sensitive))))
    _canonical_owner_directory(owner_root, require_existing=True)
    lock_path = owner_root / ".hermes-whatsapp-provision.lock"
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
        observed = os.lstat(lock_path)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(observed.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or (hasattr(os, "getuid") and opened.st_uid != os.getuid())
            or lock_path.resolve(strict=True) != lock_path
        ):
            raise WhatsAppProvisioningError("provisioning lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except WhatsAppProvisioningError:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    except (OSError, ValueError):
        if "descriptor" in locals():
            os.close(descriptor)
        raise WhatsAppProvisioningError(
            "another WhatsApp provisioning attempt is active"
        ) from None


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
    if _is_windows():
        raise WhatsAppProvisioningError(
            "native Windows offline provisioning is unsupported; use a pre-provisioned session from a supported POSIX host or WhatsApp Cloud"
        )
    if role not in _ROLES:
        raise WhatsAppProvisioningError("provisioning role is invalid")
    if not validate_only and not operator.isatty():
        raise WhatsAppProvisioningError("an interactive operator channel is required")
    node = find_node_executable("node")
    if not node:
        raise WhatsAppProvisioningError("Node.js is unavailable")
    script = _provisioner_script()
    _ensure_provisioner_dependencies(node, script)
    ordinary, sensitive = resolve_provisioning_roots(
        role=role,
        reprovision=reprovision,
    )
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
    child_args = [node, str(script)]
    if not validate_only:
        child_args.append("--operator-stdio")
    # Validation is strictly read-only.  A provisioning child holds the
    # cross-role advisory lock for its exact lifetime; validation instead
    # tolerates a concurrent atomic rename by returning not-ready/failing
    # closed without creating a persistent lock path.
    lock_descriptor = (
        None if validate_only else _acquire_provisioning_lock(ordinary, sensitive)
    )
    phone = None
    ordinary = None
    sensitive = None
    try:
        # Native Windows returned before this point. Keep the POSIX-only
        # process-group option as an explicit keyword so static typing does
        # not lose all Popen overload information through dict[str, object].
        process: subprocess.Popen[str] = subprocess.Popen(
            child_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if not validate_only else subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            env=_minimal_node_environment(node),
            start_new_session=True,
        )
    except BaseException:
        request = ""
        request_value.clear()
        phone = None
        ordinary = None
        sensitive = None
        if lock_descriptor is not None:
            os.close(lock_descriptor)
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
                    "error": event.get("error"),
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
        if final.get("error") == "unsafe_existing_session_requires_reprovision":
            raise WhatsAppProvisioningError(
                "existing WhatsApp session is unsafe to reuse; run again with explicit --reprovision"
            )
        final.pop("error", None)
        machine_output.write(json.dumps(final, sort_keys=True) + "\n")
        machine_output.flush()
        return final
    except BaseException:
        if process.poll() is None:
            try:
                os.killpg(process.pid, 15)  # windows-footgun: ok — native win32 rejected before launch
                process.wait(timeout=3)
            except BaseException:
                try:
                    os.killpg(process.pid, 9)  # windows-footgun: ok — native win32 rejected before launch
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
        if lock_descriptor is not None:
            try:
                os.close(lock_descriptor)
            except OSError:
                pass


def command(args) -> int:
    if _is_windows():
        raise WhatsAppProvisioningError(
            "native Windows offline provisioning is unsupported; use a pre-provisioned session from a supported POSIX host or WhatsApp Cloud"
        )
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
                if role == "ordinary":
                    from cli import save_config_value

                    if save_config_value("platforms.whatsapp.enabled", True) is not True:
                        raise WhatsAppProvisioningError(
                            "ordinary provisioning completed but configuration was not enabled"
                        )
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
