"""Default-off gateway owner for trusted private-read authorization.

The host owns the coordinator lease, the request-local context capability and
the worker task.  Provider-specific I/O is expressed by a closed dependency
object so tests can exercise the complete state machine without contacting a
provider.  Production construction is fail-closed unless every dependency is
present and healthy.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import hmac
import hashlib
import os
from pathlib import Path
import secrets
import stat
import time
from typing import Awaitable, Callable

from gateway.authorization_contracts import (
    AuthorizationNotificationWorkItem,
    AuthorizationPdpCheckContext,
    AuthorizationTaskWorkItem,
    ClaimIdentity,
    CoordinatorIdentity,
    ExternalPdpDecisionResult,
    NotificationAttemptSpec,
    OwnerDecision,
    ProviderAcceptanceEvidence,
)
from gateway.authorization_sensitive_delivery import AuthorizationSensitiveDeliveryBridge
from gateway.authorization_tasks import AuthorizationTaskStore
from gateway.private_read_authorization import (
    PrivateReadCapabilityRegistry,
    PrivateReadCapabilitySpec,
    PrivateReadRequestRuntime,
    TrustedPrivateReadHostContext,
)
from gateway.sensitive_delivery import (
    SensitiveDeliveryHostAuthority,
    SensitiveDeliveryRouter,
    SensitiveDeliveryTransportRegistration,
    SensitiveDeliveryTransportRegistry,
)
from tools.private_read_request_tool import configure_private_read_request_runtime


SENSITIVE_VERIFIED_LAUNCHER_SHA256 = (
    "e2ee6973e7502aff1ae2c17b30b44e592ed18d202232d2b4322a5558aadeef9a"
)
SENSITIVE_RUNTIME_LAUNCHER_PATH = (
    Path(__file__).absolute().parent.parent
    / "scripts"
    / "whatsapp-sensitive-bridge"
    / "launcher.js"
)


class TrustedPrivateReadConfigurationError(RuntimeError):
    """A deliberately path- and identifier-free configuration failure."""


def _owner_file(path: Path, *, mode: int = 0o600) -> Path:
    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise TrustedPrivateReadConfigurationError("trusted host file is unsafe")
    try:
        if path.resolve(strict=True) != path:
            raise TrustedPrivateReadConfigurationError("trusted host file is unsafe")
        info = path.lstat()
    except OSError as exc:
        raise TrustedPrivateReadConfigurationError("trusted host file is unavailable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != mode
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
    ):
        raise TrustedPrivateReadConfigurationError("trusted host file is unsafe")
    cursor = path.parent
    for ancestor in tuple(cursor.parents)[::-1] + (cursor,):
        item = ancestor.lstat()
        bits = stat.S_IMODE(item.st_mode)
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            raise TrustedPrivateReadConfigurationError("trusted host path is unsafe")
        if hasattr(os, "getuid") and item.st_uid not in {0, os.getuid()}:
            raise TrustedPrivateReadConfigurationError("trusted host path is unsafe")
        if bits & 0o022 and not (item.st_uid == 0 and bits & stat.S_ISVTX):
            raise TrustedPrivateReadConfigurationError("trusted host path is unsafe")
    return path


def _owner_directory(path: Path) -> Path:
    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise TrustedPrivateReadConfigurationError("trusted host directory is unsafe")
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
        if path.resolve(strict=True) != path:
            raise TrustedPrivateReadConfigurationError("trusted host directory is unsafe")
        info = path.lstat()
    except OSError as exc:
        raise TrustedPrivateReadConfigurationError("trusted host directory is unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
    ):
        raise TrustedPrivateReadConfigurationError("trusted host directory is unsafe")
    cursor = path.parent
    for ancestor in tuple(cursor.parents)[::-1] + (cursor,):
        item = ancestor.lstat()
        bits = stat.S_IMODE(item.st_mode)
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
            raise TrustedPrivateReadConfigurationError("trusted host path is unsafe")
        if hasattr(os, "getuid") and item.st_uid not in {0, os.getuid()}:
            raise TrustedPrivateReadConfigurationError("trusted host path is unsafe")
        if bits & 0o022 and not (item.st_uid == 0 and bits & stat.S_ISVTX):
            raise TrustedPrivateReadConfigurationError("trusted host path is unsafe")
    return path


def _sensitive_launcher_seal(
    path: Path = SENSITIVE_RUNTIME_LAUNCHER_PATH,
) -> tuple[int, int, int, int, int, str]:
    """Verify the actual canonical sensitive launcher through an open fd.

    The allowlist's reported digest remains receipt evidence; this seal is the
    trusted host's independent pre-spawn proof.  Error text is deliberately
    path- and identity-free.
    """
    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise TrustedPrivateReadConfigurationError(
            "sensitive runtime launcher is unsafe"
        )
    cursor = path.parent
    try:
        for ancestor in tuple(cursor.parents)[::-1] + (cursor,):
            item = ancestor.lstat()
            bits = stat.S_IMODE(item.st_mode)
            if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode):
                raise TrustedPrivateReadConfigurationError(
                    "sensitive runtime launcher path is unsafe"
                )
            if hasattr(os, "getuid") and item.st_uid not in {0, os.getuid()}:
                raise TrustedPrivateReadConfigurationError(
                    "sensitive runtime launcher path is unsafe"
                )
            if bits & 0o022 and not (
                item.st_uid == 0 and bits & stat.S_ISVTX
            ):
                raise TrustedPrivateReadConfigurationError(
                    "sensitive runtime launcher path is unsafe"
                )
        before = path.lstat()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except TrustedPrivateReadConfigurationError:
        raise
    except OSError as exc:
        raise TrustedPrivateReadConfigurationError(
            "sensitive runtime launcher is unavailable"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_dev != opened.st_dev
            or before.st_ino != opened.st_ino
            or before.st_nlink != 1
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) & 0o022
            or (
                hasattr(os, "getuid")
                and opened.st_uid not in {0, os.getuid()}
            )
        ):
            raise TrustedPrivateReadConfigurationError(
                "sensitive runtime launcher is unsafe"
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > 1024 * 1024:
                raise TrustedPrivateReadConfigurationError(
                    "sensitive runtime launcher is oversized"
                )
            digest.update(chunk)
        observed_digest = digest.hexdigest()
        after = path.lstat()
        if (
            after.st_dev != opened.st_dev
            or after.st_ino != opened.st_ino
            or after.st_size != total
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or after.st_uid != opened.st_uid
            or after.st_nlink != opened.st_nlink
            or stat.S_IMODE(after.st_mode) != stat.S_IMODE(opened.st_mode)
            or not hmac.compare_digest(
                observed_digest, SENSITIVE_VERIFIED_LAUNCHER_SHA256
            )
        ):
            raise TrustedPrivateReadConfigurationError(
                "sensitive runtime launcher identity is invalid"
            )
        return (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            stat.S_IMODE(opened.st_mode),
            observed_digest,
        )
    except TrustedPrivateReadConfigurationError:
        raise
    except OSError as exc:
        raise TrustedPrivateReadConfigurationError(
            "sensitive runtime launcher is unavailable"
        ) from exc
    finally:
        os.close(descriptor)


def _path_seal(path: Path) -> tuple[int, int, int, int, str]:
    info = path.lstat()
    digest = ""
    if stat.S_ISREG(info.st_mode):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return (info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), info.st_uid, digest)


def _closed_json_file(path: Path, required: set[str]) -> dict:
    raw = _owner_file(path).read_bytes()
    if len(raw) > 64 * 1024:
        raise TrustedPrivateReadConfigurationError("trusted host file is oversized")
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (ValueError, UnicodeError) as exc:
        raise TrustedPrivateReadConfigurationError("trusted host file is invalid") from exc
    if type(value) is not dict or set(value) != required:
        raise TrustedPrivateReadConfigurationError("trusted host file shape is invalid")
    return value


def _hex_key(value: object) -> bytes:
    if type(value) is not str or len(value) not in {64, 96, 128}:
        raise TrustedPrivateReadConfigurationError("trusted host key is invalid")
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise TrustedPrivateReadConfigurationError("trusted host key is invalid") from exc
    if len(key) < 32:
        raise TrustedPrivateReadConfigurationError("trusted host key is invalid")
    return key


@dataclass(frozen=True, slots=True, repr=False)
class TrustedPrivateReadHostConfig:
    state_dir: Path
    key_file: Path
    allowlist_file: Path
    openfga_version: str
    key_version: str
    audit_key: bytes
    request_key: bytes
    request_id_key: bytes
    authorization_key: bytes
    receipt_key: bytes
    capabilities: PrivateReadCapabilityRegistry
    transport_identity: tuple[tuple[str, str], ...]
    poll_seconds: float
    lease_seconds: float
    state_seal: tuple[int, int, int, int, str]
    key_seal: tuple[int, int, int, int, str]
    allowlist_seal: tuple[int, int, int, int, str]
    sensitive_launcher_path: Path
    sensitive_launcher_seal: tuple[int, int, int, int, int, str]

    def __repr__(self) -> str:
        return "<TrustedPrivateReadHostConfig redacted>"

    def files_unchanged(self) -> bool:
        try:
            _owner_directory(self.state_dir)
            _owner_file(self.key_file)
            _owner_file(self.allowlist_file)
            return (
                hmac.compare_digest(repr(_path_seal(self.state_dir)), repr(self.state_seal))
                and hmac.compare_digest(repr(_path_seal(self.key_file)), repr(self.key_seal))
                and hmac.compare_digest(
                    repr(_path_seal(self.allowlist_file)), repr(self.allowlist_seal)
                )
                and self.sensitive_launcher_path == SENSITIVE_RUNTIME_LAUNCHER_PATH
                and hmac.compare_digest(
                    repr(_sensitive_launcher_seal(self.sensitive_launcher_path)),
                    repr(self.sensitive_launcher_seal),
                )
            )
        except BaseException:
            return False

    @classmethod
    def parse(cls, raw: object) -> "TrustedPrivateReadHostConfig | None":
        if raw is None:
            return None
        if type(raw) is not dict:
            raise TrustedPrivateReadConfigurationError("trusted host config is invalid")
        if raw.get("enabled") is not True:
            return None
        required = {
            "version", "enabled", "state_dir", "key_file", "allowlist_file",
            "openfga_version", "capabilities",
        }
        optional = {"poll_seconds", "lease_seconds"}
        if set(raw) - required - optional or not required.issubset(raw) or raw["version"] != 1:
            raise TrustedPrivateReadConfigurationError("trusted host config shape is invalid")
        state_dir = _owner_directory(Path(raw["state_dir"]))
        key_file = _owner_file(Path(raw["key_file"]))
        allowlist_file = _owner_file(Path(raw["allowlist_file"]))
        launcher_seal = _sensitive_launcher_seal()
        if raw["openfga_version"] != "1.18.2":
            raise TrustedPrivateReadConfigurationError(
                "trusted host policy service version is invalid"
            )
        keys = _closed_json_file(
            key_file,
            {"version", "key_version", "audit_hmac", "request_hmac", "request_id_hmac", "authorization_hmac", "receipt_hmac"},
        )
        if keys["version"] != 1 or type(keys["key_version"]) is not str:
            raise TrustedPrivateReadConfigurationError("trusted host key bundle is invalid")
        allowlist = _closed_json_file(allowlist_file, {"version", "transport_identity"})
        identity = allowlist.get("transport_identity")
        identity_fields = {
            "manifest_sha256", "verifier_sha256", "source_sha256",
            "node_modules_tree_sha256", "package_sha256", "lock_sha256",
            "launcher_sha256",
            "package_name", "package_version", "baileys_spec",
            "baileys_lock_version", "baileys_lock_resolved",
            "baileys_lock_integrity", "baileys_installed_name", "baileys_version",
            "baileys_package_sha256", "baileys_tree_sha256",
            "baileys_reviewed_release_git_head",
        }
        if allowlist["version"] != 1 or type(identity) is not dict or set(identity) != identity_fields:
            raise TrustedPrivateReadConfigurationError("transport allowlist is invalid")
        for name, value in identity.items():
            if type(value) is not str or not value or len(value.encode()) > 512:
                raise TrustedPrivateReadConfigurationError("transport allowlist is invalid")
            if name.endswith("sha256") and (len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
                raise TrustedPrivateReadConfigurationError("transport allowlist is invalid")
        if not hmac.compare_digest(
            identity["launcher_sha256"], SENSITIVE_VERIFIED_LAUNCHER_SHA256
        ):
            raise TrustedPrivateReadConfigurationError(
                "sensitive launcher identity is invalid"
            )
        specs = raw["capabilities"]
        if type(specs) is not list:
            raise TrustedPrivateReadConfigurationError("trusted capabilities are invalid")
        capabilities = PrivateReadCapabilityRegistry(tuple(
            PrivateReadCapabilitySpec(
                capability_id=item["id"],
                operation=item["operation"],
                resource_type=item["resource_type"],
                fields=tuple(item["fields"]),
            )
            for item in specs
            if type(item) is dict and set(item) == {"id", "operation", "resource_type", "fields"}
        ))
        if len(capabilities.capabilities) != len(specs):
            raise TrustedPrivateReadConfigurationError("trusted capabilities are invalid")
        poll = float(raw.get("poll_seconds", 1.0))
        lease = float(raw.get("lease_seconds", 30.0))
        if not 0.1 <= poll <= 10 or not 5 <= lease <= 120 or lease <= poll * 2:
            raise TrustedPrivateReadConfigurationError("trusted host timing is invalid")
        return cls(
            state_dir=state_dir,
            key_file=key_file,
            allowlist_file=allowlist_file,
            openfga_version="1.18.2",
            key_version=keys["key_version"],
            audit_key=_hex_key(keys["audit_hmac"]),
            request_key=_hex_key(keys["request_hmac"]),
            request_id_key=_hex_key(keys["request_id_hmac"]),
            authorization_key=_hex_key(keys["authorization_hmac"]),
            receipt_key=_hex_key(keys["receipt_hmac"]),
            capabilities=capabilities,
            transport_identity=tuple(sorted(identity.items())),
            poll_seconds=poll,
            lease_seconds=lease,
            state_seal=_path_seal(state_dir),
            key_seal=_path_seal(key_file),
            allowlist_seal=_path_seal(allowlist_file),
            sensitive_launcher_path=SENSITIVE_RUNTIME_LAUNCHER_PATH,
            sensitive_launcher_seal=launcher_seal,
        )


@dataclass(frozen=True, slots=True, repr=False)
class TrustedPrivateReadHostServices:
    healthy: Callable[[], bool]
    context_for_current_event: Callable[[], TrustedPrivateReadHostContext | None]
    pdp_check: Callable[[AuthorizationPdpCheckContext], Awaitable[ExternalPdpDecisionResult]]
    transport_registration: Callable[[AuthorizationTaskWorkItem], Awaitable[SensitiveDeliveryTransportRegistration]]
    private_read: Callable[[AuthorizationTaskWorkItem], Awaitable[str]]
    deliver_notification: Callable[
        [AuthorizationNotificationWorkItem, ClaimIdentity],
        Awaitable[ProviderAcceptanceEvidence],
    ]
    decision_for_event: Callable[
        [object], tuple[str, OwnerDecision, NotificationAttemptSpec] | None
    ]
    close: Callable[[], Awaitable[None]]
    transport_identity: Callable[[], dict[str, str]] = lambda: {}
    account_state: Callable[[], tuple[str, str, str, bool]] = lambda: ("", "", "", False)
    bind_event: Callable[[object], object] = lambda _event: None
    unbind_event: Callable[[object], None] = lambda _token: None

    def __repr__(self) -> str:
        return "<TrustedPrivateReadHostServices redacted>"

    def __post_init__(self) -> None:
        for name in ("healthy", "context_for_current_event", "pdp_check", "transport_registration", "private_read", "deliver_notification", "decision_for_event", "close", "transport_identity", "account_state", "bind_event", "unbind_event"):
            if not callable(getattr(self, name)):
                raise TypeError("trusted host services are incomplete")


@dataclass(frozen=True, slots=True, repr=False)
class TrustedPrivateReadEventBinding:
    """Proof that the host installed a context for one logical event.

    ``private_context`` distinguishes an authenticated private context from an
    explicit empty context.  The opaque service token is intentionally kept
    inside this exact wrapper, so ``None`` can never be confused with a
    successful bind at the gateway boundary.
    """

    token: object
    private_context: bool


class _ContextProvider:
    def __init__(self, host: "TrustedPrivateReadGatewayHost") -> None:
        self._host = host

    def current(self) -> TrustedPrivateReadHostContext | None:
        if not self._host.is_healthy():
            return None
        return self._host.services.context_for_current_event()


class TrustedPrivateReadGatewayHost:
    """Own and revoke the complete runtime as one gateway lifecycle unit."""

    def __init__(self, config: TrustedPrivateReadHostConfig, services: TrustedPrivateReadHostServices):
        if type(config) is not TrustedPrivateReadHostConfig or type(services) is not TrustedPrivateReadHostServices:
            raise TypeError("exact trusted host configuration and services are required")
        self.config = config
        self.services = services
        self.store: AuthorizationTaskStore | None = None
        self.authority: SensitiveDeliveryHostAuthority | None = None
        self._lock = None
        self._task: asyncio.Task | None = None
        self._healthy = False
        self._closed = False
        self._worker_claim: ClaimIdentity | None = None
        self._services_closed = False

    def is_healthy(self) -> bool:
        if not self._healthy or self._closed:
            return False
        try:
            if not self.config.files_unchanged() or self.services.healthy() is not True:
                return False
            observed_identity = self.services.transport_identity()
            if type(observed_identity) is not dict:
                return False
            expected = dict(self.config.transport_identity)
            if set(observed_identity) != set(expected):
                return False
            for name, value in expected.items():
                actual = observed_identity.get(name)
                if type(actual) is not str or not hmac.compare_digest(actual, value):
                    return False
            accounts = self.services.account_state()
            if type(accounts) is not tuple or len(accounts) != 4:
                return False
            ordinary, sensitive, namespace, lid_ready = accounts
            return bool(
                type(ordinary) is str
                and type(sensitive) is str
                and ordinary
                and sensitive
                and hmac.compare_digest(ordinary, sensitive)
                and type(namespace) is str
                and namespace
                and ordinary.endswith("@" + namespace)
                and sensitive.endswith("@" + namespace)
                and lid_ready is True
            )
        except BaseException:
            return False

    async def start(self) -> bool:
        if self._closed or not self.services.healthy():
            return False
        store = AuthorizationTaskStore(
            db_path=self.config.state_dir / "authorization.db",
            audit_hmac_key=self.config.audit_key,
            request_hmac_key=self.config.request_key,
            key_version=self.config.key_version,
        )
        lock = store.acquire_coordinator_lock()
        if lock is None:
            store.close()
            return False
        now_us = time.time_ns() // 1000
        identity = CoordinatorIdentity(
            "gateway-private-read",
            hmac.new(
                self.config.request_key,
                b"hermes-gateway-private-read-coordinator-v1",
                hashlib.sha256,
            ).hexdigest(),
        )
        fence = store.acquire_coordinator(
            identity,
            now_us=now_us,
            lease_expires_at_us=now_us + int(self.config.lease_seconds * 1_000_000),
            lock_session=lock,
        )
        if fence is None:
            store.close()
            return False
        self.store = store
        self._lock = lock
        self.authority = SensitiveDeliveryHostAuthority(
            self.config.authorization_key,
            self.config.receipt_key,
        )
        self._worker_claim = ClaimIdentity(
            owner_profile="gateway",
            owner_agent="private-read-worker",
            owner_account="trusted-host",
            nonce=secrets.token_hex(32),
            generation=1,
        )
        self._healthy = True
        if not self.is_healthy():
            await self._cleanup()
            return False
        runtime = PrivateReadRequestRuntime(
            store=store,
            id_hmac_key=self.config.request_id_key,
            host_contexts=_ContextProvider(self),
            capabilities=self.config.capabilities,
            enabled=True,
        )
        configure_private_read_request_runtime(
            runtime,
            health_check=self.is_healthy,
        )
        self._task = asyncio.create_task(self._run(), name="trusted-private-read-host")
        return True

    async def _run(self) -> None:
        try:
            while self.is_healthy():
                await self._renew_and_process()
                await asyncio.sleep(self.config.poll_seconds)
        except asyncio.CancelledError:
            raise
        except BaseException:
            self._healthy = False
        finally:
            configure_private_read_request_runtime(None)
            await self._cleanup()

    async def _cleanup(self) -> None:
        self._healthy = False
        try:
            if not self._services_closed:
                self._services_closed = True
                await self.services.close()
        finally:
            if self.store is not None:
                self.store.close()
            self.store = None
            self.authority = None
            self._lock = None

    async def _renew_and_process(self) -> None:
        store = self.store
        claim = self._worker_claim
        if store is None or claim is None or self._lock is None:
            raise RuntimeError("trusted host is unavailable")
        now_us = time.time_ns() // 1000
        identity = store._coordinator_identity
        if identity is None or store.acquire_coordinator(
            identity,
            now_us=now_us,
            lease_expires_at_us=now_us + int(self.config.lease_seconds * 1_000_000),
            lock_session=self._lock,
        ) is None:
            raise RuntimeError("trusted host coordinator is unavailable")
        store.expire_due(now_us=now_us)
        await self._process_notifications(now_us)
        for item in store.list_approved_task_work_items(now_us=now_us, limit=8):
            await self._process_item(item)

    def _notification_claim(self, generation: int) -> ClaimIdentity:
        return ClaimIdentity(
            owner_profile="gateway",
            owner_agent="authorization-notifier",
            owner_account="trusted-host",
            nonce=secrets.token_hex(32),
            generation=generation,
        )

    async def _process_notifications(self, now_us: int) -> None:
        store = self.store
        if store is None:
            return
        pending = store.list_pending_due_notification_work_items(
            now_us=now_us, limit=8
        )
        stale = store.list_stale_pre_send_notification_work_items(
            now_us=now_us, limit=8
        )
        for item in (*pending, *stale):
            generation = (
                1
                if item.notification.status == "pending"
                else int(item.notification.claim_generation or 0) + 1
            )
            claim = self._notification_claim(generation)
            lease = now_us + int(self.config.lease_seconds * 1_000_000)
            mutation = (
                store.claim_notification(
                    item.attempt_id,
                    claim,
                    now_us=now_us,
                    lease_expires_at_us=lease,
                )
                if item.notification.status == "pending"
                else store.take_over_stale_notification(
                    item.attempt_id,
                    claim,
                    now_us=now_us,
                    lease_expires_at_us=lease,
                )
            )
            if not mutation.applied:
                continue
            send_at = max(time.time_ns() // 1000, now_us)
            started = store.record_notification_send_started(
                item.attempt_id, claim, now_us=send_at
            )
            if not started.applied or started.idempotent:
                continue
            evidence = None
            try:
                evidence = await self.services.deliver_notification(item, claim)
            except asyncio.CancelledError:
                store.finish_notification(
                    item.attempt_id,
                    claim,
                    now_us=max(time.time_ns() // 1000, send_at),
                    outcome="failed",
                    receipt_code="ambiguous_after_restart",
                )
                raise
            except BaseException:
                pass
            finished_at = max(time.time_ns() // 1000, send_at)
            if type(evidence) is ProviderAcceptanceEvidence:
                store.finish_notification(
                    item.attempt_id,
                    claim,
                    now_us=finished_at,
                    outcome="provider_accepted",
                    receipt_code="provider_accepted",
                    evidence=evidence,
                )
            else:
                store.finish_notification(
                    item.attempt_id,
                    claim,
                    now_us=finished_at,
                    outcome="failed",
                    receipt_code="internal_failure",
                )

    async def _check(self, item: AuthorizationTaskWorkItem, claim: ClaimIdentity, stage: str):
        store = self.store
        if store is None:
            raise RuntimeError("trusted host is unavailable")
        now_us = time.time_ns() // 1000
        context = store.create_pdp_check_context(item.task_id, claim, stage=stage, now_us=now_us)
        result = await self.services.pdp_check(context)
        if result.consistency != "strongest" or result.cache_used:
            result = ExternalPdpDecisionResult(
                context_id=context.context_id,
                pdp_call_id=context.pdp_call_id,
                decision="failure",
                checked_at_us=max(time.time_ns() // 1000, context.created_at_us),
                consistency="unknown",
                cache_used=False,
            )
        return store.create_pdp_decision_evidence(context, claim, result)

    async def _process_item(self, item: AuthorizationTaskWorkItem) -> None:
        store = self.store
        authority = self.authority
        base_claim = self._worker_claim
        if store is None or authority is None or base_claim is None or not self.is_healthy():
            return
        claim = ClaimIdentity(
            base_claim.owner_profile,
            base_claim.owner_agent,
            base_claim.owner_account,
            secrets.token_hex(32),
            1,
        )
        evidence = await self._check(item, claim, "pre_claim")
        now_us = evidence.checked_at_us
        if evidence.decision != "allow":
            store.reject_from_pdp(item.task_id, item.binding, evidence, now_us=now_us)
            return
        mutation = store.claim(
            item.task_id,
            item.binding,
            claim,
            now_us=now_us,
            lease_expires_at_us=now_us + int(self.config.lease_seconds * 1_000_000),
            pdp_evidence=evidence,
        )
        if not mutation.applied:
            return
        claimed = store.load_task_work_item(item.task_id, now_us=time.time_ns() // 1000)
        bridge = AuthorizationSensitiveDeliveryBridge(
            store=store,
            binding=claimed.binding,
            claim=claim,
            host_authority=authority,
        )
        registration = await self.services.transport_registration(claimed)
        registry = SensitiveDeliveryTransportRegistry([registration], max_registrations=1)
        router = SensitiveDeliveryRouter(transport_registry=registry, authorization_bridge=bridge)
        prepared = None
        plaintext = None
        try:
            prepared = await router.prepare()
            if not hasattr(prepared, "authorize_private_read"):
                return
            second = await self._check(claimed, claim, "pre_private_read")
            if second.decision != "allow" or not prepared.authorize_private_read(second, now_us=second.checked_at_us):
                prepared.discard()
                return
            try:
                plaintext = await self.services.private_read(claimed)
            except asyncio.CancelledError:
                raise
            except BaseException:
                raise RuntimeError("trusted private read failed") from None
            if not self.is_healthy():
                prepared.discard()
                return
            try:
                await prepared.deliver(plaintext)
            except asyncio.CancelledError:
                raise
            except BaseException:
                raise RuntimeError("trusted sensitive delivery failed") from None
            plaintext = None
        finally:
            plaintext = None
            if prepared is not None and hasattr(prepared, "discard"):
                prepared.discard()
            await router.aclose()

    async def stop(self) -> None:
        if self._closed:
            return
        self._healthy = False
        self._closed = True
        configure_private_read_request_runtime(None)
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        await self._cleanup()

    def health(self) -> dict[str, object]:
        return {
            "enabled": not self._closed,
            "ready": self.is_healthy(),
            "worker_running": bool(self._task is not None and not self._task.done()),
        }

    def _install_empty_event_context(self) -> TrustedPrivateReadEventBinding:
        """Install a task-local no-private context or fail before execution."""
        try:
            token = self.services.bind_event(None)
            if self.services.context_for_current_event() is not None:
                raise RuntimeError("trusted private-read empty context was not installed")
        except BaseException:
            if "token" in locals():
                try:
                    self.services.unbind_event(token)
                except BaseException:
                    pass
            self._healthy = False
            configure_private_read_request_runtime(None)
            raise RuntimeError("trusted private-read event binding failed") from None
        return TrustedPrivateReadEventBinding(token=token, private_context=False)

    def bind_event(self, event: object) -> TrustedPrivateReadEventBinding:
        if not self.is_healthy():
            raise RuntimeError("trusted private-read host is unavailable")
        try:
            decision = self.services.decision_for_event(event)
        except BaseException:
            return self._install_empty_event_context()
        if decision is not None:
            if type(decision) is not tuple or len(decision) != 3:
                return self._install_empty_event_context()
            outcome, owner_decision, resolution = decision
            if (
                outcome not in {"approve", "deny"}
                or type(owner_decision) is not OwnerDecision
                or type(resolution) is not NotificationAttemptSpec
                or self.store is None
            ):
                return self._install_empty_event_context()
            try:
                item = self.store.load_task_work_item(
                    owner_decision.task_id, now_us=time.time_ns() // 1000
                )
                if outcome == "approve":
                    result = self.store.approve(
                        item.task_id,
                        item.binding,
                        owner_decision,
                        resolution_notification=resolution,
                        now_us=resolution.created_at_us,
                    )
                else:
                    result = self.store.deny(
                        item.task_id,
                        item.binding,
                        owner_decision,
                        resolution_notification=resolution,
                        now_us=resolution.created_at_us,
                        reason_code="owner_rejected",
                    )
                if not result.applied:
                    return self._install_empty_event_context()
            except BaseException:
                return self._install_empty_event_context()
        try:
            token = self.services.bind_event(event)
            context = self.services.context_for_current_event()
        except BaseException:
            if "token" in locals():
                try:
                    self.services.unbind_event(token)
                except BaseException:
                    pass
            self._healthy = False
            configure_private_read_request_runtime(None)
            raise RuntimeError("trusted private-read event binding failed") from None
        return TrustedPrivateReadEventBinding(
            token=token,
            private_context=context is not None,
        )

    def unbind_event(self, binding: TrustedPrivateReadEventBinding) -> None:
        if type(binding) is not TrustedPrivateReadEventBinding:
            self._healthy = False
            configure_private_read_request_runtime(None)
            raise TypeError("exact trusted event binding is required")
        try:
            self.services.unbind_event(binding.token)
        except BaseException:
            self._healthy = False
            configure_private_read_request_runtime(None)
            raise RuntimeError("trusted private-read event cleanup failed") from None


def compose_trusted_private_read_services(
    _runner: object,
    _config: object,
) -> object:
    """Gateway-owned production composition boundary.

    The WIP accepted an arbitrary import path whose factory could self-assert
    requester identity, policy evidence, session/process isolation, and delivery
    authority. That is not a trustworthy composition mechanism. Version 2
    resolves only to the built-in Juno MVP adapters below; the version-1
    high-assurance design remains dormant for future hardening. Configuration
    never selects executable code.
    """
    from gateway.juno_private_read_mvp import (
        JunoPrivateReadMvpConfig,
        compose_juno_private_read_mvp_services,
    )
    if type(_config) is JunoPrivateReadMvpConfig:
        return compose_juno_private_read_mvp_services(_runner, _config)
    return None


__all__ = [
    "TrustedPrivateReadConfigurationError",
    "TrustedPrivateReadGatewayHost",
    "TrustedPrivateReadHostConfig",
    "TrustedPrivateReadHostServices",
    "TrustedPrivateReadEventBinding",
    "compose_trusted_private_read_services",
]
