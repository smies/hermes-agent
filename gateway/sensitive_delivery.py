"""Host-owned, fail-closed sensitive delivery through one-shot processes.

This module is deliberately disconnected from ordinary gateway adapters and
``SendResult``.  A sensitive transport is inert until trusted host code
registers an exact executable manifest, verifier, live runtime identity, and
bounded live-account probe.  Plaintext crosses the transport boundary only on
the bounded stdin of a newly-created process in its own session.

Python host code in this module is part of the trusted computing base.  The
process boundary prevents transport/plugin callbacks from retaining plaintext;
it is not language-level isolation from arbitrary code already executing in
the host interpreter.  The digest-allowlisted executable is also trusted code,
not a sandbox for arbitrary same-UID hostile programs.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, fields
from enum import Enum
import hashlib
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import weakref
import warnings
from typing import Optional

from gateway.config import Platform


MAX_SENSITIVE_PLAINTEXT_BYTES = 4096
MAX_SENSITIVE_REGISTRATIONS = 64
MAX_SENSITIVE_COMMAND_ARGUMENTS = 16
MAX_SENSITIVE_EVIDENCE_BYTES = 16 * 1024
MAX_SENSITIVE_STDERR_BYTES = 16 * 1024
MAX_SENSITIVE_STDIN_BYTES = 5 * 1024
MAX_SENSITIVE_EXECUTABLE_BYTES = 256 * 1024 * 1024
MIN_SENSITIVE_WAIT_SECONDS = 0.1
MAX_SENSITIVE_WAIT_SECONDS = 120.0
_MAX_TEXT_BYTES = 512
_MAX_MACHINE_BYTES = 128
_MAX_EVIDENCE_FIELDS = 32
_MAX_BOUND_INTEGER = (1 << 63) - 1
_CLEANUP_POLL_SECONDS = 0.001
_MIN_CLEANUP_KILL_SECONDS = 0.25
_TASK_JOIN_RESERVE_SECONDS = 0.02
_TOKEN_RE = re.compile(r"^hmac-sha256:v1:[0-9a-f]{64}$")
_HEX256_RE = re.compile(r"^[0-9a-f]{64}$")
_MACHINE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_BIND_CONTEXT = b"hermes-sensitive-delivery-account:v1"
_AUTH_CONTEXT = b"hermes-sensitive-delivery-authorization:v1"
_RECEIPT_CONTEXT = b"hermes-sensitive-delivery-receipt:v1"
_PROBE_CONTEXT = b"hermes-sensitive-delivery-account-probe:v1"

_RECEIPT_FIELD_NAMES = (
    "outcome",
    "error_code",
    "provenance",
    "destination",
    "attempt",
    "provider_message_id",
    "non_acceptance_provider_message_id",
    "submission_id",
    "evidence_id",
    "acceptance_status",
    "acceptance_signal",
    "non_acceptance_signal",
    "acceptance_observed_us",
    "provider_observed_us",
    "_seal",
)


def _lifecycle_checkpoint(name):
    """Stable fault-injection seam for lifecycle ownership tests."""

    return None


class SensitiveDeliveryOutcome(str, Enum):
    ACCEPTED = "accepted"
    UNSUPPORTED = "unsupported"
    REJECTED = "rejected"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"


class SensitiveDeliveryAcceptanceStatus(str, Enum):
    ACCEPTED = "provider_accepted"
    REJECTED = "provider_rejected"
    UNKNOWN = "acceptance_status_unknown"


class SensitiveDeliveryErrorCode(str, Enum):
    def __new__(cls, value: str, outcome: SensitiveDeliveryOutcome):
        member = str.__new__(cls, value)
        member._value_ = value
        member.outcome = outcome
        return member

    UNSUPPORTED = "unsupported", SensitiveDeliveryOutcome.UNSUPPORTED
    PROFILE_NOT_FOUND = "profile_not_found", SensitiveDeliveryOutcome.REJECTED
    PLATFORM_NOT_FOUND = "platform_not_found", SensitiveDeliveryOutcome.REJECTED
    PROVENANCE_MISMATCH = "provenance_mismatch", SensitiveDeliveryOutcome.REJECTED
    ACCOUNT_MISMATCH = "account_mismatch", SensitiveDeliveryOutcome.REJECTED
    RUNTIME_UNAVAILABLE = "runtime_unavailable", SensitiveDeliveryOutcome.REJECTED
    EXECUTABLE_INVALID = "executable_invalid", SensitiveDeliveryOutcome.REJECTED
    ROUTER_CLOSED = "router_closed", SensitiveDeliveryOutcome.REJECTED
    HANDLE_USED = "handle_used", SensitiveDeliveryOutcome.REJECTED
    PREPARED_LIMIT = "prepared_limit", SensitiveDeliveryOutcome.REJECTED
    IN_FLIGHT_LIMIT = "in_flight_limit", SensitiveDeliveryOutcome.REJECTED
    SEND_AUTHORITY_INVALID = "send_authority_invalid", SensitiveDeliveryOutcome.FAILED
    SEND_START_UNCERTAIN = "send_start_uncertain", SensitiveDeliveryOutcome.AMBIGUOUS
    CANCELLED_BEFORE_SEND = (
        "cancelled_before_send",
        SensitiveDeliveryOutcome.REJECTED,
    )
    CANCELLED = "cancelled", SensitiveDeliveryOutcome.AMBIGUOUS
    TIMEOUT = "timeout", SensitiveDeliveryOutcome.AMBIGUOUS
    TRANSPORT_FAILED = "transport_failed", SensitiveDeliveryOutcome.AMBIGUOUS
    OUTPUT_LIMIT = "output_limit", SensitiveDeliveryOutcome.AMBIGUOUS
    INPUT_LIMIT = "input_limit", SensitiveDeliveryOutcome.REJECTED
    CLEANUP_FAILED = "cleanup_failed", SensitiveDeliveryOutcome.AMBIGUOUS
    INVALID_EVIDENCE = "invalid_evidence", SensitiveDeliveryOutcome.AMBIGUOUS
    CORRELATION_MISMATCH = "correlation_mismatch", SensitiveDeliveryOutcome.AMBIGUOUS
    ACCEPTANCE_UNCONFIRMED = (
        "acceptance_unconfirmed",
        SensitiveDeliveryOutcome.AMBIGUOUS,
    )
    INVALID_EVIDENCE_TIME = (
        "invalid_evidence_time",
        SensitiveDeliveryOutcome.AMBIGUOUS,
    )
    TRANSPORT_REJECTED = "transport_rejected", SensitiveDeliveryOutcome.REJECTED
    AUTHORIZATION_FINISH_UNCERTAIN = (
        "authorization_finish_uncertain",
        SensitiveDeliveryOutcome.AMBIGUOUS,
    )


class SensitiveDeliveryCleanupError(RuntimeError):
    """Raised when bounded process-group cleanup cannot be proven complete."""


class _OwnedBaseExceptionCarrier(Exception):
    """Moves a non-Exception failure across an asyncio task boundary safely."""

    __slots__ = ("failure",)

    def __init__(self, failure):
        super().__init__(type(failure).__name__)
        self.failure = failure


class _NoCopyOrPickle:
    __slots__ = ()

    def __copy__(self):
        raise TypeError(f"{type(self).__name__} cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError(f"{type(self).__name__} cannot be deep-copied")

    def __reduce_ex__(self, protocol):
        raise TypeError(f"{type(self).__name__} cannot be serialized")


def _text(value, name, *, optional=False, machine=False):
    if value is None and optional:
        return None
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{name} must be an exact non-empty string")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise ValueError(f"{name} must be valid UTF-8") from exc
    if len(encoded) > (_MAX_MACHINE_BYTES if machine else _MAX_TEXT_BYTES):
        raise ValueError(f"{name} exceeds its bounded metadata limit")
    if machine and _MACHINE_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a bounded machine identifier")
    return value


def _platform(value):
    if type(value) is not Platform:
        raise TypeError("platform must be a Platform")
    return value


def _profile(value):
    value = _text(value, "profile")
    from hermes_cli.profiles import normalize_profile_name, validate_profile_name

    canonical = normalize_profile_name(value)
    validate_profile_name(canonical)
    if canonical != value or canonical == "custom":
        raise ValueError("profile must be an exact canonical identity")
    return value


def _token(value, name):
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a versioned HMAC-SHA256 token")
    return value


def _utc_us(value, name):
    if type(value) is not int or not 0 < value <= _MAX_BOUND_INTEGER:
        raise ValueError(
            f"{name} must be a bounded positive integer UTC epoch microseconds"
        )
    return value


def _positive_bounded_integer(value, name):
    if type(value) is not int or not 0 < value <= _MAX_BOUND_INTEGER:
        raise ValueError(f"{name} must be a bounded positive integer")
    return value


def _seconds(value, name, minimum=MIN_SENSITIVE_WAIT_SECONDS, maximum=MAX_SENSITIVE_WAIT_SECONDS):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise TypeError(f"{name} must be finite")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside safe bounds")
    return float(value)


def _frame(parts):
    encoded = []
    for part in parts:
        if isinstance(part, Enum):
            part = part.value
        if part is None:
            raw = b""
        elif type(part) is bytes:
            raw = part
        else:
            raw = str(part).encode("utf-8", "strict")
        encoded.append(len(raw).to_bytes(4, "big") + raw)
    return b"".join(encoded)


_PROVENANCE_FIELDS = (
    "correlation_id",
    "authorization_task_id",
    "operation_id",
    "resource_type",
    "resource_id",
    "binding_digest",
    "request_digest",
    "request_hmac",
    "request_key_version",
    "policy_namespace",
    "policy_version",
    "policy_hash",
    "decision_model_id",
    "worker_profile",
    "worker_agent",
    "worker_account",
    "claim_nonce",
    "claim_generation",
)


@dataclass(frozen=True, slots=True, repr=False)
class SensitiveDeliveryAuthorizationProvenance:
    correlation_id: str
    authorization_task_id: str
    operation_id: str
    resource_type: str
    resource_id: str
    binding_digest: str
    request_digest: str
    request_hmac: str
    request_key_version: str
    policy_namespace: str
    policy_version: str
    policy_hash: str
    decision_model_id: str
    worker_profile: str
    worker_agent: str
    worker_account: str
    claim_nonce: str
    claim_generation: int

    def __post_init__(self):
        for name in _PROVENANCE_FIELDS:
            value = getattr(self, name)
            if name == "request_hmac":
                _token(value, name)
            elif name == "claim_generation":
                _positive_bounded_integer(value, name)
            else:
                _text(value, name)

    def binding_tuple(self):
        return tuple(getattr(self, name) for name in _PROVENANCE_FIELDS)

    def __repr__(self):
        return "<SensitiveDeliveryAuthorizationProvenance redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class SensitiveDeliveryDestination:
    authorization_task_id: str
    operation_id: str
    profile: str
    platform: Platform
    account_binding_token: str
    chat_id: str
    thread_id: Optional[str] = None

    def __post_init__(self):
        _text(self.authorization_task_id, "authorization_task_id", machine=True)
        _text(self.operation_id, "operation_id", machine=True)
        _profile(self.profile)
        _platform(self.platform)
        _token(self.account_binding_token, "account_binding_token")
        _text(self.chat_id, "chat_id")
        _text(self.thread_id, "thread_id", optional=True)

    def binding_tuple(self):
        return (
            self.authorization_task_id,
            self.operation_id,
            self.profile,
            self.platform,
            self.account_binding_token,
            self.chat_id,
            self.thread_id,
        )

    def __repr__(self):
        return (
            f"<SensitiveDeliveryDestination profile={self.profile!r} "
            f"platform={self.platform.value!r} redacted>"
        )


class SensitiveDeliveryAccountBinder(_NoCopyOrPickle):
    __slots__ = ("__secret",)

    def __init__(self, secret):
        if type(secret) is not bytes or len(secret) < 32:
            raise ValueError("binding secret must be at least 32 bytes")
        self.__secret = bytes(secret)

    def __repr__(self):
        return "<SensitiveDeliveryAccountBinder redacted>"

    __str__ = __repr__

    def bind_sensitive_account(self, platform, account_identity):
        _platform(platform)
        _text(account_identity, "provider-canonical account identity")
        message = _frame((_BIND_CONTEXT, platform, account_identity))
        return "hmac-sha256:v1:" + hmac.new(
            self.__secret, message, hashlib.sha256
        ).hexdigest()


class SensitiveDeliveryHostAuthority(_NoCopyOrPickle):
    """Key-bearing host authority.  It is never placed in a registration."""

    __slots__ = (
        "__authorization_key",
        "__receipt_key",
        "__issued_receipts",
        "__issued_receipts_lock",
        "__weakref__",
    )

    def __init__(self, authorization_key, receipt_key):
        for key, name in (
            (authorization_key, "authorization key"),
            (receipt_key, "receipt key"),
        ):
            if type(key) is not bytes or len(key) < 32:
                raise ValueError(f"{name} must be at least 32 bytes")
        self.__authorization_key = bytes(authorization_key)
        self.__receipt_key = bytes(receipt_key)
        # Receipt authority is object authority, not merely possession of a
        # valid-looking bearer artifact.  Key by ``id`` and retain only a weak
        # reference so equality/hash customization cannot transfer membership
        # and dead receipts cannot accumulate in the authority.
        self.__issued_receipts = {}
        self.__issued_receipts_lock = threading.Lock()

    def __repr__(self):
        return "<SensitiveDeliveryHostAuthority redacted>"

    __str__ = __repr__

    def _authorize_verified(self, **values):
        """Seal one bridge-verified authorization work item.

        The public delivery route never accepts caller-created provenance;
        only ``AuthorizationSensitiveDeliveryBridge`` calls this method and
        retains the exact returned object.
        """
        if set(values) != set(_PROVENANCE_FIELDS) - {"request_hmac"}:
            raise TypeError("authorization authority requires the exact field set")
        unsigned = tuple(values[name] for name in _PROVENANCE_FIELDS if name != "request_hmac")
        request_hmac = "hmac-sha256:v1:" + hmac.new(
            self.__authorization_key,
            _frame((_AUTH_CONTEXT, *unsigned)),
            hashlib.sha256,
        ).hexdigest()
        values["request_hmac"] = request_hmac
        return SensitiveDeliveryAuthorizationProvenance(
            **{name: values[name] for name in _PROVENANCE_FIELDS}
        )

    def verify_authorization(self, provenance):
        if type(provenance) is not SensitiveDeliveryAuthorizationProvenance:
            return False
        unsigned = tuple(
            getattr(provenance, name)
            for name in _PROVENANCE_FIELDS
            if name != "request_hmac"
        )
        expected = "hmac-sha256:v1:" + hmac.new(
            self.__authorization_key,
            _frame((_AUTH_CONTEXT, *unsigned)),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, provenance.request_hmac)

    def _seal_values(self, values):
        return "hmac-sha256:v1:" + hmac.new(
            self.__receipt_key,
            _frame((_RECEIPT_CONTEXT, *values)),
            hashlib.sha256,
        ).hexdigest()

    def verify_receipt(self, receipt):
        if type(receipt) is not SensitiveDeliveryReceipt:
            return False
        receipt_id = id(receipt)
        with self.__issued_receipts_lock:
            issued_ref = self.__issued_receipts.get(receipt_id)
            if issued_ref is None or issued_ref() is not receipt:
                return False
        try:
            receipt._validate_shape()
            if not self.verify_authorization(receipt.provenance):
                return False
            expected = self._seal_values(receipt._seal_values())
        except Exception:
            return False
        return type(receipt._seal) is str and hmac.compare_digest(
            expected, receipt._seal
        )

    def _mint_receipt(self, **values):
        expected_fields = set(_RECEIPT_FIELD_NAMES) - {"_seal"}
        if set(values) != expected_fields:
            raise TypeError("receipt authority requires the exact closed field set")
        receipt = object.__new__(SensitiveDeliveryReceipt)
        for name in _RECEIPT_FIELD_NAMES:
            object.__setattr__(
                receipt,
                name,
                "pending" if name == "_seal" else values[name],
            )
        receipt._validate_shape(require_seal=False)
        object.__setattr__(receipt, "_seal", self._seal_values(receipt._seal_values()))
        receipt._validate_shape()
        receipt_id = id(receipt)

        def forget(dead_ref, *, authority_ref=weakref.ref(self), key=receipt_id):
            authority = authority_ref()
            if authority is None:
                return
            with authority.__issued_receipts_lock:
                if authority.__issued_receipts.get(key) is dead_ref:
                    authority.__issued_receipts.pop(key, None)

        issued_ref = weakref.ref(receipt, forget)
        with self.__issued_receipts_lock:
            self.__issued_receipts[receipt_id] = issued_ref
        return receipt


class SensitiveDeliverySendGrant(_NoCopyOrPickle):
    """Opaque, live, single-use authority minted after durable send-start."""

    __slots__ = (
        "grant_id", "attempt_id", "authorization_task_id", "correlation_id",
        "operation_id", "resource_type", "resource_id", "binding_digest",
        "request_digest", "request_key_version", "worker_profile",
        "worker_agent", "worker_account", "claim_nonce", "claim_generation",
        "send_started_us", "observation_id", "__weakref__",
    )

    def __new__(cls, *args, **kwargs):
        raise TypeError("send grants are minted only by authorization authority")

    def __repr__(self):
        return "<SensitiveDeliverySendGrant redacted>"

    __str__ = __repr__


class SensitiveDeliveryAccountObservation(_NoCopyOrPickle):
    """Opaque proof returned by one exact configured live probe."""

    __slots__ = (
        "observation_id", "account_binding_token", "runtime_instance_token",
        "process_identity", "session_identity", "connection_epoch",
        "observed_at_us", "__weakref__",
    )

    def __new__(cls, *args, **kwargs):
        raise TypeError("account observations are minted only by a live probe")

    def __repr__(self):
        return "<SensitiveDeliveryAccountObservation redacted>"

    __str__ = __repr__


class SensitiveDeliveryLoopbackAccountProbe(_NoCopyOrPickle):
    """Challenge a configured loopback sidecar for its current account state.

    The endpoint is provider-neutral.  A persistent transport sidecar returns
    a signed, closed JSON record containing its canonical account identity and
    exact runtime/process/session/epoch.  No private payload is in this
    protocol, and the probe creates no process or descendant.
    """

    __slots__ = (
        "host", "port", "unix_socket", "_key", "_binder", "timeout_seconds",
        "max_response_bytes", "_issued", "_issued_lock", "_socket",
        "_async_lock", "_failed", "__weakref__",
    )

    def __init__(
        self,
        *,
        host=None,
        port=None,
        unix_socket=None,
        connected_socket=None,
        probe_hmac_key,
        account_binder,
        timeout_seconds=2.0,
        max_response_bytes=4096,
    ):
        endpoint_count = sum(
            (host is not None or port is not None, unix_socket is not None, connected_socket is not None)
        )
        if endpoint_count != 1:
            raise ValueError("account probe must configure exactly one endpoint")
        if connected_socket is not None:
            if type(connected_socket) is not socket.socket or connected_socket.fileno() < 0:
                raise TypeError("account probe connected socket must be exact and live")
            if connected_socket.type & socket.SOCK_STREAM != socket.SOCK_STREAM:
                raise ValueError("account probe connected socket must be a stream")
            connected_socket.setblocking(False)
            address = None
            socket_path = None
            host = None
            port = None
        elif unix_socket is None:
            try:
                address = ipaddress.ip_address(host)
            except ValueError as exc:
                raise ValueError("account probe host must be a literal loopback address") from exc
            if not address.is_loopback:
                raise ValueError("account probe host must be loopback")
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("account probe port is invalid")
            socket_path = None
        else:
            if host is not None or port is not None:
                raise ValueError("account probe must configure exactly one endpoint")
            if type(unix_socket) is not str or not os.path.isabs(unix_socket):
                raise ValueError("account probe Unix socket must be an absolute path")
            socket_path = os.path.abspath(unix_socket)
            if socket_path != unix_socket or len(os.fsencode(socket_path)) > 100:
                raise ValueError("account probe Unix socket path is not canonical and bounded")
            address = None
        if type(probe_hmac_key) is not bytes or len(probe_hmac_key) < 32:
            raise ValueError("account probe HMAC key must be at least 32 bytes")
        if type(account_binder) is not SensitiveDeliveryAccountBinder:
            raise TypeError("account probe requires the exact host account binder")
        if type(max_response_bytes) is not int or not 256 <= max_response_bytes <= 16 * 1024:
            raise ValueError("account probe response cap is invalid")
        self.host = None if address is None else str(address)
        self.port = port
        self.unix_socket = socket_path
        self._key = bytes(probe_hmac_key)
        self._binder = account_binder
        self.timeout_seconds = _seconds(
            timeout_seconds, "account_probe_timeout_seconds", 0.05, 10.0
        )
        self.max_response_bytes = max_response_bytes
        self._issued = {}
        self._issued_lock = threading.Lock()
        self._socket = connected_socket
        self._async_lock = None
        self._failed = False

    def __repr__(self):
        return "<SensitiveDeliveryLoopbackAccountProbe redacted>"

    __str__ = __repr__

    def _signature(self, values):
        return "hmac-sha256:v1:" + hmac.new(
            self._key,
            _frame((_PROBE_CONTEXT, *values)),
            hashlib.sha256,
        ).hexdigest()

    async def observe(self, *, platform, deadline, monotonic_clock):
        _platform(platform)
        logical_deadline = min(
            deadline,
            monotonic_clock() + self.timeout_seconds,
        )
        real_deadline = time.monotonic() + max(
            0.0,
            logical_deadline - monotonic_clock(),
        )

        def remaining_timeout():
            remaining = _dual_remaining(
                logical_deadline,
                real_deadline,
                monotonic_clock,
            )
            if remaining <= 0:
                raise TimeoutError
            return remaining

        if logical_deadline <= monotonic_clock():
            raise TimeoutError
        challenge = secrets.token_hex(32)
        reader = writer = None
        lock = None
        lock_owned = False
        try:
            request = json.dumps(
                {"version": 1, "challenge": challenge},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii") + b"\n"
            if self._socket is not None:
                if self._failed:
                    raise RuntimeError("account probe channel is invalid")
                if self._async_lock is None:
                    self._async_lock = asyncio.Lock()
                lock = self._async_lock
                await asyncio.wait_for(lock.acquire(), timeout=remaining_timeout())
                lock_owned = True
                loop = asyncio.get_running_loop()
                await asyncio.wait_for(
                    loop.sock_sendall(self._socket, request),
                    timeout=remaining_timeout(),
                )
                buffered = bytearray()
                while not buffered.endswith(b"\n"):
                    chunk = await asyncio.wait_for(
                        loop.sock_recv(self._socket, min(4096, self.max_response_bytes + 1 - len(buffered))),
                        timeout=remaining_timeout(),
                    )
                    if not chunk:
                        raise BrokenPipeError("account probe channel closed")
                    buffered.extend(chunk)
                    if len(buffered) > self.max_response_bytes:
                        raise ValueError("account probe response is oversized")
                raw = bytes(buffered)
                buffered.clear()
            else:
                connector = (
                asyncio.open_unix_connection(
                    self.unix_socket,
                    limit=self.max_response_bytes + 1,
                )
                if self.unix_socket is not None
                else asyncio.open_connection(
                    self.host,
                    self.port,
                    family=socket.AF_INET6 if ":" in self.host else socket.AF_INET,
                    limit=self.max_response_bytes + 1,
                )
                )
                reader, writer = await asyncio.wait_for(
                    connector,
                    timeout=remaining_timeout(),
                )
                writer.write(request)
                await asyncio.wait_for(
                    writer.drain(), timeout=remaining_timeout()
                )
                raw = await asyncio.wait_for(
                    reader.readline(), timeout=remaining_timeout()
                )
            if not raw.endswith(b"\n") or len(raw) > self.max_response_bytes:
                raise ValueError("account probe response is incomplete or oversized")
            response = _decode_closed_evidence(raw[:-1])
            required = {
                "version", "challenge", "account_identity", "runtime_instance_token",
                "process_identity", "session_identity", "connection_epoch",
                "observed_at_us", "signature",
            }
            if set(response) != required or response["version"] != 1:
                raise ValueError("account probe response has an invalid field set")
            if response["challenge"] != challenge:
                raise ValueError("account probe challenge mismatch")
            for name in (
                "account_identity", "runtime_instance_token", "process_identity",
                "session_identity",
            ):
                _text(response[name], name, machine=name != "account_identity")
            _positive_bounded_integer(response["connection_epoch"], "connection_epoch")
            _utc_us(response["observed_at_us"], "observed_at_us")
            _token(response["signature"], "signature")
            signed = (
                response["challenge"], response["account_identity"],
                response["runtime_instance_token"], response["process_identity"],
                response["session_identity"], response["connection_epoch"],
                response["observed_at_us"],
            )
            if not hmac.compare_digest(response["signature"], self._signature(signed)):
                raise ValueError("account probe signature mismatch")
            observation = object.__new__(SensitiveDeliveryAccountObservation)
            values = {
                "observation_id": challenge,
                "account_binding_token": self._binder.bind_sensitive_account(
                    platform, response["account_identity"]
                ),
                "runtime_instance_token": response["runtime_instance_token"],
                "process_identity": response["process_identity"],
                "session_identity": response["session_identity"],
                "connection_epoch": response["connection_epoch"],
                "observed_at_us": response["observed_at_us"],
            }
            for name, value in values.items():
                object.__setattr__(observation, name, value)
            observation_id = id(observation)

            def forget(dead_ref, *, probe_ref=weakref.ref(self), key=observation_id):
                probe = probe_ref()
                if probe is not None:
                    with probe._issued_lock:
                        if probe._issued.get(key) is dead_ref:
                            probe._issued.pop(key, None)

            issued_ref = weakref.ref(observation, forget)
            with self._issued_lock:
                self._issued[observation_id] = issued_ref
            return observation
        except BaseException:
            if self._socket is not None:
                self._failed = True
                self._socket.close()
            raise
        finally:
            if lock_owned:
                lock.release()
            reader = None
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.25)
                except BaseException:
                    pass
            writer = None

    def close(self):
        if self._socket is not None:
            self._failed = True
            self._socket.close()

    def owns(self, observation):
        if type(observation) is not SensitiveDeliveryAccountObservation:
            return False
        with self._issued_lock:
            issued_ref = self._issued.get(id(observation))
            return issued_ref is not None and issued_ref() is observation


@dataclass(frozen=True, slots=True, repr=False)
class SensitiveDeliveryTransportCommand(_NoCopyOrPickle):
    executable: str
    executable_sha256: str
    arguments: tuple[str, ...] = ()

    def __post_init__(self):
        if type(self.executable) is not str or not os.path.isabs(self.executable):
            raise ValueError("transport executable must be an absolute path")
        if type(self.executable_sha256) is not str or _HEX256_RE.fullmatch(self.executable_sha256) is None:
            raise ValueError("transport executable digest must be lowercase SHA-256")
        if type(self.arguments) is not tuple or len(self.arguments) > MAX_SENSITIVE_COMMAND_ARGUMENTS:
            raise ValueError("transport arguments must be an explicitly bounded tuple")
        for argument in self.arguments:
            _text(argument, "transport argument")
            if "\x00" in argument:
                raise ValueError("transport arguments cannot contain NUL")

    def __repr__(self):
        return "<SensitiveDeliveryTransportCommand redacted>"


@dataclass(frozen=True, slots=True, repr=False)
class SensitiveDeliveryRuntimeIdentity:
    profile: str
    platform: Platform
    transport_implementation_id: str
    runtime_instance_token: str
    process_identity: str
    session_identity: str
    account_binding_token: str
    connection_epoch: int

    def __post_init__(self):
        _profile(self.profile)
        _platform(self.platform)
        for name in (
            "transport_implementation_id",
            "runtime_instance_token",
            "process_identity",
            "session_identity",
        ):
            _text(getattr(self, name), name, machine=True)
        _token(self.account_binding_token, "account_binding_token")
        _positive_bounded_integer(self.connection_epoch, "connection_epoch")

    def binding_tuple(self):
        return tuple(getattr(self, field) for field in (
            "profile", "platform", "transport_implementation_id",
            "runtime_instance_token", "process_identity", "session_identity",
            "account_binding_token", "connection_epoch",
        ))

    def __repr__(self):
        return "<SensitiveDeliveryRuntimeIdentity redacted>"


class SensitiveDeliveryProcessLease(_NoCopyOrPickle):
    """Host-owned lifecycle lease for an optional provider sidecar child."""

    __leased_processes = weakref.WeakSet()
    __lease_registry_lock = threading.Lock()

    __slots__ = (
        "_process",
        "process_identity",
        "_lock",
        "_invalid",
        "_registered",
        "__weakref__",
    )

    def __init__(self, process, process_identity):
        if type(process) is not subprocess.Popen:
            raise TypeError("sidecar lease requires an exact host Popen child")
        _text(process_identity, "process_identity", machine=True)
        if process.pid <= 0 or process.poll() is not None:
            raise ValueError("sidecar lease requires a live direct child")
        try:
            process_group_id = os.getpgid(process.pid)
        except ProcessLookupError as exc:
            raise ValueError("sidecar lease requires a live direct child") from exc
        if process_group_id != process.pid:
            raise ValueError(
                "sidecar lease requires a child leading its dedicated process group"
            )
        with self.__lease_registry_lock:
            if process in self.__leased_processes:
                raise ValueError("sidecar process already has a lifecycle lease")
            self.__leased_processes.add(process)
        self._process = process
        self.process_identity = process_identity
        self._lock = threading.Lock()
        self._invalid = False
        self._registered = False

    def __repr__(self):
        return "<SensitiveDeliveryProcessLease redacted>"

    def is_live(self, expected_process_identity):
        with self._lock:
            return (
                not self._invalid
                and expected_process_identity == self.process_identity
                and self._process.poll() is None
                and _process_group_is_dedicated_leader(self._process.pid)
            )

    def _register_once(self):
        with self._lock:
            if self._registered:
                raise ValueError("sidecar lease/process identity is already registered")
            if self._invalid or self._process.poll() is not None:
                raise ValueError("sidecar lease is not live")
            if not _process_group_is_dedicated_leader(self._process.pid):
                raise ValueError("sidecar lease lost its dedicated process group")
            self._registered = True

    def _rollback_registration(self):
        with self._lock:
            self._registered = False

    async def invalidate_and_reap(
        self,
        term_grace_seconds,
        *,
        cleanup_deadline=None,
        monotonic_clock=time.monotonic,
    ):
        term_grace_seconds = _seconds(
            term_grace_seconds,
            "termination_grace_seconds",
            0.01,
            5.0,
        )
        now = monotonic_clock()
        maximum_deadline = now + _cleanup_budget_seconds(term_grace_seconds)
        if cleanup_deadline is None:
            cleanup_deadline = maximum_deadline
        elif (
            type(cleanup_deadline) not in (int, float)
            or not math.isfinite(cleanup_deadline)
        ):
            raise ValueError("cleanup deadline must be finite")
        else:
            cleanup_deadline = min(float(cleanup_deadline), maximum_deadline)
        owned_cleanup_deadline = max(
            now,
            cleanup_deadline - _TASK_JOIN_RESERVE_SECONDS,
        )
        cleanup_task = asyncio.create_task(
            self._invalidate_and_reap_owned(
                term_grace_seconds,
                owned_cleanup_deadline,
                monotonic_clock,
            ),
            name="sensitive-delivery-sidecar-cleanup",
        )
        _, cancellation_requested = await _await_task_non_discardable(
            cleanup_task,
            deadline=cleanup_deadline,
            monotonic_clock=monotonic_clock,
        )
        if cancellation_requested:
            raise asyncio.CancelledError

    async def _invalidate_and_reap_owned(
        self,
        term_grace_seconds,
        cleanup_deadline,
        monotonic_clock,
    ):
        with self._lock:
            if (
                self._invalid
                and self._process.poll() is not None
                and not _process_group_exists(self._process.pid)
            ):
                return
            self._invalid = True
            process = self._process

        real_cleanup_deadline = _real_deadline_for(
            cleanup_deadline,
            monotonic_clock,
        )
        process_group_id = process.pid
        _signal_process_group(process_group_id, signal.SIGTERM)
        grace_deadline = min(
            cleanup_deadline,
            monotonic_clock() + term_grace_seconds,
        )
        while (
            _process_group_exists(process_group_id)
            and monotonic_clock() < grace_deadline
            and time.monotonic() < real_cleanup_deadline
        ):
            process.poll()
            await asyncio.sleep(
                min(
                    _CLEANUP_POLL_SECONDS,
                    max(0.0, grace_deadline - monotonic_clock()),
                )
            )

        if _process_group_exists(process_group_id):
            _signal_process_group(process_group_id, signal.SIGKILL)
        while (
            monotonic_clock() < cleanup_deadline
            and time.monotonic() < real_cleanup_deadline
        ):
            child_exited = process.poll() is not None
            group_exited = not _process_group_exists(process_group_id)
            if child_exited and group_exited:
                break
            await asyncio.sleep(
                min(
                    _CLEANUP_POLL_SECONDS,
                    max(0.0, cleanup_deadline - monotonic_clock()),
                )
            )

        remaining = _dual_remaining(
            cleanup_deadline,
            real_cleanup_deadline,
            monotonic_clock,
        )
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise SensitiveDeliveryCleanupError(
                "sidecar direct child did not exit within cleanup deadline"
            ) from exc
        if _process_group_exists(process_group_id):
            try:
                _signal_process_group(process_group_id, signal.SIGKILL)
            finally:
                raise SensitiveDeliveryCleanupError(
                    "sidecar process-group cleanup could not be proven"
                )


@dataclass(frozen=True, slots=True)
class _EvidenceDecision:
    status: SensitiveDeliveryAcceptanceStatus
    signal: str
    provider_message_id: str
    submission_id: str
    evidence_id: str
    provider_observed_us: Optional[int]


def _closed_evidence_object(pairs):
    """Reject duplicate keys and oversized objects at every JSON object level."""

    if len(pairs) > _MAX_EVIDENCE_FIELDS:
        raise ValueError("evidence object exceeds its field cap")
    result = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("evidence object has an invalid or duplicate key")
        result[key] = value
    return result


def _decode_closed_evidence(raw_bytes):
    return json.loads(
        raw_bytes.decode("utf-8", "strict"),
        object_pairs_hook=_closed_evidence_object,
    )


@dataclass(frozen=True, slots=True, repr=False)
class SensitiveDeliveryDestinationEvidenceVerifier(_NoCopyOrPickle):
    """Exact host-owned policy for a transport's closed destination evidence."""

    identity: str
    accepted_signals: tuple[str, ...]
    rejected_signals: tuple[str, ...]

    def __post_init__(self):
        _text(self.identity, "evidence verifier identity", machine=True)
        accepted = self._validate_signals(self.accepted_signals, "accepted_signals")
        rejected = self._validate_signals(self.rejected_signals, "rejected_signals")
        if set(accepted) & set(rejected):
            raise ValueError("accepted and rejected evidence signals must be disjoint")

    @staticmethod
    def _validate_signals(values, label):
        if type(values) is not tuple or not 1 <= len(values) <= 16:
            raise TypeError(f"{label} must be an exact bounded tuple")
        if len(set(values)) != len(values):
            raise ValueError(f"{label} must contain unique signals")
        for value in values:
            _text(value, label, machine=True)
        return values

    def __repr__(self):
        return "<SensitiveDeliveryDestinationEvidenceVerifier redacted>"

    def verify(self, raw, *, attempt, identity):
        if type(raw) is not dict or not 1 <= len(raw) <= _MAX_EVIDENCE_FIELDS:
            raise ValueError("invalid closed evidence object")
        if any(type(key) is not str for key in raw):
            raise ValueError("invalid evidence key")
        for value in raw.values():
            if value is not None and type(value) not in (str, int, bool):
                raise ValueError("nested evidence is forbidden")
            if type(value) is str and len(value.encode("utf-8", "strict")) > _MAX_TEXT_BYTES:
                raise ValueError("evidence value exceeds its bound")
        correlation = {
            "version": 1,
            "attempt_id": attempt.attempt_id,
            "authorization_task_id": attempt.authorization_task_id,
            "correlation_id": attempt.correlation_id,
            "operation_id": attempt.operation_id,
            "authorization_binding_digest": attempt.binding_digest,
            "request_digest": attempt.request_digest,
            "request_key_version": attempt.request_key_version,
            "worker_profile": attempt.worker_profile,
            "worker_agent": attempt.worker_agent,
            "worker_account": attempt.worker_account,
            "claim_nonce": attempt.claim_nonce,
            "claim_generation": attempt.claim_generation,
            "destination_profile": attempt.profile,
            "destination_platform": attempt.platform.value,
            "transport_implementation_id": attempt.transport_implementation_id,
            "destination_chat_id": attempt.chat_id,
            "destination_thread_id": attempt.thread_id,
            "destination_account_binding_token": attempt.account_binding_token,
            "connection_epoch": attempt.connection_epoch,
            "runtime_instance_token": attempt.runtime_instance_token,
            "process_identity": attempt.process_identity,
            "session_identity": attempt.session_identity,
            "account_observation_id": attempt.account_observation_id,
            "account_observed_at_us": attempt.account_observed_at_us,
            "origin": "destination",
        }
        allowed_fields = set(correlation) | {
            "signal",
            "provider_message_id",
            "submission_id",
            "evidence_id",
            "provider_observed_us",
            "thread_id",
            # A transport-supplied status is explicitly recognized only so it
            # can be ignored; acceptance is derived solely from ``signal``.
            "status",
        }
        if not set(raw).issubset(allowed_fields):
            raise ValueError("evidence contains a field outside the closed schema")
        for key, expected in correlation.items():
            if key not in raw:
                raise LookupError("evidence correlation field is missing")
            actual = raw.get(key)
            if key == "destination_account_binding_token":
                if type(actual) is not str or not hmac.compare_digest(actual, expected):
                    raise LookupError("evidence correlation mismatch")
            elif type(actual) is not type(expected) or actual != expected:
                raise LookupError("evidence correlation mismatch")
        if "thread_id" in raw:
            raise LookupError("non-canonical thread correlation field")
        if "status" in raw:
            _text(raw["status"], "status", machine=True)
        signal_name = _text(raw.get("signal"), "signal", machine=True)
        provider_message_id = _text(raw.get("provider_message_id"), "provider_message_id")
        submission_id = _text(raw.get("submission_id"), "submission_id", machine=True)
        evidence_id = _text(raw.get("evidence_id"), "evidence_id", machine=True)
        provider_observed_us = raw.get("provider_observed_us")
        if provider_observed_us is not None:
            _utc_us(provider_observed_us, "provider_observed_us")
        if signal_name in self.accepted_signals:
            status = SensitiveDeliveryAcceptanceStatus.ACCEPTED
        elif signal_name in self.rejected_signals:
            status = SensitiveDeliveryAcceptanceStatus.REJECTED
        else:
            # SERVER_ACK, sender-companion, unknown, and a forged transport
            # ``status=accepted`` are all non-accepting by construction.
            status = SensitiveDeliveryAcceptanceStatus.UNKNOWN
        return _EvidenceDecision(
            status,
            signal_name,
            provider_message_id,
            submission_id,
            evidence_id,
            provider_observed_us,
        )


@dataclass(frozen=True, slots=True, repr=False)
class SensitiveDeliveryTransportRegistration(_NoCopyOrPickle):
    command: SensitiveDeliveryTransportCommand
    identity: SensitiveDeliveryRuntimeIdentity
    verifier: SensitiveDeliveryDestinationEvidenceVerifier
    verifier_type: type
    verifier_identity: str
    account_probe: SensitiveDeliveryLoopbackAccountProbe
    max_sensitive_payload_bytes: int
    max_stdout_bytes: int
    max_stderr_bytes: int
    sidecar_lease: Optional[SensitiveDeliveryProcessLease] = None

    def __post_init__(self):
        if type(self.command) is not SensitiveDeliveryTransportCommand:
            raise TypeError("registration requires an exact command manifest")
        if type(self.identity) is not SensitiveDeliveryRuntimeIdentity:
            raise TypeError("registration requires an exact runtime identity")
        if (
            self.verifier_type is not SensitiveDeliveryDestinationEvidenceVerifier
            or type(self.verifier) is not SensitiveDeliveryDestinationEvidenceVerifier
            or self.verifier_identity != self.verifier.identity
        ):
            raise TypeError("registration requires the exact host evidence verifier")
        if type(self.sidecar_lease) not in (type(None), SensitiveDeliveryProcessLease):
            raise TypeError("sidecar lease must be host-owned")
        if type(self.account_probe) is not SensitiveDeliveryLoopbackAccountProbe:
            raise TypeError("sensitive transport requires an exact live account probe")
        if self.sidecar_lease is not None and self.sidecar_lease.process_identity != self.identity.process_identity:
            raise ValueError("sidecar lease identity mismatch")
        if type(self.max_sensitive_payload_bytes) is not int or not 1 <= self.max_sensitive_payload_bytes <= MAX_SENSITIVE_PLAINTEXT_BYTES:
            raise ValueError("invalid sensitive payload cap")
        for value, name, maximum in (
            (self.max_stdout_bytes, "stdout", MAX_SENSITIVE_EVIDENCE_BYTES),
            (self.max_stderr_bytes, "stderr", MAX_SENSITIVE_STDERR_BYTES),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"invalid {name} cap")

    def __repr__(self):
        return "<SensitiveDeliveryTransportRegistration redacted>"


class SensitiveDeliveryTransportRegistry(_NoCopyOrPickle):
    __slots__ = (
        "_registrations",
        "_max_registrations",
        "_router_claimed",
        "_lock",
    )

    def __init__(self, registrations, *, max_registrations):
        if type(registrations) not in (list, tuple):
            raise TypeError(
                "registrations must be an exact finite sequence (list or tuple)"
            )
        if type(max_registrations) is not int or not 0 <= max_registrations <= MAX_SENSITIVE_REGISTRATIONS:
            raise ValueError("invalid explicit registration cap")
        # Slice the two exact built-in sequence types to one beyond the cap.
        # This both bounds allocation and applies the cap to the exact snapshot
        # used below, even if another thread appends to a list between checks.
        snapshot = tuple(registrations[: max_registrations + 1])
        if len(snapshot) > max_registrations:
            raise ValueError("registration cap exceeded")
        if any(type(item) is not SensitiveDeliveryTransportRegistration for item in snapshot):
            raise TypeError("registry entries must be exact host registrations")
        if len({id(item) for item in snapshot}) != len(snapshot):
            raise ValueError("duplicate registration object")
        routes = [
            (r.identity.profile, r.identity.platform, r.identity.account_binding_token)
            for r in snapshot
        ]
        runtimes = [r.identity.runtime_instance_token for r in snapshot]
        process_identities = [r.identity.process_identity for r in snapshot]
        leases = [r.sidecar_lease for r in snapshot if r.sidecar_lease is not None]
        lease_processes = [lease._process for lease in leases]
        if (
            len(routes) != len(set(routes))
            or len(runtimes) != len(set(runtimes))
            or len(process_identities) != len(set(process_identities))
            or len({id(lease) for lease in leases}) != len(leases)
            or len({id(process) for process in lease_processes}) != len(lease_processes)
        ):
            raise ValueError(
                "registered routes, runtimes, leases, and process identities must be unique"
            )
        marked_leases = []
        try:
            for lease in leases:
                lease._register_once()
                marked_leases.append(lease)
        except BaseException:
            for lease in marked_leases:
                lease._rollback_registration()
            raise
        self._registrations = snapshot
        self._max_registrations = max_registrations
        self._router_claimed = False
        self._lock = threading.Lock()

    def __repr__(self):
        return f"<SensitiveDeliveryTransportRegistry registrations={len(self._registrations)} redacted>"

    def resolve(self, destination):
        if not self._registrations:
            return None, SensitiveDeliveryErrorCode.UNSUPPORTED
        profile = [r for r in self._registrations if r.identity.profile == destination.profile]
        if not profile:
            return None, SensitiveDeliveryErrorCode.PROFILE_NOT_FOUND
        platform = [r for r in profile if r.identity.platform is destination.platform]
        if not platform:
            return None, SensitiveDeliveryErrorCode.PLATFORM_NOT_FOUND
        for registration in platform:
            if hmac.compare_digest(
                registration.identity.account_binding_token,
                destination.account_binding_token,
            ):
                return registration, None
        return None, SensitiveDeliveryErrorCode.ACCOUNT_MISMATCH

    def _claim_router_once(self):
        if not any(
            registration.sidecar_lease is not None
            for registration in self._registrations
        ):
            return
        with self._lock:
            if self._router_claimed:
                raise ValueError(
                    "a registry with process leases already has lifecycle authority"
                )
            self._router_claimed = True

@dataclass(frozen=True, slots=True, repr=False)
class SensitiveDeliveryAttempt:
    attempt_id: str
    authorization_task_id: str
    correlation_id: str
    operation_id: str
    resource_type: str
    resource_id: str
    binding_digest: str
    request_digest: str
    request_key_version: str
    worker_profile: str
    worker_agent: str
    worker_account: str
    claim_nonce: str
    claim_generation: int
    profile: str
    platform: Platform
    transport_implementation_id: str
    runtime_instance_token: str
    process_identity: str
    session_identity: str
    account_binding_token: str
    connection_epoch: int
    account_observation_id: str
    account_observed_at_us: int
    chat_id: str
    thread_id: Optional[str]
    send_started_us: int

    def __post_init__(self):
        _text(self.attempt_id, "attempt_id", machine=True)
        for name in (
            "authorization_task_id", "correlation_id", "operation_id",
            "worker_profile", "worker_agent", "worker_account", "claim_nonce",
            "account_observation_id",
        ):
            _text(getattr(self, name), name)
        for name in (
            "resource_type", "resource_id", "binding_digest", "request_digest",
            "request_key_version",
        ):
            _text(getattr(self, name), name)
        _positive_bounded_integer(self.claim_generation, "claim_generation")
        _profile(self.profile)
        _platform(self.platform)
        for name in (
            "transport_implementation_id", "runtime_instance_token",
            "process_identity", "session_identity",
        ):
            _text(getattr(self, name), name, machine=True)
        _token(self.account_binding_token, "account_binding_token")
        _positive_bounded_integer(self.connection_epoch, "connection_epoch")
        _utc_us(self.account_observed_at_us, "account_observed_at_us")
        _text(self.chat_id, "chat_id")
        _text(self.thread_id, "thread_id", optional=True)
        _utc_us(self.send_started_us, "send_started_us")

    def binding_tuple(self):
        return tuple(getattr(self, field.name) for field in fields(self))

    def __repr__(self):
        return "<SensitiveDeliveryAttempt redacted>"


class SensitiveDeliveryReceipt(_NoCopyOrPickle):
    """Exact live authority object; deliberately opaque to generic serializers."""

    __slots__ = (*_RECEIPT_FIELD_NAMES, "__weakref__")

    def __new__(cls, *args, **kwargs):
        raise TypeError("sensitive delivery receipts are minted only by the host authority")

    def __init__(self, *args, **kwargs):
        raise TypeError("sensitive delivery receipts are minted only by the host authority")

    def __setattr__(self, name, value):
        raise TypeError("sensitive delivery receipts are immutable")

    def __delattr__(self, name):
        raise TypeError("sensitive delivery receipts are immutable")

    def __repr__(self):
        return (
            f"<SensitiveDeliveryReceipt outcome={self.outcome.value!r} "
            f"error_code={getattr(self.error_code, 'value', None)!r} redacted>"
        )

    __str__ = __repr__

    def _validate_shape(self, *, require_seal=True):
        if type(self.outcome) is not SensitiveDeliveryOutcome:
            raise TypeError("invalid receipt outcome")
        if type(self.provenance) is not SensitiveDeliveryAuthorizationProvenance:
            raise TypeError("invalid receipt provenance")
        if type(self.destination) is not SensitiveDeliveryDestination:
            raise TypeError("invalid receipt destination")
        SensitiveDeliveryAuthorizationProvenance.__post_init__(self.provenance)
        SensitiveDeliveryDestination.__post_init__(self.destination)
        if (
            self.provenance.authorization_task_id
            != self.destination.authorization_task_id
            or self.provenance.operation_id != self.destination.operation_id
        ):
            raise ValueError("receipt provenance and destination contradict")
        if self.attempt is not None:
            if type(self.attempt) is not SensitiveDeliveryAttempt:
                raise TypeError("invalid receipt attempt")
            SensitiveDeliveryAttempt.__post_init__(self.attempt)
            if (
                self.attempt.profile != self.destination.profile
                or self.attempt.platform is not self.destination.platform
                or not hmac.compare_digest(
                    self.attempt.account_binding_token,
                    self.destination.account_binding_token,
                )
                or self.attempt.chat_id != self.destination.chat_id
                or self.attempt.thread_id != self.destination.thread_id
            ):
                raise ValueError("receipt destination and attempt contradict")
        if type(self.acceptance_status) is not SensitiveDeliveryAcceptanceStatus:
            raise TypeError("invalid receipt acceptance status")
        for name, machine in (
            ("provider_message_id", False),
            ("non_acceptance_provider_message_id", False),
            ("submission_id", True),
            ("evidence_id", True),
            ("acceptance_signal", True),
            ("non_acceptance_signal", True),
        ):
            value = getattr(self, name)
            if value is not None:
                _text(value, name, machine=machine)
        if self.outcome is SensitiveDeliveryOutcome.ACCEPTED:
            if self.error_code is not None or self.acceptance_status is not SensitiveDeliveryAcceptanceStatus.ACCEPTED:
                raise ValueError("accepted receipt has contradictory state")
            if any(value is None for value in (
                self.attempt, self.provider_message_id, self.submission_id,
                self.evidence_id, self.acceptance_signal, self.acceptance_observed_us,
            )):
                raise ValueError("accepted receipt is incomplete")
            if self.non_acceptance_provider_message_id is not None or self.non_acceptance_signal is not None:
                raise ValueError("accepted receipt has non-acceptance evidence")
        elif type(self.error_code) is not SensitiveDeliveryErrorCode or self.error_code.outcome is not self.outcome:
            raise ValueError("receipt outcome and error code contradict")
        elif (
            self.error_code is SensitiveDeliveryErrorCode.AUTHORIZATION_FINISH_UNCERTAIN
            and self.acceptance_status is SensitiveDeliveryAcceptanceStatus.ACCEPTED
        ):
            if any(value is None for value in (
                self.attempt, self.provider_message_id, self.submission_id,
                self.evidence_id, self.acceptance_signal, self.acceptance_observed_us,
            )):
                raise ValueError("accepted-but-unfinalized receipt is incomplete")
            if (
                self.non_acceptance_provider_message_id is not None
                or self.non_acceptance_signal is not None
            ):
                raise ValueError("accepted-but-unfinalized receipt contradicts itself")
        elif self.provider_message_id is not None or self.acceptance_signal is not None or self.acceptance_observed_us is not None:
            raise ValueError("non-accepted receipt implies host acceptance")
        elif self.error_code is SensitiveDeliveryErrorCode.TRANSPORT_REJECTED:
            if self.acceptance_status is not SensitiveDeliveryAcceptanceStatus.REJECTED:
                raise ValueError("provider rejection requires exact rejected status")
        elif self.acceptance_status is not SensitiveDeliveryAcceptanceStatus.UNKNOWN:
            raise ValueError("non-rejection failure requires unknown acceptance status")
        non_acceptance_evidence = (
            self.non_acceptance_provider_message_id,
            self.submission_id,
            self.evidence_id,
            self.non_acceptance_signal,
        )
        if self.error_code in (
            SensitiveDeliveryErrorCode.TRANSPORT_REJECTED,
            SensitiveDeliveryErrorCode.ACCEPTANCE_UNCONFIRMED,
        ) and any(value is None for value in non_acceptance_evidence):
            raise ValueError("provider non-acceptance evidence is incomplete")
        if (
            self.outcome is not SensitiveDeliveryOutcome.ACCEPTED
            and not (
                self.error_code
                is SensitiveDeliveryErrorCode.AUTHORIZATION_FINISH_UNCERTAIN
                and self.acceptance_status
                is SensitiveDeliveryAcceptanceStatus.ACCEPTED
            )
            and any(value is not None for value in non_acceptance_evidence)
            and any(value is None for value in non_acceptance_evidence)
        ):
            raise ValueError("non-acceptance evidence is incomplete")
        if self.attempt is None and any(
            value is not None
            for value in (
                self.provider_message_id,
                self.non_acceptance_provider_message_id,
                self.submission_id,
                self.evidence_id,
                self.acceptance_signal,
                self.non_acceptance_signal,
                self.acceptance_observed_us,
                self.provider_observed_us,
            )
        ):
            raise ValueError("receipt evidence requires an exact attempt")
        if self.acceptance_observed_us is not None:
            _utc_us(self.acceptance_observed_us, "acceptance_observed_us")
            if (
                self.attempt is None
                or self.acceptance_observed_us < self.attempt.send_started_us
            ):
                raise ValueError("host acceptance predates the send attempt")
        if self.provider_observed_us is not None:
            _utc_us(self.provider_observed_us, "provider_observed_us")
            if (
                self.attempt is None
                or self.provider_observed_us < self.attempt.send_started_us
            ):
                raise ValueError("provider observation predates the send attempt")
        if require_seal:
            _token(self._seal, "receipt seal")

    def _seal_values(self):
        provenance_values = tuple(
            getattr(self.provenance, name) for name in _PROVENANCE_FIELDS
        )
        destination_values = (
            self.destination.authorization_task_id,
            self.destination.operation_id,
            self.destination.profile,
            self.destination.platform,
            self.destination.account_binding_token,
            self.destination.chat_id,
            self.destination.thread_id,
        )
        attempt_values = (
            tuple(getattr(self.attempt, field.name) for field in fields(self.attempt))
            if self.attempt is not None
            else ()
        )
        return (
            *provenance_values, *destination_values,
            *attempt_values, self.provider_message_id, self.submission_id,
            self.non_acceptance_provider_message_id, self.evidence_id,
            self.acceptance_status, self.acceptance_signal,
            self.non_acceptance_signal,
            self.acceptance_observed_us, self.provider_observed_us, self.outcome,
            self.error_code,
        )

    @property
    def success(self):
        return self.outcome is SensitiveDeliveryOutcome.ACCEPTED

    @property
    def seal(self):
        return self._seal


@dataclass(slots=True)
class _ActiveProcess:
    process: "_OwnedProcess"
    stdout_task: asyncio.Task
    stderr_task: asyncio.Task
    stdout_buffer: "_WipeableBoundedOutput"


class _WipeableBoundedOutput:
    """A bounded mutable buffer whose bytes never become a Task result."""

    __slots__ = ("data",)

    def __init__(self):
        self.data = bytearray()

    def retain(self, chunk, cap):
        available = max(0, cap - len(self.data))
        if available:
            self.data.extend(chunk[:available])
        return len(chunk) > available

    def wipe(self):
        _wipe(self.data)
        self.data.clear()


@dataclass(slots=True)
class _DirectChildOwnership:
    """Retained ownership state for one exact direct child.

    ``waitpid`` is the portable ownership API on supported Python/macOS, but
    it reaps an exited child.  Keeping that transition beside the PID lets
    cleanup defer every reap until after group-wide SIGKILL and makes later
    cleanup passes no-ops instead of signalling a reused numeric PID.
    """

    pid: int
    state: str = "owned"

    def signal_group_after_leader_reap(self, sig):
        if self.state != "leader_reaped":
            return False
        return _signal_process_group(self.pid, sig)


@dataclass(slots=True)
class _OwnedProcess:
    """Direct fork child whose PID and every pipe are owned synchronously."""

    pid: int
    stdin_fd: Optional[int]
    stdout_fd: Optional[int]
    stderr_fd: Optional[int]
    returncode: Optional[int] = None
    child_ownership: Optional[_DirectChildOwnership] = None

    def __post_init__(self):
        if self.child_ownership is None:
            self.child_ownership = _DirectChildOwnership(self.pid)

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        try:
            waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            # No other code is permitted to reap this private direct child.  If
            # that invariant is violated, preserve the unknown state so close
            # fails rather than claiming cleanup success.
            return None
        if waited_pid == self.pid:
            self.child_ownership.state = "leader_reaped"
            self.returncode = os.waitstatus_to_exitcode(status)
        return self.returncode

    def close_stdin(self):
        if self.stdin_fd is not None:
            _close_fd(self.stdin_fd)
            self.stdin_fd = None

    def close_output_pipes(self):
        for name in ("stdout_fd", "stderr_fd"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                _close_fd(descriptor)
                setattr(self, name, None)


class _OwnedPipeReader:
    __slots__ = ("_process", "_field", "_deadline", "_monotonic")

    def __init__(self, process, field, deadline, monotonic_clock):
        self._process = process
        self._field = field
        self._deadline = deadline
        self._monotonic = monotonic_clock

    async def read(self, size):
        while True:
            descriptor = getattr(self._process, self._field)
            if descriptor is None:
                return b""
            try:
                chunk = os.read(descriptor, size)
            except BlockingIOError:
                await _wait_fd_ready(
                    descriptor,
                    write=False,
                    deadline=self._deadline,
                    monotonic_clock=self._monotonic,
                )
                continue
            except OSError:
                if getattr(self._process, self._field) is None:
                    return b""
                raise
            if not chunk:
                _close_fd(descriptor)
                if getattr(self._process, self._field) == descriptor:
                    setattr(self._process, self._field, None)
            return chunk


@dataclass(frozen=True, slots=True)
class _LaunchCopy:
    directory: str
    executable: str


def _remove_launch_directory(directory):
    """Delete one private launch tree and prove its published path is absent."""

    deletion_error = None
    try:
        _lifecycle_checkpoint("launch.deletion")
        shutil.rmtree(directory)
    except FileNotFoundError:
        pass
    except BaseException as exc:
        deletion_error = exc
        # A failed high-level deletion is not success.  Make one independent,
        # bounded best-effort pass so an injected failure does not itself leak
        # the secret-bearing launch pathname, then still surface the failure.
        try:
            for root, directories, files in os.walk(directory, topdown=False):
                for filename in files:
                    os.unlink(os.path.join(root, filename))
                for child in directories:
                    os.rmdir(os.path.join(root, child))
            os.rmdir(directory)
        except FileNotFoundError:
            pass
        except BaseException as fallback_error:
            if os.path.lexists(directory):
                raise SensitiveDeliveryCleanupError(
                    "private launch directory deletion failed"
                ) from fallback_error
    if os.path.lexists(directory):
        raise SensitiveDeliveryCleanupError(
            "private launch directory remains after deletion"
        ) from deletion_error
    if deletion_error is not None:
        raise SensitiveDeliveryCleanupError(
            "private launch directory required recovery deletion"
        ) from deletion_error


class PreparedSensitiveDelivery(_NoCopyOrPickle):
    __slots__ = ("_router", "destination", "_registration", "_observation", "_used")

    def __init__(self, router, destination, registration, observation):
        self._router = router
        self.destination = destination
        self._registration = registration
        self._observation = observation
        self._used = False

    def __repr__(self):
        return (
            f"<PreparedSensitiveDelivery profile={self.destination.profile!r} "
            f"platform={self.destination.platform.value!r} used={self._used} redacted>"
        )

    def authorize_private_read(self, evidence, *, now_us):
        """Apply the typed second PDP check after this live preparation."""
        self._router._assert_owner()
        if self._used:
            return False
        return self._router._bridge.authorize_private_read(
            evidence,
            now_us=now_us,
        )

    async def deliver(self, plaintext):
        self._router._assert_owner()
        if self._used:
            return self._router._failure(SensitiveDeliveryErrorCode.HANDLE_USED, self.destination)
        self._used = True
        self._router._release_prepared()
        payload = _validate_plaintext(
            plaintext,
            self._registration.max_sensitive_payload_bytes,
        )
        plaintext = None
        if payload is None:
            return self._router._finish_public_receipt(self._router._failure(
                SensitiveDeliveryErrorCode.INPUT_LIMIT,
                self.destination,
            ))
        try:
            receipt = await self._router._run_owned(self, payload)
        except BaseException:
            _wipe(payload)
            self._router._finish_public_receipt(self._router._failure(
                SensitiveDeliveryErrorCode.TRANSPORT_FAILED,
                self.destination,
            ))
            raise
        return self._router._finish_public_receipt(receipt)

    def discard(self):
        self._router._assert_owner()
        if not self._used:
            self._used = True
            self._router._release_prepared()
            self._router._finish_public_receipt(self._router._failure(
                SensitiveDeliveryErrorCode.CANCELLED_BEFORE_SEND,
                self.destination,
            ))


def _validate_plaintext(value, transport_cap):
    encoded = None
    try:
        if type(value) is not str:
            return None
        try:
            encoded = bytearray(value.encode("utf-8", "strict"))
        except UnicodeError:
            # Do not propagate the encoder exception: its traceback owns this
            # frame and would otherwise retain ``value``.  Clearing the local
            # before leaving the handler makes the fixed failure content-free.
            value = None
            return None
        value = None
        if not encoded:
            return None
        if (
            len(encoded) > MAX_SENSITIVE_PLAINTEXT_BYTES
            or len(encoded) > transport_cap
        ):
            _wipe(encoded)
            return None
        return encoded
    finally:
        value = None


class SensitiveDeliveryRouter(_NoCopyOrPickle):
    __slots__ = (
        "_registry", "_authority", "_provenance", "_bridge",
        "_monotonic", "_deadline_seconds", "_term_grace",
        "_cleanup_budget",
        "_provider_max_age_us", "_max_future_skew_us", "_max_prepared",
        "_max_in_flight", "_prepared", "_attempt_tasks", "_active", "_closed",
        "_spawning", "_leases", "_close_task", "_close_deadline",
        "_owner_thread", "_owner_loop",
    )

    def __init__(
        self,
        *,
        transport_registry,
        authorization_bridge,
        deadline_seconds=30.0,
        termination_grace_seconds=0.2,
        provider_evidence_max_age_seconds=300.0,
        max_future_skew_seconds=5.0,
        max_prepared_handles=64,
        max_in_flight_attempts=8,
        monotonic_clock=None,
    ):
        if type(transport_registry) is not SensitiveDeliveryTransportRegistry:
            raise TypeError("transport registry must be host-owned")
        from gateway.authorization_sensitive_delivery import (
            AuthorizationSensitiveDeliveryBridge,
        )
        if type(authorization_bridge) is not AuthorizationSensitiveDeliveryBridge:
            raise TypeError("an exact authorization sensitive-delivery bridge is required")
        for value, name, maximum in (
            (max_prepared_handles, "max_prepared_handles", 1024),
            (max_in_flight_attempts, "max_in_flight_attempts", 1024),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"invalid {name} cap")
        self._registry = transport_registry
        self._bridge = authorization_bridge
        self._authority = authorization_bridge.authority
        self._provenance = authorization_bridge.provenance
        self._deadline_seconds = _seconds(deadline_seconds, "deadline_seconds")
        self._term_grace = _seconds(termination_grace_seconds, "termination_grace_seconds", 0.01, 5.0)
        self._cleanup_budget = _cleanup_budget_seconds(self._term_grace)
        self._provider_max_age_us = int(_seconds(provider_evidence_max_age_seconds, "provider_evidence_max_age_seconds", 0.1, 3600.0) * 1_000_000)
        self._max_future_skew_us = int(_seconds(max_future_skew_seconds, "max_future_skew_seconds", 0.0, 60.0) * 1_000_000)
        self._max_prepared = max_prepared_handles
        self._max_in_flight = max_in_flight_attempts
        self._monotonic = monotonic_clock or time.monotonic
        self._prepared = 0
        self._attempt_tasks = set()
        self._active = {}
        self._spawning = {}
        self._closed = False
        self._registry._claim_router_once()
        self._leases = tuple(
            registration.sidecar_lease
            for registration in self._registry._registrations
            if registration.sidecar_lease is not None
        )
        self._close_task = None
        self._close_deadline = None
        self._owner_thread = None
        self._owner_loop = None

    def __repr__(self):
        return "<SensitiveDeliveryRouter redacted>"

    def _assert_owner(self):
        loop = asyncio.get_running_loop()
        thread_id = threading.get_ident()
        if self._owner_loop is None:
            self._owner_loop = loop
            self._owner_thread = thread_id
        elif self._owner_loop is not loop or self._owner_thread != thread_id:
            raise RuntimeError("SensitiveDeliveryRouter is bound to one event loop and thread")

    def _now_us(self):
        return _utc_us(self._bridge.now_us(), "host wall clock")

    async def prepare(self):
        self._assert_owner()
        destination = self._bridge.destination
        if self._closed:
            return self._finish_public_receipt(
                self._failure(SensitiveDeliveryErrorCode.ROUTER_CLOSED, destination)
            )
        if not self._authority.verify_authorization(self._provenance):
            return self._finish_public_receipt(
                self._failure(SensitiveDeliveryErrorCode.PROVENANCE_MISMATCH, destination)
            )
        if destination is not self._bridge.destination or self._provenance is not self._bridge.provenance:
            return self._finish_public_receipt(
                self._failure(SensitiveDeliveryErrorCode.PROVENANCE_MISMATCH, destination)
            )
        registration, code = self._registry.resolve(destination)
        if registration is None:
            return self._finish_public_receipt(self._failure(code, destination))
        identity = registration.identity
        binding = self._bridge.binding
        if (
            not self._registration_live(registration)
            or identity.transport_implementation_id
            != binding.delivery_transport_implementation
            or identity.runtime_instance_token != binding.delivery_runtime_identity
            or identity.connection_epoch != binding.delivery_connection_epoch
        ):
            return self._finish_public_receipt(
                self._failure(SensitiveDeliveryErrorCode.RUNTIME_UNAVAILABLE, destination)
            )
        if self._prepared >= self._max_prepared:
            return self._failure(SensitiveDeliveryErrorCode.PREPARED_LIMIT, destination)
        probe_deadline = self._monotonic() + min(
            self._deadline_seconds, registration.account_probe.timeout_seconds
        )
        try:
            observation = await registration.account_probe.observe(
                platform=destination.platform,
                deadline=probe_deadline,
                monotonic_clock=self._monotonic,
            )
        except BaseException:
            return self._finish_public_receipt(
                self._failure(SensitiveDeliveryErrorCode.RUNTIME_UNAVAILABLE, destination)
            )
        if not self._observation_live(registration, observation):
            return self._finish_public_receipt(
                self._failure(SensitiveDeliveryErrorCode.ACCOUNT_MISMATCH, destination)
            )
        if not self._bridge.accept_prepared_observation(observation):
            return self._finish_public_receipt(
                self._failure(SensitiveDeliveryErrorCode.PROVENANCE_MISMATCH, destination)
            )
        self._prepared += 1
        return PreparedSensitiveDelivery(self, destination, registration, observation)

    def _release_prepared(self):
        self._prepared = max(0, self._prepared - 1)

    def _registration_live(self, registration):
        return (
            type(registration.verifier) is registration.verifier_type
            and registration.verifier_type is SensitiveDeliveryDestinationEvidenceVerifier
            and registration.verifier.identity == registration.verifier_identity
            and (
                registration.sidecar_lease is None
                or registration.sidecar_lease.is_live(registration.identity.process_identity)
            )
        )

    def _observation_live(self, registration, observation):
        identity = registration.identity
        now_us = self._now_us()
        return (
            registration.account_probe.owns(observation)
            and observation.account_binding_token == identity.account_binding_token
            and observation.account_binding_token == self._bridge.destination.account_binding_token
            and observation.runtime_instance_token == identity.runtime_instance_token
            and observation.process_identity == identity.process_identity
            and observation.session_identity == identity.session_identity
            and observation.connection_epoch == identity.connection_epoch
            and observation.observed_at_us <= now_us + self._max_future_skew_us
            and now_us - observation.observed_at_us <= self._provider_max_age_us
            and self._registration_live(registration)
        )

    def _finish_public_receipt(self, receipt):
        if self._bridge.finish_receipt(receipt, now_us=self._now_us()):
            return receipt
        return self._finalization_uncertain(
            receipt,
            self._bridge.destination,
            getattr(receipt, "attempt", None),
        )

    async def _run_owned(self, prepared, payload):
        if len(self._attempt_tasks) >= self._max_in_flight:
            _wipe(payload)
            return self._failure(SensitiveDeliveryErrorCode.IN_FLIGHT_LIMIT, prepared.destination)
        attempt_deadline = self._monotonic() + self._deadline_seconds
        return_deadline = attempt_deadline + self._cleanup_budget
        cleanup_deadline = (
            return_deadline - _TASK_JOIN_RESERVE_SECONDS
        )
        task = asyncio.create_task(
            self._deliver(
                prepared,
                payload,
                attempt_deadline,
                cleanup_deadline,
            ),
            name="sensitive-delivery-attempt",
        )
        self._attempt_tasks.add(task)
        result = None
        pending_base_exception = None
        try:
            result, _ = await _await_task_non_discardable(
                task,
                deadline=return_deadline,
                monotonic_clock=self._monotonic,
                cancel_on_first_cancellation=True,
            )
        except _OwnedBaseExceptionCarrier as exc:
            pending_base_exception = exc.failure
        except BaseException as exc:
            pending_base_exception = exc
        finally:
            self._attempt_tasks.discard(task)
        if pending_base_exception is not None:
            raise pending_base_exception
        return result

    async def _deliver(self, prepared, payload, deadline, cleanup_deadline):
        registration = prepared._registration
        destination = prepared.destination
        grant = None
        attempt = None
        launch = None
        receipt = None
        pending_base_exception = None
        try:
            if self._closed:
                return self._failure(SensitiveDeliveryErrorCode.ROUTER_CLOSED, destination)
            current, _ = self._registry.resolve(destination)
            if current is not registration or not self._registration_live(registration):
                return self._failure(SensitiveDeliveryErrorCode.RUNTIME_UNAVAILABLE, destination)
            launch = self._stage_verified_executable(registration.command, deadline)
            if launch is None:
                return self._failure(SensitiveDeliveryErrorCode.EXECUTABLE_INVALID, destination)
            if not self._observation_live(registration, prepared._observation):
                return self._failure(SensitiveDeliveryErrorCode.ACCOUNT_MISMATCH, destination)
            send_started_us = self._now_us()
            grant = self._bridge.record_send_started(
                prepared._observation,
                now_us=send_started_us,
            )
            if type(grant) is not SensitiveDeliverySendGrant:
                return self._failure(SensitiveDeliveryErrorCode.SEND_START_UNCERTAIN, destination)
            identity = registration.identity
            attempt = SensitiveDeliveryAttempt(
                attempt_id=grant.attempt_id,
                authorization_task_id=grant.authorization_task_id,
                correlation_id=grant.correlation_id,
                operation_id=grant.operation_id,
                resource_type=grant.resource_type,
                resource_id=grant.resource_id,
                binding_digest=grant.binding_digest,
                request_digest=grant.request_digest,
                request_key_version=grant.request_key_version,
                worker_profile=grant.worker_profile,
                worker_agent=grant.worker_agent,
                worker_account=grant.worker_account,
                claim_nonce=grant.claim_nonce,
                claim_generation=grant.claim_generation,
                profile=identity.profile,
                platform=identity.platform,
                transport_implementation_id=identity.transport_implementation_id,
                runtime_instance_token=prepared._observation.runtime_instance_token,
                process_identity=prepared._observation.process_identity,
                session_identity=prepared._observation.session_identity,
                account_binding_token=prepared._observation.account_binding_token,
                connection_epoch=prepared._observation.connection_epoch,
                account_observation_id=prepared._observation.observation_id,
                account_observed_at_us=prepared._observation.observed_at_us,
                chat_id=destination.chat_id,
                thread_id=destination.thread_id,
                send_started_us=grant.send_started_us,
            )
            receipt = await self._execute(
                registration,
                destination,
                attempt,
                grant,
                prepared._observation,
                launch,
                payload,
                deadline,
                cleanup_deadline,
            )
        except asyncio.CancelledError:
            code = SensitiveDeliveryErrorCode.CANCELLED if grant is not None else SensitiveDeliveryErrorCode.CANCELLED_BEFORE_SEND
            receipt = self._failure(code, destination, attempt=attempt)
        except Exception:
            code = SensitiveDeliveryErrorCode.TRANSPORT_FAILED if grant is not None else SensitiveDeliveryErrorCode.EXECUTABLE_INVALID
            receipt = self._failure(code, destination, attempt=attempt)
        except BaseException as exc:
            pending_base_exception = exc
        finally:
            _wipe(payload)
            if launch is not None:
                try:
                    _remove_launch_directory(launch.directory)
                except BaseException as exc:
                    if pending_base_exception is None:
                        receipt = self._failure(
                            SensitiveDeliveryErrorCode.CLEANUP_FAILED,
                            destination,
                            attempt=attempt,
                        )
                    else:
                        triggering_failure = pending_base_exception
                        cleanup_failure = SensitiveDeliveryCleanupError(
                            "launch cleanup failed while propagating host failure"
                        )
                        cleanup_failure.add_note(
                            f"deletion failure: {type(exc).__name__}"
                        )
                        cleanup_failure.__cause__ = triggering_failure
                        pending_base_exception = cleanup_failure
            if grant is not None and registration.sidecar_lease is not None:
                try:
                    await registration.sidecar_lease.invalidate_and_reap(
                        self._term_grace,
                        cleanup_deadline=min(
                            cleanup_deadline,
                            self._monotonic() + self._cleanup_budget,
                        ),
                        monotonic_clock=self._monotonic,
                    )
                except asyncio.CancelledError:
                    receipt = self._failure(
                        SensitiveDeliveryErrorCode.CANCELLED,
                        destination,
                        attempt=attempt,
                    )
                except BaseException:
                    receipt = self._failure(
                        SensitiveDeliveryErrorCode.CLEANUP_FAILED,
                        destination,
                        attempt=attempt,
                    )
        if pending_base_exception is not None:
            raise _OwnedBaseExceptionCarrier(pending_base_exception)
        return receipt or self._failure(
            SensitiveDeliveryErrorCode.TRANSPORT_FAILED,
            destination,
            attempt=attempt,
        )

    def _stage_verified_executable(self, command, deadline):
        directory = None
        target = None
        source_fd = None
        target_fd = None
        launch = None
        invalid = False
        pending_base_exception = None
        cleanup_error = None
        digest = hashlib.sha256()
        total = 0
        try:
            directory = tempfile.mkdtemp(prefix="hermes-sensitive-delivery-")
            _lifecycle_checkpoint("launch.after_mkdir")
            target = os.path.join(directory, "transport")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            source_fd = os.open(command.executable, flags)
            _lifecycle_checkpoint("launch.after_source_open")
            source_stat = os.fstat(source_fd)
            if not stat.S_ISREG(source_stat.st_mode):
                raise ValueError("transport executable is not a regular file")
            target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500)
            _lifecycle_checkpoint("launch.after_target_open")
            while True:
                if self._monotonic() >= deadline:
                    raise TimeoutError("executable verification exceeded the hard deadline")
                chunk = os.read(source_fd, 64 * 1024)
                if not chunk:
                    break
                _lifecycle_checkpoint("launch.copy")
                total += len(chunk)
                if total > MAX_SENSITIVE_EXECUTABLE_BYTES:
                    raise ValueError("transport executable exceeds audit bound")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(target_fd, view)
                    view = view[written:]
            # This private copy is an immediate exec source, not durable state;
            # forcing filesystem persistence would be an unbounded synchronous
            # operation inside the absolute attempt deadline.
            os.fchmod(target_fd, 0o500)
            _lifecycle_checkpoint("launch.after_chmod")
            if not hmac.compare_digest(digest.hexdigest(), command.executable_sha256):
                raise ValueError("transport executable digest changed")
            target_stat = os.fstat(target_fd)
            if not stat.S_ISREG(target_stat.st_mode) or target_stat.st_size != total:
                raise ValueError("private executable verification failed")
            _lifecycle_checkpoint("launch.after_verification")
            launch = _LaunchCopy(directory, target)
            _lifecycle_checkpoint("launch.publication")
        except Exception:
            invalid = True
        except BaseException as exc:
            pending_base_exception = exc
        finally:
            if source_fd is not None:
                try:
                    os.close(source_fd)
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
            if target_fd is not None:
                try:
                    os.close(target_fd)
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
            if directory is not None and (launch is None or invalid or pending_base_exception is not None):
                try:
                    _remove_launch_directory(directory)
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
        if cleanup_error is not None:
            raise SensitiveDeliveryCleanupError(
                "private executable staging cleanup failed"
            ) from (pending_base_exception or cleanup_error)
        if pending_base_exception is not None:
            raise pending_base_exception
        if invalid:
            return None
        return launch

    def _spawn(
        self,
        attempt_id,
        executable,
        arguments,
        deadline,
        cleanup_deadline,
    ):
        """Fork an owned supervisor which immediately becomes the transport.

        ``asyncio.create_subprocess_exec`` does not expose a PID until its
        awaitable completes.  A cancellation-ignoring or stalled launch can
        therefore create a child after the caller has timed out.  Here the
        router receives the fork PID and all parent pipe ends synchronously;
        every later phase (including a delayed ``execve``) is killable and
        reapable through that already-owned PID.
        """

        if self._monotonic() >= deadline:
            raise TimeoutError
        pipes = []
        pid = None
        child_ownership = None
        process = None
        try:
            stdin_read, stdin_write = _pipe_above_stdio()
            pipes.extend((stdin_read, stdin_write))
            stdout_read, stdout_write = _pipe_above_stdio()
            pipes.extend((stdout_read, stdout_write))
            stderr_read, stderr_write = _pipe_above_stdio()
            pipes.extend((stderr_read, stderr_write))
            # Python warns about fork from a multi-threaded host because the
            # child may stall before exec on an inherited runtime lock.  That
            # exact failure is contained here: the parent receives and owns
            # the PID immediately and reaps it under the attempt deadline.
            with warnings.catch_warnings():
                warnings.filterwarnings(
                    "ignore",
                    message=r".*multi-threaded.*fork.*deadlocks.*",
                    category=DeprecationWarning,
                )
                pid = os.fork()
            if pid == 0:
                try:
                    os.setsid()
                    os.dup2(stdin_read, 0)
                    os.dup2(stdout_write, 1)
                    os.dup2(stderr_write, 2)
                    for descriptor in pipes:
                        if descriptor not in (0, 1, 2):
                            _close_fd(descriptor)
                    os.execve(
                        executable,
                        (executable, *arguments),
                        {"PATH": os.defpath, "LANG": "C.UTF-8"},
                    )
                except BaseException:
                    os._exit(127)
                os._exit(127)

            child_ownership = _DirectChildOwnership(pid)

            # The enclosing ownership region was entered before ``fork``.  No
            # parent bytecode after a successful fork can run outside it.
            _lifecycle_checkpoint("spawn.after_fork")
            _lifecycle_checkpoint("spawn.process_construction")
            process = _OwnedProcess(
                pid,
                stdin_write,
                stdout_read,
                stderr_read,
                child_ownership=child_ownership,
            )
            _lifecycle_checkpoint("spawn.after_process_construction")
            _lifecycle_checkpoint("spawn.publication")
            self._spawning[attempt_id] = process
            _lifecycle_checkpoint("spawn.after_publication")
            for descriptor in (stdin_read, stdout_write, stderr_write):
                _close_fd(descriptor)
                _lifecycle_checkpoint("spawn.parent_end_close")
            for descriptor in (stdin_write, stdout_read, stderr_read):
                os.set_blocking(descriptor, False)
            return process
        except BaseException as exc:
            if pid == 0:
                os._exit(127)
            _remove_exact_publication(self._spawning, attempt_id, process)
            for descriptor in pipes:
                _close_fd(descriptor)
            if process is not None:
                process.stdin_fd = None
                process.stdout_fd = None
                process.stderr_fd = None
            if pid is not None:
                try:
                    if child_ownership is None:
                        _cleanup_raw_fork_pid(
                            pid,
                            cleanup_deadline,
                            self._term_grace,
                            self._monotonic,
                        )
                    else:
                        _cleanup_raw_fork_child(
                            child_ownership,
                            cleanup_deadline,
                            self._term_grace,
                            self._monotonic,
                        )
                except BaseException as cleanup_exc:
                    failure = SensitiveDeliveryCleanupError(
                        "fork child publication rollback could not be proven"
                    )
                    failure.add_note(
                        f"cleanup failure: {type(cleanup_exc).__name__}"
                    )
                    raise failure from exc
            raise

    async def _execute(
        self,
        registration,
        destination,
        attempt,
        grant,
        observation,
        launch,
        payload,
        deadline,
        attempt_cleanup_deadline,
    ):
        process = None
        active = None
        return_code = None
        terminal_code = None
        pending_base_exception = None
        cleanup_failed = False
        cancellation_requested = False
        stdout_buffer = _WipeableBoundedOutput()
        try:
            header = self._build_stdin_header(destination, attempt, payload)
        except (TypeError, ValueError):
            return self._failure(
                SensitiveDeliveryErrorCode.INPUT_LIMIT,
                destination,
                attempt=attempt,
            )
        try:
            if (
                not self._observation_live(registration, observation)
                or not self._bridge.consume_send_grant(grant, observation, attempt)
            ):
                return self._failure(
                    SensitiveDeliveryErrorCode.SEND_AUTHORITY_INVALID,
                    destination,
                    attempt=attempt,
                )
            process = self._spawn(
                attempt.attempt_id,
                launch.executable,
                registration.command.arguments,
                deadline,
                attempt_cleanup_deadline,
            )
            stdout_task = asyncio.create_task(
                _read_bounded_status(
                    _OwnedPipeReader(
                        process,
                        "stdout_fd",
                        attempt_cleanup_deadline,
                        self._monotonic,
                    ),
                    registration.max_stdout_bytes,
                    stdout_buffer,
                ),
                name="sensitive-delivery-stdout",
            )
            stderr_task = asyncio.create_task(
                _read_bounded_status(
                    _OwnedPipeReader(
                        process,
                        "stderr_fd",
                        attempt_cleanup_deadline,
                        self._monotonic,
                    ),
                    registration.max_stderr_bytes,
                    None,
                ),
                name="sensitive-delivery-stderr",
            )
            active = _ActiveProcess(process, stdout_task, stderr_task, stdout_buffer)
            self._active[attempt.attempt_id] = active
            self._spawning.pop(attempt.attempt_id, None)
            await _write_all_fd_before_deadline(
                process,
                (header, payload),
                deadline,
                self._monotonic,
            )
            process.close_stdin()
            _wipe(payload)
            await _wait_for_async_process_exit(process, deadline, self._monotonic)
            return_code = process.returncode
        except TimeoutError:
            terminal_code = SensitiveDeliveryErrorCode.TIMEOUT
        except asyncio.CancelledError:
            cancellation_requested = True
            terminal_code = SensitiveDeliveryErrorCode.CANCELLED
        except Exception:
            terminal_code = SensitiveDeliveryErrorCode.TRANSPORT_FAILED
        except BaseException as exc:
            pending_base_exception = exc
        finally:
            if process is None:
                process = self._spawning.pop(attempt.attempt_id, None)
            cleanup_tasks = []
            if process is not None:
                cleanup_join_deadline = min(
                    attempt_cleanup_deadline,
                    self._monotonic() + self._cleanup_budget,
                )
                cleanup_deadline = max(
                    self._monotonic(),
                    cleanup_join_deadline - _TASK_JOIN_RESERVE_SECONDS,
                )
                cleanup_tasks.append(
                    asyncio.create_task(
                        self._cleanup_spawned_process(
                            process,
                            active,
                            cleanup_deadline,
                        ),
                        name="sensitive-delivery-process-cleanup",
                    )
                )
                if registration.sidecar_lease is not None:
                    cleanup_tasks.append(
                        asyncio.create_task(
                            registration.sidecar_lease._invalidate_and_reap_owned(
                                self._term_grace,
                                cleanup_deadline,
                                self._monotonic,
                            ),
                            name="sensitive-delivery-attempt-sidecar-cleanup",
                        )
                    )
            for cleanup_task in cleanup_tasks:
                try:
                    _, cleanup_cancelled = await _await_task_non_discardable(
                        cleanup_task,
                        deadline=cleanup_join_deadline,
                        monotonic_clock=self._monotonic,
                    )
                    cancellation_requested = (
                        cancellation_requested or cleanup_cancelled
                    )
                except BaseException:
                    cleanup_failed = True
            self._active.pop(attempt.attempt_id, None)
            self._spawning.pop(attempt.attempt_id, None)

        try:
            if pending_base_exception is not None:
                raise pending_base_exception
            if cleanup_failed:
                return self._failure(
                    SensitiveDeliveryErrorCode.CLEANUP_FAILED,
                    destination,
                    attempt=attempt,
                )
            if cancellation_requested:
                terminal_code = SensitiveDeliveryErrorCode.CANCELLED
            if terminal_code is not None:
                return self._failure(terminal_code, destination, attempt=attempt)
            try:
                stdout_status, stdout_overflow = active.stdout_task.result()
                stderr_status, stderr_overflow = active.stderr_task.result()
            except BaseException:
                return self._failure(
                    SensitiveDeliveryErrorCode.TRANSPORT_FAILED,
                    destination,
                    attempt=attempt,
                )
            if stdout_status != "ok" or stderr_status != "ok":
                return self._failure(
                    SensitiveDeliveryErrorCode.TRANSPORT_FAILED,
                    destination,
                    attempt=attempt,
                )
            if stdout_overflow or stderr_overflow:
                return self._failure(
                    SensitiveDeliveryErrorCode.OUTPUT_LIMIT,
                    destination,
                    attempt=attempt,
                )
            if return_code != 0:
                return self._failure(
                    SensitiveDeliveryErrorCode.TRANSPORT_FAILED,
                    destination,
                    attempt=attempt,
                )
            return self._receipt_from_evidence(
                registration,
                destination,
                attempt,
                stdout_buffer.data,
            )
        finally:
            stdout_buffer.wipe()
            active = None
            process = None

    def _build_stdin_header(self, destination, attempt, payload):
        header = json.dumps(
            {
                "version": 1,
                "payload_bytes": len(payload),
                "attempt_id": attempt.attempt_id,
                "authorization_task_id": attempt.authorization_task_id,
                "correlation_id": attempt.correlation_id,
                "operation_id": attempt.operation_id,
                "authorization_binding_digest": attempt.binding_digest,
                "request_digest": attempt.request_digest,
                "request_key_version": attempt.request_key_version,
                "worker_profile": attempt.worker_profile,
                "worker_agent": attempt.worker_agent,
                "worker_account": attempt.worker_account,
                "claim_nonce": attempt.claim_nonce,
                "claim_generation": attempt.claim_generation,
                "destination_profile": attempt.profile,
                "destination_platform": attempt.platform.value,
                "transport_implementation_id": attempt.transport_implementation_id,
                "destination_chat_id": destination.chat_id,
                "destination_thread_id": destination.thread_id,
                "destination_account_binding_token": attempt.account_binding_token,
                "connection_epoch": attempt.connection_epoch,
                "runtime_instance_token": attempt.runtime_instance_token,
                "process_identity": attempt.process_identity,
                "session_identity": attempt.session_identity,
                "account_observation_id": attempt.account_observation_id,
                "account_observed_at_us": attempt.account_observed_at_us,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", "strict") + b"\n"
        if len(header) + len(payload) > MAX_SENSITIVE_STDIN_BYTES:
            raise ValueError("aggregate sensitive stdin frame exceeds its byte cap")
        return header

    async def _cleanup_spawned_process(self, process, active, cleanup_deadline):
        cleanup_errors = []
        real_cleanup_deadline = _real_deadline_for(
            cleanup_deadline,
            self._monotonic,
        )
        try:
            process.close_stdin()
        except BaseException as exc:
            cleanup_errors.append(exc)
        process_group_id = process.pid
        _signal_owned_process(process, signal.SIGTERM)
        reader_reserve = 0.05
        process_deadline = max(
            self._monotonic(),
            cleanup_deadline - reader_reserve,
        )
        grace_deadline = min(
            process_deadline,
            self._monotonic() + self._term_grace,
        )
        while (
            _process_group_exists(process_group_id)
            and not _owned_pid_number_was_reused(process)
            and self._monotonic() < grace_deadline
            and time.monotonic() < real_cleanup_deadline
        ):
            process.poll()
            await asyncio.sleep(
                min(
                    _CLEANUP_POLL_SECONDS,
                    max(0.0, grace_deadline - self._monotonic()),
                )
            )
        if _process_group_exists(process_group_id):
            _signal_owned_process(process, signal.SIGKILL)

        while (
            self._monotonic() < process_deadline
            and time.monotonic() < real_cleanup_deadline
        ):
            child_exited = process.poll() is not None
            group_exists = _process_group_exists(process_group_id)
            if (
                child_exited
                and not group_exists
                and process.child_ownership.state == "leader_reaped"
            ):
                process.child_ownership.state = "reaped"
            group_exited = not group_exists or _owned_pid_number_was_reused(process)
            if child_exited and group_exited:
                break
            await asyncio.sleep(
                min(
                    _CLEANUP_POLL_SECONDS,
                    max(0.0, process_deadline - self._monotonic()),
                )
            )

        if process.poll() is None:
            cleanup_errors.append(
                SensitiveDeliveryCleanupError(
                    "direct child did not reap within cleanup deadline"
                )
            )
        if active is not None:
            try:
                await _join_reader_tasks(
                    active,
                    cleanup_deadline,
                    self._monotonic,
                )
            except BaseException as exc:
                cleanup_errors.append(exc)
        else:
            process.close_output_pipes()
        group_exists = _process_group_exists(process_group_id)
        if (
            process.returncode is not None
            and not group_exists
            and process.child_ownership.state == "leader_reaped"
        ):
            process.child_ownership.state = "reaped"
        if group_exists and not _owned_pid_number_was_reused(process):
            _signal_owned_process(process, signal.SIGKILL)
            cleanup_errors.append(
                SensitiveDeliveryCleanupError(
                    "one-shot process-group cleanup could not be proven"
                )
            )
        if process.poll() is None:
            cleanup_errors.append(
                SensitiveDeliveryCleanupError(
                    "direct child did not reap within cleanup deadline"
                )
            )
        if cleanup_errors:
            raise SensitiveDeliveryCleanupError(
                "one-shot cleanup could not be proven complete"
            ) from cleanup_errors[0]

    def _receipt_from_evidence(self, registration, destination, attempt, raw_bytes):
        try:
            raw = _decode_closed_evidence(raw_bytes)
            decision = registration.verifier.verify(
                raw, attempt=attempt, identity=registration.identity
            )
        except LookupError:
            return self._failure(SensitiveDeliveryErrorCode.CORRELATION_MISMATCH, destination, attempt=attempt)
        except Exception:
            return self._failure(SensitiveDeliveryErrorCode.INVALID_EVIDENCE, destination, attempt=attempt)
        observed_us = self._now_us()
        provider_us = decision.provider_observed_us
        if provider_us is not None and (
            provider_us < attempt.send_started_us
            or provider_us > observed_us + self._max_future_skew_us
            or observed_us - provider_us > self._provider_max_age_us
        ):
            return self._failure(SensitiveDeliveryErrorCode.INVALID_EVIDENCE_TIME, destination, attempt=attempt)
        if observed_us < attempt.send_started_us:
            return self._failure(SensitiveDeliveryErrorCode.INVALID_EVIDENCE_TIME, destination, attempt=attempt)
        if decision.status is SensitiveDeliveryAcceptanceStatus.REJECTED:
            return self._failure(
                SensitiveDeliveryErrorCode.TRANSPORT_REJECTED,
                destination,
                attempt=attempt,
                status=decision.status,
                signal=decision.signal,
                provider_message_id=decision.provider_message_id,
                submission_id=decision.submission_id,
                evidence_id=decision.evidence_id,
                provider_observed_us=provider_us,
            )
        if decision.status is not SensitiveDeliveryAcceptanceStatus.ACCEPTED:
            return self._failure(
                SensitiveDeliveryErrorCode.ACCEPTANCE_UNCONFIRMED,
                destination,
                attempt=attempt,
                signal=decision.signal,
                provider_message_id=decision.provider_message_id,
                submission_id=decision.submission_id,
                evidence_id=decision.evidence_id,
                provider_observed_us=provider_us,
            )
        return self._authority._mint_receipt(
            outcome=SensitiveDeliveryOutcome.ACCEPTED,
            error_code=None,
            provenance=self._provenance,
            destination=destination,
            attempt=attempt,
            provider_message_id=decision.provider_message_id,
            non_acceptance_provider_message_id=None,
            submission_id=decision.submission_id,
            evidence_id=decision.evidence_id,
            acceptance_status=SensitiveDeliveryAcceptanceStatus.ACCEPTED,
            acceptance_signal=decision.signal,
            non_acceptance_signal=None,
            acceptance_observed_us=observed_us,
            provider_observed_us=provider_us,
        )

    def _failure(
        self,
        code,
        destination,
        *,
        attempt=None,
        status=SensitiveDeliveryAcceptanceStatus.UNKNOWN,
        signal=None,
        provider_message_id=None,
        submission_id=None,
        evidence_id=None,
        provider_observed_us=None,
    ):
        return self._authority._mint_receipt(
            outcome=code.outcome,
            error_code=code,
            provenance=self._provenance,
            destination=destination,
            attempt=attempt,
            provider_message_id=None,
            non_acceptance_provider_message_id=provider_message_id,
            submission_id=submission_id,
            evidence_id=evidence_id,
            acceptance_status=status,
            acceptance_signal=None,
            non_acceptance_signal=signal,
            acceptance_observed_us=None,
            provider_observed_us=provider_observed_us,
        )

    def _finalization_uncertain(self, terminal, destination, attempt):
        if terminal.outcome is SensitiveDeliveryOutcome.ACCEPTED:
            return self._authority._mint_receipt(
                outcome=SensitiveDeliveryOutcome.AMBIGUOUS,
                error_code=SensitiveDeliveryErrorCode.AUTHORIZATION_FINISH_UNCERTAIN,
                provenance=self._provenance,
                destination=destination,
                attempt=attempt,
                provider_message_id=terminal.provider_message_id,
                non_acceptance_provider_message_id=None,
                submission_id=terminal.submission_id,
                evidence_id=terminal.evidence_id,
                acceptance_status=SensitiveDeliveryAcceptanceStatus.ACCEPTED,
                acceptance_signal=terminal.acceptance_signal,
                non_acceptance_signal=None,
                acceptance_observed_us=terminal.acceptance_observed_us,
                provider_observed_us=terminal.provider_observed_us,
            )
        return self._failure(
            SensitiveDeliveryErrorCode.AUTHORIZATION_FINISH_UNCERTAIN,
            destination,
            attempt=attempt,
        )

    async def aclose(self):
        self._assert_owner()
        self._closed = True
        if self._prepared:
            self._finish_public_receipt(
                self._failure(
                    SensitiveDeliveryErrorCode.CANCELLED_BEFORE_SEND,
                    self._bridge.destination,
                )
            )
        self._prepared = 0
        if self._close_task is None:
            self._close_deadline = (
                self._monotonic()
                + self._deadline_seconds
                + self._cleanup_budget
            )
            owned_close_deadline = (
                self._close_deadline - _TASK_JOIN_RESERVE_SECONDS
            )
            self._close_task = asyncio.create_task(
                self._aclose_owned(
                    owned_close_deadline,
                    self._close_deadline,
                ),
                name="sensitive-delivery-router-close",
            )
        _, cancellation_requested = await _await_task_non_discardable(
            self._close_task,
            deadline=self._close_deadline,
            monotonic_clock=self._monotonic,
        )
        if cancellation_requested:
            raise asyncio.CancelledError

    async def _aclose_owned(self, close_deadline, join_deadline):
        current = asyncio.current_task()
        tasks = tuple(task for task in self._attempt_tasks if task is not current)
        for task in tasks:
            task.cancel()
        cleanup_failures = []
        if tasks:
            _, pending = await _wait_tasks_before_deadline(
                tasks,
                join_deadline,
                self._monotonic,
                cancel_deadline=close_deadline,
            )
            self._attempt_tasks.difference_update(task for task in tasks if task.done())
            if pending:
                cleanup_failures.append(
                    SensitiveDeliveryCleanupError(
                        "attempt tasks did not join within router close deadline"
                    )
                )

        cleanup_tasks = []
        for process in tuple(self._spawning.values()):
            cleanup_tasks.append(
                asyncio.create_task(
                    self._cleanup_spawned_process(
                        process,
                        None,
                        close_deadline,
                    ),
                    name="sensitive-delivery-close-spawn-cleanup",
                )
            )
        for active in tuple(self._active.values()):
            cleanup_tasks.append(
                asyncio.create_task(
                    self._cleanup_spawned_process(
                        active.process,
                        active,
                        close_deadline,
                    ),
                    name="sensitive-delivery-close-process-cleanup",
                )
            )
        for lease in self._leases:
            cleanup_tasks.append(
                asyncio.create_task(
                    lease._invalidate_and_reap_owned(
                        self._term_grace,
                        close_deadline,
                        self._monotonic,
                    ),
                    name="sensitive-delivery-close-sidecar-cleanup",
                )
            )
        if cleanup_tasks:
            _, pending = await _wait_tasks_before_deadline(
                cleanup_tasks,
                join_deadline,
                self._monotonic,
                cancel_deadline=close_deadline,
                cancel_pending=False,
            )
            for task in cleanup_tasks:
                if task.done() and not task.cancelled():
                    exception = task.exception()
                    if exception is not None:
                        cleanup_failures.append(exception)
            if pending:
                cleanup_failures.append(
                    SensitiveDeliveryCleanupError(
                        "cleanup tasks did not join within router close deadline"
                    )
                )
        self._active.clear()
        self._spawning.clear()
        if self._attempt_tasks:
            _, pending = await _wait_tasks_before_deadline(
                tuple(self._attempt_tasks),
                join_deadline,
                self._monotonic,
                cancel_deadline=close_deadline,
            )
            self._attempt_tasks.difference_update(
                task for task in self._attempt_tasks if task.done()
            )
            if pending:
                cleanup_failures.append(
                    SensitiveDeliveryCleanupError(
                        "router retained attempt tasks after close cleanup"
                    )
                )
        if cleanup_failures:
            raise SensitiveDeliveryCleanupError(
                "router close could not prove all process groups were reaped"
            )

    shutdown = aclose


async def _read_bounded_status(stream, cap, output):
    """Read with a status-only Task result; stderr may be discarded entirely."""

    overflow = False
    status = "ok"
    chunk = None
    try:
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                break
            if output is None:
                if len(chunk) > cap:
                    overflow = True
                cap = max(0, cap - len(chunk))
            else:
                overflow = output.retain(chunk, cap) or overflow
            chunk = None
    except BaseException:
        status = "failed"
        if output is not None:
            output.wipe()
    finally:
        chunk = None
        stream = None
    return status, overflow


async def _join_reader_tasks(active, deadline, monotonic_clock):
    real_deadline = _real_deadline_for(deadline, monotonic_clock)
    tasks = (active.stdout_task, active.stderr_task)
    pending = {task for task in tasks if not task.done()}
    if pending:
        remaining = _dual_remaining(deadline, real_deadline, monotonic_clock)
        preserve_timeout = max(0.0, remaining - 0.05)
        if preserve_timeout:
            _, pending = await asyncio.wait(pending, timeout=preserve_timeout)
    if pending:
        _close_async_process_pipes(active.process)
        for task in pending:
            task.cancel()
        remaining = _dual_remaining(deadline, real_deadline, monotonic_clock)
        if remaining:
            _, pending = await asyncio.wait(pending, timeout=remaining)
    if pending:
        raise SensitiveDeliveryCleanupError(
            "bounded pipe readers did not join within cleanup deadline"
        )
    reader_errors = []
    for task in tasks:
        if task.cancelled():
            reader_errors.append(
                SensitiveDeliveryCleanupError(
                    "bounded pipe reader was cancelled during cleanup"
                )
            )
        else:
            exception = task.exception()
            if exception is not None:
                reader_errors.append(exception)
            elif task.result()[0] != "ok":
                reader_errors.append(
                    SensitiveDeliveryCleanupError("bounded pipe reader failed")
                )
    _close_async_process_pipes(active.process)
    if reader_errors:
        raise SensitiveDeliveryCleanupError(
            "bounded pipe reader failed during cleanup"
        ) from reader_errors[0]


async def _await_task_non_discardable(
    task,
    *,
    deadline,
    monotonic_clock,
    cancel_on_first_cancellation=False,
):
    """Join an owned task through caller cancellation under one deadline."""

    cancellation_requested = False
    cancellation_forwarded = False
    real_deadline = _real_deadline_for(deadline, monotonic_clock)
    while not task.done():
        remaining = _dual_remaining(deadline, real_deadline, monotonic_clock)
        if remaining <= 0:
            task.cancel()
            break
        try:
            await asyncio.wait(
                (task,),
                timeout=min(_CLEANUP_POLL_SECONDS, remaining),
            )
        except asyncio.CancelledError:
            if task.done():
                break
            cancellation_requested = True
            if cancel_on_first_cancellation and not cancellation_forwarded:
                task.cancel()
                cancellation_forwarded = True
    if not task.done():
        raise SensitiveDeliveryCleanupError(
            "owned task did not join within its absolute cleanup deadline"
        )
    return task.result(), cancellation_requested


async def _wait_tasks_before_deadline(
    tasks,
    deadline,
    monotonic_clock,
    *,
    cancel_deadline=None,
    cancel_pending=True,
):
    pending = {task for task in tasks if not task.done()}
    cancel_deadline = deadline if cancel_deadline is None else min(
        deadline,
        cancel_deadline,
    )
    real_deadline = _real_deadline_for(deadline, monotonic_clock)
    real_cancel_deadline = _real_deadline_for(cancel_deadline, monotonic_clock)
    while pending:
        remaining = _dual_remaining(
            cancel_deadline,
            real_cancel_deadline,
            monotonic_clock,
        )
        if remaining <= 0:
            break
        _, pending = await asyncio.wait(
            pending,
            timeout=min(_CLEANUP_POLL_SECONDS, remaining),
        )
    if cancel_pending:
        for task in pending:
            task.cancel()
    while pending:
        remaining = _dual_remaining(deadline, real_deadline, monotonic_clock)
        if remaining <= 0:
            break
        _, pending = await asyncio.wait(
            pending,
            timeout=min(_CLEANUP_POLL_SECONDS, remaining),
        )
    return {task for task in tasks if task.done()}, pending


def _real_deadline_for(logical_deadline, monotonic_clock):
    """Mirror an injected logical deadline with a finite host-clock ceiling."""

    return time.monotonic() + max(0.0, logical_deadline - monotonic_clock())


def _dual_remaining(logical_deadline, real_deadline, monotonic_clock):
    return max(
        0.0,
        min(
            logical_deadline - monotonic_clock(),
            real_deadline - time.monotonic(),
        ),
    )


async def _wait_fd_ready(
    descriptor,
    *,
    write,
    deadline,
    monotonic_clock,
):
    remaining = deadline - monotonic_clock()
    if remaining <= 0:
        raise TimeoutError
    loop = asyncio.get_running_loop()
    ready = loop.create_future()

    def mark_ready():
        if not ready.done():
            ready.set_result(None)

    register = loop.add_writer if write else loop.add_reader
    unregister = loop.remove_writer if write else loop.remove_reader
    register(descriptor, mark_ready)
    try:
        await asyncio.wait_for(ready, timeout=remaining)
    finally:
        unregister(descriptor)


async def _write_all_fd_before_deadline(
    process,
    parts,
    deadline,
    monotonic_clock,
):
    for part in parts:
        view = memoryview(part)
        while view:
            descriptor = process.stdin_fd
            if descriptor is None:
                raise BrokenPipeError("sensitive delivery stdin closed")
            try:
                written = os.write(descriptor, view)
            except BlockingIOError:
                await _wait_fd_ready(
                    descriptor,
                    write=True,
                    deadline=deadline,
                    monotonic_clock=monotonic_clock,
                )
                continue
            view = view[written:]


async def _wait_for_async_process_exit(process, deadline, monotonic_clock):
    real_deadline = _real_deadline_for(deadline, monotonic_clock)
    while process.poll() is None:
        remaining = _dual_remaining(deadline, real_deadline, monotonic_clock)
        if remaining <= 0:
            raise TimeoutError
        await asyncio.sleep(min(_CLEANUP_POLL_SECONDS, remaining))


def _cleanup_budget_seconds(term_grace_seconds):
    return term_grace_seconds + max(
        _MIN_CLEANUP_KILL_SECONDS,
        min(term_grace_seconds, 1.0),
    )


def _signal_process_group(process_group_id, sig):
    try:
        os.killpg(process_group_id, sig)
    except ProcessLookupError:
        return False
    except OSError:
        return False
    return True


def _remove_exact_publication(mapping, key, expected):
    """Remove a possibly half-published exact object without virtual dispatch."""

    try:
        current = dict.__getitem__(mapping, key)
    except (KeyError, TypeError):
        return
    if expected is None or current is expected:
        try:
            dict.__delitem__(mapping, key)
        except (KeyError, TypeError):
            pass


def _cleanup_raw_fork_child(
    child_ownership,
    cleanup_deadline,
    term_grace_seconds,
    monotonic_clock,
    *,
    skip_term=False,
):
    """Synchronously kill/reap an unpublished child under logical and real ceilings."""

    if type(child_ownership) is not _DirectChildOwnership:
        return
    if child_ownership.state not in ("owned", "leader_reaped"):
        return
    pid = child_ownership.pid
    if type(pid) is not int or pid <= 0:
        child_ownership.state = "lost"
        return
    child_ownership.state = _cleanup_raw_fork_pid(
        pid,
        cleanup_deadline,
        term_grace_seconds,
        monotonic_clock,
        skip_term=skip_term,
        leader_reaped=child_ownership.state == "leader_reaped",
        state_target=child_ownership,
    )


def _cleanup_raw_fork_pid(
    pid,
    cleanup_deadline,
    term_grace_seconds,
    monotonic_clock,
    *,
    skip_term=False,
    leader_reaped=False,
    state_target=None,
):
    """Allocation-independent rollback for the first parent edge after fork.

    Only the primitive PID, booleans, numeric deadlines, raw signals, and
    ``waitpid`` are required.  In particular, cleanup never constructs an
    ownership wrapper, including when wrapper allocation itself failed.
    """

    if type(pid) is not int or pid <= 0:
        return "lost"
    real_deadline = time.monotonic() + _cleanup_budget_seconds(term_grace_seconds)
    grace_logical = min(cleanup_deadline, monotonic_clock() + term_grace_seconds)
    grace_real = min(real_deadline, time.monotonic() + term_grace_seconds)
    if not skip_term:
        _signal_process_group(pid, signal.SIGTERM)
        if not leader_reaped:
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                pass
        while (
            monotonic_clock() < grace_logical
            and time.monotonic() < grace_real
        ):
            # Deliberately do not reap the leader before the group-wide KILL.
            # Its unreaped PID prevents fast PID/PGID reuse from redirecting
            # cleanup checks or signals at an unrelated process group.
            time.sleep(_CLEANUP_POLL_SECONDS)

    _signal_process_group(pid, signal.SIGKILL)
    if not leader_reaped:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
    child_state = "leader_reaped" if leader_reaped else "owned"
    while (
        child_state == "owned"
        and monotonic_clock() < cleanup_deadline
        and time.monotonic() < real_deadline
    ):
        try:
            waited_pid, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            child_state = "lost"
        else:
            if waited_pid == pid:
                child_state = "leader_reaped"
        if state_target is not None:
            state_target.state = child_state
        time.sleep(_CLEANUP_POLL_SECONDS)
    if child_state == "owned":
        try:
            waited_pid, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            child_state = "lost"
        else:
            if waited_pid == pid:
                child_state = "leader_reaped"
        if state_target is not None:
            state_target.state = child_state
    while (
        child_state == "leader_reaped"
        and _process_group_exists(pid)
        and monotonic_clock() < cleanup_deadline
        and time.monotonic() < real_deadline
    ):
        # Never signal after reap: the numeric PID/PGID may have been reused.
        time.sleep(_CLEANUP_POLL_SECONDS)
    if child_state == "leader_reaped" and not _process_group_exists(pid):
        child_state = "reaped"
        if state_target is not None:
            state_target.state = child_state
    if child_state != "reaped" or _process_group_exists(pid):
        raise SensitiveDeliveryCleanupError(
            "unpublished child/group cleanup could not be proven after SIGKILL"
        )
    return child_state


def _signal_owned_process(process, sig):
    """Signal the dedicated group, or the direct pre-``setsid`` child."""

    ownership = getattr(process, "child_ownership", None)
    if type(ownership) is not _DirectChildOwnership:
        return False
    if ownership.state == "leader_reaped":
        return ownership.signal_group_after_leader_reap(sig)
    if ownership.state != "owned" or process.returncode is not None:
        return False
    if _owned_pid_number_was_reused(process):
        return False

    # The group can outlive its leader, so ``getpgid(leader_pid)`` is not a
    # valid prerequisite for signalling descendants.  Try the router-owned
    # PGID first; before ``setsid`` it cannot name the child's inherited group
    # because the child PID is new and therefore is not that group leader.
    if _signal_process_group(process.pid, sig):
        return True
    try:
        os.kill(process.pid, sig)
    except ProcessLookupError:
        return False
    except OSError:
        return False
    return True


def _owned_pid_number_was_reused(process):
    """Distinguish a reaped child from a new process reusing its numeric PID."""

    ownership = getattr(process, "child_ownership", None)
    if (
        type(ownership) is _DirectChildOwnership
        and ownership.state in ("owned", "leader_reaped")
    ):
        return False
    return True


def _process_group_exists(process_group_id):
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_group_is_dedicated_leader(pid):
    try:
        return os.getpgid(pid) == pid
    except ProcessLookupError:
        return False


def _close_async_process_pipes(process):
    process.close_output_pipes()


def _close_fd(descriptor):
    try:
        os.close(descriptor)
    except OSError:
        pass


def _pipe_above_stdio():
    """Create a non-inheritable pipe without reusing descriptors 0, 1, or 2."""

    import fcntl

    descriptors = list(os.pipe())
    try:
        for index, descriptor in enumerate(descriptors):
            if descriptor <= 2:
                replacement = fcntl.fcntl(
                    descriptor,
                    fcntl.F_DUPFD_CLOEXEC,
                    3,
                )
                _close_fd(descriptor)
                descriptors[index] = replacement
        return tuple(descriptors)
    except BaseException:
        for descriptor in descriptors:
            _close_fd(descriptor)
        raise


def _wipe(payload):
    if type(payload) is bytearray:
        for index in range(len(payload)):
            payload[index] = 0


__all__ = [name for name in globals() if name.startswith("SensitiveDelivery")] + [
    "MAX_SENSITIVE_PLAINTEXT_BYTES",
    "MAX_SENSITIVE_REGISTRATIONS",
    "MAX_SENSITIVE_EVIDENCE_BYTES",
    "MAX_SENSITIVE_STDIN_BYTES",
]
