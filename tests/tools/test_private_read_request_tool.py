"""Model-surface and terminal-boundary tests for private-read requests."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import socket
import sqlite3
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

import model_tools
import tools.private_read_request_tool as private_read_tool
from agent.tool_outcomes import TerminalToolInvocation, ToolExecutionResult
from gateway.authorization_contracts import CoordinatorIdentity
from gateway.authorization_tasks import AuthorizationTaskStore
from gateway.private_read_authorization import (
    MAX_CAPABILITY_ID_BYTES,
    PrivateReadCapabilityRegistry,
    PrivateReadCapabilitySpec,
    PrivateReadRequestRuntime,
    TrustedPrivateReadHostContext,
)
from tools.private_read_request_tool import (
    PRIVATE_READ_REQUEST_SCHEMA,
    PRIVATE_READ_REQUEST_TOOL_NAME,
    check_private_read_request_runtime,
    configure_private_read_request_runtime,
)
from tools.registry import registry


PRIVATE_SENTINEL = "PRIVATE-TOOL-VALUE-MUST-REMAIN-ABSENT"
AUDIT_KEY = b"private-tool-audit-key-for-tests-32b"
REQUEST_KEY = b"private-tool-request-key-tests-32b"
OPAQUE_ID_KEY = b"private-tool-opaque-key-for-tests-32"


class TextSubclass(str):
    pass


class FakeHostContexts:
    def __init__(self, context: object) -> None:
        self.context = context
        self.calls = 0

    def current(self) -> object:
        self.calls += 1
        return self.context


def _context(**changes: object) -> TrustedPrivateReadHostContext:
    values: dict[str, object] = {
        "requester_profile": "requester-profile",
        "requester_agent": "requester-agent",
        "source_platform": "source-platform",
        "source_account": "source-account",
        "source_user": "source-user",
        "source_chat": "source-chat",
        "source_thread": "source-thread",
        "source_message": "source-message",
        "source_provenance": "authenticated_inbound",
        "resource_id": "trusted-resource-id",
        "approval_profile": "approval-profile",
        "approval_account": "approval-account",
        "approval_user": "approval-user",
        "approval_chat": "approval-chat",
        "approval_thread": "approval-thread",
        "delivery_profile": "delivery-profile",
        "delivery_platform": "delivery-platform",
        "delivery_account": "delivery-account",
        "delivery_chat": "delivery-chat",
        "delivery_thread": "delivery-thread",
        "delivery_transport_implementation": "delivery-transport-v1",
        "delivery_runtime_identity": "delivery-runtime",
        "delivery_account_binding": "delivery-binding",
        "delivery_connection_epoch": 3,
        "created_at_us": 2_000_000,
        "expires_at_us": 10_000_000,
        "pdp_identity": "decision-service-instance",
        "policy_identity": "policy-identity",
        "policy_version": "policy-version",
        "policy_hash": "a" * 64,
        "model_identity": "model-identity",
    }
    values.update(changes)
    return TrustedPrivateReadHostContext(**values)


def _capability(
    capability_id: str = "records.summary.read",
    *,
    operation: str = "retrieve",
) -> PrivateReadCapabilitySpec:
    return PrivateReadCapabilitySpec(
        capability_id=capability_id,
        operation=operation,
        resource_type="synthetic.record",
        fields=("summary", "timestamp"),
    )


def _activate_store(tmp_path: Path, name: str = "authorization") -> AuthorizationTaskStore:
    root = (tmp_path / name).absolute()
    root.mkdir(mode=0o700)
    store = AuthorizationTaskStore(
        db_path=root / "tasks.db",
        audit_hmac_key=AUDIT_KEY,
        request_hmac_key=REQUEST_KEY,
        key_version="private-tool-test-k1",
    )
    lock = store.acquire_coordinator_lock()
    assert lock is not None
    fence = store.acquire_coordinator(
        CoordinatorIdentity(owner_id=f"private-tool-{name}", nonce="c" * 32),
        now_us=1_000_000,
        lease_expires_at_us=20_000_000,
        lock_session=lock,
    )
    assert fence is not None
    return store


def _runtime(
    store: AuthorizationTaskStore,
    *,
    enabled: bool = True,
    context: object | None = None,
    capabilities: tuple[PrivateReadCapabilitySpec, ...] | None = None,
) -> tuple[PrivateReadRequestRuntime, FakeHostContexts]:
    contexts = FakeHostContexts(_context() if context is None else context)
    runtime = PrivateReadRequestRuntime(
        store=store,
        id_hmac_key=OPAQUE_ID_KEY,
        host_contexts=contexts,
        capabilities=PrivateReadCapabilityRegistry(
            capabilities if capabilities is not None else (_capability(),)
        ),
        enabled=enabled,
    )
    return runtime, contexts


def _valid_args(capability_id: str = "records.summary.read") -> dict[str, str]:
    return {"capability_id": capability_id}


def _task_count(store: AuthorizationTaskStore) -> int:
    with sqlite3.connect(store.db_path) as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM authorization_tasks"
        ).fetchone()[0]


def _dispatch_current_runtime(
    args: object,
    *,
    tool_call_id: str,
) -> tuple[ToolExecutionResult, TerminalToolInvocation]:
    capability = registry.snapshot_terminal_capability(
        PRIVATE_READ_REQUEST_TOOL_NAME
    )
    assert capability is not None
    invocation = TerminalToolInvocation(capability)
    visible = model_tools.handle_function_call(
        PRIVATE_READ_REQUEST_TOOL_NAME,
        args,
        tool_call_id=tool_call_id,
        skip_pre_tool_call_hook=True,
        skip_tool_execution_middleware=True,
        terminal_invocation=invocation,
    )
    assert invocation.handler_entered is True
    sealed = invocation.seal(visible)
    assert isinstance(sealed, ToolExecutionResult)
    return sealed, invocation


@pytest.fixture(autouse=True)
def _clear_runtime():
    configure_private_read_request_runtime(None)
    yield
    configure_private_read_request_runtime(None)


def test_schema_exposes_only_exact_closed_bounded_capability_id() -> None:
    parameters = PRIVATE_READ_REQUEST_SCHEMA["parameters"]
    assert parameters == {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "capability_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_CAPABILITY_ID_BYTES,
            }
        },
        "required": ["capability_id"],
    }
    serialized = json.dumps(PRIVATE_READ_REQUEST_SCHEMA).lower()
    for forbidden in (
        "identity",
        "account",
        "group",
        "thread",
        "message",
        "tool_call_id",
        "operation",
        "resource_type",
        "resource_id",
        "fields",
        "query",
        "path",
        "recipient",
        "policy",
        "destination",
    ):
        assert forbidden not in serialized


def test_runtime_contains_only_model_turn_dependencies() -> None:
    assert {field.name for field in dataclasses.fields(PrivateReadRequestRuntime)} == {
        "store",
        "id_hmac_key",
        "host_contexts",
        "capabilities",
        "enabled",
    }


def test_module_exports_no_direct_private_read_handler() -> None:
    assert "private_read_request" not in vars(private_read_tool)
    assert "private_read_request" not in private_read_tool.__all__


def test_tool_is_absent_until_complete_enabled_runtime_is_installed(
    tmp_path: Path,
) -> None:
    assert check_private_read_request_runtime() is False
    assert registry.get_definitions({PRIVATE_READ_REQUEST_TOOL_NAME}) == []

    with pytest.raises(ValueError, match="non-empty bounded tuple"):
        PrivateReadCapabilityRegistry(())

    store = _activate_store(tmp_path)
    try:
        disabled, _ = _runtime(store, enabled=False)
        configure_private_read_request_runtime(disabled)
        assert check_private_read_request_runtime() is False
        assert registry.get_definitions({PRIVATE_READ_REQUEST_TOOL_NAME}) == []

        enabled, _ = _runtime(store, enabled=True)
        configure_private_read_request_runtime(enabled)
        assert check_private_read_request_runtime() is True
        assert registry.get_definitions({PRIVATE_READ_REQUEST_TOOL_NAME}) == [
            {"type": "function", "function": PRIVATE_READ_REQUEST_SCHEMA}
        ]
    finally:
        store.close()


def test_registry_dispatch_without_terminal_commitment_cannot_execute(
    tmp_path: Path,
) -> None:
    store = _activate_store(tmp_path)
    runtime, contexts = _runtime(store)
    configure_private_read_request_runtime(runtime)
    try:
        result = registry.dispatch(
            PRIVATE_READ_REQUEST_TOOL_NAME,
            _valid_args(),
            tool_call_id="uncommitted-provider-call",
        )

        assert isinstance(result, str)
        assert "exact host invocation" in result
        assert contexts.calls == 0
        assert _task_count(store) == 0
    finally:
        store.close()


def test_model_turn_only_creates_pending_state_and_forwards_exact_host_call_id(
    tmp_path: Path, caplog
) -> None:
    store = _activate_store(tmp_path)
    runtime, contexts = _runtime(store)
    configure_private_read_request_runtime(runtime)
    invocation = TerminalToolInvocation(
        registry.snapshot_terminal_capability(PRIVATE_READ_REQUEST_TOOL_NAME)
    )
    try:
        with (
            patch.object(
                threading.Thread,
                "start",
                side_effect=AssertionError("worker must remain dormant"),
            ),
            patch.object(
                asyncio,
                "create_task",
                side_effect=AssertionError("async work must remain dormant"),
            ),
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network must remain dormant"),
            ),
        ):
            visible = model_tools.handle_function_call(
                PRIVATE_READ_REQUEST_TOOL_NAME,
                _valid_args(),
                tool_call_id="provider-exact-call-001",
                skip_pre_tool_call_hook=True,
                skip_tool_execution_middleware=True,
                terminal_invocation=invocation,
            )
        sealed = invocation.seal(visible)

        assert invocation.handler_entered is True
        assert isinstance(sealed, ToolExecutionResult)
        assert json.loads(sealed.content) == {
            "reason": "approval_required",
            "status": "deferred",
        }
        assert sealed.terminal is not None
        assert sealed.terminal.status == "deferred"
        assert sealed.terminal.reason == "approval_required"
        assert dict(sealed.terminal.metadata).keys() == {
            "task_id",
            "correlation_id",
        }
        assert PRIVATE_SENTINEL not in repr(sealed)
        assert PRIVATE_SENTINEL not in caplog.text
        assert PRIVATE_SENTINEL.encode() not in store.db_path.read_bytes()
        assert contexts.calls == 1

        with sqlite3.connect(store.db_path) as connection:
            binding = json.loads(
                connection.execute(
                    "SELECT binding_json FROM authorization_tasks"
                ).fetchone()[0]
            )
            notification = connection.execute(
                "SELECT status,send_started_at_us FROM "
                "authorization_notification_attempts"
            ).fetchone()
        assert binding["tool_call_id"] == "provider-exact-call-001"
        assert binding["operation"] == "retrieve"
        assert binding["resource_type"] == "synthetic.record"
        assert binding["resource_id"] == "trusted-resource-id"
        assert binding["fields"] == ["summary", "timestamp"]
        assert notification == ("pending", None)
    finally:
        store.close()


@pytest.mark.parametrize(
    "extra",
    [
        "identity",
        "account",
        "group",
        "thread",
        "message",
        "tool_call_id",
        "operation",
        "resource_type",
        "resource_id",
        "fields",
        "query",
        "path",
        "recipient",
        "policy",
        "destination",
    ],
)
def test_model_cannot_inject_trusted_fields(tmp_path: Path, extra: str) -> None:
    store = _activate_store(tmp_path)
    runtime, contexts = _runtime(store)
    configure_private_read_request_runtime(runtime)
    try:
        result, _invocation = _dispatch_current_runtime(
            _valid_args() | {extra: "model-forgery"},
            tool_call_id="provider-exact-call",
        )

        assert isinstance(result, ToolExecutionResult)
        assert result.terminal is not None
        assert result.terminal.status == "safe_failure"
        assert contexts.calls == 0
        assert _task_count(store) == 0
    finally:
        store.close()


@pytest.mark.parametrize(
    "args",
    [
        {"capability_id": "arbitrary.unknown"},
        {"capability_id": "\x00bad"},
        {"capability_id": "\ud800"},
        {"capability_id": "é" * (MAX_CAPABILITY_ID_BYTES // 2 + 1)},
        {"capability_id": TextSubclass("records.summary.read")},
        {TextSubclass("capability_id"): "records.summary.read"},
        (("capability_id", "records.summary.read"),),
        (value for value in ("records.summary.read",)),
    ],
)
def test_unknown_or_non_exact_capability_input_fails_before_host_context(
    tmp_path: Path, args: object
) -> None:
    store = _activate_store(tmp_path)
    runtime, contexts = _runtime(store)
    configure_private_read_request_runtime(runtime)
    try:
        result, _invocation = _dispatch_current_runtime(
            args,
            tool_call_id="provider-exact-call",
        )

        assert result.terminal is not None
        assert result.terminal.status == "safe_failure"
        assert contexts.calls == 0
        assert _task_count(store) == 0
    finally:
        store.close()


def test_invalid_host_context_is_sealed_without_persistence(tmp_path: Path) -> None:
    store = _activate_store(tmp_path)
    runtime, contexts = _runtime(store, context={"resource_id": "untrusted"})
    configure_private_read_request_runtime(runtime)
    try:
        result, _invocation = _dispatch_current_runtime(
            _valid_args(), tool_call_id="provider-exact-call"
        )

        assert result.terminal is not None
        assert result.terminal.status == "safe_failure"
        assert contexts.calls == 1
        assert _task_count(store) == 0
    finally:
        store.close()


def test_runtime_disable_revokes_preplanned_terminal_invocation(tmp_path: Path) -> None:
    store = _activate_store(tmp_path)
    runtime, contexts = _runtime(store)
    configure_private_read_request_runtime(runtime)
    invocation = TerminalToolInvocation(
        registry.snapshot_terminal_capability(PRIVATE_READ_REQUEST_TOOL_NAME)
    )
    configure_private_read_request_runtime(None)
    try:
        result = model_tools.handle_function_call(
            PRIVATE_READ_REQUEST_TOOL_NAME,
            _valid_args(),
            tool_call_id="provider-call-before-disable",
            skip_pre_tool_call_hook=True,
            skip_tool_execution_middleware=True,
            terminal_invocation=invocation,
        )

        assert isinstance(result, str)
        assert any(
            marker in result
            for marker in ("changed", "available", "current registration")
        )
        assert invocation.handler_entered is False
        assert contexts.calls == 0
        assert _task_count(store) == 0
    finally:
        store.close()


def test_runtime_replacement_revokes_old_plan_and_new_plan_uses_new_context(
    tmp_path: Path,
) -> None:
    first_store = _activate_store(tmp_path, "first")
    second_store = _activate_store(tmp_path, "second")
    first_runtime, first_contexts = _runtime(first_store)
    second_runtime, second_contexts = _runtime(
        second_store,
        context=_context(resource_id="replacement-resource"),
    )
    configure_private_read_request_runtime(first_runtime)
    old_invocation = TerminalToolInvocation(
        registry.snapshot_terminal_capability(PRIVATE_READ_REQUEST_TOOL_NAME)
    )
    configure_private_read_request_runtime(second_runtime)
    try:
        old_result = model_tools.handle_function_call(
            PRIVATE_READ_REQUEST_TOOL_NAME,
            _valid_args(),
            tool_call_id="provider-old-plan",
            skip_pre_tool_call_hook=True,
            skip_tool_execution_middleware=True,
            terminal_invocation=old_invocation,
        )
        assert isinstance(old_result, str)
        assert old_invocation.handler_entered is False
        assert first_contexts.calls == 0
        assert second_contexts.calls == 0
        assert _task_count(first_store) == 0
        assert _task_count(second_store) == 0

        new_invocation = TerminalToolInvocation(
            registry.snapshot_terminal_capability(PRIVATE_READ_REQUEST_TOOL_NAME)
        )
        visible = model_tools.handle_function_call(
            PRIVATE_READ_REQUEST_TOOL_NAME,
            _valid_args(),
            tool_call_id="provider-new-plan",
            skip_pre_tool_call_hook=True,
            skip_tool_execution_middleware=True,
            terminal_invocation=new_invocation,
        )
        sealed = new_invocation.seal(visible)
        assert new_invocation.handler_entered is True
        assert isinstance(sealed, ToolExecutionResult)
        assert sealed.terminal is not None
        assert sealed.terminal.status == "deferred"
        assert second_contexts.calls == 1
        with sqlite3.connect(second_store.db_path) as connection:
            binding = json.loads(
                connection.execute(
                    "SELECT binding_json FROM authorization_tasks"
                ).fetchone()[0]
            )
        assert binding["resource_id"] == "replacement-resource"
    finally:
        first_store.close()
        second_store.close()


def test_runtime_replacement_after_terminal_entry_uses_captured_runtime(
    tmp_path: Path,
) -> None:
    first_store = _activate_store(tmp_path, "entered-first")
    second_store = _activate_store(tmp_path, "entered-second")
    first_runtime, first_contexts = _runtime(
        first_store,
        capabilities=(_capability(operation="old-operation"),),
    )
    second_runtime, second_contexts = _runtime(
        second_store,
        capabilities=(_capability(operation="new-operation"),),
    )
    configure_private_read_request_runtime(first_runtime)
    invocation = TerminalToolInvocation(
        registry.snapshot_terminal_capability(PRIVATE_READ_REQUEST_TOOL_NAME)
    )
    handler_started = threading.Event()
    resume_handler = threading.Event()
    outcome: dict[str, object] = {}
    original = private_read_tool._private_read_request_for_runtime

    def pause_after_entry(
        runtime: PrivateReadRequestRuntime | None,
        args: object,
        *,
        tool_call_id: str | None,
    ) -> ToolExecutionResult:
        handler_started.set()
        if not resume_handler.wait(timeout=5):
            raise AssertionError("terminal handler was not resumed")
        return original(runtime, args, tool_call_id=tool_call_id)

    def invoke() -> None:
        try:
            outcome["visible"] = model_tools.handle_function_call(
                PRIVATE_READ_REQUEST_TOOL_NAME,
                _valid_args(),
                tool_call_id="provider-entered-runtime-a",
                skip_pre_tool_call_hook=True,
                skip_tool_execution_middleware=True,
                terminal_invocation=invocation,
            )
        except BaseException as error:
            outcome["error"] = error

    try:
        with patch.object(
            private_read_tool,
            "_private_read_request_for_runtime",
            side_effect=pause_after_entry,
        ):
            dispatch_thread = threading.Thread(target=invoke)
            dispatch_thread.start()
            assert handler_started.wait(timeout=5)
            assert invocation.handler_entered is True

            configure_private_read_request_runtime(second_runtime)
            resume_handler.set()
            dispatch_thread.join(timeout=5)

        assert dispatch_thread.is_alive() is False
        assert "error" not in outcome
        sealed = invocation.seal(outcome["visible"])
        assert isinstance(sealed, ToolExecutionResult)
        assert sealed.terminal is not None
        assert sealed.terminal.status == "deferred"
        assert first_contexts.calls == 1
        assert second_contexts.calls == 0
        with sqlite3.connect(first_store.db_path) as connection:
            first_binding = json.loads(
                connection.execute(
                    "SELECT binding_json FROM authorization_tasks"
                ).fetchone()[0]
            )
        assert first_binding["operation"] == "old-operation"
        assert _task_count(second_store) == 0

        new_invocation = TerminalToolInvocation(
            registry.snapshot_terminal_capability(PRIVATE_READ_REQUEST_TOOL_NAME)
        )
        new_visible = model_tools.handle_function_call(
            PRIVATE_READ_REQUEST_TOOL_NAME,
            _valid_args(),
            tool_call_id="provider-runtime-b",
            skip_pre_tool_call_hook=True,
            skip_tool_execution_middleware=True,
            terminal_invocation=new_invocation,
        )
        new_sealed = new_invocation.seal(new_visible)
        assert new_invocation.handler_entered is True
        assert isinstance(new_sealed, ToolExecutionResult)
        assert new_sealed.terminal is not None
        assert new_sealed.terminal.status == "deferred"
        assert second_contexts.calls == 1
        with sqlite3.connect(second_store.db_path) as connection:
            second_binding = json.loads(
                connection.execute(
                    "SELECT binding_json FROM authorization_tasks"
                ).fetchone()[0]
            )
        assert second_binding["operation"] == "new-operation"
    finally:
        resume_handler.set()
        first_store.close()
        second_store.close()


def test_exact_model_turn_replay_is_idempotent(tmp_path: Path) -> None:
    store = _activate_store(tmp_path)
    runtime, contexts = _runtime(store)
    configure_private_read_request_runtime(runtime)
    try:
        first, first_invocation = _dispatch_current_runtime(
            _valid_args(), tool_call_id="provider-replay-call"
        )
        second, second_invocation = _dispatch_current_runtime(
            _valid_args(), tool_call_id="provider-replay-call"
        )

        assert first_invocation.handler_entered is True
        assert second_invocation.handler_entered is True
        assert first.terminal is not None
        assert second.terminal is not None
        assert first.terminal.metadata == second.terminal.metadata
        assert contexts.calls == 2
        assert _task_count(store) == 1
        with sqlite3.connect(store.db_path) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM authorization_notification_attempts"
            ).fetchone()[0] == 1
    finally:
        store.close()


def test_store_failure_returns_sealed_content_free_terminal_failure(
    tmp_path: Path, caplog
) -> None:
    store = _activate_store(tmp_path)

    def fail_on_write(step: str) -> None:
        if step == "transition.before":
            raise RuntimeError(PRIVATE_SENTINEL)

    store._fault_hook = fail_on_write
    runtime, contexts = _runtime(store)
    configure_private_read_request_runtime(runtime)
    try:
        result, invocation = _dispatch_current_runtime(
            _valid_args(), tool_call_id="provider-failing-call"
        )

        assert invocation.handler_entered is True
        assert isinstance(result, ToolExecutionResult)
        assert result.terminal is not None
        assert result.terminal.status == "safe_failure"
        assert PRIVATE_SENTINEL not in repr(result)
        assert PRIVATE_SENTINEL not in caplog.text
        assert PRIVATE_SENTINEL.encode() not in store.db_path.read_bytes()
        assert contexts.calls == 1
        assert _task_count(store) == 0
    finally:
        store.close()
