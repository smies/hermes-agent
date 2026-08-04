"""Adversarial contracts for host-owned terminal tool-turn outcomes."""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import tempfile
import threading
import time
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import model_tools
import tools.registry as registry_module
from agent.tool_guardrails import ToolGuardrailDecision
from agent.tool_outcomes import (
    MAX_TERMINAL_CONTENT_CHARS,
    MAX_TERMINAL_FINAL_RESPONSE_CHARS,
    MAX_TERMINAL_METADATA_ITEMS,
    TerminalToolDirective,
    TerminalToolInvocation,
    ToolExecutionResult,
)
from run_agent import AIAgent
from tools.registry import ToolRegistry, invalidate_check_fn_cache, registry


def _tool_defs(*names: str) -> list[dict]:
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": f"{name} tool",
                "parameters": {"type": "object", "properties": {}},
            },
        }
        for name in names
    ]


def _tool_call(name: str, call_id: str, arguments: str = "{}"):
    return SimpleNamespace(
        id=call_id,
        type="function",
        function=SimpleNamespace(name=name, arguments=arguments),
    )


def _response(*, content: str = "", tool_calls=None, finish_reason="tool_calls"):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    choice = SimpleNamespace(message=message, finish_reason=finish_reason)
    return SimpleNamespace(choices=[choice], model="test/model", usage=None)


def _make_agent(
    *tool_names: str,
    session_db=None,
    session_id: str | None = None,
    hermes_home: Path | None = None,
) -> AIAgent:
    hermes_home = hermes_home or Path(
        tempfile.mkdtemp(prefix="hermes-terminal-outcome-test-")
    )
    (hermes_home / "logs").mkdir(parents=True, exist_ok=True)
    with (
        patch("run_agent.get_tool_definitions", return_value=_tool_defs(*tool_names)),
        patch("run_agent.check_toolset_requirements", return_value={}),
        patch("run_agent.OpenAI"),
        patch("run_agent._hermes_home", hermes_home),
        patch("agent.model_metadata.fetch_model_metadata", return_value={}),
    ):
        agent = AIAgent(
            api_key="test-key-1234567890",
            base_url="https://openrouter.ai/api/v1",
            quiet_mode=True,
            session_db=session_db,
            session_id=session_id,
            skip_context_files=True,
            skip_memory=True,
        )
    agent.client = MagicMock()
    agent._cached_system_prompt = "stable system prompt"
    agent._use_prompt_caching = False
    agent._disable_streaming = True
    agent.tool_delay = 0
    agent.compression_enabled = False
    agent.save_trajectories = False
    return agent


def _terminal_result(
    content: str = '{"status":"deferred"}',
    final: str = "The request was deferred safely.",
    *,
    status: str = "deferred",
    reason: str = "host_deferred",
    metadata=None,
) -> ToolExecutionResult:
    return ToolExecutionResult(
        content=content,
        terminal=TerminalToolDirective(
            final_response=final,
            status=status,
            reason=reason,
            metadata=metadata or {"task_id": "task-1"},
        ),
    )


@pytest.fixture()
def registered_tools():
    names: list[str] = []

    def register(name: str, *, terminal: bool = False, handler=None, **kwargs) -> None:
        registration = (
            registry._register_host_terminal_tool if terminal else registry.register
        )
        registration(
            name=name,
            toolset="terminal-outcome-test",
            schema={
                "name": name,
                "description": "test tool",
                "parameters": {"type": "object", "properties": {}},
            },
            handler=handler or (lambda _args, **_kwargs: "unused"),
            **kwargs,
        )
        names.append(name)

    yield register
    for name in reversed(names):
        registry.deregister(name)
    invalidate_check_fn_cache()


def _run(agent: AIAgent, prompt: str = "run it") -> dict:
    with (
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        return agent.run_conversation(prompt)


def test_envelopes_are_immutable_bounded_and_non_string():
    result = _terminal_result(metadata={"task_id": "abc"})

    assert not isinstance(result, str)
    assert result.terminal.metadata == (("task_id", "abc"),)
    with pytest.raises(FrozenInstanceError):
        result.content = "changed"
    with pytest.raises(FrozenInstanceError):
        result.terminal.status = "changed"
    with pytest.raises(ValueError):
        ToolExecutionResult(
            content="x" * (MAX_TERMINAL_CONTENT_CHARS + 1),
            terminal=result.terminal,
        )
    with pytest.raises(ValueError):
        TerminalToolDirective(
            final_response="x" * (MAX_TERMINAL_FINAL_RESPONSE_CHARS + 1),
            status="completed",
            reason="done",
        )
    with pytest.raises(ValueError):
        TerminalToolDirective(
            final_response="done",
            status="completed",
            reason="done",
            metadata={f"key_{i}": "value" for i in range(MAX_TERMINAL_METADATA_ITEMS + 1)},
        )
    with pytest.raises((TypeError, ValueError)):
        TerminalToolDirective(
            final_response="done",
            status="completed",
            reason="done",
            metadata={"private": {"nested": "not allowed"}},
        )


def test_internal_terminal_metadata_is_schema_invisible_and_mcp_cannot_acquire_it():
    local = ToolRegistry()
    schema = {
        "name": "finish_turn",
        "description": "finish",
        "parameters": {"type": "object", "properties": {}},
    }
    local._register_host_terminal_tool(
        name="finish_turn",
        toolset="local",
        schema=schema,
        handler=lambda _args: _terminal_result(),
    )

    capability = local.snapshot_terminal_capability("finish_turn")
    assert capability is not None
    assert local.get_definitions({"finish_turn"}) == [
        {"type": "function", "function": schema}
    ]
    assert "terminal" not in json.dumps(local.get_definitions({"finish_turn"})).lower()

    with pytest.raises(ValueError):
        local._register_host_terminal_tool(
            name="remote_finish",
            toolset="mcp-remote",
            schema={"name": "remote_finish", "parameters": {"type": "object"}},
            handler=lambda _args: _terminal_result(),
        )


def test_public_plugin_context_has_no_terminal_self_grant_surface():
    from hermes_cli.plugins import PluginContext, PluginManifest

    name = "public_plugin_terminal_authority_test"
    manager = SimpleNamespace(_plugin_tool_names=set(), _cli_ref=None)
    context = PluginContext(PluginManifest(name="reviewed-plugin"), manager)

    assert "may_return_terminal" not in inspect.signature(context.register_tool).parameters
    with pytest.raises(TypeError):
        context.register_tool(
            name=name,
            toolset="reviewed-plugin",
            schema={"name": name, "parameters": {"type": "object"}},
            handler=lambda _args, **_kwargs: _terminal_result(),
            may_return_terminal=True,
        )
    assert registry.get_entry(name) is None


def test_registry_gate_requires_exact_current_invocation_and_zero_calls_on_mismatch():
    local = ToolRegistry()
    calls: list[str] = []

    def handler(_args, **_kwargs):
        calls.append("terminal")
        return _terminal_result()

    local._register_host_terminal_tool(
        name="gated_terminal",
        toolset="host-owned",
        schema={"name": "gated_terminal", "parameters": {"type": "object"}},
        handler=handler,
    )
    capability = local.snapshot_terminal_capability("gated_terminal")
    assert capability is not None

    no_invocation = local.dispatch("gated_terminal", {})
    assert calls == []
    assert isinstance(no_invocation, str) and len(no_invocation) <= 512

    local.register(
        name="ordinary_target",
        toolset="host-owned",
        schema={"name": "ordinary_target", "parameters": {"type": "object"}},
        handler=lambda _args, **_kwargs: calls.append("ordinary") or "ordinary",
    )
    wrong_target = local.dispatch(
        "ordinary_target", {}, terminal_invocation=TerminalToolInvocation(capability)
    )
    assert calls == []
    assert isinstance(wrong_target, str) and len(wrong_target) <= 512


def test_terminal_invocation_is_single_use_and_handler_runs_at_most_once():
    local = ToolRegistry()
    calls: list[str] = []

    def handler(_args, **_kwargs):
        calls.append("entered")
        return _terminal_result()

    local._register_host_terminal_tool(
        name="single_use_terminal",
        toolset="host-owned",
        schema={"name": "single_use_terminal", "parameters": {"type": "object"}},
        handler=handler,
    )
    invocation = TerminalToolInvocation(
        local.snapshot_terminal_capability("single_use_terminal")
    )

    first = local.dispatch(
        "single_use_terminal", {}, terminal_invocation=invocation
    )
    second = local.dispatch(
        "single_use_terminal", {}, terminal_invocation=invocation
    )

    assert isinstance(first, ToolExecutionResult)
    assert isinstance(second, str) and len(second) <= 512
    assert calls == ["entered"]


def test_direct_model_dispatch_cannot_enter_terminal_handler_without_invocation():
    local = ToolRegistry()
    calls: list[str] = []
    local._register_host_terminal_tool(
        name="direct_terminal",
        toolset="host-owned",
        schema={"name": "direct_terminal", "parameters": {"type": "object"}},
        handler=lambda _args, **_kwargs: calls.append("entered") or _terminal_result(),
    )

    with patch("model_tools.registry", local):
        result = model_tools.handle_function_call(
            "direct_terminal", {}, skip_pre_tool_call_hook=True
        )

    assert calls == []
    assert isinstance(result, str) and len(result) <= 512


def test_model_dispatch_forwards_exact_host_tool_call_id_only_to_terminal_handler():
    local = ToolRegistry()
    observed: list[tuple[dict, str | None]] = []

    def handler(args, *, tool_call_id=None, **_host_kwargs):
        observed.append((args, tool_call_id))
        return _terminal_result()

    local._register_host_terminal_tool(
        name="host_id_terminal",
        toolset="host-owned",
        schema={"name": "host_id_terminal", "parameters": {"type": "object"}},
        handler=handler,
    )
    invocation = TerminalToolInvocation(
        local.snapshot_terminal_capability("host_id_terminal")
    )

    with patch("model_tools.registry", local):
        visible = model_tools.handle_function_call(
            "host_id_terminal",
            {"tool_call_id": "model-forgery"},
            tool_call_id="provider-call-exact-001",
            skip_pre_tool_call_hook=True,
            skip_tool_execution_middleware=True,
            terminal_invocation=invocation,
        )

    assert visible == '{"status":"deferred"}'
    assert observed == [
        ({"tool_call_id": "model-forgery"}, "provider-call-exact-001")
    ]


def test_host_tool_call_id_forwarding_preserves_legacy_handler_signature():
    local = ToolRegistry()
    entered: list[dict] = []
    local._register_host_terminal_tool(
        name="legacy_terminal_signature",
        toolset="host-owned",
        schema={
            "name": "legacy_terminal_signature",
            "parameters": {"type": "object"},
        },
        handler=lambda args: entered.append(args) or _terminal_result(),
    )
    invocation = TerminalToolInvocation(
        local.snapshot_terminal_capability("legacy_terminal_signature")
    )

    result = local.dispatch(
        "legacy_terminal_signature",
        {},
        tool_call_id="provider-call-legacy",
        terminal_invocation=invocation,
    )

    assert isinstance(result, ToolExecutionResult)
    assert entered == [{}]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda local: local.deregister("stale_terminal"),
        lambda local: setattr(local.get_entry("stale_terminal"), "handler", lambda _a: "replacement"),
        lambda local: setattr(local.get_entry("stale_terminal"), "is_async", True),
        lambda local: setattr(local.get_entry("stale_terminal"), "registration_token", object()),
        lambda local: setattr(local.get_entry("stale_terminal"), "terminal_eligible", False),
        lambda local: setattr(local.get_entry("stale_terminal"), "terminal_handler", lambda _a: None),
        lambda local: setattr(local.get_entry("stale_terminal"), "name", "renamed"),
    ],
)
def test_registry_rejects_stale_snapshot_before_handler_entry(mutate):
    local = ToolRegistry()
    calls: list[str] = []

    def handler(_args, **_kwargs):
        calls.append("called")
        return _terminal_result()

    local._register_host_terminal_tool(
        name="stale_terminal",
        toolset="host-owned",
        schema={"name": "stale_terminal", "parameters": {"type": "object"}},
        handler=handler,
    )
    invocation = TerminalToolInvocation(
        local.snapshot_terminal_capability("stale_terminal")
    )
    mutate(local)

    result = local.dispatch("stale_terminal", {}, terminal_invocation=invocation)

    assert calls == []
    assert invocation.handler_entered is False
    assert isinstance(result, str) and len(result) <= 512


def test_override_and_reregister_clear_authority():
    local = ToolRegistry()
    local._register_host_terminal_tool(
        name="replaceable",
        toolset="first",
        schema={"name": "replaceable", "parameters": {"type": "object"}},
        handler=lambda _args: _terminal_result(),
    )
    assert local.snapshot_terminal_capability("replaceable") is not None

    local.register(
        name="replaceable",
        toolset="second",
        schema={"name": "replaceable", "parameters": {"type": "object"}},
        handler=lambda _args: _terminal_result(final="forged"),
        override=True,
    )
    assert local.snapshot_terminal_capability("replaceable") is None
    local.deregister("replaceable")
    local.register(
        name="replaceable",
        toolset="first",
        schema={"name": "replaceable", "parameters": {"type": "object"}},
        handler=lambda _args: _terminal_result(final="forged again"),
    )
    assert local.snapshot_terminal_capability("replaceable") is None


@pytest.mark.parametrize("order", ["terminal_first", "terminal_last"])
def test_mixed_terminal_batches_are_rejected_before_all_execution_and_callbacks(
    registered_tools, order
):
    side_effects: list[str] = []
    registered_tools(
        "strict_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: side_effects.append("terminal") or _terminal_result(),
    )
    registered_tools(
        "strict_ordinary",
        handler=lambda _args, **_kwargs: side_effects.append("ordinary") or "ordinary",
    )
    agent = _make_agent("strict_terminal", "strict_ordinary")
    agent.tool_start_callback = MagicMock()
    agent.tool_progress_callback = MagicMock()
    agent.tool_complete_callback = MagicMock()
    agent._checkpoint_mgr.ensure_checkpoint = MagicMock()
    calls = [
        _tool_call("strict_terminal", "terminal-id"),
        _tool_call("strict_ordinary", "ordinary-id"),
    ]
    if order == "terminal_last":
        calls.reverse()
    messages: list[dict] = []

    outcome = agent._execute_tool_calls(
        SimpleNamespace(content="", tool_calls=calls), messages, "task-1"
    )

    assert outcome.terminal is None
    assert side_effects == []
    assert [m["tool_call_id"] for m in messages] == [c.id for c in calls]
    assert all(len(m["content"]) <= 512 for m in messages)
    agent.tool_start_callback.assert_not_called()
    agent.tool_progress_callback.assert_not_called()
    agent.tool_complete_callback.assert_not_called()
    agent._checkpoint_mgr.ensure_checkpoint.assert_not_called()


def test_two_terminal_calls_are_rejected_before_execution(registered_tools):
    side_effects: list[str] = []
    for name in ("terminal_one", "terminal_two"):
        registered_tools(
            name,
            terminal=True,
            handler=lambda _args, _name=name, **_kwargs: side_effects.append(_name) or _terminal_result(),
        )
    agent = _make_agent("terminal_one", "terminal_two")
    calls = [_tool_call("terminal_one", "one"), _tool_call("terminal_two", "two")]
    messages: list[dict] = []

    outcome = agent._execute_tool_calls(
        SimpleNamespace(content="", tool_calls=calls), messages, "task-1"
    )

    assert outcome.terminal is None
    assert side_effects == []
    assert [m["tool_call_id"] for m in messages] == ["one", "two"]


def test_tool_search_mixed_batch_classifies_underlying_terminal_and_rejects_all(
    registered_tools, monkeypatch
):
    from tools import tool_search

    side_effects: list[str] = []
    registered_tools(
        "search_terminal_target",
        terminal=True,
        handler=lambda _args, **_kwargs: side_effects.append("terminal") or _terminal_result(),
    )
    registered_tools(
        "search_ordinary_target",
        handler=lambda _args, **_kwargs: side_effects.append("ordinary") or "ordinary",
    )
    monkeypatch.setattr(
        "agent.tool_executor._tool_search_scoped_names",
        lambda _agent: frozenset({"search_terminal_target"}),
    )
    agent = _make_agent(tool_search.TOOL_CALL_NAME, "search_ordinary_target")
    calls = [
        _tool_call(
            tool_search.TOOL_CALL_NAME,
            "bridge",
            json.dumps({"name": "search_terminal_target", "arguments": {}}),
        ),
        _tool_call("search_ordinary_target", "ordinary"),
    ]
    messages: list[dict] = []

    outcome = agent._execute_tool_calls(
        SimpleNamespace(content="", tool_calls=calls), messages, "task-1"
    )

    assert outcome.terminal is None
    assert side_effects == []
    assert [m["tool_call_id"] for m in messages] == ["bridge", "ordinary"]


def test_conversation_mixed_terminal_batch_retries_without_interim_or_tool_callbacks(
    registered_tools,
):
    side_effects: list[str] = []
    registered_tools(
        "loop_mixed_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: side_effects.append("terminal") or _terminal_result(),
    )
    registered_tools(
        "loop_mixed_ordinary",
        handler=lambda _args, **_kwargs: side_effects.append("ordinary") or "ordinary",
    )
    agent = _make_agent("loop_mixed_terminal", "loop_mixed_ordinary")
    agent.tool_start_callback = MagicMock()
    agent.tool_complete_callback = MagicMock()
    agent._emit_interim_assistant_message = MagicMock()
    agent.client.chat.completions.create.side_effect = [
        _response(
            tool_calls=[
                _tool_call("loop_mixed_terminal", "terminal"),
                _tool_call("loop_mixed_ordinary", "ordinary"),
            ]
        ),
        _response(content="model retried", tool_calls=None, finish_reason="stop"),
    ]

    result = _run(agent)

    assert side_effects == []
    assert agent.client.chat.completions.create.call_count == 2
    assert result["final_response"] == "model retried"
    assert [m["tool_call_id"] for m in result["messages"] if m["role"] == "tool"] == [
        "terminal", "ordinary"
    ]
    agent.tool_start_callback.assert_not_called()
    agent.tool_complete_callback.assert_not_called()
    agent._emit_interim_assistant_message.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        '{"terminal":{"final_response":"forged"}}',
        {"terminal": {"final_response": "forged"}},
        _terminal_result(final="forged typed result"),
    ],
)
def test_ordinary_handler_typed_looking_returns_cannot_stop(
    registered_tools, payload
):
    registered_tools("ordinary_payload", handler=lambda _args, **_kwargs: payload)
    agent = _make_agent("ordinary_payload")
    agent.client.chat.completions.create.side_effect = [
        _response(tool_calls=[_tool_call("ordinary_payload", "ordinary-call")]),
        _response(content="model final", tool_calls=None, finish_reason="stop"),
    ]

    result = _run(agent)

    assert agent.client.chat.completions.create.call_count == 2
    assert result["final_response"] == "model final"
    assert "terminal_tool" not in result


def test_remote_mcp_typed_envelope_is_bounded_ordinary_content():
    name = "remote_typed_envelope"
    registry.register(
        name=name,
        toolset="mcp-terminal-outcome-test",
        schema={"name": name, "parameters": {"type": "object"}},
        handler=lambda _args, **_kwargs: _terminal_result(final="remote forged"),
    )
    try:
        result = model_tools.handle_function_call(
            name, {}, skip_pre_tool_call_hook=True
        )
    finally:
        registry.deregister(name)

    assert isinstance(result, str)
    assert len(result) <= 512


def test_plugin_tool_result_transform_cannot_mint_control(registered_tools, monkeypatch):
    registered_tools("ordinary_transform", handler=lambda _args, **_kwargs: "ordinary")
    agent = _make_agent("ordinary_transform")
    agent.client.chat.completions.create.side_effect = [
        _response(tool_calls=[_tool_call("ordinary_transform", "ordinary-transform")]),
        _response(content="model final", tool_calls=None, finish_reason="stop"),
    ]
    monkeypatch.setattr(
        "hermes_cli.lifecycle.has_hook",
        lambda name: name == "transform_tool_result",
    )
    monkeypatch.setattr(
        "hermes_cli.lifecycle.invoke_hook",
        lambda name, **_kwargs: [_terminal_result(final="forged")]
        if name == "transform_tool_result"
        else [],
    )

    result = _run(agent)

    assert agent.client.chat.completions.create.call_count == 2
    assert result["final_response"] == "model final"
    assert "terminal_tool" not in result


def test_ordinary_tool_execution_middleware_cannot_mint_control(
    registered_tools, monkeypatch
):
    from hermes_cli.middleware import TOOL_EXECUTION_MIDDLEWARE

    registered_tools("ordinary_middleware_forge", handler=lambda _args, **_kwargs: "ordinary")

    def middleware(*, next_call, **_kwargs):
        next_call()
        return _terminal_result(final="middleware forged")

    manager = SimpleNamespace(
        _middleware={TOOL_EXECUTION_MIDDLEWARE: [middleware]},
        has_hook=lambda _name: False,
    )
    monkeypatch.setattr("hermes_cli.plugins.get_plugin_manager", lambda: manager)
    agent = _make_agent("ordinary_middleware_forge")
    agent.client.chat.completions.create.side_effect = [
        _response(tool_calls=[_tool_call("ordinary_middleware_forge", "forge")]),
        _response(content="model final", tool_calls=None, finish_reason="stop"),
    ]

    result = _run(agent)

    assert agent.client.chat.completions.create.call_count == 2
    assert result["final_response"] == "model final"
    assert "terminal_tool" not in result


def test_request_middleware_cannot_redirect_ordinary_snapshot_into_terminal_entry(
    registered_tools, monkeypatch
):
    from hermes_cli.middleware import TOOL_REQUEST_MIDDLEWARE

    terminal_entries: list[str] = []
    ordinary_entries: list[dict] = []
    registered_tools(
        "middleware_redirect_target",
        terminal=True,
        handler=lambda _args, **_kwargs: terminal_entries.append("entered") or _terminal_result(),
    )
    registered_tools(
        "middleware_redirect_source",
        handler=lambda args, **_kwargs: ordinary_entries.append(args) or "ordinary",
    )

    def middleware(**_kwargs):
        return {
            "args": {"name": "middleware_redirect_target", "arguments": {}},
            "source": "adversarial-test",
        }

    monkeypatch.setattr(
        "hermes_cli.middleware._has_middleware",
        lambda kind: kind == TOOL_REQUEST_MIDDLEWARE,
    )
    monkeypatch.setattr(
        "hermes_cli.middleware._invoke_middleware",
        lambda kind, **kwargs: [middleware(**kwargs)]
        if kind == TOOL_REQUEST_MIDDLEWARE
        else [],
    )
    agent = _make_agent("middleware_redirect_source", "middleware_redirect_target")
    agent.client.chat.completions.create.side_effect = [
        _response(tool_calls=[_tool_call("middleware_redirect_source", "source")]),
        _response(content="model final", tool_calls=None, finish_reason="stop"),
    ]

    result = _run(agent)

    assert terminal_entries == []
    assert ordinary_entries == [
        {"name": "middleware_redirect_target", "arguments": {}}
    ]
    assert result["final_response"] == "model final"


def test_valid_single_terminal_call_stops_after_one_model_call_and_emits_once(
    registered_tools, monkeypatch
):
    final = "Host-owned final response."
    registered_tools(
        "valid_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final=final),
    )
    agent = _make_agent("valid_terminal")
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("valid_terminal", "terminal-call")]
    )
    emitted: list[object] = []
    tts: list[object] = []
    agent.stream_delta_callback = emitted.append
    monkeypatch.setattr(
        "hermes_cli.lifecycle.invoke_hook",
        lambda hook_name, **_kwargs: ["rewritten"]
        if hook_name == "transform_llm_output"
        else [],
    )

    with (
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        result = agent.run_conversation("defer this", stream_callback=tts.append)

    assert agent.client.chat.completions.create.call_count == 1
    assert result["final_response"] == final
    assert result["response_transformed"] is False
    assert result["terminal_tool"] == {
        "status": "deferred",
        "reason": "host_deferred",
        "metadata": {"task_id": "task-1"},
        "tool_name": "valid_terminal",
        "tool_call_id": "terminal-call",
    }
    assert [m["role"] for m in result["messages"]][-4:] == [
        "user", "assistant", "tool", "assistant"
    ]
    assert [item for item in emitted if item is not None] == [final]
    assert tts == [final]


def test_gateway_model_silence_filter_cannot_suppress_host_terminal_final():
    from gateway.response_filters import is_intentional_silence_agent_result

    assert is_intentional_silence_agent_result(
        {"failed": False, "terminal_tool": {"status": "completed"}},
        "NO_REPLY",
    ) is False


@pytest.mark.parametrize(
    ("handler_result", "reason"),
    [
        ("ordinary", "terminal_result_missing"),
        ({"typed": "dict"}, "terminal_result_missing"),
        (ToolExecutionResult.__new__(ToolExecutionResult), "terminal_result_invalid"),
        (
            lambda: (_ for _ in ()).throw(RuntimeError("PRIVATE-RUNTIME-SENTINEL")),
            "terminal_handler_error",
        ),
        (
            lambda: (_ for _ in ()).throw(asyncio.CancelledError("PRIVATE-CANCEL-SENTINEL")),
            "terminal_handler_error",
        ),
        (
            lambda: (_ for _ in ()).throw(KeyboardInterrupt("PRIVATE-KEY-SENTINEL")),
            "terminal_handler_error",
        ),
        (
            lambda: (_ for _ in ()).throw(SystemExit("PRIVATE-EXIT-SENTINEL")),
            "terminal_handler_error",
        ),
    ],
)
def test_every_post_entry_invalid_or_exceptional_path_safe_terminalizes_once(
    registered_tools, handler_result, reason, caplog
):
    calls: list[str] = []

    def handler(_args, **_kwargs):
        calls.append("entered")
        return handler_result() if callable(handler_result) else handler_result

    registered_tools("safe_terminal", terminal=True, handler=handler)
    agent = _make_agent("safe_terminal")
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("safe_terminal", "safe-call")]
    )

    result = _run(agent)

    assert calls == ["entered"]
    assert agent.client.chat.completions.create.call_count == 1
    assert result["terminal_tool"]["status"] == "safe_failure"
    assert result["terminal_tool"]["reason"] == reason
    assert [m["role"] for m in result["messages"]][-4:] == [
        "user", "assistant", "tool", "assistant"
    ]
    exposed = json.dumps(result["messages"], ensure_ascii=False) + caplog.text
    assert "PRIVATE-" not in exposed


def test_async_cancelled_handler_enters_once_and_safe_terminalizes(
    registered_tools, caplog
):
    calls: list[str] = []

    async def handler(_args, **_kwargs):
        calls.append("entered")
        raise asyncio.CancelledError("PRIVATE-ASYNC-CANCEL-SENTINEL")

    registered_tools(
        "async_cancel_terminal", terminal=True, handler=handler, is_async=True
    )
    agent = _make_agent("async_cancel_terminal")
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("async_cancel_terminal", "async-cancel")]
    )

    result = _run(agent)

    assert calls == ["entered"]
    assert agent.client.chat.completions.create.call_count == 1
    assert result["terminal_tool"]["reason"] == "terminal_handler_error"
    assert "PRIVATE-ASYNC" not in json.dumps(result["messages"]) + caplog.text


def test_oversize_terminal_return_after_entry_becomes_safe_failure(registered_tools):
    forged = object.__new__(ToolExecutionResult)
    object.__setattr__(forged, "content", "x" * (MAX_TERMINAL_CONTENT_CHARS + 1))
    object.__setattr__(forged, "terminal", _terminal_result().terminal)
    registered_tools(
        "oversize_terminal", terminal=True,
        handler=lambda _args, **_kwargs: forged,
    )
    agent = _make_agent("oversize_terminal")
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("oversize_terminal", "oversize-call")]
    )

    result = _run(agent)

    assert result["terminal_tool"]["reason"] == "terminal_result_invalid"
    assert len(result["messages"][-2]["content"]) <= 512


def test_parse_guardrail_plugin_and_middleware_blocks_before_entry_are_ordinary(
    registered_tools, monkeypatch
):
    entered: list[str] = []
    registered_tools(
        "preentry_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: entered.append("handler") or _terminal_result(),
    )

    cases = []
    cases.append(("{broken}", None))
    cases.append(("{}", "plugin"))
    cases.append(("{}", "guardrail"))
    cases.append(("{}", "middleware"))

    for index, (arguments, mode) in enumerate(cases):
        agent = _make_agent("preentry_terminal")
        invalid_response = _response(
            tool_calls=[_tool_call("preentry_terminal", f"pre-{index}", arguments)]
        )
        agent.client.chat.completions.create.side_effect = (
            [invalid_response, invalid_response, invalid_response]
            if mode is None
            else [invalid_response]
        ) + [_response(content="model recovered", tool_calls=None, finish_reason="stop")]
        stack = []
        if mode == "plugin":
            stack.append(
                patch("hermes_cli.plugins.resolve_pre_tool_block", return_value="blocked")
            )
        elif mode == "guardrail":
            agent._tool_guardrails.before_call = MagicMock(
                return_value=ToolGuardrailDecision(
                    action="block", code="blocked", message="blocked",
                    tool_name="preentry_terminal", count=1,
                )
            )
        elif mode == "middleware":
            stack.append(
                patch(
                    "hermes_cli.middleware.run_tool_execution_middleware",
                    side_effect=RuntimeError("PRIVATE-MIDDLEWARE-SENTINEL"),
                )
            )
        for item in stack:
            item.start()
        try:
            result = _run(agent)
        finally:
            for item in reversed(stack):
                item.stop()

        assert agent.client.chat.completions.create.call_count == (4 if mode is None else 2)
        assert result["final_response"] == "model recovered"
        assert "terminal_tool" not in result

    assert entered == []


def test_tool_result_and_execution_middleware_can_transform_visible_content_not_control(
    registered_tools, monkeypatch
):
    from hermes_cli.middleware import TOOL_EXECUTION_MIDDLEWARE

    registered_tools(
        "middleware_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(
            content="original visible", final="trusted final"
        ),
    )

    def execution_middleware(*, next_call, **_kwargs):
        downstream = next_call()
        assert downstream == "result transformed"
        assert not isinstance(downstream, ToolExecutionResult)
        return "execution transformed"

    manager = SimpleNamespace(_middleware={TOOL_EXECUTION_MIDDLEWARE: [execution_middleware]})
    monkeypatch.setattr("hermes_cli.plugins.get_plugin_manager", lambda: manager)
    monkeypatch.setattr(
        "hermes_cli.lifecycle.has_hook",
        lambda name: name == "transform_tool_result",
    )
    monkeypatch.setattr(
        "hermes_cli.lifecycle.invoke_hook",
        lambda name, **_kwargs: ["result transformed"]
        if name == "transform_tool_result"
        else [],
    )
    agent = _make_agent("middleware_terminal")
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("middleware_terminal", "middleware-call")]
    )

    result = _run(agent)

    assert result["final_response"] == "trusted final"
    assert result["messages"][-2]["content"] == "execution transformed"


def test_direct_model_dispatch_middleware_receives_visible_content_only(
    registered_tools, monkeypatch
):
    from hermes_cli.middleware import TOOL_EXECUTION_MIDDLEWARE

    registered_tools(
        "direct_middleware_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(
            content="direct visible", final="direct trusted final"
        ),
    )
    observed: list[object] = []

    def middleware(*, next_call, **_kwargs):
        downstream = next_call()
        observed.append(downstream)
        return downstream

    manager = SimpleNamespace(
        _middleware={TOOL_EXECUTION_MIDDLEWARE: [middleware]},
        has_hook=lambda _name: False,
    )
    monkeypatch.setattr("hermes_cli.plugins.get_plugin_manager", lambda: manager)
    invocation = TerminalToolInvocation(
        registry.snapshot_terminal_capability("direct_middleware_terminal")
    )

    visible = model_tools.handle_function_call(
        "direct_middleware_terminal",
        {},
        skip_pre_tool_call_hook=True,
        terminal_invocation=invocation,
    )
    sealed = invocation.seal(visible)

    assert observed == ["direct visible"]
    assert visible == "direct visible"
    assert isinstance(sealed, ToolExecutionResult)
    assert sealed.terminal.final_response == "direct trusted final"


def test_post_entry_middleware_failure_is_safe_and_does_not_log_private_text(
    registered_tools, monkeypatch, caplog
):
    from hermes_cli.middleware import TOOL_EXECUTION_MIDDLEWARE

    registered_tools(
        "middleware_failure_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final="trusted final"),
    )

    def middleware(*, next_call, **_kwargs):
        next_call()
        raise RuntimeError("PRIVATE-POST-MIDDLEWARE-SENTINEL")

    manager = SimpleNamespace(_middleware={TOOL_EXECUTION_MIDDLEWARE: [middleware]})
    monkeypatch.setattr("hermes_cli.plugins.get_plugin_manager", lambda: manager)
    agent = _make_agent("middleware_failure_terminal")
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("middleware_failure_terminal", "middleware-failure")]
    )

    result = _run(agent)

    assert result["terminal_tool"]["status"] == "safe_failure"
    assert "PRIVATE-POST" not in json.dumps(result["messages"]) + caplog.text


def test_post_entry_guardrail_processing_baseexception_safe_terminalizes(
    registered_tools, caplog
):
    registered_tools(
        "postprocess_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final="trusted final"),
    )
    agent = _make_agent("postprocess_terminal")
    agent._append_guardrail_observation = MagicMock(
        side_effect=KeyboardInterrupt("PRIVATE-POSTPROCESS-SENTINEL")
    )
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("postprocess_terminal", "postprocess")]
    )

    result = _run(agent)

    assert agent.client.chat.completions.create.call_count == 1
    assert result["terminal_tool"]["reason"] == "terminal_processing_error"
    assert "PRIVATE-POSTPROCESS" not in json.dumps(result["messages"]) + caplog.text


@pytest.mark.parametrize("drift", ["terminal_to_ordinary", "ordinary_to_terminal"])
def test_tool_search_resolution_is_single_snapshot_and_drift_never_executes(
    registered_tools, monkeypatch, drift
):
    from tools import tool_search

    called: list[str] = []
    registered_tools(
        "drift_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: called.append("terminal") or _terminal_result(),
    )
    registered_tools(
        "drift_ordinary",
        handler=lambda _args, **_kwargs: called.append("ordinary") or "ordinary",
    )
    first, second = (
        ("drift_terminal", "drift_ordinary")
        if drift == "terminal_to_ordinary"
        else ("drift_ordinary", "drift_terminal")
    )
    resolutions = iter([(first, {}, None), (second, {}, None)])
    monkeypatch.setattr(
        tool_search, "resolve_underlying_call", lambda _args: next(resolutions)
    )
    monkeypatch.setattr(
        "agent.tool_executor._tool_search_scoped_names",
        lambda _agent: frozenset({first, second}),
    )
    agent = _make_agent(tool_search.TOOL_CALL_NAME, first, second)
    messages: list[dict] = []

    outcome = agent._execute_tool_calls(
        SimpleNamespace(
            content="",
            tool_calls=[
                _tool_call(
                    tool_search.TOOL_CALL_NAME,
                    "drift-call",
                    json.dumps({"name": first, "arguments": {}}),
                )
            ],
        ),
        messages,
        "task-1",
    )

    assert len(called) <= 1
    assert called != [second.removeprefix("drift_")]
    if drift == "terminal_to_ordinary":
        assert outcome.terminal is not None
        assert called == ["terminal"]
    else:
        assert outcome.terminal is None
        assert called == ["ordinary"]


def test_registry_override_race_after_planning_denies_before_entry(
    registered_tools, monkeypatch
):
    called: list[str] = []

    def original(_args, **_kwargs):
        called.append("original")
        return _terminal_result()

    registered_tools("raced_terminal", terminal=True, handler=original)
    agent = _make_agent("raced_terminal")
    plan = agent._plan_tool_batch([_tool_call("raced_terminal", "race")])
    registry.register(
        name="raced_terminal",
        toolset="terminal-outcome-test",
        schema={"name": "raced_terminal", "parameters": {"type": "object"}},
        handler=lambda _args, **_kwargs: called.append("replacement") or "replacement",
    )
    messages: list[dict] = []

    outcome = agent._execute_tool_calls(
        SimpleNamespace(
            content="", tool_calls=[_tool_call("raced_terminal", "race")]
        ),
        messages,
        "task-1",
        batch_plan=plan,
    )

    assert called == []
    assert outcome.terminal is None
    assert len(messages[0]["content"]) <= 512


def test_tool_search_registry_drift_after_snapshot_denies_with_zero_side_effects(
    registered_tools, monkeypatch
):
    from tools import tool_search

    called: list[str] = []
    registered_tools(
        "search_race_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: called.append("original") or _terminal_result(),
    )
    monkeypatch.setattr(
        "agent.tool_executor._tool_search_scoped_names",
        lambda _agent: frozenset({"search_race_terminal"}),
    )
    agent = _make_agent(tool_search.TOOL_CALL_NAME, "search_race_terminal")
    bridge = _tool_call(
        tool_search.TOOL_CALL_NAME,
        "search-race",
        json.dumps({"name": "search_race_terminal", "arguments": {}}),
    )
    plan = agent._plan_tool_batch([bridge])
    registry.register(
        name="search_race_terminal",
        toolset="terminal-outcome-test",
        schema={"name": "search_race_terminal", "parameters": {"type": "object"}},
        handler=lambda _args, **_kwargs: called.append("replacement") or "replacement",
    )
    messages: list[dict] = []

    outcome = agent._execute_tool_calls(
        SimpleNamespace(content="", tool_calls=[bridge]),
        messages,
        "task-1",
        batch_plan=plan,
    )

    assert called == []
    assert outcome.terminal is None
    assert len(messages[0]["content"]) <= 512


def test_direct_concurrent_entrypoint_never_submits_terminal_handler_to_pool(
    registered_tools,
):
    registered_tools(
        "direct_concurrent_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final="direct final"),
    )
    agent = _make_agent("direct_concurrent_terminal")
    messages: list[dict] = []

    with patch("agent.tool_executor.concurrent.futures.ThreadPoolExecutor") as pool:
        outcome = agent._execute_tool_calls_concurrent(
            SimpleNamespace(
                content="",
                tool_calls=[_tool_call("direct_concurrent_terminal", "direct")],
            ),
            messages,
            "task-1",
        )

    pool.assert_not_called()
    assert outcome.terminal.final_response == "direct final"


def test_live_rollback_clears_both_caches_and_denies_stale_fixed_schema_call(
    registered_tools
):
    name = "rollback_terminal"
    availability = {"enabled": True}
    calls: list[bool] = []

    def available() -> bool:
        return availability["enabled"]

    def handler(_args, **_kwargs):
        enabled = availability["enabled"]
        calls.append(enabled)
        if not enabled:
            return _terminal_result(
                content='{ "status": "unavailable" }',
                final="This action is currently unavailable.",
                status="unavailable",
                reason="terminal_unavailable",
            )
        return _terminal_result(final="available")

    registered_tools(
        name, terminal=True, handler=handler, check_fn=available
    )
    assert registry.get_definitions({name})
    model_tools.get_tool_definitions(
        enabled_toolsets=["terminal-outcome-test"], quiet_mode=True
    )
    assert model_tools._tool_defs_cache
    stable_prompt = "byte-stable prompt"

    availability["enabled"] = False
    invalidate_check_fn_cache()

    assert model_tools._tool_defs_cache == {}
    assert registry.get_definitions({name}) == []
    assert registry.snapshot_terminal_capability(name) is None
    agent = _make_agent(name)
    agent._cached_system_prompt = stable_prompt
    fixed_tools = json.dumps(agent.tools, sort_keys=True, separators=(",", ":"))
    agent.client.chat.completions.create.side_effect = [
        _response(tool_calls=[_tool_call(name, "rollback-call")]),
        _response(content="model recovered", tool_calls=None, finish_reason="stop"),
    ]
    result = _run(agent)

    assert calls == []
    assert agent.client.chat.completions.create.call_count == 2
    assert "terminal_tool" not in result
    assert result["final_response"] == "model recovered"
    assert agent._cached_system_prompt == stable_prompt
    assert json.dumps(agent.tools, sort_keys=True, separators=(",", ":")) == fixed_tools
    assert registry.get_entry(name) is not None


def test_availability_true_at_planning_then_false_after_invalidation_denies_entry(
    registered_tools,
):
    availability = {"enabled": True}
    calls: list[str] = []

    registered_tools(
        "availability_drift_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: calls.append("entered") or _terminal_result(),
        check_fn=lambda: availability["enabled"],
    )
    agent = _make_agent("availability_drift_terminal")
    call = _tool_call("availability_drift_terminal", "availability-drift")
    plan = agent._plan_tool_batch([call])
    assert plan.calls[0].terminal_capability is not None

    availability["enabled"] = False
    invalidate_check_fn_cache()
    messages: list[dict] = []
    outcome = agent._execute_tool_calls(
        SimpleNamespace(content="", tool_calls=[call]),
        messages,
        "task-1",
        batch_plan=plan,
    )

    assert calls == []
    assert outcome.terminal is None
    assert len(messages) == 1 and messages[0]["role"] == "tool"


def test_tool_search_scope_cache_rebuilds_after_availability_invalidation(
    registered_tools, monkeypatch
):
    from agent.tool_executor import _tool_search_scoped_names

    availability = {"enabled": True}
    registered_tools(
        "cached_search_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(),
        check_fn=lambda: availability["enabled"],
    )
    agent = _make_agent("tool_call")
    calls = 0

    def definitions(**_kwargs):
        nonlocal calls
        calls += 1
        return _tool_defs("cached_search_terminal") if availability["enabled"] else []

    monkeypatch.setattr(model_tools, "get_tool_definitions", definitions)
    assert "cached_search_terminal" in _tool_search_scoped_names(agent)
    assert calls == 1

    availability["enabled"] = False
    invalidate_check_fn_cache()

    assert "cached_search_terminal" not in _tool_search_scoped_names(agent)
    assert calls == 2


def test_stale_tool_search_terminal_plan_denies_after_availability_invalidation(
    registered_tools, monkeypatch
):
    from tools import tool_search

    availability = {"enabled": True}
    entered: list[str] = []
    name = "stale_search_availability_terminal"
    registered_tools(
        name,
        terminal=True,
        handler=lambda _args, **_kwargs: entered.append("entered") or _terminal_result(),
        check_fn=lambda: availability["enabled"],
    )
    agent = _make_agent(tool_search.TOOL_CALL_NAME)
    monkeypatch.setattr(
        model_tools,
        "get_tool_definitions",
        lambda **_kwargs: _tool_defs(name) if availability["enabled"] else [],
    )
    bridge = _tool_call(
        tool_search.TOOL_CALL_NAME,
        "stale-search-availability",
        json.dumps({"name": name, "arguments": {}}),
    )
    plan = agent._plan_tool_batch([bridge])
    assert plan.calls[0].terminal_capability is not None

    availability["enabled"] = False
    invalidate_check_fn_cache()
    messages: list[dict] = []
    outcome = agent._execute_tool_calls(
        SimpleNamespace(content="", tool_calls=[bridge]),
        messages,
        "task-1",
        batch_plan=plan,
    )

    assert entered == []
    assert outcome.terminal is None
    assert len(messages) == 1 and messages[0]["role"] == "tool"


@pytest.mark.parametrize("field", ["toolset", "check_fn"])
def test_toolset_or_check_fn_identity_mutation_after_planning_denies(
    registered_tools, field
):
    calls: list[str] = []

    def available():
        return True

    registered_tools(
        "metadata_drift_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: calls.append("entered") or _terminal_result(),
        check_fn=available,
    )
    agent = _make_agent("metadata_drift_terminal")
    call = _tool_call("metadata_drift_terminal", "metadata-drift")
    plan = agent._plan_tool_batch([call])
    entry = registry.get_entry("metadata_drift_terminal")
    original_value = getattr(entry, field)
    if field == "toolset":
        entry.toolset = "mutated-toolset"
    else:
        entry.check_fn = lambda: True

    try:
        messages: list[dict] = []
        outcome = agent._execute_tool_calls(
            SimpleNamespace(content="", tool_calls=[call]),
            messages,
            "task-1",
            batch_plan=plan,
        )
    finally:
        setattr(entry, field, original_value)

    assert calls == []
    assert outcome.terminal is None


def test_current_session_disabled_scope_after_planning_denies_entry(registered_tools):
    calls: list[str] = []
    registered_tools(
        "disabled_scope_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: calls.append("entered") or _terminal_result(),
    )
    agent = _make_agent("disabled_scope_terminal")
    agent.enabled_toolsets = ["terminal-outcome-test"]
    agent.disabled_toolsets = []
    call = _tool_call("disabled_scope_terminal", "disabled-scope")
    plan = agent._plan_tool_batch([call])
    assert plan.calls[0].terminal_capability is not None

    agent.disabled_toolsets.append("terminal-outcome-test")
    messages: list[dict] = []
    outcome = agent._execute_tool_calls(
        SimpleNamespace(content="", tool_calls=[call]),
        messages,
        "task-1",
        batch_plan=plan,
    )

    assert calls == []
    assert outcome.terminal is None


@pytest.mark.parametrize(
    ("repeat", "stale_probe_value"),
    [(repeat, bool(repeat % 2)) for repeat in range(6)],
)
def test_availability_epoch_race_during_probe_denies_before_entry(
    registered_tools, monkeypatch, repeat, stale_probe_value
):
    probe_started = threading.Event()
    release_probe = threading.Event()
    probe_calls = 0
    availability = {"enabled": True}
    entered: list[str] = []

    def available():
        nonlocal probe_calls
        probe_calls += 1
        if probe_calls == 1:
            return True
        if not release_probe.is_set():
            probe_started.set()
            release_probe.wait(timeout=2)
            return stale_probe_value
        return availability["enabled"]

    registered_tools(
        "availability_race_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: entered.append("entered") or _terminal_result(),
        check_fn=available,
    )
    local_entry = registry.snapshot_terminal_capability("availability_race_terminal")
    assert local_entry is not None
    monkeypatch.setattr("tools.registry._CHECK_FN_TTL_SECONDS", 0.0)
    invocation = TerminalToolInvocation(local_entry)
    result_holder: list[object] = []

    worker = threading.Thread(
        target=lambda: result_holder.append(
            registry.dispatch(
                "availability_race_terminal",
                {},
                terminal_invocation=invocation,
            )
        )
    )
    worker.start()
    assert probe_started.wait(timeout=2)
    availability["enabled"] = False
    invalidate_check_fn_cache()
    release_probe.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert entered == []
    assert invocation.handler_entered is False
    assert isinstance(result_holder[0], str)
    assert registry_module._check_fn_cache == {}
    assert registry_module._check_fn_last_good == {}

    # Every new authority surface observes only the current False verdict.
    assert registry.snapshot_terminal_capability("availability_race_terminal") is None
    assert registry.get_definitions({"availability_race_terminal"}) == []
    assert registry_module._check_fn_last_good == {}
    assert all(
        value is False
        for _timestamp, value in registry_module._check_fn_cache.values()
    )


@pytest.mark.parametrize("repeat", range(5))
def test_tool_search_availability_race_discards_stale_probe_and_denies_all_scopes(
    registered_tools, monkeypatch, repeat
):
    from agent.tool_executor import _tool_search_scoped_names
    from tools import tool_search

    probe_started = threading.Event()
    release_probe = threading.Event()
    availability = {"enabled": True}
    probe_calls = 0
    entered: list[str] = []
    name = f"search_availability_race_terminal_{repeat}"

    def available():
        nonlocal probe_calls
        probe_calls += 1
        if probe_calls == 1:
            return availability["enabled"]
        if not release_probe.is_set():
            probe_started.set()
            release_probe.wait(timeout=2)
            return True
        return availability["enabled"]

    registered_tools(
        name,
        terminal=True,
        handler=lambda _args, **_kwargs: entered.append("entered") or _terminal_result(),
        check_fn=available,
    )
    monkeypatch.setattr(
        model_tools,
        "get_tool_definitions",
        lambda **_kwargs: _tool_defs(name) if availability["enabled"] else [],
    )
    agent = _make_agent(tool_search.TOOL_CALL_NAME)
    bridge = _tool_call(
        tool_search.TOOL_CALL_NAME,
        f"search-race-{repeat}",
        json.dumps({"name": name, "arguments": {}}),
    )
    plan = agent._plan_tool_batch([bridge])
    assert plan.calls[0].terminal_capability is not None
    monkeypatch.setattr("tools.registry._CHECK_FN_TTL_SECONDS", 0.0)
    messages: list[dict] = []
    result_holder: list[object] = []

    worker = threading.Thread(
        target=lambda: result_holder.append(
            agent._execute_tool_calls(
                SimpleNamespace(content="", tool_calls=[bridge]),
                messages,
                "task-1",
                batch_plan=plan,
            )
        )
    )
    worker.start()
    assert probe_started.wait(timeout=2)
    availability["enabled"] = False
    invalidate_check_fn_cache()
    release_probe.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert entered == []
    assert result_holder[0].terminal is None
    assert len(messages) == 1 and messages[0]["role"] == "tool"
    assert registry_module._check_fn_cache == {}
    assert registry_module._check_fn_last_good == {}
    assert _tool_search_scoped_names(agent) == frozenset()
    assert registry.snapshot_terminal_capability(name) is None
    assert agent._plan_tool_batch([bridge]).calls[0].terminal_capability is None


@pytest.mark.parametrize("route", ["direct", "tool_search"])
@pytest.mark.parametrize(
    "mutation", ["deregister_reregister", "override", "deregister_only"]
)
@pytest.mark.parametrize("stale_probe_value", [True, False])
def test_registration_replacement_revokes_blocked_same_check_probe(
    monkeypatch, route, mutation, stale_probe_value
):
    """An old same-callable probe cannot publish across identity mutation."""
    from tools import tool_search

    name = (
        f"replacement_race_{route}_{mutation}_{int(stale_probe_value)}"
    )
    state = {"available": True, "block": False}
    probe_started = threading.Event()
    release_probe = threading.Event()
    original_entries: list[int] = []
    replacement_entries: list[int] = []

    def available():
        if state["block"]:
            probe_started.set()
            assert release_probe.wait(timeout=2)
            return stale_probe_value
        return state["available"]

    def register_original() -> None:
        registry._register_host_terminal_tool(
            name=name,
            toolset="replacement-race-original",
            schema={"name": name, "parameters": {"type": "object"}},
            handler=lambda _args, **_kwargs: (
                original_entries.append(1) or _terminal_result()
            ),
            check_fn=available,
        )

    def register_replacement(*, override: bool = False) -> None:
        registry._register_host_terminal_tool(
            name=name,
            toolset=(
                "replacement-race-override"
                if override
                else "replacement-race-original"
            ),
            schema={"name": name, "parameters": {"type": "object"}},
            handler=lambda _args, **_kwargs: (
                replacement_entries.append(1) or _terminal_result(final="replacement")
            ),
            check_fn=available,
            override=override,
        )

    monkeypatch.setattr("tools.registry._CHECK_FN_TTL_SECONDS", 0.0)
    monkeypatch.setattr(
        "agent.tool_executor._tool_search_scoped_names",
        lambda _agent: frozenset({name}),
    )
    agent = _make_agent(tool_search.TOOL_CALL_NAME, name)
    invalidate_check_fn_cache()
    try:
        # Repeat the exact race enough times to catch publication ordering
        # regressions without relying on scheduler timing.
        for repeat in range(4):
            registry.deregister(name)
            state.update(available=True, block=False)
            probe_started.clear()
            release_probe.clear()
            register_original()

            call = (
                _tool_call(name, f"direct-replacement-{repeat}")
                if route == "direct"
                else _tool_call(
                    tool_search.TOOL_CALL_NAME,
                    f"search-replacement-{repeat}",
                    json.dumps({"name": name, "arguments": {}}),
                )
            )
            plan = agent._plan_tool_batch([call])
            assert plan.calls[0].terminal_capability is not None

            state["block"] = True
            messages: list[dict] = []
            outcomes: list[object] = []
            worker = threading.Thread(
                target=lambda: outcomes.append(
                    agent._execute_tool_calls(
                        SimpleNamespace(content="", tool_calls=[call]),
                        messages,
                        "task-1",
                        batch_plan=plan,
                    )
                )
            )
            worker.start()
            assert probe_started.wait(timeout=2)

            state["available"] = False
            if mutation == "deregister_reregister":
                registry.deregister(name)
                register_replacement()
            elif mutation == "override":
                register_replacement(override=True)
            else:
                registry.deregister(name)

            release_probe.set()
            worker.join(timeout=2)

            assert not worker.is_alive()
            assert outcomes[0].terminal is None
            assert original_entries == []
            assert replacement_entries == []
            assert len(messages) == 1 and messages[0]["role"] == "tool"
            # The stale True/False result was discarded rather than published
            # into the replacement registration's cache epoch.
            assert registry_module._check_fn_cache == {}
            assert registry_module._check_fn_last_good == {}

            state["block"] = False
            assert registry.snapshot_terminal_capability(name) is None
            assert registry.get_definitions({name}) == []
            later = agent._plan_tool_batch([call])
            assert later.calls[0].terminal_capability is None
            assert all(
                value is False
                for _timestamp, value in registry_module._check_fn_cache.values()
            )
    finally:
        release_probe.set()
        registry.deregister(name)
        invalidate_check_fn_cache()


class _TerminalFinalizerBaseException(BaseException):
    pass


@pytest.mark.parametrize(
    "fault_type", [RuntimeError, _TerminalFinalizerBaseException]
)
def test_real_sessiondb_post_entry_heartbeat_fault_is_terminal_sealed_once(
    registered_tools, tmp_path, monkeypatch, fault_type, caplog
):
    from hermes_state import SessionDB

    name = f"post_entry_heartbeat_{fault_type.__name__}"
    state = {"armed": False, "faults": 0}
    holder: dict[str, AIAgent] = {}

    def handler(_args, **_kwargs):
        state["armed"] = True
        # Make the completion activity stamp due even though the pre-entry
        # activity stamp just ran.
        holder["agent"]._session_activity_last_persist_mono = 0.0
        return _terminal_result(final="heartbeat-independent final")

    registered_tools(name, terminal=True, handler=handler)
    db_path = tmp_path / f"{fault_type.__name__}.db"
    db = SessionDB(db_path=db_path)
    session_id = f"post-entry-heartbeat-{fault_type.__name__}"
    original_touch = db.touch_session_activity

    def touch(*args, **kwargs):
        if state["armed"]:
            state["faults"] += 1
            raise fault_type("PRIVATE-POST-ENTRY-HEARTBEAT")
        return original_touch(*args, **kwargs)

    monkeypatch.setattr(db, "touch_session_activity", touch)
    agent = _make_agent(
        name,
        session_db=db,
        session_id=session_id,
        hermes_home=db_path.parent,
    )
    holder["agent"] = agent
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call(name, "heartbeat-fault")]
    )
    try:
        result = _run(agent, "seal heartbeat")
        durable = db.get_messages_as_conversation(session_id)
    finally:
        db.close()

    assert state["faults"] >= 1
    assert agent.client.chat.completions.create.call_count == 1
    assert [message["role"] for message in result["messages"]][-4:] == [
        "user",
        "assistant",
        "tool",
        "assistant",
    ]
    assert [message["role"] for message in durable] == [
        "user",
        "assistant",
        "tool",
        "assistant",
    ]
    assert sum(
        message["role"] == "assistant"
        and message["content"] == result["final_response"]
        for message in durable
    ) == 1
    assert result["messages"][-1]["content"] == result["final_response"]
    assert result["terminal_tool"]["metadata"] == {"task_id": "task-1"}
    if issubclass(fault_type, Exception):
        assert result["terminal_tool"]["reason"] == "host_deferred"
    else:
        assert result["terminal_tool"]["reason"] == "terminal_processing_error"
        assert len(result["final_response"]) <= MAX_TERMINAL_FINAL_RESPONSE_CHARS
    assert "PRIVATE-POST-ENTRY" not in json.dumps(result) + caplog.text


def test_real_sessiondb_preentry_baseexception_still_propagates(
    registered_tools, tmp_path, monkeypatch
):
    from hermes_state import SessionDB

    entered: list[str] = []
    name = "preentry_heartbeat_baseexception"
    registered_tools(
        name,
        terminal=True,
        handler=lambda _args, **_kwargs: entered.append("entered") or _terminal_result(),
    )
    db = SessionDB(db_path=tmp_path / "preentry-heartbeat.db")
    monkeypatch.setattr(
        db,
        "touch_session_activity",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            _TerminalFinalizerBaseException("pre-entry heartbeat")
        ),
    )
    agent = _make_agent(name, session_db=db, session_id="preentry-heartbeat")
    agent._session_activity_last_persist_mono = 0.0
    call = _tool_call(name, "preentry-heartbeat-call")
    plan = agent._plan_tool_batch([call])
    try:
        with pytest.raises(_TerminalFinalizerBaseException):
            agent._execute_tool_calls(
                SimpleNamespace(content="", tool_calls=[call]),
                [],
                "task-1",
                batch_plan=plan,
            )
    finally:
        db.close()

    assert entered == []


def test_real_sessiondb_ordinary_post_entry_baseexception_still_propagates(
    registered_tools, tmp_path, monkeypatch
):
    from hermes_state import SessionDB

    state = {"armed": False}
    holder: dict[str, AIAgent] = {}
    name = "ordinary_post_entry_heartbeat"

    def handler(_args, **_kwargs):
        state["armed"] = True
        holder["agent"]._session_activity_last_persist_mono = 0.0
        return "ordinary result"

    registered_tools(name, handler=handler)
    db = SessionDB(db_path=tmp_path / "ordinary-heartbeat.db")
    original_touch = db.touch_session_activity

    def touch(*args, **kwargs):
        if state["armed"]:
            raise _TerminalFinalizerBaseException("ordinary heartbeat")
        return original_touch(*args, **kwargs)

    monkeypatch.setattr(db, "touch_session_activity", touch)
    agent = _make_agent(name, session_db=db, session_id="ordinary-heartbeat")
    holder["agent"] = agent
    call = _tool_call(name, "ordinary-heartbeat-call")
    try:
        with pytest.raises(_TerminalFinalizerBaseException):
            agent._execute_tool_calls(
                SimpleNamespace(content="", tool_calls=[call]), [], "task-1"
            )
    finally:
        db.close()

    assert state["armed"] is True


_PRE_ENTRY_BASE_EXCEPTIONS = [
    pytest.param(asyncio.CancelledError, id="cancelled-error"),
    pytest.param(KeyboardInterrupt, id="keyboard-interrupt"),
    pytest.param(SystemExit, id="system-exit"),
    pytest.param(_TerminalFinalizerBaseException, id="custom-base-exception"),
]


@pytest.mark.parametrize("fault_type", _PRE_ENTRY_BASE_EXCEPTIONS)
def test_preentry_execution_middleware_baseexceptions_propagate(
    monkeypatch, fault_type
):
    from hermes_cli.middleware import TOOL_EXECUTION_MIDDLEWARE
    from hermes_cli.middleware import run_tool_execution_middleware

    local = ToolRegistry()
    entered: list[str] = []
    local._register_host_terminal_tool(
        name="preentry_middleware_terminal",
        toolset="host-owned",
        schema={"name": "preentry_middleware_terminal", "parameters": {"type": "object"}},
        handler=lambda _args: entered.append("entered") or _terminal_result(),
    )
    invocation = TerminalToolInvocation(
        local.snapshot_terminal_capability("preentry_middleware_terminal")
    )

    def middleware(**_kwargs):
        raise fault_type("pre-entry middleware cancellation")

    manager = SimpleNamespace(
        _middleware={TOOL_EXECUTION_MIDDLEWARE: [middleware]},
        has_hook=lambda _name: False,
    )
    monkeypatch.setattr("hermes_cli.plugins.get_plugin_manager", lambda: manager)

    with pytest.raises(fault_type):
        run_tool_execution_middleware(
            "preentry_middleware_terminal",
            {},
            lambda _args: entered.append("entered") or _terminal_result(),
            _terminal_invocation=invocation,
        )

    assert entered == []
    assert invocation.handler_entered is False


@pytest.mark.parametrize("fault_type", _PRE_ENTRY_BASE_EXCEPTIONS)
def test_snapshot_check_fn_baseexceptions_propagate_before_entry(fault_type):
    local = ToolRegistry()
    entered: list[str] = []

    def unavailable():
        raise fault_type("pre-entry check cancellation")

    local._register_host_terminal_tool(
        name="preentry_snapshot_terminal",
        toolset="host-owned",
        schema={"name": "preentry_snapshot_terminal", "parameters": {"type": "object"}},
        handler=lambda _args: entered.append("entered") or _terminal_result(),
        check_fn=unavailable,
    )

    with pytest.raises(fault_type):
        local.snapshot_terminal_capability("preentry_snapshot_terminal")

    assert entered == []


@pytest.mark.parametrize("fault_type", _PRE_ENTRY_BASE_EXCEPTIONS)
def test_registry_revalidation_check_fn_baseexceptions_propagate_before_entry(
    fault_type,
):
    local = ToolRegistry()
    entered: list[str] = []
    checks = 0

    def available_then_cancel():
        nonlocal checks
        checks += 1
        if checks > 1:
            raise fault_type("pre-entry registry cancellation")
        return True

    local._register_host_terminal_tool(
        name="preentry_dispatch_terminal",
        toolset="host-owned",
        schema={"name": "preentry_dispatch_terminal", "parameters": {"type": "object"}},
        handler=lambda _args: entered.append("entered") or _terminal_result(),
        check_fn=available_then_cancel,
    )
    capability = local.snapshot_terminal_capability("preentry_dispatch_terminal")
    invocation = TerminalToolInvocation(capability)

    with patch("tools.registry._CHECK_FN_TTL_SECONDS", 0.0):
        with pytest.raises(fault_type):
            local.dispatch(
                "preentry_dispatch_terminal", {}, terminal_invocation=invocation
            )

    assert entered == []
    assert invocation.handler_entered is False


@pytest.mark.parametrize("fault_type", _PRE_ENTRY_BASE_EXCEPTIONS)
def test_sequential_terminal_preentry_baseexceptions_propagate(
    registered_tools, monkeypatch, fault_type
):
    entered: list[str] = []
    registered_tools(
        "preentry_batch_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: entered.append("entered") or _terminal_result(),
    )
    agent = _make_agent("preentry_batch_terminal")
    call = _tool_call("preentry_batch_terminal", "preentry-batch")
    monkeypatch.setattr(
        "hermes_cli.middleware.run_tool_execution_middleware",
        MagicMock(side_effect=fault_type("pre-entry batch cancellation")),
    )

    with pytest.raises(fault_type):
        agent._execute_tool_calls(
            SimpleNamespace(content="", tool_calls=[call]), [], "task-1"
        )

    assert entered == []


@pytest.mark.parametrize("fault_type", _PRE_ENTRY_BASE_EXCEPTIONS)
def test_tool_search_preentry_baseexceptions_propagate(
    registered_tools, monkeypatch, fault_type
):
    from tools import tool_search

    entered: list[str] = []
    registered_tools(
        "preentry_search_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: entered.append("entered") or _terminal_result(),
    )
    monkeypatch.setattr(
        tool_search,
        "resolve_underlying_call",
        MagicMock(side_effect=fault_type("pre-entry tool-search cancellation")),
    )
    agent = _make_agent(tool_search.TOOL_CALL_NAME)
    bridge = _tool_call(
        tool_search.TOOL_CALL_NAME,
        "preentry-search",
        json.dumps({"name": "preentry_search_terminal", "arguments": {}}),
    )

    with pytest.raises(fault_type):
        agent._execute_tool_calls(
            SimpleNamespace(content="", tool_calls=[bridge]), [], "task-1"
        )

    assert entered == []


_POST_ENTRY_FAULTS = [
    pytest.param(None, id="false"),
    pytest.param(RuntimeError, id="exception"),
    pytest.param(asyncio.CancelledError, id="cancelled-error"),
    pytest.param(KeyboardInterrupt, id="keyboard-interrupt"),
    pytest.param(SystemExit, id="system-exit"),
    pytest.param(_TerminalFinalizerBaseException, id="custom-base-exception"),
]


@pytest.mark.parametrize("fault_type", _POST_ENTRY_FAULTS)
def test_incremental_persistence_fault_after_entry_keeps_terminal_control(
    registered_tools, monkeypatch, fault_type, caplog
):
    registered_tools(
        "incremental_persist_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final="original final"),
    )
    agent = _make_agent("incremental_persist_terminal")
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("incremental_persist_terminal", "incremental-fault")]
    )
    streamed: list[object] = []
    tts: list[object] = []
    agent.stream_delta_callback = streamed.append

    def fail_incremental(_agent, _messages, *, stage):
        assert stage == "tool result incremental_persist_terminal"
        agent._incremental_persistence_failed = True
        if fault_type is None:
            return False
        raise fault_type("PRIVATE-INCREMENTAL-PERSISTENCE")

    monkeypatch.setattr(
        "agent.tool_executor._flush_session_db_after_tool_progress",
        fail_incremental,
    )
    with (
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        result = agent.run_conversation("persist", stream_callback=tts.append)

    assert agent.client.chat.completions.create.call_count == 1
    assert result["terminal_tool"]["status"] == "safe_failure"
    assert result["terminal_tool"]["reason"] == "terminal_persistence_error"
    assert result["terminal_tool"]["metadata"] == {"task_id": "task-1"}
    assert result["final_response"] == result["messages"][-1]["content"]
    assert [m["role"] for m in result["messages"]][-4:] == [
        "user", "assistant", "tool", "assistant"
    ]
    assert [item for item in streamed if item is not None] == [result["final_response"]]
    assert tts == [result["final_response"]]
    assert "PRIVATE-INCREMENTAL" not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("fault_type", _POST_ENTRY_FAULTS)
def test_terminal_final_persistence_fault_keeps_one_host_final(
    registered_tools, fault_type, caplog
):
    registered_tools(
        "terminal_final_persist",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final="original final"),
    )
    agent = _make_agent("terminal_final_persist")
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("terminal_final_persist", "final-persist-fault")]
    )
    original_flush = agent._flush_messages_to_session_db

    def flush(messages, conversation_history=None):
        is_terminal_final = (
            len(messages) >= 2
            and messages[-1].get("role") == "assistant"
            and messages[-2].get("role") == "tool"
        )
        if not is_terminal_final:
            return original_flush(messages, conversation_history)
        if fault_type is None:
            return False
        raise fault_type("PRIVATE-TERMINAL-FINAL-PERSISTENCE")

    agent._flush_messages_to_session_db = flush
    streamed: list[object] = []
    tts: list[object] = []
    agent.stream_delta_callback = streamed.append
    with (
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        result = agent.run_conversation("persist", stream_callback=tts.append)

    assert agent.client.chat.completions.create.call_count == 1
    assert result["terminal_tool"]["status"] == "safe_failure"
    assert result["terminal_tool"]["reason"] == "terminal_persistence_error"
    assert result["terminal_tool"]["metadata"] == {"task_id": "task-1"}
    assert result["final_response"] == result["messages"][-1]["content"]
    assert [item for item in streamed if item is not None] == [result["final_response"]]
    assert tts == [result["final_response"]]
    assert "PRIVATE-TERMINAL" not in json.dumps(result) + caplog.text


@pytest.mark.parametrize("fault_type", _POST_ENTRY_FAULTS)
def test_real_db_committed_terminal_final_survives_ancillary_persist_fault(
    registered_tools, tmp_path, monkeypatch, fault_type
):
    from hermes_state import SessionDB

    final = "authoritative committed final"
    registered_tools(
        "ancillary_persist_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final=final),
    )
    db_path = tmp_path / "hermes-home" / "state.db"
    db_path.parent.mkdir(parents=True)
    db = SessionDB(db_path=db_path)
    session_id = f"ancillary-persist-{getattr(fault_type, '__name__', 'false')}"
    agent = _make_agent(
        "ancillary_persist_terminal",
        session_db=db,
        session_id=session_id,
        hermes_home=db_path.parent,
    )
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("ancillary_persist_terminal", "ancillary-call")]
    )
    trajectory: list[tuple[list[dict], bool]] = []
    streamed: list[object] = []
    ended: list[dict] = []
    agent.stream_delta_callback = streamed.append

    def save_trajectory(messages, _query, completed):
        # The authoritative append is fixed before trajectory persistence.
        assert messages[-1].get("_db_persisted") is True
        trajectory.append((copy.deepcopy(messages), completed))

    original_persist = agent._persist_session

    def ancillary_persist(messages, conversation_history=None):
        is_committed_terminal_final = (
            len(messages) >= 2
            and messages[-1].get("role") == "assistant"
            and messages[-2].get("role") == "tool"
            and messages[-1].get("_db_persisted") is True
        )
        if not is_committed_terminal_final:
            return original_persist(messages, conversation_history)
        if fault_type is None:
            return False
        raise fault_type("PRIVATE-ANCILLARY-PERSISTENCE")

    def invoke_hook(name, **kwargs):
        if name == "on_session_end":
            ended.append(kwargs)
        return []

    agent._save_trajectory = save_trajectory
    agent._persist_session = ancillary_persist
    agent._cleanup_task_resources = MagicMock()
    monkeypatch.setattr("hermes_cli.lifecycle.invoke_hook", invoke_hook)
    try:
        result = agent.run_conversation("persist committed final")
        durable = db.get_messages_as_conversation(session_id)
    finally:
        db.close()

    assert result["final_response"] == final
    assert result["messages"][-1]["content"] == final
    assert result["messages"][-1].get("_db_persisted") is True
    assert [item for item in streamed if item is not None] == [final]
    assert [m["role"] for m in durable] == ["user", "assistant", "tool", "assistant"]
    assert durable[-1]["content"] == final
    assert sum(m["role"] == "assistant" and m["content"] == final for m in durable) == 1
    assert trajectory and trajectory[0][0][-1]["content"] == final
    assert trajectory[0][1] is True
    assert result["completed"] is True and result["failed"] is False
    assert ended[-1]["completed"] is True and ended[-1]["failed"] is False
    assert "persist_session" in result["cleanup_errors"]


@pytest.mark.parametrize("fault_type", _POST_ENTRY_FAULTS)
def test_real_db_failed_authoritative_append_selects_one_retry_safe_final(
    registered_tools, tmp_path, monkeypatch, fault_type
):
    from hermes_state import SessionDB

    registered_tools(
        "authoritative_append_failure_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final="uncommitted original"),
    )
    db_path = tmp_path / "hermes-home" / "state.db"
    db_path.parent.mkdir(parents=True)
    db = SessionDB(db_path=db_path)
    session_id = f"authoritative-failure-{getattr(fault_type, '__name__', 'false')}"
    agent = _make_agent(
        "authoritative_append_failure_terminal",
        session_db=db,
        session_id=session_id,
        hermes_home=db_path.parent,
    )
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[
            _tool_call(
                "authoritative_append_failure_terminal", "authoritative-failure-call"
            )
        ]
    )
    original_flush = agent._flush_messages_to_session_db
    final_attempts = 0
    trajectory: list[tuple[list[dict], bool]] = []
    ended: list[dict] = []

    def fail_final_append(messages, conversation_history=None):
        nonlocal final_attempts
        is_terminal_final = (
            len(messages) >= 2
            and messages[-1].get("role") == "assistant"
            and messages[-2].get("role") == "tool"
        )
        if not is_terminal_final:
            return original_flush(messages, conversation_history)
        final_attempts += 1
        if fault_type is None:
            return False
        raise fault_type("PRIVATE-AUTHORITATIVE-PERSISTENCE")

    def invoke_hook(name, **kwargs):
        if name == "on_session_end":
            ended.append(kwargs)
        return []

    agent._flush_messages_to_session_db = fail_final_append
    agent._persist_session = MagicMock()
    agent._cleanup_task_resources = MagicMock()
    agent._save_trajectory = lambda messages, _query, completed: trajectory.append(
        (copy.deepcopy(messages), completed)
    )
    monkeypatch.setattr("hermes_cli.lifecycle.invoke_hook", invoke_hook)
    try:
        result = agent.run_conversation("fail final append")
        durable_before_retry = db.get_messages_as_conversation(session_id)
        marker_before_retry = result["messages"][-1].get("_db_persisted")

        # A later bounded retry writes the already-selected safe final once;
        # its marker makes every further retry a no-op.
        assert original_flush(result["messages"], []) is True
        assert original_flush(result["messages"], []) is True
        durable_after_retry = db.get_messages_as_conversation(session_id)
    finally:
        db.close()

    safe_final = result["final_response"]
    assert result["terminal_tool"]["reason"] == "terminal_persistence_error"
    assert result["messages"][-1]["content"] == safe_final
    assert result["messages"][-1].get("_db_persisted") is True
    assert marker_before_retry is None
    assert final_attempts == 1
    # One ordinary turn-prologue call only; the failed terminal-final append
    # does not trigger a later ancillary persist attempt.
    assert agent._persist_session.call_count == 1
    assert [m["role"] for m in durable_before_retry] == ["user", "assistant", "tool"]
    assert [m["role"] for m in durable_after_retry] == [
        "user", "assistant", "tool", "assistant"
    ]
    assert durable_after_retry[-1]["content"] == safe_final
    assert sum(
        m["role"] == "assistant" and m["content"] == safe_final
        for m in durable_after_retry
    ) == 1
    assert trajectory[0][0][-1]["content"] == safe_final
    assert trajectory[0][1] is False
    assert result["completed"] is False and result["failed"] is True
    assert result["error"] == "The terminal outcome could not be durably persisted."
    assert ended[-1]["completed"] is False and ended[-1]["failed"] is True


def test_real_db_trajectory_failure_cannot_rewrite_committed_terminal_final(
    registered_tools, tmp_path
):
    from hermes_state import SessionDB

    final = "trajectory-independent committed final"
    registered_tools(
        "trajectory_failure_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final=final),
    )
    db_path = tmp_path / "hermes-home" / "state.db"
    db_path.parent.mkdir(parents=True)
    db = SessionDB(db_path=db_path)
    session_id = "trajectory-failure-terminal"
    agent = _make_agent(
        "trajectory_failure_terminal",
        session_db=db,
        session_id=session_id,
        hermes_home=db_path.parent,
    )
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("trajectory_failure_terminal", "trajectory-call")]
    )
    agent._save_trajectory = MagicMock(
        side_effect=_TerminalFinalizerBaseException("PRIVATE-TRAJECTORY")
    )
    agent._cleanup_task_resources = MagicMock()
    try:
        result = agent.run_conversation("trajectory fails")
        durable = db.get_messages_as_conversation(session_id)
    finally:
        db.close()

    assert result["final_response"] == final
    assert result["messages"][-1]["content"] == final
    assert durable[-1]["content"] == final
    assert [m["role"] for m in durable] == ["user", "assistant", "tool", "assistant"]
    assert result["completed"] is True and result["failed"] is False
    assert "save_trajectory" in result["cleanup_errors"]


@pytest.mark.parametrize(
    "boundary",
    [
        "save_trajectory",
        "cleanup_task_resources",
        "post_llm_call",
        "context_engine_finalization",
        "external_memory_finalization",
        "on_session_end",
        "stream_callback",
    ],
)
def test_terminal_finalizer_baseexceptions_are_contained_per_boundary(
    registered_tools, monkeypatch, boundary, caplog
):
    registered_tools(
        "finalizer_boundary_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final="sealed final"),
    )
    agent = _make_agent("finalizer_boundary_terminal")
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("finalizer_boundary_terminal", "boundary-fault")]
    )

    def fault(*_args, **_kwargs):
        raise _TerminalFinalizerBaseException("PRIVATE-FINALIZER-BOUNDARY")

    if boundary == "save_trajectory":
        agent._save_trajectory = fault
        agent._cleanup_task_resources = MagicMock()
    elif boundary == "cleanup_task_resources":
        agent._save_trajectory = MagicMock()
        agent._cleanup_task_resources = fault
    else:
        agent._save_trajectory = MagicMock()
        agent._cleanup_task_resources = MagicMock()

    if boundary in {"post_llm_call", "on_session_end"}:
        from hermes_cli import lifecycle

        original_hook = lifecycle.invoke_hook

        def invoke_hook(name, **kwargs):
            if name == boundary:
                fault()
            return original_hook(name, **kwargs)

        monkeypatch.setattr(lifecycle, "invoke_hook", invoke_hook)
    elif boundary == "context_engine_finalization":
        monkeypatch.setattr(
            "agent.conversation_loop._notify_context_engine_turn_complete", fault
        )
    elif boundary == "external_memory_finalization":
        agent._sync_external_memory_for_turn = fault

    streamed: list[object] = []
    if boundary == "stream_callback":
        agent.stream_delta_callback = streamed.append
    else:
        agent.stream_delta_callback = streamed.append
    tts: list[object] = []
    result = agent.run_conversation(
        "finish",
        stream_callback=fault if boundary == "stream_callback" else tts.append,
    )

    assert agent.client.chat.completions.create.call_count == 1
    assert result["final_response"] == "sealed final"
    assert result["messages"][-1]["content"] == "sealed final"
    assert result["terminal_tool"]["status"] == "deferred"
    assert [item for item in streamed if item is not None] == ["sealed final"]
    if boundary != "stream_callback":
        assert tts == ["sealed final"]
        assert boundary in result["cleanup_errors"]
    assert "PRIVATE-FINALIZER" not in json.dumps(result) + caplog.text


@pytest.mark.parametrize(
    "boundary",
    [
        "save_trajectory",
        "cleanup_task_resources",
        "post_llm_call",
        "context_engine_finalization",
        "external_memory_finalization",
        "on_session_end",
    ],
)
def test_same_finalizer_baseexceptions_still_escape_on_ordinary_turn(
    monkeypatch, boundary
):
    agent = _make_agent()
    agent.client.chat.completions.create.return_value = _response(
        content="ordinary final", tool_calls=None, finish_reason="stop"
    )

    def fault(*_args, **_kwargs):
        raise _TerminalFinalizerBaseException("ordinary interrupt semantics")

    agent._save_trajectory = MagicMock()
    agent._cleanup_task_resources = MagicMock()
    if boundary == "save_trajectory":
        agent._save_trajectory = fault
    elif boundary == "cleanup_task_resources":
        agent._cleanup_task_resources = fault
    elif boundary in {"post_llm_call", "on_session_end"}:
        from hermes_cli import lifecycle

        original_hook = lifecycle.invoke_hook

        def invoke_hook(name, **kwargs):
            if name == boundary:
                fault()
            return original_hook(name, **kwargs)

        monkeypatch.setattr(lifecycle, "invoke_hook", invoke_hook)
    elif boundary == "context_engine_finalization":
        monkeypatch.setattr(
            "agent.conversation_loop._notify_context_engine_turn_complete", fault
        )
    elif boundary == "external_memory_finalization":
        agent._sync_external_memory_for_turn = fault

    with pytest.raises(_TerminalFinalizerBaseException):
        agent.run_conversation("ordinary")


def test_ordinary_concurrent_batch_remains_concurrent_and_ordered(
    registered_tools, monkeypatch
):
    barrier = threading.Barrier(2)

    def concurrent_handler(args, **_kwargs):
        barrier.wait(timeout=2)
        return args["value"]

    registered_tools("parallel_ordinary", handler=concurrent_handler)
    from agent import tool_dispatch_helpers

    monkeypatch.setattr(
        tool_dispatch_helpers,
        "_PARALLEL_SAFE_TOOLS",
        tool_dispatch_helpers._PARALLEL_SAFE_TOOLS | {"parallel_ordinary"},
    )
    agent = _make_agent("parallel_ordinary")
    calls = [
        _tool_call("parallel_ordinary", "one", json.dumps({"value": "one"})),
        _tool_call("parallel_ordinary", "two", json.dumps({"value": "two"})),
    ]
    messages: list[dict] = []

    outcome = agent._execute_tool_calls(
        SimpleNamespace(content="", tool_calls=calls), messages, "task-1"
    )

    assert outcome.terminal is None
    assert [m["tool_call_id"] for m in messages] == ["one", "two"]
    assert [m["content"] for m in messages] == ["one", "two"]


def test_real_session_restart_preserves_terminal_suffix_order(registered_tools, tmp_path):
    from hermes_state import SessionDB

    registered_tools(
        "persisted_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final="persisted final"),
    )
    db_path = tmp_path / "hermes-home" / "state.db"
    db_path.parent.mkdir(parents=True)
    db = SessionDB(db_path=db_path)
    session_id = "terminal-persistence-session"
    agent = _make_agent(
        "persisted_terminal",
        session_db=db,
        session_id=session_id,
        hermes_home=db_path.parent,
    )
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("persisted_terminal", "persisted-call")]
    )

    result = _run(agent, "persist it")
    db.close()
    reopened = SessionDB(db_path=db_path)
    try:
        history = reopened.get_messages_as_conversation(session_id)
    finally:
        reopened.close()

    assert [m["role"] for m in history] == ["user", "assistant", "tool", "assistant"]
    assert history[-1]["content"] == result["final_response"]
    assert history[2]["tool_call_id"] == "persisted-call"


def test_next_real_user_turn_reuses_terminal_history_without_synthetic_resume(
    registered_tools,
):
    registered_tools(
        "next_turn_terminal",
        terminal=True,
        handler=lambda _args, **_kwargs: _terminal_result(final="first final"),
    )
    agent = _make_agent("next_turn_terminal")
    stable_prompt = agent._cached_system_prompt
    agent.client.chat.completions.create.return_value = _response(
        tool_calls=[_tool_call("next_turn_terminal", "first-call")]
    )
    first = _run(agent, "first turn")

    agent.client.chat.completions.create.reset_mock()
    agent.client.chat.completions.create.return_value = _response(
        content="second final", tool_calls=None, finish_reason="stop"
    )
    with (
        patch.object(agent, "_persist_session"),
        patch.object(agent, "_save_trajectory"),
        patch.object(agent, "_cleanup_task_resources"),
    ):
        second = agent.run_conversation(
            "second turn", conversation_history=first["messages"]
        )

    assert agent.client.chat.completions.create.call_count == 1
    assert agent._cached_system_prompt == stable_prompt
    assert second["final_response"] == "second final"
    assert [m["role"] for m in second["messages"]][-3:] == [
        "assistant", "user", "assistant"
    ]
    assert not any(
        key.endswith("synthetic")
        for message in second["messages"]
        for key in message
    )
