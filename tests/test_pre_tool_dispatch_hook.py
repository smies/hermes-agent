"""Generic final tool-dispatch integrity seam regressions."""

from __future__ import annotations

import model_tools
import tools.registry as registry_module
from hermes_cli.plugins import get_plugin_manager
from tools.registry import ToolRegistry


def _isolated_dispatch(monkeypatch):
    registry = ToolRegistry()
    monkeypatch.setattr(registry_module, "registry", registry)
    monkeypatch.setattr(model_tools, "registry", registry)
    manager = get_plugin_manager()
    monkeypatch.setitem(manager._hooks, "pre_tool_call", [])
    monkeypatch.setitem(manager._hooks, "pre_tool_dispatch", [])
    monkeypatch.setitem(manager._middleware, "tool_execution", [])
    return registry, manager


def _register(registry, name, effects):
    def handler(args, **_kwargs):
        effects.append(dict(args))
        return "handled"

    registry.register(
        name=name,
        toolset="dispatch_integrity_fixture",
        schema={"description": "fixture", "parameters": {"type": "object"}},
        handler=handler,
    )


def test_later_pre_hook_mutation_is_blocked_before_handler(monkeypatch):
    registry, manager = _isolated_dispatch(monkeypatch)
    effects = []
    _register(registry, "dispatch_integrity_hook_mutation", effects)

    def authorize(**kwargs):
        assert kwargs["args"] == {"value": "approved"}

    def mutate(**kwargs):
        kwargs["args"]["value"] = "changed-after-policy"

    def final_check(**kwargs):
        if kwargs["args"] != {"value": "approved"}:
            return {"action": "block", "message": "exact final args changed"}
        return None

    manager._hooks["pre_tool_call"] = [authorize, mutate]
    manager._hooks["pre_tool_dispatch"] = [final_check]
    result = model_tools.handle_function_call(
        "dispatch_integrity_hook_mutation",
        {"value": "approved"},
        session_id="fixture-session",
        turn_id="fixture-turn",
    )
    assert effects == []
    assert "exact final args changed" in result


def test_execution_middleware_mutation_is_blocked_before_handler(monkeypatch):
    registry, manager = _isolated_dispatch(monkeypatch)
    effects = []
    _register(registry, "dispatch_integrity_middleware_mutation", effects)

    def final_check(**kwargs):
        if kwargs["args"] != {"value": "approved"}:
            return {"action": "block", "message": "middleware changed exact args"}
        return None

    def mutate(args, next_call, **_kwargs):
        assert args == {"value": "approved"}
        return next_call({"value": "changed-by-middleware"})

    manager._hooks["pre_tool_dispatch"] = [final_check]
    manager._middleware["tool_execution"] = [mutate]
    result = model_tools.handle_function_call(
        "dispatch_integrity_middleware_mutation",
        {"value": "approved"},
        session_id="fixture-session",
        turn_id="fixture-turn",
    )
    assert effects == []
    assert "middleware changed exact args" in result


def test_final_hooks_receive_isolated_snapshots_and_ordinary_tool_runs(monkeypatch):
    registry, manager = _isolated_dispatch(monkeypatch)
    effects = []
    seen = []
    _register(registry, "dispatch_integrity_ordinary", effects)

    def observer(**kwargs):
        seen.append(dict(kwargs["args"]))

    def attempted_mutation(**kwargs):
        kwargs["args"]["value"] = "mutated-hook-copy"

    manager._hooks["pre_tool_dispatch"] = [observer, attempted_mutation]
    result = model_tools.handle_function_call(
        "dispatch_integrity_ordinary",
        {"value": "ordinary"},
        session_id="fixture-session",
        turn_id="fixture-turn",
    )
    assert result == "handled"
    assert seen == [{"value": "ordinary"}]
    assert effects == [{"value": "ordinary"}]


def test_final_block_without_message_uses_bounded_default(monkeypatch):
    registry, manager = _isolated_dispatch(monkeypatch)
    effects = []
    _register(registry, "dispatch_integrity_default_block", effects)
    manager._hooks["pre_tool_dispatch"] = [
        lambda **_kwargs: {"action": "block"}
    ]

    result = model_tools.handle_function_call(
        "dispatch_integrity_default_block",
        {"value": "ordinary"},
        session_id="fixture-session",
        turn_id="fixture-turn",
    )

    assert effects == []
    assert (
        "BLOCKED: final tool dispatch policy denied "
        "dispatch_integrity_default_block" in result
    )
