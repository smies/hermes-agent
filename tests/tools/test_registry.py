"""Tests for the central tool registry."""

import json
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path
from unittest.mock import patch

from tools.registry import ToolRegistry, _module_registers_tools, discover_builtin_tools


def _dummy_handler(args, **kwargs):
    return json.dumps({"ok": True})


def _make_schema(name="test_tool"):
    return {
        "name": name,
        "description": f"A {name}",
        "parameters": {"type": "object", "properties": {}},
    }


class TestRegisterAndDispatch:
    def test_register_and_dispatch(self):
        reg = ToolRegistry()
        reg.register(
            name="alpha",
            toolset="core",
            schema=_make_schema("alpha"),
            handler=_dummy_handler,
        )
        result = json.loads(reg.dispatch("alpha", {}))
        assert result == {"ok": True}


    def test_host_tool_call_id_does_not_change_ordinary_handler_signature(self):
        reg = ToolRegistry()
        observed = []
        reg.register(
            name="ordinary_signature",
            toolset="core",
            schema=_make_schema("ordinary_signature"),
            handler=lambda args: observed.append(args) or "ok",
        )

        assert reg.dispatch(
            "ordinary_signature", {}, tool_call_id="provider-call"
        ) == "ok"
        assert observed == [{}]


    def test_cross_mcp_toolsets_do_not_overwrite_atomically(self, caplog):
        """Parallel MCP registrations with one name leave exactly one owner."""
        reg = ToolRegistry()
        barrier = threading.Barrier(3)
        errors = []

        def _register(toolset, owner):
            try:
                barrier.wait(timeout=5)

                def _handler(args, **kwargs):
                    return json.dumps({"owner": owner})

                reg.register(
                    name="mcp__foo_bar__search",
                    toolset=toolset,
                    schema=_make_schema("mcp__foo_bar__search"),
                    handler=_handler,
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        threads = [
            threading.Thread(target=_register, args=("mcp-foo-bar", "dash")),
            threading.Thread(target=_register, args=("mcp-foo_bar", "underscore")),
        ]

        with caplog.at_level(logging.ERROR, logger="tools.registry"):
            for thread in threads:
                thread.start()
            barrier.wait(timeout=5)
            for thread in threads:
                thread.join(timeout=10)

        assert all(not thread.is_alive() for thread in threads)
        assert errors == []
        assert reg._generation == 1

        entry = reg.get_entry("mcp__foo_bar__search")
        assert entry is not None
        assert entry.toolset in {"mcp-foo-bar", "mcp-foo_bar"}
        assert json.loads(reg.dispatch("mcp__foo_bar__search", {}))["owner"] in {
            "dash",
            "underscore",
        }
        assert any(
            "REJECTED" in record.message
            and "mcp__foo_bar__search" in record.message
            for record in caplog.records
        )

class TestGetDefinitions:
    def test_returns_openai_format(self):
        reg = ToolRegistry()
        reg.register(
            name="t1", toolset="s1", schema=_make_schema("t1"), handler=_dummy_handler
        )
        reg.register(
            name="t2", toolset="s1", schema=_make_schema("t2"), handler=_dummy_handler
        )

        defs = reg.get_definitions({"t1", "t2"})
        assert len(defs) == 2
        assert all(d["type"] == "function" for d in defs)
        names = {d["function"]["name"] for d in defs}
        assert names == {"t1", "t2"}


    def test_reuses_shared_check_fn_once_per_call(self):
        reg = ToolRegistry()
        calls = {"count": 0}

        def shared_check():
            calls["count"] += 1
            return True

        reg.register(
            name="first",
            toolset="shared",
            schema=_make_schema("first"),
            handler=_dummy_handler,
            check_fn=shared_check,
        )
        reg.register(
            name="second",
            toolset="shared",
            schema=_make_schema("second"),
            handler=_dummy_handler,
            check_fn=shared_check,
        )

        defs = reg.get_definitions({"first", "second"})
        assert len(defs) == 2
        assert calls["count"] == 1


class TestUnknownToolDispatch:
    def test_returns_error_json(self):
        reg = ToolRegistry()
        result = json.loads(reg.dispatch("nonexistent", {}))
        assert "error" in result
        assert "Unknown tool" in result["error"]


class TestToolsetAvailability:
    def test_no_check_fn_is_available(self):
        reg = ToolRegistry()
        reg.register(
            name="t", toolset="free", schema=_make_schema(), handler=_dummy_handler
        )
        assert reg.is_toolset_available("free") is True

    def test_check_fn_controls_availability(self):
        reg = ToolRegistry()
        reg.register(
            name="t",
            toolset="locked",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: False,
        )
        assert reg.is_toolset_available("locked") is False


    def test_handler_exception_returns_error(self):
        reg = ToolRegistry()

        def bad_handler(args, **kw):
            raise RuntimeError("boom")

        reg.register(
            name="bad", toolset="s", schema=_make_schema(), handler=bad_handler
        )
        result = json.loads(reg.dispatch("bad", {}))
        assert "error" in result
        assert "RuntimeError" in result["error"]


class TestCheckFnExceptionHandling:
    """Verify that a raising check_fn is caught rather than crashing."""

    def test_is_toolset_available_catches_exception(self):
        reg = ToolRegistry()
        reg.register(
            name="t",
            toolset="broken",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: 1 / 0,  # ZeroDivisionError
        )
        # Should return False, not raise
        assert reg.is_toolset_available("broken") is False


    def test_check_tool_availability_survives_raising_check(self):
        reg = ToolRegistry()
        reg.register(
            name="a",
            toolset="works",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: True,
        )
        reg.register(
            name="b",
            toolset="crashes",
            schema=_make_schema(),
            handler=_dummy_handler,
            check_fn=lambda: 1 / 0,
        )

        available, unavailable = reg.check_tool_availability()
        assert "works" in available
        assert any(u["name"] == "crashes" for u in unavailable)


class TestBuiltinDiscovery:
    def test_discovers_all_real_self_registering_builtin_tool_modules(self):
        tools_dir = Path(__file__).resolve().parents[2] / "tools"
        expected = [
            f"tools.{path.stem}"
            for path in sorted(tools_dir.glob("*.py"))
            if path.name not in {"__init__.py", "registry.py", "mcp_tool.py"}
            and _module_registers_tools(path)
        ]

        with patch("tools.registry.importlib.import_module"):
            imported = discover_builtin_tools(tools_dir)

        assert imported == expected


    def test_skips_mcp_tool_even_if_it_registers(self, tmp_path):
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        (tools_dir / "__init__.py").write_text("", encoding="utf-8")
        (tools_dir / "mcp_tool.py").write_text(
            "from tools.registry import registry\nregistry.register(name='mcp_alpha', toolset='mcp-test', schema={}, handler=lambda *_a, **_k: '{}')\n",
            encoding="utf-8",
        )
        (tools_dir / "alpha.py").write_text(
            "from tools.registry import registry\nregistry.register(name='alpha', toolset='x', schema={}, handler=lambda *_a, **_k: '{}')\n",
            encoding="utf-8",
        )

        with patch("tools.registry.importlib.import_module") as mock_import:
            imported = discover_builtin_tools(tools_dir)

        assert imported == ["tools.alpha"]
        mock_import.assert_called_once_with("tools.alpha")


    def test_discovers_module_with_only_host_terminal_registration(self, tmp_path):
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        (tools_dir / "__init__.py").write_text("", encoding="utf-8")
        (tools_dir / "terminal_only.py").write_text(
            "from tools.registry import registry\n"
            "registry._register_host_terminal_tool("
            "name='terminal_only', toolset='host', schema={}, "
            "handler=lambda *_a, **_k: '{}')\n",
            encoding="utf-8",
        )

        with patch("tools.registry.importlib.import_module") as mock_import:
            imported = discover_builtin_tools(tools_dir)

        assert imported == ["tools.terminal_only"]
        mock_import.assert_called_once_with("tools.terminal_only")


    def test_fresh_model_tools_discovery_registers_dormant_private_read(
        self, tmp_path
    ):
        isolated_home = tmp_path / "home"
        hermes_home = isolated_home / ".hermes"
        pycache = tmp_path / "pycache"
        isolated_home.mkdir()
        script = r'''
import json
import os
import socket
import sqlite3
import sys
import threading
from pathlib import Path

def forbidden_thread_start(*_args, **_kwargs):
    raise AssertionError("fresh discovery must not start threads")

def forbid_socket_events(event, _args):
    if event.startswith("socket."):
        raise AssertionError("fresh discovery must not use sockets")

threading.Thread.start = forbidden_thread_start
sys.addaudithook(forbid_socket_events)
assert "tools.private_read_request_tool" not in sys.modules
import model_tools
from gateway.authorization_tasks import AuthorizationTaskStore
from gateway.private_read_authorization import (
    PrivateReadCapabilityRegistry,
    PrivateReadCapabilitySpec,
    PrivateReadRequestRuntime,
)
from tools.registry import registry

name = "private_read_request"
assert "tools.private_read_request_tool" in sys.modules
module = sys.modules["tools.private_read_request_tool"]
entry = registry.get_entry(name)
assert entry is not None
assert entry.terminal_eligible and entry.terminal_handler is entry.handler
schema = entry.schema
assert registry.get_definitions({name}) == []
assert model_tools.get_tool_definitions(
    enabled_toolsets=["private-read-request"],
    quiet_mode=True,
    skip_tool_search_assembly=True,
) == []

class HostContexts:
    calls = 0

    def current(self):
        self.calls += 1
        return None

contexts = HostContexts()
store = AuthorizationTaskStore(
    db_path=Path(os.environ["HERMES_HOME"]) / "tasks.db",
    audit_hmac_key=b"a" * 32,
    request_hmac_key=b"r" * 32,
    key_version="discovery-test-k1",
)
try:
    runtime = PrivateReadRequestRuntime(
        store=store,
        id_hmac_key=b"i" * 32,
        host_contexts=contexts,
        capabilities=PrivateReadCapabilityRegistry((
            PrivateReadCapabilitySpec(
                capability_id="records.summary.read",
                operation="retrieve",
                resource_type="synthetic.record",
                fields=("summary",),
            ),
        )),
        enabled=True,
    )
    module.configure_private_read_request_runtime(runtime)
    active = registry.get_entry(name)
    assert active is not None and active is not entry
    assert active.schema is schema
    definitions = model_tools.get_tool_definitions(
        enabled_toolsets=["private-read-request"],
        quiet_mode=True,
        skip_tool_search_assembly=True,
    )
    assert definitions == [{"type": "function", "function": schema}]
    assert contexts.calls == 0
    with sqlite3.connect(store.db_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM authorization_tasks"
        ).fetchone()[0] == 0
finally:
    store.close()
print(json.dumps({"discovered": True, "schema_stable": True}))
'''
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(isolated_home),
                "HERMES_HOME": str(hermes_home),
                "PYTHONPYCACHEPREFIX": str(pycache),
            }
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            input="",
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout.strip()) == {
            "discovered": True,
            "schema_stable": True,
        }


    def test_legacy_cache_cannot_hide_host_terminal_registration(self, tmp_path):
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        terminal_module = tools_dir / "terminal_only.py"
        terminal_module.write_text(
            "from tools.registry import registry\n"
            "registry._register_host_terminal_tool("
            "name='terminal_only', toolset='host', schema={}, "
            "handler=lambda *_a, **_k: '{}')\n",
            encoding="utf-8",
        )
        stat = terminal_module.stat()
        cache_path = tmp_path / "legacy-discovery-cache.json"
        cache_path.write_text(
            json.dumps(
                {
                    str(terminal_module.resolve()): [
                        stat.st_mtime_ns,
                        stat.st_size,
                        False,
                    ]
                }
            ),
            encoding="utf-8",
        )

        with (
            patch("tools.registry._discovery_cache_path", return_value=cache_path),
            patch("tools.registry.importlib.import_module") as mock_import,
        ):
            imported = discover_builtin_tools(tools_dir)

        assert imported == ["tools.terminal_only"]
        mock_import.assert_called_once_with("tools.terminal_only")


    def test_skips_mcp_tool_with_host_terminal_registration(self, tmp_path):
        tools_dir = tmp_path / "tools"
        tools_dir.mkdir()
        (tools_dir / "mcp_tool.py").write_text(
            "from tools.registry import registry\n"
            "registry._register_host_terminal_tool("
            "name='forbidden', toolset='host', schema={}, "
            "handler=lambda *_a, **_k: '{}')\n",
            encoding="utf-8",
        )

        with patch("tools.registry.importlib.import_module") as mock_import:
            imported = discover_builtin_tools(tools_dir)

        assert imported == []
        mock_import.assert_not_called()


class TestEmojiMetadata:
    """Verify per-tool emoji registration and lookup."""

    def test_emoji_stored_on_entry(self):
        reg = ToolRegistry()
        reg.register(
            name="t", toolset="s", schema=_make_schema(),
            handler=_dummy_handler, emoji="🔥",
        )
        assert reg._tools["t"].emoji == "🔥"


    def test_emoji_empty_string_treated_as_unset(self):
        reg = ToolRegistry()
        reg.register(
            name="t", toolset="s", schema=_make_schema(),
            handler=_dummy_handler, emoji="",
        )
        assert reg.get_emoji("t") == "⚡"


class TestEntryLookup:
    def test_get_entry_returns_registered_entry(self):
        reg = ToolRegistry()
        reg.register(
            name="alpha", toolset="core", schema=_make_schema("alpha"), handler=_dummy_handler
        )
        entry = reg.get_entry("alpha")
        assert entry is not None
        assert entry.name == "alpha"
        assert entry.toolset == "core"

    def test_get_entry_returns_none_for_unknown_tool(self):
        reg = ToolRegistry()
        assert reg.get_entry("missing") is None


class TestSecretCaptureResultContract:
    def test_secret_request_result_does_not_include_secret_value(self):
        result = {
            "success": True,
            "stored_as": "TENOR_API_KEY",
            "validated": False,
        }
        assert "secret" not in json.dumps(result).lower()


class TestThreadSafety:
    def test_get_available_toolsets_uses_coherent_snapshot(self, monkeypatch):
        reg = ToolRegistry()
        reg.register(
            name="alpha",
            toolset="gated",
            schema=_make_schema("alpha"),
            handler=_dummy_handler,
            check_fn=lambda: False,
        )

        entries, toolset_checks = reg._snapshot_state()

        def snapshot_then_mutate():
            reg.deregister("alpha")
            return entries, toolset_checks

        monkeypatch.setattr(reg, "_snapshot_state", snapshot_then_mutate)

        toolsets = reg.get_available_toolsets()
        assert toolsets["gated"]["available"] is False
        assert toolsets["gated"]["tools"] == ["alpha"]

    def test_check_tool_availability_tolerates_concurrent_register(self):
        reg = ToolRegistry()
        check_started = threading.Event()
        writer_done = threading.Event()
        errors = []
        result_holder = {}
        writer_completed_during_check = {}

        def blocking_check():
            check_started.set()
            writer_completed_during_check["value"] = writer_done.wait(timeout=10)
            return True

        reg.register(
            name="alpha",
            toolset="gated",
            schema=_make_schema("alpha"),
            handler=_dummy_handler,
            check_fn=blocking_check,
        )
        reg.register(
            name="beta",
            toolset="plain",
            schema=_make_schema("beta"),
            handler=_dummy_handler,
        )

        def reader():
            try:
                result_holder["value"] = reg.check_tool_availability()
            except Exception as exc:  # pragma: no cover - exercised on failure only
                errors.append(exc)

        def writer():
            assert check_started.wait(timeout=10)
            reg.register(
                name="gamma",
                toolset="new",
                schema=_make_schema("gamma"),
                handler=_dummy_handler,
            )
            writer_done.set()

        reader_thread = threading.Thread(target=reader)
        writer_thread = threading.Thread(target=writer)
        reader_thread.start()
        writer_thread.start()
        reader_thread.join(timeout=15)
        writer_thread.join(timeout=15)

        assert not reader_thread.is_alive()
        assert not writer_thread.is_alive()
        assert writer_completed_during_check["value"] is True
        assert errors == []

        available, unavailable = result_holder["value"]
        # The writer must not wait on the expensive probe. Its registration
        # mutation advances the process-wide availability epoch, so the old
        # blocked result is deliberately discarded and this snapshot fails
        # the gated toolset closed.
        assert "plain" in available
        assert [item["name"] for item in unavailable] == ["gated"]

    def test_get_available_toolsets_tolerates_concurrent_deregister(self):
        reg = ToolRegistry()
        check_started = threading.Event()
        writer_done = threading.Event()
        errors = []
        result_holder = {}
        writer_completed_during_check = {}

        def blocking_check():
            check_started.set()
            writer_completed_during_check["value"] = writer_done.wait(timeout=10)
            return True

        reg.register(
            name="alpha",
            toolset="gated",
            schema=_make_schema("alpha"),
            handler=_dummy_handler,
            check_fn=blocking_check,
        )
        reg.register(
            name="beta",
            toolset="plain",
            schema=_make_schema("beta"),
            handler=_dummy_handler,
        )

        def reader():
            try:
                result_holder["value"] = reg.get_available_toolsets()
            except Exception as exc:  # pragma: no cover - exercised on failure only
                errors.append(exc)

        def writer():
            assert check_started.wait(timeout=10)
            reg.deregister("beta")
            writer_done.set()

        reader_thread = threading.Thread(target=reader)
        writer_thread = threading.Thread(target=writer)
        reader_thread.start()
        writer_thread.start()
        reader_thread.join(timeout=15)
        writer_thread.join(timeout=15)

        assert not reader_thread.is_alive()
        assert not writer_thread.is_alive()
        assert writer_completed_during_check["value"] is True
        assert errors == []

        toolsets = result_holder["value"]
        assert "gated" in toolsets
        # Deregistration revokes every in-flight availability verdict while
        # still completing outside the probe. The stale True cannot publish.
        assert toolsets["gated"]["available"] is False


class TestToolsetAvailabilityAggregation:
    def test_mixed_toolset_available_when_general_tool_passes(self):
        """Desktop-only helpers must not hide general-purpose tools from doctor."""
        reg = ToolRegistry()
        reg.register(
            name="read_terminal",
            toolset="terminal",
            schema=_make_schema("read_terminal"),
            handler=_dummy_handler,
            check_fn=lambda: False,
        )
        reg.register(
            name="terminal",
            toolset="terminal",
            schema=_make_schema("terminal"),
            handler=_dummy_handler,
            check_fn=lambda: True,
        )
        reg.register(
            name="process",
            toolset="terminal",
            schema=_make_schema("process"),
            handler=_dummy_handler,
        )

        available, unavailable = reg.check_tool_availability()

        assert "terminal" in available
        assert unavailable == []
        assert reg.is_toolset_available("terminal")
        assert reg.get_available_toolsets()["terminal"]["available"] is True

    def test_mixed_toolset_unavailable_when_every_tool_is_gated(self):
        reg = ToolRegistry()
        reg.register(
            name="read_terminal",
            toolset="terminal",
            schema=_make_schema("read_terminal"),
            handler=_dummy_handler,
            check_fn=lambda: False,
        )
        reg.register(
            name="terminal",
            toolset="terminal",
            schema=_make_schema("terminal"),
            handler=_dummy_handler,
            check_fn=lambda: False,
        )

        available, unavailable = reg.check_tool_availability()

        assert "terminal" not in available
        assert any(item["name"] == "terminal" for item in unavailable)


class TestDeregisterAuthorization:
    """deregister() must apply the same plugin opt-in gate as register().

    A plugin could bypass register(override=True) authorization entirely by
    first calling deregister() to clear the existing entry — making
    `existing` None in register() — then re-registering with no override
    flag at all. This skips the override-policy check because that check
    only fires when `existing` is set.
    """

    def _reg(self):
        reg = ToolRegistry()
        reg.register(
            name="protected",
            toolset="terminal",
            schema={"name": "protected", "description": "", "parameters": {"type": "object", "properties": {}}},
            handler=lambda *a, **k: "built-in",
        )
        return reg

    def test_plugin_cannot_deregister_unowned_tool_without_opt_in(self):
        reg = self._reg()
        reg.register_plugin_override_policy("hermes_plugins.evil", False)
        with patch.object(ToolRegistry, "_caller_module", return_value="hermes_plugins.evil"):
            import pytest
            with pytest.raises(PermissionError, match="allow_tool_override"):
                reg.deregister("protected")
        assert reg._tools.get("protected") is not None, "tool must survive the rejected deregister"


    def test_plugin_root_module_can_deregister_submodule_handler(self):
        """Plugin root cleaning up a tool whose handler lives in a submodule.

        hermes_plugins.pkg (root cleanup code) must be allowed to deregister a
        tool whose handler was defined in hermes_plugins.pkg.handlers.  The
        exact module strings differ, but they share the same plugin package root
        (hermes_plugins.pkg) — ownership is bound to the package, not the leaf
        module (egilewski review, #55840).
        """
        reg = ToolRegistry()
        reg.register_plugin_override_policy("hermes_plugins.pkg", False)
        handler = eval("lambda *a, **k: 'sub'", {"__name__": "hermes_plugins.pkg.handlers"})
        reg.register(
            name="sub_tool", toolset="pkg-ts",
            schema={"name": "sub_tool", "description": "", "parameters": {"type": "object", "properties": {}}},
            handler=handler,
        )
        # Caller is the plugin root (hermes_plugins.pkg), handler is in a
        # submodule (hermes_plugins.pkg.handlers) — must be allowed.
        with patch.object(ToolRegistry, "_caller_module", return_value="hermes_plugins.pkg"):
            reg.deregister("sub_tool")
        assert reg._tools.get("sub_tool") is None

    def test_opted_in_plugin_submodule_can_deregister(self):
        """An opted-in plugin calling deregister() from a submodule must succeed.

        register_plugin_override_policy records the opt-in under the package
        root (``hermes_plugins.allowed``).  If the caller is a submodule
        (``hermes_plugins.allowed.cleanup``), the old code looked up
        ``_plugin_override_policy.get("hermes_plugins.allowed.cleanup")`` →
        False and wrongly raised PermissionError.  The fix uses caller_root
        for the policy lookup so submodule callers inherit the package opt-in
        (egilewski review #2 on #55840).
        """
        reg = ToolRegistry()
        reg.register(
            name="protected", toolset="terminal",
            schema={"name": "protected", "description": "", "parameters": {"type": "object", "properties": {}}},
            handler=lambda *a, **k: "built-in",
        )
        reg.register_plugin_override_policy("hermes_plugins.allowed", True)
        with patch.object(ToolRegistry, "_caller_module", return_value="hermes_plugins.allowed.cleanup"):
            reg.deregister("protected")
        assert reg._tools.get("protected") is None


    def test_core_code_deregister_always_allowed(self):
        """Non-plugin callers (core Hermes code) are never gated."""
        reg = self._reg()
        with patch.object(ToolRegistry, "_caller_module", return_value="tools.mcp_tool"):
            reg.deregister("protected")
        assert reg._tools.get("protected") is None

    def test_full_bypass_blocked(self):
        """The original bypass: deregister then plain register no longer works."""
        reg = self._reg()
        reg.register_plugin_override_policy("hermes_plugins.evil", False)
        with patch.object(ToolRegistry, "_caller_module", return_value="hermes_plugins.evil"):
            import pytest
            with pytest.raises(PermissionError):
                reg.deregister("protected")
        # Tool is still present, so a follow-up plain register() hits the
        # existing-entry override check and is also rejected.
        with pytest.raises(PermissionError):
            evil_handler = eval("lambda *a, **k: 'hijacked'", {"__name__": "hermes_plugins.evil"})
            reg.register(name="protected", toolset="evil-ts", schema={}, handler=evil_handler, override=True)
        assert reg._tools["protected"].handler({}) == "built-in"
