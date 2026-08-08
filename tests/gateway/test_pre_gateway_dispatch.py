"""Tests for the pre_gateway_dispatch plugin hook.

The hook allows plugins to intercept incoming messages before auth and
agent dispatch. It runs in _handle_message and acts on returned action
dicts: {"action": "skip"|"rewrite"|"allow"}.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import GatewayConfig, Platform, PlatformConfig
from gateway.platforms.base import MessageEvent
from gateway.session import SessionSource


def _clear_auth_env(monkeypatch) -> None:
    for key in (
        "TELEGRAM_ALLOWED_USERS",
        "WHATSAPP_ALLOWED_USERS",
        "GATEWAY_ALLOWED_USERS",
        "TELEGRAM_ALLOW_ALL_USERS",
        "WHATSAPP_ALLOW_ALL_USERS",
        "GATEWAY_ALLOW_ALL_USERS",
    ):
        monkeypatch.delenv(key, raising=False)


def _make_event(text: str = "hello", platform: Platform = Platform.WHATSAPP) -> MessageEvent:
    return MessageEvent(
        text=text,
        message_id="m1",
        source=SessionSource(
            platform=platform,
            user_id="15551234567@s.whatsapp.net",
            chat_id="15551234567@s.whatsapp.net",
            user_name="tester",
            chat_type="dm",
        ),
    )


def _make_runner(platform: Platform):
    from gateway.run import GatewayRunner

    config = GatewayConfig(
        platforms={platform: PlatformConfig(enabled=True)},
    )
    runner = object.__new__(GatewayRunner)
    runner.config = config
    adapter = SimpleNamespace(send=AsyncMock())
    runner.adapters = {platform: adapter}
    runner.pairing_store = MagicMock()
    runner.pairing_store.is_approved.return_value = False
    runner.pairing_store._is_rate_limited.return_value = False
    runner.session_store = MagicMock()
    runner._running_agents = {}
    runner._update_prompt_pending = {}
    return runner, adapter


def _critical_juno_runner():
    runner, adapter = _make_runner(Platform.WHATSAPP)
    runner.config = GatewayConfig(
        platforms={Platform.WHATSAPP: PlatformConfig(enabled=True)},
        enabled_plugins=("juno_kite_trusted_principal",),
        juno_kite_trusted_principal={
            "version": 2,
            "enabled": True,
            "mode": "juno",
            "profile": "juno",
            "kite_plugin": "juno_kite_trusted_principal",
            "mapping_path": "/private/tmp/synthetic-juno-critical.sqlite3",
            "mapping_key_env": "SYNTHETIC_MAPPING_KEY",
            "request_key_env": "SYNTHETIC_REQUEST_KEY",
            "response_key_env": "SYNTHETIC_RESPONSE_KEY",
            "kite_peer": "kite",
            "kite_url": "http://127.0.0.1:9917",
            "policy_generation": "synthetic-v2",
            "allowed_group_conversations": [
                {"platform": "whatsapp", "chat_id": "300000000000000@g.us"}
            ],
            "principal_bindings": [
                {
                    "platform": "whatsapp",
                    "user_id": "15551234567@s.whatsapp.net",
                    "principal": "owner",
                }
            ],
            "policy": {
                "principals": {
                    "owner": {
                        "conversation_eligibility": {"dm": True, "group": True},
                        "required_group_co_principals": [],
                        "read_capability_ids": ["private.owner"],
                        "action_capability_ids": [],
                        "semantic_policy": {"private.owner": {"disclose": ["own"]}},
                    }
                },
                "tool_classes": {"read": ["read_file"], "mutating": []},
                "action_rules": [],
            },
            "limits": {
                "question_chars": 120,
                "context_turns": 2,
                "context_turn_chars": 48,
                "handoff_bytes": 2400,
                "policy_view_chars": 3000,
                "output_chars": 64,
                "response_bytes": 1800,
                "turn_ttl_seconds": 30,
                "roster_timeout_seconds": 2,
            },
        },
    )
    runner._active_profile_name = lambda: "juno"
    runner._is_user_authorized = MagicMock(
        side_effect=AssertionError("authorization must not run")
    )
    runner._async_session_store = SimpleNamespace(
        _store=runner.session_store,
        get_or_create_session=AsyncMock(
            side_effect=AssertionError("session access must not run")
        ),
    )
    runner._handle_message_with_agent = AsyncMock(
        side_effect=AssertionError("model dispatch must not run")
    )
    return runner, adapter


@pytest.mark.asyncio
async def test_internal_events_bypass_hook(monkeypatch):
    """Internal events (event.internal=True) skip the plugin hook entirely."""
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("WHATSAPP_ALLOWED_USERS", "*")

    called = {"count": 0}

    def _fake_hook(name, **kwargs):
        called["count"] += 1
        return [{"action": "skip"}]

    async def _capture(event, source, _quick_key, _run_generation):
        return "ok"

    monkeypatch.setattr("hermes_cli.plugins.invoke_hook", _fake_hook)

    runner, _adapter = _make_runner(Platform.WHATSAPP)
    runner._handle_message_with_agent = _capture  # noqa: SLF001

    event = _make_event("hi")
    event.internal = True

    # Even though the hook would say skip, internal events bypass it.
    await runner._handle_message(event)
    assert called["count"] == 0


@pytest.mark.asyncio
async def test_hook_fires_without_session_store_attribute(monkeypatch):
    """A runner missing session_store still delivers the event to plugins.

    Regression: the hook kwargs read ``self.session_store`` directly, so a
    partially-initialized runner raised AttributeError inside the dispatch
    try-block — the hook never fired, and every message logged
    "pre_gateway_dispatch invocation failed: 'GatewayRunner' object has no
    attribute 'session_store'". Plugins must receive the event (with
    session_store=None) instead.
    """
    _clear_auth_env(monkeypatch)

    seen = {}

    def _fake_hook(name, **kwargs):
        if name == "pre_gateway_dispatch":
            seen["session_store"] = kwargs.get("session_store", "MISSING")
            return [{"action": "skip", "reason": "plugin-handled"}]
        return []

    monkeypatch.setattr("hermes_cli.plugins.invoke_hook", _fake_hook)

    runner, adapter = _make_runner(Platform.WHATSAPP)
    del runner.session_store

    result = await runner._handle_message(_make_event("hi"))
    assert result is None
    # Hook actually fired (skip short-circuited before auth) with a None store.
    assert seen == {"session_store": None}
    adapter.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_awaited_hook_skips_before_auth_and_session_creation(monkeypatch):
    """Async authority hooks finish on the dispatch task before every auth/session path."""
    _clear_auth_env(monkeypatch)
    order = []

    async def _decision():
        order.append("hook")
        return {"action": "skip", "reason": "synthetic-protected-principal"}

    def _fake_hook(name, **_kwargs):
        assert name == "pre_gateway_dispatch"
        return [_decision()]

    monkeypatch.setattr("hermes_cli.plugins.invoke_hook", _fake_hook)
    runner, adapter = _make_runner(Platform.WHATSAPP)
    runner._is_user_authorized = MagicMock(
        side_effect=AssertionError("authorization ran before authority hook")
    )
    runner._async_session_store = SimpleNamespace(
        _store=runner.session_store,
        get_or_create_session=AsyncMock(
            side_effect=AssertionError("session creation ran before authority hook")
        )
    )

    assert await runner._handle_message(_make_event("protected")) is None
    assert order == ["hook"]
    adapter.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_critical_sync_callback_failure_is_silent_before_all_effects(
    monkeypatch, caplog
):
    from hermes_cli.plugins import get_plugin_manager

    def broken_callback(**_kwargs):
        raise RuntimeError("synthetic callback failure")

    manager = get_plugin_manager()
    monkeypatch.setitem(manager._hooks, "pre_gateway_dispatch", [broken_callback])
    runner, adapter = _critical_juno_runner()

    assert await runner._handle_message(_make_event("protected")) is None
    adapter.send.assert_not_awaited()
    assert "15551234567" not in caplog.text


@pytest.mark.asyncio
async def test_critical_async_callback_failure_is_silent_before_all_effects(
    monkeypatch, caplog
):
    async def broken_callback():
        raise RuntimeError("synthetic awaited failure")

    monkeypatch.setattr(
        "hermes_cli.plugins.invoke_hook",
        lambda _name, **_kwargs: [broken_callback()],
    )
    runner, adapter = _critical_juno_runner()

    assert await runner._handle_message(_make_event("protected")) is None
    adapter.send.assert_not_awaited()
    assert "15551234567" not in caplog.text


@pytest.mark.asyncio
async def test_critical_hook_invoker_failure_is_silent_before_all_effects(
    monkeypatch, caplog
):
    def broken_invoker(*_args, **_kwargs):
        raise RuntimeError("synthetic invoker failure")

    monkeypatch.setattr("hermes_cli.lifecycle.invoke_hook", broken_invoker)
    runner, adapter = _critical_juno_runner()

    assert await runner._handle_message(_make_event("protected")) is None
    adapter.send.assert_not_awaited()
    assert "15551234567" not in caplog.text


@pytest.mark.asyncio
async def test_malformed_critical_result_is_silent_before_all_effects(monkeypatch):
    monkeypatch.setattr(
        "hermes_cli.plugins.invoke_hook",
        lambda _name, **_kwargs: [
            {
                "action": "critical_allow",
                "scope": "juno-trusted-principal-v2",
            }
        ],
    )
    runner, adapter = _critical_juno_runner()

    assert await runner._handle_message(_make_event("protected")) is None
    adapter.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_well_formed_critical_result_without_bound_token_fails_closed(
    monkeypatch,
):
    monkeypatch.setattr(
        "hermes_cli.plugins.invoke_hook",
        lambda _name, **_kwargs: [
            {
                "action": "critical_allow",
                "scope": "juno-trusted-principal-v2",
                "redact_scope": True,
            }
        ],
    )
    runner, adapter = _critical_juno_runner()

    assert await runner._handle_message(_make_event("protected")) is None
    adapter.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_gateway_startup_reload_uses_active_juno_profile_and_reaches_dispatch(
    tmp_path, monkeypatch, caplog
):
    """Gateway startup replaces a stale hook with the active-profile runtime."""
    import hermes_cli.plugins as plugins_module
    import plugins.juno_kite_trusted_principal as juno_plugin
    import tools.registry as registry_module
    from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
    from tools.registry import ToolRegistry

    runner, _adapter = _critical_juno_runner()
    section = runner.config.juno_kite_trusted_principal
    section["mapping_path"] = str(tmp_path / "mapping.sqlite3")
    host_config = {
        "a2a_agents": {
            "kite": {
                "url": "http://127.0.0.1:9917",
                "auth": {"type": "bearer", "token": "synthetic-peer-token"},
                "timeout": 5,
            }
        },
        "juno_kite_trusted_principal": section,
    }
    monkeypatch.setenv("SYNTHETIC_MAPPING_KEY", "m" * 32)
    monkeypatch.setenv("SYNTHETIC_REQUEST_KEY", "r" * 32)
    monkeypatch.setenv("SYNTHETIC_RESPONSE_KEY", "s" * 32)
    monkeypatch.setattr("hermes_cli.config.load_config", lambda: host_config)
    monkeypatch.setattr(
        "hermes_cli.profiles.get_active_profile_name", lambda: "default"
    )

    manager = PluginManager()
    monkeypatch.setattr(plugins_module, "_plugin_manager", manager)
    monkeypatch.setattr(registry_module, "registry", ToolRegistry())
    context = PluginContext(
        PluginManifest(name="juno_kite_trusted_principal", source="bundled"),
        manager,
    )
    juno_plugin.register(context)

    stale_callback = manager._hooks["pre_gateway_dispatch"][0]
    assert stale_callback.__self__.active_profile == "default"

    monkeypatch.setattr(
        "hermes_cli.profiles.get_active_profile_name", lambda: "juno"
    )

    def reload_active_profile_plugins():
        juno_plugin.register(context)

    monkeypatch.setattr(
        manager, "_discover_and_load_inner", reload_active_profile_plugins
    )
    runner._reload_plugins_for_active_profile()

    callback = manager._hooks["pre_gateway_dispatch"][0]
    assert callback.__self__.active_profile == "juno"
    observed = []

    async def tracked_callback(**kwargs):
        result = await callback(**kwargs)
        observed.append(result)
        return result

    manager._hooks["pre_gateway_dispatch"] = [tracked_callback]
    runner._is_user_authorized = MagicMock(return_value=True)
    runner._handle_message_with_agent = AsyncMock(return_value="restored-reply")

    assert await runner._handle_message(_make_event("protected")) == "restored-reply"
    assert observed == [
        {
            "action": "critical_allow",
            "scope": "juno-trusted-principal-v2",
            "redact_scope": True,
        }
    ]
    runner._handle_message_with_agent.assert_awaited_once()
    assert "protected pre_gateway_dispatch proof missing" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("malformed", (None, {"version": 2, "mode": "juno", "profile": "juno"}))
async def test_missing_or_malformed_dedicated_config_is_silent_before_all_effects(
    malformed, monkeypatch
):
    monkeypatch.setattr("hermes_cli.plugins.invoke_hook", lambda _name, **_kwargs: [])
    runner, adapter = _critical_juno_runner()
    runner.config.juno_kite_trusted_principal = malformed

    assert await runner._handle_message(_make_event("protected")) is None
    adapter.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_critical_await_cancellation_is_silent_before_all_effects(monkeypatch):
    async def cancelled_callback():
        raise asyncio.CancelledError

    monkeypatch.setattr(
        "hermes_cli.plugins.invoke_hook",
        lambda _name, **_kwargs: [cancelled_callback()],
    )
    runner, adapter = _critical_juno_runner()

    assert await runner._handle_message(_make_event("protected")) is None
    adapter.send.assert_not_awaited()


@pytest.mark.asyncio
async def test_non_juno_hook_failure_retains_legacy_nonfatal_behavior(monkeypatch):
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("WHATSAPP_ALLOWED_USERS", "*")
    monkeypatch.setattr(
        "hermes_cli.lifecycle.invoke_hook",
        MagicMock(side_effect=RuntimeError("ordinary plugin failure")),
    )
    runner, _adapter = _make_runner(Platform.WHATSAPP)
    handled = AsyncMock(return_value="ordinary-result")
    runner._handle_message_with_agent = handled

    assert await runner._handle_message(_make_event("ordinary")) == "ordinary-result"
    handled.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mismatch",
    ("platform", "profile", "mode", "configured_profile", "version", "disabled", "multiplex"),
)
async def test_critical_scope_mismatches_cannot_claim_fail_closed_behavior(
    mismatch, monkeypatch
):
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("WHATSAPP_ALLOWED_USERS", "*")
    runner, _adapter = _critical_juno_runner()
    event = _make_event("ordinary")
    if mismatch == "platform":
        event = _make_event("ordinary", Platform.TELEGRAM)
        runner.config.platforms[Platform.TELEGRAM] = PlatformConfig(enabled=True)
    elif mismatch == "profile":
        runner._active_profile_name = lambda: "default"
    elif mismatch == "mode":
        runner.config.juno_kite_trusted_principal["mode"] = "kite"
    elif mismatch == "configured_profile":
        runner.config.juno_kite_trusted_principal["profile"] = "other"
    elif mismatch == "version":
        runner.config.juno_kite_trusted_principal["version"] = 1
    elif mismatch == "disabled":
        runner.config.enabled_plugins = ()
    else:
        runner.config.multiplex_profiles = True
    monkeypatch.setattr(
        "hermes_cli.lifecycle.invoke_hook",
        MagicMock(side_effect=RuntimeError("ordinary isolated failure")),
    )
    runner._is_user_authorized = MagicMock(return_value=True)
    handled = AsyncMock(return_value="ordinary-result")
    runner._handle_message_with_agent = handled

    assert await runner._handle_message(event) == "ordinary-result"
    handled.assert_awaited_once()
