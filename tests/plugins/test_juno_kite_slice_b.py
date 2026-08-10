"""Slice B semantic disclosure and exact private-read connector tests.

All connector data and identities are synthetic. No test contacts a private
provider, starts a listener, or reads an operator source.
"""

from __future__ import annotations

import copy
import json
from contextvars import copy_context
from pathlib import Path
from types import SimpleNamespace

import pytest

from gateway.session_context import clear_session_vars, set_session_vars
from plugins.juno_kite_trusted_principal.disclosure import (
    BOUNDED_EXCERPT,
    BULK_RAW,
    DOCUMENT_DESCRIPTOR,
    MINIMIZED,
    classify_output_tier,
    disclosure_decision,
    generated_semantic_guidance,
)
from plugins.juno_kite_trusted_principal.private_reads import (
    KITE_GMAIL,
    PERSONAL_GMAIL,
    PRIVATE_READ_TOOLSET,
    THINGS_CLIENT,
    THINGS_ENDPOINT,
    THINGS_PROJECT_TITLE,
    THINGS_PROJECT_UUID,
    TOOL_NAMES,
    TOOL_SCHEMAS,
    WHATSAPP_QUERY,
    PrivateReadService,
)
from plugins.juno_kite_trusted_principal.runtime import (
    RESPONSE_PREFIX,
    TrustedPrincipalRuntime,
)
from tests.plugins.test_juno_kite_trusted_principal import (
    _base_config,
    _run_in_session,
)


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setenv("JK_MAPPING_KEY", "mapping-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_REQUEST_KEY", "request-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_RESPONSE_KEY", "response-key-with-at-least-thirty-two-bytes")


@pytest.fixture(autouse=True)
def _fresh_preview_cache():
    """No test inherits another's extraction.

    The document preview cache is process-global on purpose -- it exists so a
    later turn does not pay the recogniser again -- which means a test that
    stubs the reader would otherwise be answered by whatever an earlier test
    stubbed for the same bytes.
    """
    from plugins.juno_kite_trusted_principal import private_reads as pr

    pr._reset_document_preview_cache()
    yield
    pr._reset_document_preview_cache()


class RecordingBackend:
    def __init__(self, results=None, failure=None):
        self.results = dict(results or {})
        self.failure = failure
        self.calls = []

    def execute(self, operation, args):
        self.calls.append((operation, copy.deepcopy(args)))
        if self.failure:
            raise self.failure
        value = self.results.get(operation, [])
        return copy.deepcopy(value(args) if callable(value) else value)


def _slice_b_config(tmp_path: Path, *, mode="juno") -> dict:
    config = _base_config(tmp_path)
    section = config["juno_kite_trusted_principal"]
    section.update(
        mode=mode,
        profile=mode,
        policy_generation="slice-b-policy-v1",
        private_reads={
            "enabled": True,
            "timeout_seconds": 5,
            "output_bytes": 65_536,
        },
    )
    section["limits"].update(
        question_chars=512,
        policy_view_chars=20_000,
        output_chars=4_000,
        response_bytes=12_000,
    )
    principals = section["policy"]["principals"]
    shared = [
        "juno.public",
        "juno.shared.children",
        "juno.shared.family",
        "juno.shared.mauritius",
        "juno.shared.property_intel",
        "juno.shared.villa_lena",
    ]
    james_caps = ["juno.private.james", *shared]
    principals["james"].update(
        read_capability_ids=james_caps,
        action_capability_ids=[],
        semantic_policy={name: {"domain": name} for name in james_caps},
    )
    principals["lucy"].update(
        conversation_eligibility={"dm": True, "group": True},
        read_capability_ids=shared,
        action_capability_ids=[],
        semantic_policy={name: {"domain": name} for name in shared},
    )
    section["policy"]["tool_classes"] = {"read": [], "mutating": []}
    section["policy"]["action_rules"] = []
    return config


def _runtime(tmp_path: Path, *, mode="juno", backends=None):
    return TrustedPrincipalRuntime(
        _slice_b_config(tmp_path, mode=mode),
        active_profile=mode,
        private_read_backends=backends,
    )


def _bound_turn(
    tmp_path: Path,
    backends,
    callback,
    question="What is the current status?",
    *,
    principal="james",
):
    juno = _runtime(tmp_path, mode="juno", backends=backends)
    user_id = "fixture-user-101" if principal == "james" else "fixture-user-202"
    prepared = _run_in_session(
        lambda: juno._prepare_request({"question_or_goal": question}),
        platform="telegram",
        user_id=user_id,
        session_key=f"conversation-slice-b-{principal}",
        profile="juno",
    )
    call = {
        "message": prepared.message,
        "context_id": prepared.mapping.context_id,
    }
    kite = _runtime(tmp_path, mode="kite", backends=backends)

    def turn():
        policy = kite.pre_llm_call(
            user_message=call["message"],
            session_id="kite-session",
            turn_id="kite-turn",
        )
        assert "source-agnostic policy view" in policy["context"]
        return callback(kite)

    return _run_in_session(
        turn,
        platform="a2a",
        user_id="juno",
        session_key=f"agent:kite:a2a:dm:{call['context_id']}",
        profile="kite",
        chat_id=call["context_id"],
    )


def _invoke(kite, name, args):
    assert (
        kite.pre_tool_call(
            name,
            args,
            session_id="kite-session",
            turn_id="kite-turn",
            tool_call_id="call-1",
        )
        is None
    )
    assert (
        kite.pre_tool_dispatch(
            name,
            args,
            session_id="kite-session",
            turn_id="kite-turn",
            tool_call_id="call-1",
        )
        is None
    )
    return json.loads(kite.execute_private_read(name, args, session_id="kite-session"))


def test_kite_registers_only_exact_private_read_surface(tmp_path, monkeypatch):
    import plugins.juno_kite_trusted_principal as plugin

    kite = _runtime(tmp_path, mode="kite", backends={})
    monkeypatch.setattr(plugin, "runtime_from_host", lambda _profile: kite)
    context = SimpleNamespace(
        profile_name="kite",
        tools=[],
        hooks=[],
        register_tool=lambda **kwargs: context.tools.append(kwargs),
        register_hook=lambda name, callback: context.hooks.append((name, callback)),
    )
    plugin.register(context)
    assert {item["name"] for item in context.tools} == set(TOOL_NAMES)
    assert {item["toolset"] for item in context.tools} == {"juno_kite_private_reads"}
    assert all(item["check_fn"]() is True for item in context.tools)
    assert not {
        "terminal",
        "execute_code",
        "read_file",
        "search_files",
        "write_file",
        "patch",
        "a2a_call",
        "mcp_call",
        "homeassistant",
        "cron",
        "send_message",
    }.intersection(item["name"] for item in context.tools)


def test_juno_registers_no_private_read_tools(tmp_path, monkeypatch):
    import plugins.juno_kite_trusted_principal as plugin

    juno = _runtime(tmp_path)
    monkeypatch.setattr(plugin, "runtime_from_host", lambda _profile: juno)
    tools = []
    context = SimpleNamespace(
        profile_name="juno",
        register_tool=lambda **kwargs: tools.append(kwargs),
        register_hook=lambda *_args: None,
    )
    plugin.register(context)
    assert [item["name"] for item in tools] == ["consult_kite"]


def test_direct_kite_read_denies_before_backend(tmp_path):
    backend = RecordingBackend({"search": [{"id": "m1"}]})
    kite = _runtime(tmp_path, mode="kite", backends={"gmail": backend})
    result = _run_in_session(
        lambda: json.loads(
            kite.execute_private_read(
                "kite_gmail_search",
                {"account": "personal", "query": "trip", "max_results": 5},
                session_id="direct-session",
            )
        ),
        platform="cli",
        user_id="local",
        session_key="direct-kite",
        profile="kite",
    )
    assert result["error"]["code"] == "authority_denied"
    assert backend.calls == []


@pytest.mark.parametrize(
    "tool",
    [
        "terminal",
        "execute_code",
        "read_file",
        "search_files",
        "write_file",
        "patch",
        "mcp_call",
        "ha_get_state",
        "a2a_call",
        "memory_add",
        "cron_create",
    ],
)
def test_generic_and_mutating_tools_remain_denied_under_claim(tmp_path, tool):
    def check(kite):
        decision = kite.pre_tool_call(
            tool, {}, session_id="kite-session", turn_id="kite-turn"
        )
        assert decision["action"] == "block"

    _bound_turn(tmp_path, {}, check)


def test_deferred_broker_gates_are_exact_and_same_turn_bound(tmp_path):
    calendar_args = {
        "account": "personal",
        "start": "2026-08-08T00:00:00+01:00",
        "end": "2026-08-09T00:00:00+01:00",
        "max_results": 5,
    }

    def check(kite):
        assert kite.pre_tool_call(
            "tool_describe",
            {"name": "kite_calendar_read"},
            session_id="kite-session",
            turn_id="kite-turn",
        ) is None
        for malformed in (
            {},
            {"name": "kite_calendar_read", "extra": True},
            {"name": "read_file"},
            {"name": " kite_calendar_read"},
        ):
            assert kite.pre_tool_call(
                "tool_describe",
                malformed,
                session_id="kite-session",
                turn_id="kite-turn",
            )["action"] == "block"
        assert kite.pre_tool_call(
            "tool_describe",
            {"name": "kite_calendar_read"},
            session_id="other-session",
            turn_id="kite-turn",
        )["action"] == "block"

        broker_call = {"name": "kite_calendar_read", "arguments": calendar_args}
        assert kite.pre_tool_call(
            "tool_call",
            broker_call,
            session_id="kite-session",
            turn_id="kite-turn",
        ) is None
        assert kite.pre_tool_dispatch(
            "kite_calendar_read",
            {**calendar_args, "max_results": 6},
            session_id="kite-session",
            turn_id="kite-turn",
        )["action"] == "block"
        for malformed in (
            {"name": "read_file", "arguments": {}},
            {"name": "kite_calendar_read", "arguments": {}},
            {
                "name": "kite_calendar_read",
                "arguments": {**calendar_args, "max_results": 51},
            },
            {**broker_call, "extra": True},
        ):
            assert kite.pre_tool_call(
                "tool_call",
                malformed,
                session_id="kite-session",
                turn_id="kite-turn",
            )["action"] == "block"

    _bound_turn(tmp_path, {}, check)


def test_an_unrelated_deferred_tool_is_not_this_plugins_business(tmp_path):
    """James could not reach his own Granola connector on his own profile.

    The broker fronts every deferred tool. This hook treated any
    tool_describe/tool_call in kite mode as a possible private read and
    demanded a Juno binding before looking at what was being brokered, so an
    ordinary Mattermost turn -- no A2A, no delegation, nothing to do with
    Juno -- came back as "Juno--Kite policy blocked tool call: internal or
    missing policy binding": a policy decision about a tool this plugin does
    not own, in the name of a lane that was not involved.
    """
    kite = _runtime(tmp_path, mode="kite", backends={})
    unrelated = "mcp__granola__list_meetings"

    def ordinary_turn():
        assert kite.pre_tool_call(
            "tool_describe", {"name": unrelated},
            session_id="mm-session", turn_id="mm-turn",
        ) is None
        assert kite.pre_tool_call(
            "tool_call", {"name": unrelated, "arguments": {"limit": 5}},
            session_id="mm-session", turn_id="mm-turn",
        ) is None
        # The final-dispatch gate is the parallel path and must agree.
        assert kite.pre_tool_dispatch(
            "tool_call", {"name": unrelated, "arguments": {"limit": 5}},
            session_id="mm-session", turn_id="mm-turn",
        ) is None
        # A broker request this plugin cannot read as naming one of its own
        # readers is equally not its business; the registry validates it.
        for shape in ({}, {"name": 123}, {"arguments": {}}, None, "not-a-dict"):
            assert kite.pre_tool_call(
                "tool_describe", shape,
                session_id="mm-session", turn_id="mm-turn",
            ) is None, shape
        # ...but naming a protected reader off the lane still fails closed,
        # which is the whole point of reading the target rather than the mode.
        assert kite.pre_tool_call(
            "tool_describe", {"name": "kite_calendar_read"},
            session_id="mm-session", turn_id="mm-turn",
        )["action"] == "block"

    _run_in_session(
        ordinary_turn,
        platform="mattermost",
        user_id="james-mattermost",
        session_key="ordinary-conversation",
        profile="kite",
    )


def test_deferred_brokers_are_blocked_outside_authenticated_a2a_turn(tmp_path):
    kite = _runtime(tmp_path, mode="kite", backends={})

    def direct():
        assert kite.pre_tool_call(
            "tool_describe",
            {"name": "kite_calendar_read"},
            session_id="direct-session",
            turn_id="direct-turn",
        )["action"] == "block"
        assert kite.pre_tool_call(
            "tool_call",
            {
                "name": "kite_gmail_search",
                "arguments": {
                    "account": "personal",
                    "query": "synthetic",
                    "max_results": 2,
                },
            },
            session_id="direct-session",
            turn_id="direct-turn",
        )["action"] == "block"

    _run_in_session(
        direct,
        platform="cli",
        user_id="local",
        session_key="direct-broker",
        profile="kite",
    )


def test_real_plugin_deferred_broker_describes_and_dispatches_once(
    tmp_path, monkeypatch
):
    """Production registry + deferred broker regression for B-ACTIVE-1/4/6."""
    import hermes_cli.plugins as plugins_module
    import model_tools
    import plugins.juno_kite_trusted_principal as plugin
    from hermes_cli.plugins import (
        PluginContext,
        PluginManager,
        PluginManifest,
        resolve_pre_tool_block,
    )
    from agent.tool_executor import plan_tool_batch
    from tools.registry import registry

    gmail = RecordingBackend({"search": [{"id": "synthetic-message-1"}]})
    calendar = RecordingBackend({"list": []})

    def check(kite):
        manager = PluginManager()
        monkeypatch.setattr(plugin, "runtime_from_host", lambda _profile: kite)
        monkeypatch.setattr(plugins_module, "_plugin_manager", manager)
        context = PluginContext(
            PluginManifest(
                name="juno_kite_trusted_principal", source="bundled"
            ),
            manager,
        )
        plugin.register(context)
        try:
            definitions = model_tools.get_tool_definitions(
                enabled_toolsets=[PRIVATE_READ_TOOLSET], quiet_mode=True
            )
            visible_names = {
                item["function"]["name"] for item in definitions
            }
            assert {"tool_search", "tool_describe", "tool_call"} <= visible_names
            assert not set(TOOL_NAMES).intersection(visible_names)

            for name in ("kite_calendar_read", "kite_gmail_search"):
                assert resolve_pre_tool_block(
                    "tool_describe",
                    {"name": name},
                    session_id="kite-session",
                    turn_id="kite-turn",
                ) is None
                described = json.loads(model_tools.handle_function_call(
                    "tool_describe",
                    {"name": name},
                    session_id="kite-session",
                    turn_id="kite-turn",
                    enabled_toolsets=[PRIVATE_READ_TOOLSET],
                    skip_pre_tool_call_hook=True,
                ))
                assert described["name"] == name
                assert described["parameters"] == TOOL_SCHEMAS[name]["parameters"]

            calls = (
                (
                    "kite_calendar_read",
                    {
                        "account": "personal",
                        "start": "2026-08-08T00:00:00+01:00",
                        "end": "2026-08-09T00:00:00+01:00",
                        "max_results": 5,
                    },
                ),
                (
                    "kite_gmail_search",
                    {
                        "account": "personal",
                        "query": "synthetic",
                        "max_results": 2,
                    },
                ),
            )
            for name, nested_args in calls:
                broker_args = {"name": name, "arguments": nested_args}
                model_call = SimpleNamespace(
                    id=f"call-{name}",
                    function=SimpleNamespace(
                        name="tool_call", arguments=json.dumps(broker_args)
                    ),
                )
                agent = SimpleNamespace(
                    enabled_toolsets=[PRIVATE_READ_TOOLSET],
                    disabled_toolsets=None,
                    valid_tool_names=visible_names,
                )
                planned = plan_tool_batch(agent, [model_call]).calls[0]
                assert planned.original_name == "tool_call"
                assert planned.effective_name == name
                assert planned.args == nested_args
                assert planned.scope_block is None
                assert resolve_pre_tool_block(
                    planned.effective_name,
                    planned.args,
                    session_id="kite-session",
                    turn_id="kite-turn",
                ) is None
                result = json.loads(model_tools.handle_function_call(
                    planned.effective_name,
                    planned.args,
                    session_id="kite-session",
                    turn_id="kite-turn",
                    enabled_toolsets=[PRIVATE_READ_TOOLSET],
                    skip_pre_tool_call_hook=True,
                ))
                assert result["status"] == "ok"

            assert len(calendar.calls) == 1
            assert len(gmail.calls) == 1

            mutated = {
                "account": "personal",
                "query": "synthetic",
                "max_results": 3,
            }
            assert resolve_pre_tool_block(
                "kite_gmail_search",
                {**mutated, "max_results": 2},
                session_id="kite-session",
                turn_id="kite-turn",
            ) is None
            blocked = json.loads(model_tools.handle_function_call(
                "kite_gmail_search",
                mutated,
                session_id="kite-session",
                turn_id="kite-turn",
                enabled_toolsets=[PRIVATE_READ_TOOLSET],
                skip_pre_tool_call_hook=True,
            ))
            assert "blocked" in blocked["error"].lower()
            assert len(gmail.calls) == 1

            assert resolve_pre_tool_block(
                "tool_describe",
                {"name": "read_file"},
                session_id="kite-session",
                turn_id="kite-turn",
            ) is not None
            assert resolve_pre_tool_block(
                "read_file",
                {},
                session_id="kite-session",
                turn_id="kite-turn",
            ) is not None
        finally:
            for name in TOOL_NAMES:
                registry.deregister(name)

    _bound_turn(
        tmp_path,
        {"gmail": gmail, "calendar": calendar},
        check,
    )


def test_read_argument_change_denies_before_backend(tmp_path):
    backend = RecordingBackend({"search": []})

    def check(kite):
        original = {"account": "personal", "query": "Mauritius", "max_results": 5}
        changed = {**original, "max_results": 6}
        assert (
            kite.pre_tool_call(
                "kite_gmail_search",
                original,
                session_id="kite-session",
                turn_id="kite-turn",
            )
            is None
        )
        denied = kite.pre_tool_dispatch(
            "kite_gmail_search",
            changed,
            session_id="kite-session",
            turn_id="kite-turn",
        )
        assert denied["action"] == "block"
        assert backend.calls == []

    _bound_turn(tmp_path, {"gmail": backend}, check)


def test_gmail_accounts_and_exact_id_chain(tmp_path):
    gmail = RecordingBackend({
        "search": [{"id": "message-1", "subject": "Synthetic trip"}],
        "get": {
            "id": "message-1",
            "body": "synthetic permitted body",
            "attachments": [{"attachment_id": "attachment-1", "filename": "trip.pdf"}],
        },
        "attachment_extract": {
            "filename": "trip.pdf",
            "mime_type": "application/pdf",
            "size_bytes": 120,
            "text": "synthetic extracted itinerary",
        },
    })

    def check(kite):
        search = _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "Mauritius", "max_results": 5},
        )
        assert search["status"] == "ok"
        message = _invoke(
            kite,
            "kite_gmail_get",
            {"account": "personal", "message_id": "message-1"},
        )
        assert message["status"] == "ok"
        attachment = _invoke(
            kite,
            "kite_gmail_attachment_extract",
            {
                "account": "personal",
                "message_id": "message-1",
                "attachment_id": "attachment-1",
            },
        )
        assert attachment["data"]["text"] == "synthetic extracted itinerary"
        denied = kite.pre_tool_call(
            "kite_gmail_get",
            {"account": "personal", "message_id": "not-returned"},
            session_id="kite-session",
            turn_id="kite-turn",
        )
        assert denied["action"] == "block"

    _bound_turn(tmp_path, {"gmail": gmail}, check)
    assert gmail.calls[0][1]["account_identity"] == PERSONAL_GMAIL
    assert (
        "work"
        not in TOOL_SCHEMAS["kite_gmail_search"]["parameters"]["properties"]["account"][
            "enum"
        ]
    )
    assert not any(
        word in TOOL_NAMES
        for word in ("gmail_send", "gmail_reply", "gmail_draft", "gmail_modify")
    )


def test_gmail_kite_identity_and_unsafe_attachment_denied(tmp_path):
    gmail = RecordingBackend({
        "search": [{"id": "m2"}],
        "get": {"id": "m2", "attachments": [{"attachmentId": "a2"}]},
        "attachment_extract": {
            "filename": "macro.docm",
            "mime_type": "application/vnd.ms-word.document.macroEnabled.12",
            "size_bytes": 20,
            "text": "never execute",
        },
    })

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "kite", "query": "ops", "max_results": 2},
        )
        _invoke(kite, "kite_gmail_get", {"account": "kite", "message_id": "m2"})
        result = _invoke(
            kite,
            "kite_gmail_attachment_extract",
            {"account": "kite", "message_id": "m2", "attachment_id": "a2"},
        )
        assert result["error"]["code"] == "unsupported_content"

    _bound_turn(tmp_path, {"gmail": gmail}, check)
    assert gmail.calls[0][1]["account_identity"] == KITE_GMAIL


def test_gmail_config_cannot_alias_personal_to_work_account():
    with pytest.raises(ValueError, match="personal and Kite"):
        PrivateReadService({
            "enabled": True,
            "gmail": {
                "executable": "/synthetic/google-wrapper",
                "account_aliases": {"personal": "work", "kite": "kite"},
            },
        })


def test_work_calendar_is_deterministically_projected(tmp_path):
    calendar = RecordingBackend({
        "list": [
            {
                "id": "secret-event-id",
                "title": "Acquisition at Company",
                "summary": "Secret",
                "attendees": ["private@example.test"],
                "description": "confidential body",
                "location": "office",
                "htmlLink": "https://calendar.invalid/secret",
                "organizer": {"email": "boss@example.test"},
                "conferenceData": {"url": "https://meet.invalid"},
                "attachments": [{"title": "board.pdf"}],
                "constraints": ["Meet Secret Company directors"],
                "start": {"dateTime": "2026-08-08T09:00:00+01:00"},
                "end": {"dateTime": "2026-08-08T10:00:00+01:00"},
                "timeZone": "Europe/London",
            }
        ]
    })

    def check(kite):
        result = _invoke(
            kite,
            "kite_calendar_read",
            {
                "account": "work_free_busy",
                "start": "2026-08-08T00:00:00+01:00",
                "end": "2026-08-09T00:00:00+01:00",
                "max_results": 5,
            },
        )
        interval = result["data"][0]
        assert set(interval) == {"status", "start", "end", "timezone", "constraints"}
        assert interval["status"] == "busy"
        rendered = json.dumps(interval)
        assert not any(
            value in rendered
            for value in ("Company", "Secret", "boss", "secret-event-id", "board.pdf")
        )

    _bound_turn(tmp_path, {"calendar": calendar}, check)


def test_things_is_pinned_to_exact_personal_project(tmp_path):
    things = RecordingBackend({"snapshot": [{"uuid": "task-1", "title": "Synthetic"}]})

    def check(kite):
        result = _invoke(kite, "kite_things_read", {"operation": "snapshot"})
        assert result["status"] == "ok"

    _bound_turn(tmp_path, {"things": things}, check)
    assert things.calls == [
        (
            "snapshot",
            {
                "operation": "snapshot",
                "project_title": THINGS_PROJECT_TITLE,
                "project_uuid": THINGS_PROJECT_UUID,
            },
        )
    ]
    with pytest.raises(ValueError):
        PrivateReadService({
            "enabled": True,
            "things": {
                "client": THINGS_CLIENT,
                "endpoint": THINGS_ENDPOINT,
                "project_uuid": "another-list",
                "project_title": THINGS_PROJECT_TITLE,
            },
        })


def test_property_and_whatsapp_use_typed_read_operations(tmp_path):
    prop = RecordingBackend({
        "property": {"id": "synthetic", "publicUrl": "https://property.invalid/p/1"}
    })
    whatsapp = RecordingBackend({"search": [{"message_id": "synthetic-message"}]})

    def check(kite):
        property_result = _invoke(
            kite,
            "kite_property_read",
            {
                "operation": "property",
                "property_id": "123e4567-e89b-12d3-a456-426614174000",
            },
        )
        archive_result = _invoke(
            kite,
            "kite_whatsapp_archive_read",
            {"operation": "search", "query": "Mauritius", "max_results": 5},
        )
        assert property_result["status"] == archive_result["status"] == "ok"

    _bound_turn(tmp_path, {"property_intel": prop, "whatsapp": whatsapp}, check)
    assert prop.calls[0][0] == "property"
    assert whatsapp.calls[0][0] == "search"
    assert not any(
        "sql" in json.dumps(schema).lower() for schema in TOOL_SCHEMAS.values()
    )


def test_property_payload_preserves_unknown_nested_fields_and_sanitizes_once(
    monkeypatch,
):
    property_id = "123e4567-e89b-12d3-a456-426614174000"
    monkeypatch.setenv("PROPERTY_AUTH_TOKEN", "configured-connector-token")
    backend = RecordingBackend({
        "property": {
            "id": property_id,
            "futureField": {
                "heritageScore": 97,
                "history": [
                    {
                        "eventId": "ordinary-history-id-44",
                        "note": (
                            "Survey complete. Authorization: Bearer escaped-secret; "
                            "retain this note."
                        ),
                    }
                ],
            },
            "documents": [
                {
                    "documentId": "doc-ordinary-9",
                    "url": "https://property.example.test/documents/doc-ordinary-9",
                    "metadata": {"pages": 14, "mimeType": "application/pdf"},
                }
            ],
            "auditNote": (
                r'keep this context {\"authorization\":\"Bearer serialized-secret\",'
                r'\"ordinary\":\"preserved\"}'
            ),
            "debugMessage": "prefix configured-connector-token suffix",
            "PROPERTY_AUTH_TOKEN": "configured-connector-token",
            "connector": {
                "headers": {"Authorization": "Bearer nested-secret"},
                "environment": {"PROPERTY_TOKEN": "environment-secret"},
                "auth": {"password": "password-secret"},
            },
            "refresh\u005ftoken": "escaped-key-secret",
            "privateKey": "-----BEGIN PRIVATE KEY----- secret material",
        }
    })
    service = PrivateReadService(
        {
            "enabled": True,
            "output_bytes": 65_536,
            "property_intel": {
                "base_url": "https://property.example.test",
                "auth_env": "PROPERTY_AUTH_TOKEN",
            },
        },
        backends={"property_intel": backend},
    )

    result = json.loads(service.execute(
        "kite_property_read",
        {"operation": "property", "property_id": property_id},
    ))

    assert result["status"] == "ok"
    data = result["data"]
    assert data["id"] == property_id
    assert data["futureField"]["heritageScore"] == 97
    assert data["futureField"]["history"][0]["eventId"] == "ordinary-history-id-44"
    assert data["documents"][0]["metadata"] == {
        "mimeType": "application/pdf",
        "pages": 14,
    }
    assert data["documents"][0]["url"].endswith("/doc-ordinary-9")
    assert "retain this note" in data["futureField"]["history"][0]["note"]
    rendered = json.dumps(data)
    for secret in (
        "escaped-secret",
        "nested-secret",
        "environment-secret",
        "password-secret",
        "escaped-key-secret",
        "PRIVATE KEY",
        "PROPERTY_TOKEN",
        "Authorization",
        "serialized-secret",
        "configured-connector-token",
    ):
        assert secret not in rendered


def test_property_payload_fails_closed_on_deep_or_oversized_data():
    property_id = "123e4567-e89b-12d3-a456-426614174000"
    deep: object = "leaf"
    for _ in range(20):
        deep = {"ordinary": deep}
    deep_service = PrivateReadService(
        {"enabled": True, "output_bytes": 65_536},
        backends={"property_intel": RecordingBackend({"property": deep})},
    )
    deep_result = json.loads(deep_service.execute(
        "kite_property_read",
        {"operation": "property", "property_id": property_id},
    ))
    assert deep_result["status"] == "error"
    assert deep_result["error"]["code"] == "depth_exceeded"
    assert deep_result["complete"] is False

    oversized_service = PrivateReadService(
        {"enabled": True, "output_bytes": 4096},
        backends={
            "property_intel": RecordingBackend({
                "property": {"futureOrdinaryField": "x" * 5000}
            })
        },
    )
    oversized_result = json.loads(oversized_service.execute(
        "kite_property_read",
        {"operation": "property", "property_id": property_id},
    ))
    assert oversized_result["status"] == "error"
    assert oversized_result["error"]["code"] == "cap_exceeded"
    assert oversized_result["complete"] is False


def test_property_mode_releases_arbitrary_sanitized_facts_as_bounded_prose(tmp_path):
    property_id = "123e4567-e89b-12d3-a456-426614174000"
    prop = RecordingBackend({
        "property": {
            "id": property_id,
            "futureField": {"heritageScore": 97},
        }
    })

    def check(kite):
        _invoke(
            kite,
            "kite_property_read",
            {"operation": "property", "property_id": property_id},
        )
        answer = (
            f"- Property ID: {property_id}\n"
            "- client_id: ordinary-buyer-record-7\n"
            "- The future heritage score is 97.\n"
            "- Contact: property-agent@example.test\n"
            "- Portal link: https://property.example.test/properties/record-44"
        )
        envelope_text = kite.transform_llm_output(
            response_text=answer, session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is False
        assert envelope["answer"] == answer

    _bound_turn(tmp_path, {"property_intel": prop}, check)


@pytest.mark.parametrize(
    "answer",
    [
        '{"id":"123e4567-e89b-12d3-a456-426614174000","futureField":97}',
        "```json\n[{\"id\":\"record-1\"}]\n```",
        "Authorization: Bearer output-secret",
    ],
)
def test_property_mode_denies_container_dumps_and_credentials(tmp_path, answer):
    prop = RecordingBackend({"property": {"futureField": 97}})

    def check(kite):
        _invoke(
            kite,
            "kite_property_read",
            {
                "operation": "property",
                "property_id": "123e4567-e89b-12d3-a456-426614174000",
            },
        )
        envelope_text = kite.transform_llm_output(
            response_text=answer, session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is True
        assert answer not in envelope_text

    _bound_turn(tmp_path, {"property_intel": prop}, check)


def test_property_mode_denies_over_limit_mixed_source_and_non_james(tmp_path):
    property_id = "123e4567-e89b-12d3-a456-426614174000"

    def over_limit(kite):
        _invoke(
            kite,
            "kite_property_read",
            {"operation": "property", "property_id": property_id},
        )
        answer = "Property fact. " * 500
        envelope = json.loads(
            kite.transform_llm_output(
                response_text=answer, session_id="kite-session"
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True
        assert envelope["answer"] == ""

    _bound_turn(
        tmp_path,
        {"property_intel": RecordingBackend({"property": {"id": property_id}})},
        over_limit,
    )

    def mixed(kite):
        _invoke(
            kite,
            "kite_property_read",
            {"operation": "property", "property_id": property_id},
        )
        _invoke(
            kite,
            "kite_whatsapp_archive_read",
            {"operation": "search", "query": "property", "max_results": 2},
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text=f"Property ID: {property_id}",
                session_id="kite-session",
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True

    _bound_turn(
        tmp_path,
        {
            "property_intel": RecordingBackend({"property": {"id": property_id}}),
            "whatsapp": RecordingBackend({"search": [{"message": "ordinary"}]}),
        },
        mixed,
    )

    def non_james(kite):
        _invoke(
            kite,
            "kite_property_read",
            {"operation": "property", "property_id": property_id},
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text="The future heritage score is 97.",
                session_id="kite-session",
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True

    _bound_turn(
        tmp_path,
        {"property_intel": RecordingBackend({"property": {"futureField": 97}})},
        non_james,
        principal="lucy",
    )


def test_property_mode_denies_wrong_final_turn_binding(tmp_path):
    prop = RecordingBackend({"property": {"futureField": 97}})

    def check(kite):
        _invoke(
            kite,
            "kite_property_read",
            {
                "operation": "property",
                "property_id": "123e4567-e89b-12d3-a456-426614174000",
            },
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text="The future heritage score is 97.",
                session_id="kite-session",
                turn_id="different-turn",
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True
        assert envelope["answer"] == ""

    _bound_turn(tmp_path, {"property_intel": prop}, check)


def test_only_configured_property_public_links_may_preserve_uuid(tmp_path):
    config = _slice_b_config(tmp_path, mode="kite")
    config["juno_kite_trusted_principal"]["private_reads"]["property_intel"] = {
        "base_url": "http://127.0.0.1:3917",
        "public_base_url": "https://property.example.test",
    }
    runtime = TrustedPrincipalRuntime(config, active_profile="kite")
    identifier = "123e4567-e89b-12d3-a456-426614174000"

    assert (
        runtime._leak_reason(
            f"Property: https://property.example.test/properties/{identifier}",
            output=True,
        )
        == ""
    )
    assert (
        runtime._leak_reason(f"Internal record {identifier}", output=True)
        == "UUID-shaped private identifier"
    )


def test_whatsapp_real_boundary_uses_argv_without_shell(tmp_path):
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="[]", stderr="")

    service = PrivateReadService(
        {
            "enabled": True,
            "whatsapp": {
                "executable": "/usr/bin/node",
                "script": WHATSAPP_QUERY,
                "state_dir": str(tmp_path / "archive"),
            },
        },
        command_runner=runner,
    )
    result = json.loads(
        service.execute(
            "kite_whatsapp_archive_read",
            {
                "operation": "search",
                "name": "Synthetic Family",
                "query": "trip",
                "since": "2026-08-01",
                "max_results": 5,
            },
        )
    )
    assert result["status"] == "ok"
    argv, kwargs = calls[0]
    assert argv[:2] == ["/usr/bin/node", WHATSAPP_QUERY]
    assert kwargs["shell"] is False
    assert kwargs["env"]["WHATSAPP_READONLY_STATE_DIR"] == str(tmp_path / "archive")
    assert not {"--send", "--reply", "--react", "--mark-read"}.intersection(argv)


def test_personal_file_containment_and_bounds(tmp_path):
    root = tmp_path / "personal"
    root.mkdir()
    (root / "trip.md").write_text("Synthetic Mauritius itinerary", encoding="utf-8")
    (root / ".hidden.md").write_text("hidden", encoding="utf-8")
    (root / "api_token.json").write_text("{}", encoding="utf-8")
    (root / "program.sh").write_text("echo no", encoding="utf-8")
    (root / "id_rsa.pem").write_text("synthetic key material", encoding="utf-8")
    # A format nobody anticipated is still a document: releasing a phone photo
    # while being unable to read or list it is how the allow-list failed.
    (root / "scan.heic").write_bytes(b"\x00\x00\x00\x18ftypheic")
    outside = tmp_path / "outside.md"
    outside.write_text("outside", encoding="utf-8")
    (root / "escape.md").symlink_to(outside)
    service = PrivateReadService({
        "enabled": True,
        "output_bytes": 4096,
        "files": {"roots": [{"name": "obsidian", "path": str(root)}],
                  "allowed_bases": [str(tmp_path)]},
    })
    found = json.loads(
        service.execute(
            "kite_personal_files_read",
            {
                "operation": "search",
                "root": "obsidian",
                "query": "Mauritius",
                "max_results": 5,
            },
        )
    )
    assert found["data"] == [
        {"relative_path": "trip.md", "root": "obsidian", "size_bytes": 29}
    ]
    read = json.loads(
        service.execute(
            "kite_personal_files_read",
            {
                "operation": "read",
                "root": "obsidian",
                "relative_path": "trip.md",
                "max_lines": 10,
            },
        )
    )
    assert read["data"]["text"] == "Synthetic Mauritius itinerary"
    for relative in (
        "../outside.md",
        "/etc/passwd",
        "escape.md",
        ".hidden.md",
        "api_token.json",
        "program.sh",
        "id_rsa.pem",
    ):
        denied = json.loads(
            service.execute(
                "kite_personal_files_read",
                {
                    "operation": "read",
                    "root": "obsidian",
                    "relative_path": relative,
                    "max_lines": 10,
                },
            )
        )
        assert denied["status"] == "error"
    allowed = json.loads(
        service.execute(
            "kite_personal_files_read",
            {
                "operation": "read",
                "root": "obsidian",
                "relative_path": "scan.heic",
                "max_lines": 10,
            },
        )
    )
    assert allowed["status"] != "error", allowed


def test_a_reference_number_is_not_a_phone_number(tmp_path):
    """Four passport numbers in a list were each read as a phone number.

    The only carve-out was for a value written directly after the words
    "passport number", and a list does not do that -- Kite's answer was
    "Alex Morgan Reed - 900000001 - 4 March 2032" and never used the
    word passport at all, so no rule about surrounding words could have
    saved it. What separates a phone number from a reference is its shape:
    a country code, a trunk zero, grouping, or enough digits to dial.
    """
    runtime = _runtime(tmp_path, mode="kite")
    releasable = (
        "Chris Taylor Reed - 900000002 - 12 June 2031\n"
        "Alex Morgan Reed - 900000001 - 4 March 2032\n"
        "Robin Casey Reed - 900000003 - 9 September 2032",
        "Ref 900000001",
        # An ISO date is eight digits and two hyphens, and was withheld as a
        # phone number: every answer that mentioned a plain date was denied.
        "Filed on 2026-08-10 at 15:37",
        "Filed 2026-08-10 15:37",
        "Invoice total GBP 47,500 on 2026-07-27",
        "Account sort code 20-00-00",
        # An em dash keeps the digits apart; a hyphen does not, and the list
        # has to survive either.
        "Chris Taylor Reed \u2014 900000002 \u2014 12 June 2031",
    )
    for answer in releasable:
        assert runtime._leak_reason(answer, output=True) == "", answer

    for answer in (
        "Call me on 07700 900123",
        "Reach him at +44 7973 235379",
        "His mobile is 07700900123",
        "US contact 2025550123",
        "Office: (020) 7946 0018",
        "Tel 202 555 0123",
        "+1 (415) 555-2671",
    ):
        assert runtime._leak_reason(answer, output=True) == (
            "phone-shaped private identifier"
        ), answer


def test_formatting_does_not_decide_whether_an_answer_leaks(tmp_path):
    """The answer was refused for containing the thing it was asked for.

    Kite read Lucy's passport correctly and wrote "Passport number:
    **900000001**". The bold broke the passport carve-out, the digits
    underneath were read as a phone number, and the whole answer was
    withheld -- reported to the requester as an authorization problem. The
    gap runs the other way too: emphasis inside a token slips a credential
    pattern that the flat text catches.
    """
    runtime = _runtime(tmp_path, mode="kite")
    for answer in (
        "Passport number: **900000001**\nExpiry date: **4 March 2032**",
        "Passport number: 900000001, expiry 4 March 2032",
        "Passport no. `900000001`",
    ):
        assert runtime._leak_reason(answer, output=True) == "", answer
    # What the filter is for is untouched.
    assert runtime._leak_reason("Call me on 07700 900123", output=True) == (
        "phone-shaped private identifier"
    )
    assert runtime._leak_reason("pass**word**: hunter2000000", output=True) == (
        "credential-shaped content"
    )


def test_a_read_of_a_scan_is_bounded_by_the_read_not_by_the_preview(monkeypatch):
    """The number was returned and the expiry was cut off.

    Every local reader imposed the 600-character preview length, whatever the
    caller asked for, so a read of a passport stopped mid-page: enough to show
    the number, not enough to reach the expiry date. The model reported that
    it could not verify the passport -- which is what a truncated document
    looks like from the inside -- and declined to give either.
    """
    import plugins.juno_kite_trusted_principal.private_reads as pr

    page = "Passport No 900000001 " + ("official observations " * 200) + "Expiry 14 MAR 2031"
    assert len(page) > 4000

    monkeypatch.setattr(pr, "_normalise_artifact", lambda data, mime: (data, mime))
    monkeypatch.setattr(pr.Path, "exists", lambda self: True)
    monkeypatch.setattr(
        pr.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=page),
    )

    preview = pr._document_preview(b"synthetic", "image/jpeg")
    assert len(preview) == 600
    assert "14 MAR 2031" not in preview  # a preview only has to tell them apart

    read = pr._document_preview(b"synthetic", "image/jpeg", limit=6000)
    assert "900000001" in read
    assert "14 MAR 2031" in read, "a read must reach the end of the page"

    # And the same for a PDF with a text layer, which uses the other reader.
    pdf = pr._document_preview(b"%PDF-1.4", "application/pdf", limit=6000)
    assert "14 MAR 2031" in pdf


def test_preview_converts_what_a_phone_produces_before_trying_to_read_it(monkeypatch):
    """A HEIC photo of a document read as blank, not as unreadable.

    The release path converts HEIC and TIFF locally before inspecting them;
    the preview path dispatched straight on MIME, so the formats a family
    actually photographs documents in fell to the "" branch -- which the
    model cannot tell apart from a genuinely unidentifiable file.
    """
    import plugins.juno_kite_trusted_principal.private_reads as pr

    converted: list[str] = []

    def _fake_normalise(data, mime_type):
        if mime_type in {"image/heic", "image/tiff"}:
            converted.append(mime_type)
            return data, "image/jpeg"
        return data, mime_type

    monkeypatch.setattr(pr, "_normalise_artifact", _fake_normalise)
    monkeypatch.setattr(
        pr, "_run_preview_reader", lambda argv, limit=600: "PASSPORT 533812947"
    )
    monkeypatch.setattr(pr.Path, "exists", lambda self: True)

    for mime in ("image/heic", "image/tiff", "image/jpeg"):
        assert pr._document_preview(b"synthetic", mime) == "PASSPORT 533812947", mime
    assert converted == ["image/heic", "image/tiff"]


def test_read_caps_a_document_on_what_it_loads_not_on_what_a_text_file_returns(
    tmp_path, monkeypatch
):
    """A scan is megabytes of image behind a few hundred characters of text.

    output_bytes caps what a tool returns, and for a text file that is also
    its size on disk, so one gate served for both. Charging an extracted
    document for the size of its image data made every passport unreadable
    -- "what is Lucy's passport number" could only be answered by sending
    Lucy's passport -- while the same file previewed and released fine.
    """
    root = tmp_path / "personal"
    root.mkdir()
    filler = b"0" * 23_000
    (root / "scan.pdf").write_bytes(b"%PDF-1.4\n" + filler)
    (root / "notes.md").write_text("x" * 23_000, encoding="utf-8")
    (root / "huge.pdf").write_bytes(b"%PDF-1.4\n" + b"0" * (8 * 1024 * 1024))

    seen: list[int] = []

    def _stub(data, mime_type, *, limit=600, pages=2):
        seen.append(len(data))
        return ("Synthetic passport. Number 000000000. Expiry 01 JAN 2030. " * 400)[
            :limit
        ]

    monkeypatch.setattr(
        "plugins.juno_kite_trusted_principal.private_reads._document_preview", _stub
    )
    service = PrivateReadService({
        "enabled": True,
        "output_bytes": 20_000,
        "files": {"roots": [{"name": "obsidian", "path": str(root)}],
                  "allowed_bases": [str(tmp_path)]},
    })

    def read(relative):
        return json.loads(
            service.execute(
                "kite_personal_files_read",
                {
                    "operation": "read",
                    "root": "obsidian",
                    "relative_path": relative,
                    "max_lines": 10,
                },
            )
        )

    extracted = read("scan.pdf")
    assert extracted["status"] != "error", extracted
    assert extracted["data"]["outcome"] == "extracted"
    assert "000000000" in extracted["data"]["text"]
    # The extractor was handed the whole document, well past output_bytes...
    assert seen == [23_009]
    # ...and what came back is bounded by what a read returns, shortened to
    # fit the configured cap rather than failing against it: half of the
    # 20_000-byte envelope here, well under the 40_000 a read may ask for.
    assert len(extracted["data"]["text"]) == 10_000

    # A text file still answers for its own size: there the two are the same.
    assert read("notes.md")["status"] == "error"
    # And the new gate is a gate, not an opening.
    assert read("huge.pdf")["status"] == "error"
    assert seen == [23_009]


@pytest.mark.parametrize(
    "text",
    [
        "password: synthetic-password",
        "api_key=synthetic-key",
        "refresh_token: synthetic-refresh",
        "cookie: synthetic-session-cookie",
        "OTP code: 123456",
        "recovery code: ABCD-1234",
        "pairing code: 987654",
        "QR payload: synthetic-qr-material",
        "cvv: 123",
        "-----BEGIN PRIVATE KEY-----",
        "https://login.invalid/magic?token=synthetic-token",
    ],
)
def test_authentication_material_is_detected(tmp_path, text):
    runtime = _runtime(tmp_path, mode="kite")
    assert runtime._leak_reason(text, output=True)


def test_passport_identifier_is_not_globally_a_credential(tmp_path):
    runtime = _runtime(tmp_path, mode="kite")
    assert runtime._leak_reason("Child passport number 123456789", output=True) == ""
    assert runtime._leak_reason("Child passport no. 123 456 789", output=True) == ""


@pytest.mark.parametrize(
    "question,tier",
    [
        ("What are the next steps?", MINIMIZED),
        ("Quote the exact wording needed", BOUNDED_EXCERPT),
        ("Send me the actual passport scan", DOCUMENT_DESCRIPTOR),
        ("Export the whole raw mailbox and headers", BULK_RAW),
        ("Export all Property Intel records", BULK_RAW),
    ],
)
def test_output_tiers(question, tier):
    assert classify_output_tier(question) == tier


@pytest.mark.parametrize(
    "question",
    [
        # Named real-world documents: people do not say "PDF" or "file".
        "Send me the nacho engagement letter",
        "attach the engagement letter",
        "email me the file",
        "forward me the birth certificate",
        "can you send me the tenancy agreement",
        "whatsapp me Albie's boarding pass",
        "I need the survey report",
        "share my driving licence",
        "send me the signed engagement letter PDF from Nacho",
        # Existing artifact-noun phrasings must keep working.
        "send me the passport scan",
        "send me the document",
        # Plural and polite forms.
        "send over the boarding passes",
        "can you send me the engagement letter",
        # Viewing verbs are delivery requests too: a passport cannot be
        # "shown" in a chat without releasing the actual image.
        "Show me Lucy's passport",
        "show me the engagement letter",
        "let me see Albie's boarding pass",
        "pull up the tenancy agreement",
        "I want you to send me Lucy's passport image as a file",
    ],
)
def test_named_document_requests_select_the_document_tier(question):
    assert classify_output_tier(question) == DOCUMENT_DESCRIPTOR


@pytest.mark.parametrize(
    "question",
    [
        # Informational intent wins even next to a delivery verb, so an
        # ordinary question never escalates into a file-release proposal.
        "what did nacho say",
        "send me a summary of the engagement letter",
        "tell me about the engagement letter",
        "what's in the terms of business",
        "when did nacho email",
        "send me an update on the villa",
        "send me a note about the letter",
        "remind me about the tenancy agreement",
        # A question about a document is not a request to be sent one.
        "did nacho send the agreement",
        "has the certificate arrived",
        "is the tenancy agreement signed",
        "have you got the invoice",
        "send Lucy a note",
        # Viewing verbs must not escalate informational questions either.
        "show me what nacho said",
        "show me a summary of the letter",
        "tell me about the passport",
        # A field printed on a document is not the document. This asked for
        # four numbers and was answered with four passport scans, which is
        # both wrong and irreversible -- and it needs no question word, so
        # nothing above catches it.
        "give me the whole family's passport numbers and expiries",
        "give me the passport numbers",
        "i need the passport expiry dates",
        "give me the expiry dates on the family's passports",
        "when do the kids' passports expire",
    ],
)
def test_informational_requests_stay_minimized(question):
    assert classify_output_tier(question) == MINIMIZED


@pytest.mark.parametrize(
    "question",
    [
        # Plurals count. "Send me the passports" classified as a minimized
        # answer because the word boundary would not close after "passport",
        # so asking for several documents quietly asked for none.
        "send me the passports",
        "send me the whole family's passports",
        "send me the documents",
        "forward the scans",
        # A details *page* is the document itself, not a field printed on it.
        "give me the passport details page",
        "send me the passport photo page",
        "send me a copy of the passport",
    ],
)
def test_asking_for_several_documents_still_asks_for_documents(question):
    assert classify_output_tier(question) == DOCUMENT_DESCRIPTOR


def test_james_may_release_his_own_private_documents():
    """James asking for his own emailed document is a permitted release."""
    decision = disclosure_decision(
        principal="james",
        effective_capability_ids=["juno.private.james"],
        capability_id="juno.private.james",
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    assert decision.allowed is True
    assert decision.outcome == DOCUMENT_DESCRIPTOR


def test_lucy_may_not_release_james_private_documents():
    decision = disclosure_decision(
        principal="lucy",
        effective_capability_ids=["juno.private.james"],
        capability_id="juno.private.james",
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    assert decision.allowed is False


@pytest.mark.parametrize("principal", ["lucy", "someone_else"])
def test_non_james_never_releases_documents(principal):
    for capability_id in (
        "juno.private.james",
        "juno.shared.family",
        "juno.shared.children",
    ):
        decision = disclosure_decision(
            principal=principal,
            effective_capability_ids=[capability_id],
            capability_id=capability_id,
            output_tier=DOCUMENT_DESCRIPTOR,
        )
        assert decision.allowed is False


def test_guidance_names_releasable_document_classes_for_james():
    """The model must be told which documents are releasable.

    Without this it invents privacy-sounding refusals for requests the
    policy actually permits, which is indistinguishable from a real denial.
    """
    guidance = generated_semantic_guidance(
        principal="james",
        effective_capability_ids=[
            "juno.private.james",
            "juno.shared.children",
            "juno.shared.family",
        ],
        configured_policy={
            "juno.private.james": "personal",
            "juno.shared.children": "children",
            "juno.shared.family": "family",
        },
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    release = guidance["document_release_mode"]
    assert release["available"] is True
    assert "juno.shared.children" in release["releasable_capability_ids"]
    assert "juno.private.james" in release["releasable_capability_ids"]
    # It must instruct deferral to the host gates rather than self-refusal.
    assert "refuse" in release["self_refusal"].lower()


def test_guidance_document_release_unavailable_for_lucy():
    guidance = generated_semantic_guidance(
        principal="lucy",
        effective_capability_ids=["juno.shared.family"],
        configured_policy={"juno.shared.family": "family"},
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    assert guidance["document_release_mode"]["available"] is False
    assert guidance["document_release_mode"]["releasable_capability_ids"] == []


def test_semantic_james_lucy_domain_matrix():
    shared = {
        "juno.shared.children",
        "juno.shared.mauritius",
        "juno.shared.property_intel",
        "juno.shared.villa_lena",
    }
    for capability in shared:
        assert disclosure_decision(
            principal="lucy",
            effective_capability_ids=shared,
            capability_id=capability,
        ).allowed
    assert not disclosure_decision(
        principal="lucy",
        effective_capability_ids=shared,
        capability_id="juno.private.james",
    ).allowed
    assert disclosure_decision(
        principal="lucy",
        effective_capability_ids=shared,
        capability_id="juno.shared.villa_lena",
    ).allowed
    assert not disclosure_decision(
        principal="lucy",
        effective_capability_ids=shared,
        capability_id="juno.shared.villa_lena",
        contains_credentials=True,
    ).allowed
    assert disclosure_decision(
        principal="james",
        effective_capability_ids={"juno.private.james"},
        capability_id="juno.private.james",
    ).allowed


def test_source_failure_becomes_unverifiable_final_output(tmp_path):
    gmail = RecordingBackend(failure=TimeoutError("synthetic private detail"))

    def check(kite):
        result = _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "Mauritius", "max_results": 5},
        )
        assert result["status"] == "error"
        envelope_text = kite.transform_llm_output(
            response_text="No messages found.", session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is False
        answer = json.loads(envelope["answer"])
        assert answer["outcome"] == "unverifiable"
        assert "No messages found" not in envelope_text

    _bound_turn(tmp_path, {"gmail": gmail}, check)


def test_bulk_raw_request_cannot_invoke_backend_and_gets_structured_denial(tmp_path):
    gmail = RecordingBackend({"search": [{"id": "m1"}]})

    def check(kite):
        blocked = kite.pre_tool_call(
            "kite_gmail_search",
            {"account": "personal", "query": "topic", "max_results": 25},
            session_id="kite-session",
            turn_id="kite-turn",
        )
        assert blocked["action"] == "block"
        envelope_text = kite.transform_llm_output(
            response_text="raw content", session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert json.loads(envelope["answer"])["outcome"] == "denied"
        assert gmail.calls == []

    _bound_turn(
        tmp_path,
        {"gmail": gmail},
        check,
        question="Export the whole raw mailbox and every header",
    )


def test_specific_document_request_returns_slice_c_gate(tmp_path):
    def check(kite):
        envelope_text = kite.transform_llm_output(
            response_text="I found and attached the file.", session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert json.loads(envelope["answer"])["outcome"] == "unavailable_next_gate"

    _bound_turn(
        tmp_path,
        {},
        check,
        question="Send me the actual child passport scan",
    )


def test_raw_private_source_overlap_is_denied_at_final_output(tmp_path):
    raw_body = (
        "This is a synthetic private email body with enough exact wording to "
        "prove that a raw source copy must not cross the signed boundary."
    )
    gmail = RecordingBackend({
        "search": [{"id": "message-overlap"}],
        "get": {"id": "message-overlap", "body": raw_body},
    })

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "synthetic", "max_results": 2},
        )
        _invoke(
            kite,
            "kite_gmail_get",
            {"account": "personal", "message_id": "message-overlap"},
        )
        envelope_text = kite.transform_llm_output(
            response_text=raw_body, session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is True
        assert raw_body not in envelope_text

    _bound_turn(tmp_path, {"gmail": gmail}, check)


def test_minimized_email_summary_allows_bounded_time_sender_subject_provenance(
    tmp_path,
):
    """B-FIX-1: the reproduced long-subject summary shape is releasable."""
    messages = [
        {
            "id": "message-delivered",
            "date": "08:14",
            "from": "Green Fulfilment",
            "subject": "Your parcel from Green Fulfilment has been delivered",
        },
        {
            "id": "message-due",
            "date": "09:02",
            "from": "Green Fulfilment",
            "subject": "Your parcel from Green Fulfilment is due to be delivered today",
        },
        {
            "id": "message-appointment",
            "date": "10:35",
            "from": "Synthetic Appointments",
            "subject": (
                "Your synthetic appointment booking has been confirmed for "
                "Tuesday afternoon"
            ),
        },
        {
            "id": "message-membership",
            "date": "11:48",
            "from": "Household Memberships",
            "subject": (
                "A household membership renewal notice is ready for your review"
            ),
        },
        {
            "id": "message-travel",
            "date": "13:20",
            "from": "Synthetic Travel",
            "subject": (
                "Updated travel itinerary and check-in details for the family journey"
            ),
        },
        {
            "id": "message-receipt",
            "date": "15:41",
            "from": "Synthetic Receipts",
            "subject": (
                "Receipt for your recent synthetic household purchase is now available"
            ),
        },
    ]
    gmail = RecordingBackend({"search": messages})
    answer = "New emails today:\n" + "\n".join(
        f"- {item['date']} — {item['from']} — {item['subject']}"
        for item in messages
    )
    assert len(answer) > 400

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "after:today", "max_results": 10},
        )
        envelope_text = kite.transform_llm_output(
            response_text=answer, session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is False
        assert envelope["answer"] == answer

    _bound_turn(
        tmp_path,
        {"gmail": gmail},
        check,
        question="Any new emails today?",
    )


@pytest.mark.parametrize("content_field", ["body", "snippet"])
def test_minimized_email_content_overlap_remains_denied(tmp_path, content_field):
    """B-FIX-2: provenance does not relax body or snippet overlap."""
    raw_content = (
        "This synthetic message content is deliberately longer than forty-eight "
        "characters and must remain inside Kite."
    )
    gmail = RecordingBackend({
        "search": [{"id": "message-content"}],
        "get": {"id": "message-content", content_field: raw_content},
    })

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "synthetic", "max_results": 2},
        )
        _invoke(
            kite,
            "kite_gmail_get",
            {"account": "personal", "message_id": "message-content"},
        )
        envelope_text = kite.transform_llm_output(
            response_text=raw_content, session_id="kite-session"
        )
        envelope = json.loads(envelope_text.split(RESPONSE_PREFIX, 1)[1])
        assert envelope["denied"] is True
        assert raw_content not in envelope_text

    _bound_turn(tmp_path, {"gmail": gmail}, check)


@pytest.mark.parametrize("message_count", [11, 13])
def test_minimized_email_bulk_subject_harvest_exceeds_provenance_bounds(
    tmp_path, message_count
):
    """B-FIX-3: total-character and distinct-fragment bounds block harvesting."""
    labels = (
        "alpha",
        "bravo",
        "charlie",
        "delta",
        "echo",
        "foxtrot",
        "golf",
        "hotel",
        "india",
        "juliet",
        "kilo",
        "lima",
        "mike",
    )
    messages = [
        {
            "id": f"message-{label}",
            "subject": (
                f"Synthetic provenance {label}: household update ready for review"
            ),
        }
        for label in labels[:message_count]
    ]
    gmail = RecordingBackend({"search": messages})
    answer = "\n".join(f"- {item['subject']}" for item in messages)

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "synthetic", "max_results": 25},
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text=answer, session_id="kite-session"
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True
        assert envelope["answer"] == ""

    _bound_turn(tmp_path, {"gmail": gmail}, check)


@pytest.mark.parametrize(
    "subject,answer",
    [
        (
            "Security notice: password=synthetic-credential-value must never be exposed",
            "Security notice: password=synthetic-credential-value must never be exposed",
        ),
        (
            "Synthetic private record 123e4567-e89b-12d3-a456-426614174000 is ready",
            "Synthetic private record 123e4567-e89b-12d3-a456-426614174000 is ready",
        ),
        (
            "Synthetic household update with enough provenance text for overlap",
            json.dumps({
                "subject": (
                    "Synthetic household update with enough provenance text for overlap"
                )
            }),
        ),
    ],
)
def test_minimized_provenance_does_not_relax_absolute_output_denials(
    tmp_path, subject, answer
):
    """B-FIX-4: credentials, identifiers, and JSON containers stay denied."""
    gmail = RecordingBackend({
        "search": [{"id": "message-absolute-denial", "subject": subject}]
    })

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "synthetic", "max_results": 2},
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text=answer, session_id="kite-session"
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True
        assert envelope["answer"] == ""

    _bound_turn(tmp_path, {"gmail": gmail}, check)


def test_unrelated_tool_content_cannot_ride_on_matching_provenance(tmp_path):
    """B-FIX-5: a content-field tag wins even when provenance has the same text."""
    shared_text = (
        "Synthetic household update with enough exact wording to test source scope"
    )
    gmail = RecordingBackend({
        "search": [{"id": "message-shared", "subject": shared_text}]
    })
    whatsapp = RecordingBackend({"search": [{"text": shared_text}]})

    def check(kite):
        _invoke(
            kite,
            "kite_gmail_search",
            {"account": "personal", "query": "synthetic", "max_results": 2},
        )
        _invoke(
            kite,
            "kite_whatsapp_archive_read",
            {"operation": "search", "query": "synthetic", "max_results": 2},
        )
        envelope = json.loads(
            kite.transform_llm_output(
                response_text=shared_text, session_id="kite-session"
            ).split(RESPONSE_PREFIX, 1)[1]
        )
        assert envelope["denied"] is True
        assert envelope["answer"] == ""

    _bound_turn(
        tmp_path,
        {"gmail": gmail, "whatsapp": whatsapp},
        check,
    )


def test_private_read_config_rejects_generic_read_authority(tmp_path):
    config = _slice_b_config(tmp_path, mode="kite")
    config["juno_kite_trusted_principal"]["policy"]["tool_classes"]["read"] = [
        "read_file"
    ]
    with pytest.raises(ValueError, match="generic or non-plugin"):
        TrustedPrincipalRuntime(config, active_profile="kite")


def test_contextvar_isolation_does_not_transfer_private_read_authority(tmp_path):
    backend = RecordingBackend({"search": []})

    def check(kite):
        args = {"account": "personal", "query": "trip", "max_results": 2}
        assert (
            kite.pre_tool_call(
                "kite_gmail_search",
                args,
                session_id="kite-session",
                turn_id="kite-turn",
            )
            is None
        )

        def isolated():
            tokens = set_session_vars(
                platform="a2a",
                source="a2a",
                chat_id="different-context",
                user_id="juno",
                session_key="agent:kite:a2a:dm:different",
                session_id="other-session",
                profile="kite",
                cron_session="",
            )
            try:
                denied = kite.pre_tool_dispatch(
                    "kite_gmail_search",
                    args,
                    session_id="other-session",
                    turn_id="kite-turn",
                )
                assert denied["action"] == "block"
            finally:
                clear_session_vars(tokens)

        copy_context().run(isolated)
        assert backend.calls == []

    _bound_turn(tmp_path, {"gmail": backend}, check)
