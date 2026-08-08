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
)
from plugins.juno_kite_trusted_principal.private_reads import (
    KITE_GMAIL,
    PERSONAL_GMAIL,
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
    tmp_path: Path, backends, callback, question="What is the current status?"
):
    juno = _runtime(tmp_path, mode="juno", backends=backends)
    prepared = _run_in_session(
        lambda: juno._prepare_request({"question_or_goal": question}),
        platform="telegram",
        user_id="fixture-user-101",
        session_key="conversation-slice-b",
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
    outside = tmp_path / "outside.md"
    outside.write_text("outside", encoding="utf-8")
    (root / "escape.md").symlink_to(outside)
    service = PrivateReadService({
        "enabled": True,
        "output_bytes": 4096,
        "files": {"roots": [{"name": "obsidian", "path": str(root)}]},
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
    ],
)
def test_output_tiers(question, tier):
    assert classify_output_tier(question) == tier


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
