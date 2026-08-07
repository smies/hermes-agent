"""Frozen-contract tests for the Juno--Kite trusted-principal plugin.

All identities and content are synthetic.  The transport is an in-process
fixture; these tests never contact an A2A peer or private provider.
"""

from __future__ import annotations

import copy
import json
import os
import re
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from gateway.session_context import clear_session_vars, set_session_vars
from plugins.juno_kite_trusted_principal import mapping_store
from plugins.juno_kite_trusted_principal.mapping_store import (
    MappingSecurityError,
    MappingStore,
)
from plugins.juno_kite_trusted_principal.runtime import (
    REQUEST_PREFIX,
    RESPONSE_PREFIX,
    TrustedPrincipalRuntime,
    canonical_json,
    sign_payload,
)


FIXTURE_BINDINGS = Path(__file__).parents[1] / "fixtures" / "juno_kite" / "principals.json"


class MutableClock:
    def __init__(self, value: float = 1_800_000_000.0):
        self.value = value

    def __call__(self) -> float:
        return self.value


class RecordingTransport:
    def __init__(self, reply: str = "unsigned"):
        self.reply = reply
        self.calls = []

    def __call__(self, peer_name, peer, message, context_id):
        self.calls.append(
            {
                "peer_name": peer_name,
                "peer": copy.deepcopy(peer),
                "message": message,
                "context_id": context_id,
            }
        )
        return self.reply, context_id, "completed"


def _base_config(tmp_path: Path) -> dict:
    bindings = json.loads(FIXTURE_BINDINGS.read_text(encoding="utf-8"))
    return {
        "a2a_agents": {
            "kite": {
                "url": "http://127.0.0.1:9917",
                "auth": {"type": "bearer", "token": "fixture-peer-token"},
                "timeout": 15,
            }
        },
        "juno_kite_trusted_principal": {
            "enabled": True,
            "mode": "juno",
            "profile": "juno",
            "mapping_path": str(tmp_path / "owner" / "mapping.sqlite3"),
            "mapping_key_env": "JK_MAPPING_KEY",
            "request_key_env": "JK_REQUEST_KEY",
            "response_key_env": "JK_RESPONSE_KEY",
            "principal_bindings": bindings,
            "kite_peer": "kite",
            "kite_url": "http://127.0.0.1:9917",
            "kite_plugin": "juno_kite_trusted_principal",
            "policy_generation": "fixture-policy-v1",
            "limits": {
                "question_chars": 120,
                "context_turns": 2,
                "context_turn_chars": 48,
                "handoff_bytes": 1400,
                "policy_view_chars": 3000,
                "output_chars": 64,
                "response_bytes": 1800,
                "turn_ttl_seconds": 30,
            },
            "policy": {
                "principals": {
                    "james": {"trust_class": "trusted-family", "disclose": ["own", "shared"]},
                    "lucy": {"trust_class": "trusted-family", "disclose": ["own", "shared"]},
                },
                "tool_classes": {
                    "read": ["read_file"],
                    "mutating": ["write_file"],
                },
                "action_rules": [
                    {
                        "principal": "james",
                        "tool": "write_file",
                        "arguments": {
                            "path": str(tmp_path / "approved-write.txt"),
                            "content": "approved fixture content",
                            "encoding": "utf-8",
                        },
                    }
                ],
            },
        },
    }


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setenv("JK_MAPPING_KEY", "mapping-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_REQUEST_KEY", "request-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_RESPONSE_KEY", "response-key-with-at-least-thirty-two-bytes")


def _runtime(tmp_path, *, mode="juno", profile=None, transport=None, clock=None, config=None):
    cfg = copy.deepcopy(config or _base_config(tmp_path))
    section = cfg["juno_kite_trusted_principal"]
    section["mode"] = mode
    section["profile"] = profile or mode
    return TrustedPrincipalRuntime(
        cfg,
        active_profile=profile or mode,
        transport=transport,
        clock=clock,
    )


def _run_in_session(
    callback,
    *,
    platform,
    user_id,
    session_key,
    profile,
    cron="",
    source="",
    chat_id="fixture-chat",
):
    def run():
        tokens = set_session_vars(
            platform=platform,
            source=source,
            chat_id=chat_id,
            chat_type="dm",
            user_id=user_id,
            user_name="model-visible-name",
            session_key=session_key,
            session_id=f"session-{session_key}",
            profile=profile,
            cron_session=cron,
        )
        try:
            return callback()
        finally:
            clear_session_vars(tokens)

    return copy_context().run(run)


def _parse_prefixed(text: str, prefix: str) -> dict:
    assert text.count(prefix) == 1
    return json.loads(text.split(prefix, 1)[1])


def _issue_request(juno, *, user_id="fixture-user-101", session_key="conversation-a"):
    transport = RecordingTransport()
    juno.transport = transport
    result = _run_in_session(
        lambda: juno.consult_kite({"question_or_goal": "What is the bounded answer?"}),
        platform="telegram",
        user_id=user_id,
        session_key=session_key,
        profile="juno",
    )
    assert result.startswith("BLOCKED:")  # fixture transport deliberately returns unsigned text
    call = transport.calls[0]
    return call, _parse_prefixed(call["message"], REQUEST_PREFIX)


def _bind_kite(kite, call, *, peer="juno", context_id=None, profile="kite", message=None):
    return _run_in_session(
        lambda: kite.pre_llm_call(
            session_id="kite-session",
            turn_id="kite-turn",
            user_message=message or call["message"],
            conversation_history=[],
            is_first_turn=True,
            model="fixture-model",
            platform="a2a",
        ),
        platform="a2a",
        user_id=peer,
        session_key=f"agent:kite:a2a:dm:{context_id or call['context_id']}",
        profile=profile,
        chat_id=context_id or call["context_id"],
    )


def _round_trip_transport(kite, answer="Approved ordinary tool context"):
    def transport(peer_name, peer, message, context_id):
        def kite_turn():
            binding = kite.pre_llm_call(
                session_id="kite-session",
                turn_id="kite-turn",
                user_message=message,
                conversation_history=[],
                is_first_turn=True,
                model="fixture-model",
                platform="a2a",
            )
            assert "policy view" in binding["context"].lower()
            response = kite.transform_llm_output(
                response_text=answer,
                session_id="kite-session",
                model="fixture-model",
                platform="a2a",
            )
            return response, context_id, "completed"

        return _run_in_session(
            kite_turn,
            platform="a2a",
            user_id="juno",
            session_key=f"agent:kite:a2a:dm:{context_id}",
            profile="kite",
            chat_id=context_id,
        )

    return transport


class TestPrincipalAndDispatch:
    def test_principal_comes_from_contextvars_and_model_requester_is_ignored(self, tmp_path):
        transport = RecordingTransport()
        runtime = _runtime(tmp_path, transport=transport)
        _run_in_session(
            lambda: runtime.consult_kite(
                {"question_or_goal": "Need private context", "requester": "lucy"}
            ),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="juno",
        )
        record = runtime.store.get_by_context(transport.calls[0]["context_id"])
        assert record.principal == "james"

    @pytest.mark.parametrize(
        "platform,user_id,session_key,profile,cron",
        [
            ("", "fixture-user-101", "conversation-a", "juno", ""),
            ("telegram", "", "conversation-a", "juno", ""),
            ("telegram", "fixture-user-101", "", "juno", ""),
            ("cli", "fixture-user-101", "conversation-a", "juno", ""),
            ("a2a", "juno", "conversation-a", "juno", ""),
            ("telegram", "fixture-user-999", "conversation-a", "juno", ""),
            ("telegram", "fixture-user-101", "conversation-a", "juno", "1"),
            ("telegram", "fixture-user-101", "conversation-a", "kite", ""),
        ],
    )
    def test_invalid_context_denies_before_transport(
        self, tmp_path, platform, user_id, session_key, profile, cron
    ):
        transport = RecordingTransport()
        runtime = _runtime(tmp_path, transport=transport)
        result = _run_in_session(
            lambda: runtime.consult_kite({"question_or_goal": "Need help"}),
            platform=platform,
            user_id=user_id,
            session_key=session_key,
            profile=profile,
            cron=cron,
        )
        assert result.startswith("BLOCKED:")
        assert transport.calls == []

    def test_ambiguous_binding_denies_before_transport(self, tmp_path):
        config = _base_config(tmp_path)
        config["juno_kite_trusted_principal"]["principal_bindings"].append(
            {"platform": "telegram", "user_id": "fixture-user-101", "principal": "lucy"}
        )
        transport = RecordingTransport()
        runtime = _runtime(tmp_path, transport=transport, config=config)
        result = _run_in_session(
            lambda: runtime.consult_kite({"question_or_goal": "Need help"}),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="juno",
        )
        assert result.startswith("BLOCKED:")
        assert transport.calls == []

    def test_conflicting_platform_source_denies_before_transport(self, tmp_path):
        transport = RecordingTransport()
        runtime = _runtime(tmp_path, transport=transport)
        result = _run_in_session(
            lambda: runtime.consult_kite({"question_or_goal": "Need help"}),
            platform="telegram",
            source="discord",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="juno",
        )
        assert result.startswith("BLOCKED:")
        assert transport.calls == []

    def test_only_configured_peer_url_auth_and_mapped_context_are_used(self, tmp_path):
        transport = RecordingTransport()
        runtime = _runtime(tmp_path, transport=transport)
        _run_in_session(
            lambda: runtime.consult_kite({"question_or_goal": "Need help"}),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="juno",
        )
        call = transport.calls[0]
        assert call["peer_name"] == "kite"
        assert call["peer"] == {
            "url": "http://127.0.0.1:9917",
            "auth": {"type": "bearer", "token": "fixture-peer-token"},
            "timeout": 15,
        }
        assert call["context_id"].startswith("jk-")

    def test_model_cannot_choose_peer_url_or_context(self, tmp_path):
        transport = RecordingTransport()
        runtime = _runtime(tmp_path, transport=transport)
        _run_in_session(
            lambda: runtime.consult_kite(
                {
                    "question_or_goal": "Need help",
                    "agent": "mallory",
                    "url": "https://example.test",
                    "context_id": "chosen-by-model",
                    "principal": "lucy",
                    "approval": True,
                }
            ),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="juno",
        )
        call = transport.calls[0]
        assert call["peer_name"] == "kite"
        assert call["peer"]["url"] == "http://127.0.0.1:9917"
        assert call["context_id"] != "chosen-by-model"
        assert runtime.store.get_by_context(call["context_id"]).principal == "james"

    def test_mismatched_configured_url_fails_before_transport(self, tmp_path):
        config = _base_config(tmp_path)
        config["a2a_agents"]["kite"]["url"] = "http://127.0.0.1:9918"
        with pytest.raises(ValueError):
            _runtime(tmp_path, config=config)

    def test_returned_a2a_context_mismatch_fails_closed(self, tmp_path):
        class WrongContextTransport(RecordingTransport):
            def __call__(self, peer_name, peer, message, context_id):
                super().__call__(peer_name, peer, message, context_id)
                return "unsigned", "jk-wrong-context", "completed"

        transport = WrongContextTransport()
        runtime = _runtime(tmp_path, transport=transport)
        result = _run_in_session(
            lambda: runtime.consult_kite({"question_or_goal": "Need help"}),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="juno",
        )
        assert result.startswith("BLOCKED:")

    def test_request_credential_detector_blocks_before_transport(self, tmp_path):
        transport = RecordingTransport()
        runtime = _runtime(tmp_path, transport=transport)
        result = _run_in_session(
            lambda: runtime.consult_kite(
                {"question_or_goal": "Use ghp_" + "A" * 32 + " to inspect the repo"}
            ),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="juno",
        )
        assert result.startswith("BLOCKED:")
        assert transport.calls == []

    def test_consult_transport_refuses_redirect_without_forwarding_bearer(self, tmp_path):
        target_headers = []
        origin_hits = []

        class TargetHandler(BaseHTTPRequestHandler):
            def _record(self):
                target_headers.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"jsonrpc":"2.0","id":"target","result":{}}')

            do_GET = _record
            do_POST = _record

            def log_message(self, *_args):
                return None

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        target_url = f"http://127.0.0.1:{target.server_port}/stolen"

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                origin_hits.append(self.headers.get("Authorization"))
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                self.send_response(302)
                self.send_header("Location", target_url)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                return None

        origin = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in (target, origin)
        ]
        for thread in threads:
            thread.start()
        try:
            config = _base_config(tmp_path)
            origin_url = f"http://127.0.0.1:{origin.server_port}"
            config["a2a_agents"]["kite"]["url"] = origin_url
            config["a2a_agents"]["kite"]["auth"]["token"] = "redirect-canary"
            section = config["juno_kite_trusted_principal"]
            section["kite_url"] = origin_url
            runtime = _runtime(tmp_path, config=config)
            result = _run_in_session(
                lambda: runtime.consult_kite({"question_or_goal": "Need bounded help"}),
                platform="telegram",
                user_id="fixture-user-101",
                session_key="conversation-a",
                profile="juno",
            )
        finally:
            origin.shutdown()
            target.shutdown()
            origin.server_close()
            target.server_close()
            for thread in threads:
                thread.join(timeout=2)

        assert result.startswith("BLOCKED:")
        assert origin_hits == ["Bearer redirect-canary"]
        assert target_headers == []


class TestMappingStore:
    def test_mapping_reuses_across_restart_and_separates_principal_and_conversation(self, tmp_path):
        path = tmp_path / "owner" / "mapping.sqlite3"
        first = MappingStore(path, b"mapping-key-with-at-least-thirty-two-bytes")
        james_a = first.resolve("james", "conversation-a")
        first.close()
        second = MappingStore(path, b"mapping-key-with-at-least-thirty-two-bytes")
        assert second.resolve("james", "conversation-a") == james_a
        assert second.resolve("lucy", "conversation-a").context_id != james_a.context_id
        assert second.resolve("james", "conversation-b").context_id != james_a.context_id

    @pytest.mark.parametrize("_attempt", range(5))
    def test_mapping_unique_both_directions_under_concurrency(self, tmp_path, _attempt):
        path = tmp_path / "owner" / "mapping.sqlite3"

        def resolve(principal, conversation):
            store = MappingStore(path, b"mapping-key-with-at-least-thirty-two-bytes")
            try:
                return store.resolve(principal, conversation)
            finally:
                store.close()

        requests = [("james", "conversation-a")] * 12 + [
            ("james", "conversation-b"),
            ("lucy", "conversation-a"),
        ]
        with ThreadPoolExecutor(max_workers=8) as pool:
            records = list(pool.map(lambda item: resolve(*item), requests))
        same_pair = {record.context_id for record in records[:12]}
        all_pairs = {record.context_id for record in records}
        assert len(same_pair) == 1
        assert len(all_pairs) == 3

    def test_path_swap_to_symlink_never_opens_or_chmods_victim(self, tmp_path, monkeypatch):
        owner = tmp_path / "owner"
        owner.mkdir(mode=0o700)
        victim = tmp_path / "victim.txt"
        victim.write_text("must remain untouched", encoding="utf-8")
        victim.chmod(0o644)
        db_path = owner / "mapping.sqlite3"

        class FakeConnection:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        fake = FakeConnection()

        def swap_connect(*_args, **_kwargs):
            db_path.unlink()
            db_path.symlink_to(victim)
            return fake

        monkeypatch.setattr(mapping_store.sqlite3, "connect", swap_connect)
        with pytest.raises(MappingSecurityError):
            MappingStore(db_path, b"mapping-key-with-at-least-thirty-two-bytes")
        assert fake.closed is True
        assert victim.read_text(encoding="utf-8") == "must remain untouched"
        assert stat.S_IMODE(victim.stat().st_mode) == 0o644

    def test_symlinked_parent_is_rejected(self, tmp_path):
        real_owner = tmp_path / "real-owner"
        real_owner.mkdir(mode=0o700)
        linked_owner = tmp_path / "linked-owner"
        linked_owner.symlink_to(real_owner, target_is_directory=True)
        with pytest.raises(MappingSecurityError):
            MappingStore(
                linked_owner / "mapping.sqlite3",
                b"mapping-key-with-at-least-thirty-two-bytes",
            )
        assert not (real_owner / "mapping.sqlite3").exists()

    def test_hard_linked_database_is_rejected(self, tmp_path):
        owner = tmp_path / "owner"
        owner.mkdir(mode=0o700)
        original = tmp_path / "original.sqlite3"
        original.touch(mode=0o600)
        db_path = owner / "mapping.sqlite3"
        os.link(original, db_path)
        assert db_path.stat().st_nlink == 2
        with pytest.raises(MappingSecurityError):
            MappingStore(db_path, b"mapping-key-with-at-least-thirty-two-bytes")

    def test_non_regular_database_path_is_rejected_before_sqlite_open(self, tmp_path):
        owner = tmp_path / "owner"
        owner.mkdir(mode=0o700)
        db_path = owner / "mapping.sqlite3"
        db_path.mkdir(mode=0o700)
        with pytest.raises(MappingSecurityError):
            MappingStore(db_path, b"mapping-key-with-at-least-thirty-two-bytes")

    @pytest.mark.parametrize("transition", ["claim", "action", "release", "consume"])
    @pytest.mark.parametrize("reopen", [False, True])
    def test_ttl_transitions_deny_exactly_at_expiry(self, tmp_path, transition, reopen):
        path = tmp_path / "owner" / "mapping.sqlite3"
        key = b"mapping-key-with-at-least-thirty-two-bytes"
        store = MappingStore(path, key)
        mapping = store.resolve("james", "conversation-a")
        request_id = f"request-{transition}-{reopen}"
        store.issue_request(mapping, request_id, "policy-v1", 100)

        if transition != "claim":
            assert store.claim_request(
                request_id,
                mapping.context_id,
                mapping.correlation_id,
                "policy-v1",
                99,
            ) is not None
        if transition == "consume":
            assert store.release_request(request_id, 99) is True

        if reopen:
            store.close()
            store = MappingStore(path, key)
        try:
            if transition == "claim":
                assert store.claim_request(
                    request_id,
                    mapping.context_id,
                    mapping.correlation_id,
                    "policy-v1",
                    100,
                ) is None
            elif transition == "action":
                assert store.claim_action(request_id, "fingerprint", 100) is False
            elif transition == "release":
                assert store.release_request(request_id, 100) is False
            else:
                assert store.consume_response(
                    request_id,
                    mapping.context_id,
                    mapping.correlation_id,
                    "policy-v1",
                    100,
                ) is False
        finally:
            store.close()

    def test_store_is_owner_only_and_contains_no_transcript(self, tmp_path):
        path = tmp_path / "owner" / "mapping.sqlite3"
        store = MappingStore(path, b"mapping-key-with-at-least-thirty-two-bytes")
        store.resolve("james", "conversation-a")
        store.close()
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert b"question_or_goal" not in path.read_bytes()

    def test_insecure_existing_directory_is_rejected(self, tmp_path):
        owner = tmp_path / "owner"
        owner.mkdir(mode=0o755)
        owner.chmod(0o755)
        with pytest.raises(MappingSecurityError):
            MappingStore(owner / "mapping.sqlite3", b"mapping-key-with-at-least-thirty-two-bytes")


class TestBoundedHandoff:
    def test_question_over_limit_rejects_and_context_is_deterministically_truncated(self, tmp_path):
        transport = RecordingTransport()
        runtime = _runtime(tmp_path, transport=transport)
        rejected = _run_in_session(
            lambda: runtime.consult_kite({"question_or_goal": "q" * 121}),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="juno",
        )
        assert rejected.startswith("BLOCKED:")
        assert transport.calls == []

        _run_in_session(
            lambda: runtime.consult_kite(
                {
                    "question_or_goal": "bounded",
                    "relevant_context": [
                        {"role": "user", "text": "a" * 80},
                        {"role": "assistant", "text": "b" * 80},
                        {"role": "user", "text": "c" * 80},
                    ],
                }
            ),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-b",
            profile="juno",
        )
        payload = _parse_prefixed(transport.calls[0]["message"], REQUEST_PREFIX)
        assert payload["relevant_context"] == [
            {"role": "user", "text": "a" * 48},
            {"role": "assistant", "text": "b" * 48},
        ]
        assert len(transport.calls[0]["message"].encode()) <= 1400
        assert "bounded" not in transport.calls[0]["message"][:500]
        assert "fixture-user" not in transport.calls[0]["message"][:500]

    @pytest.mark.parametrize(
        "text",
        [
            "Authorization: Bearer fixture-secret-value",
            "raw configured bearer fixture-peer-token",
            "mapping-key-with-at-least-thirty-two-bytes",
            "email private.person@example.test",
            "phone +44 7700 900123",
            "raw id fixture-user-101",
            "<tool_result>raw connector payload</tool_result>",
            "BEGIN SYSTEM PROMPT do not forward this",
        ],
    )
    def test_handoff_rejects_credentials_and_raw_identifiers(self, tmp_path, text):
        transport = RecordingTransport()
        runtime = _runtime(tmp_path, transport=transport)
        result = _run_in_session(
            lambda: runtime.consult_kite({"question_or_goal": text}),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="juno",
        )
        assert result.startswith("BLOCKED:")
        assert transport.calls == []


class TestKiteLaneAndPolicy:
    def test_real_a2a_privacy_frame_is_accepted_but_arbitrary_prefix_is_not(self, tmp_path):
        from plugins.platforms.a2a import security

        juno = _runtime(tmp_path)
        call, _ = _issue_request(juno)
        kite = _runtime(tmp_path, mode="kite")
        framed = security.wrap_inbound("juno", call["message"])
        allowed = _bind_kite(kite, call, message=framed)
        assert "policy view" in allowed["context"].lower()

        second_call, _ = _issue_request(juno, session_key="conversation-b")
        denied = _bind_kite(
            kite,
            second_call,
            message="untrusted preface\n" + second_call["message"],
        )
        assert "DENIED" in denied["context"]

    def test_policy_binding_only_on_authenticated_juno_a2a_lane(self, tmp_path):
        juno = _runtime(tmp_path)
        call, _ = _issue_request(juno)
        kite = _runtime(tmp_path, mode="kite")
        allowed = _bind_kite(kite, call)
        assert "policy view" in allowed["context"].lower()
        assert "trusted-family" in allowed["context"]
        assert '"recipient":"the authenticated originating principal"' in allowed["context"]
        assert len(allowed["context"]) <= 3000
        wrong_peer = _bind_kite(kite, call, peer="mallory")
        assert "DENIED" in wrong_peer["context"]
        non_a2a = _run_in_session(
            lambda: kite.pre_llm_call(user_message=call["message"], platform="telegram"),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="kite",
        )
        assert non_a2a is None

    @pytest.mark.parametrize("case", ["wrong_context", "forged_identity", "wrong_generation", "expired"])
    def test_bad_request_scope_denies(self, tmp_path, case):
        clock = MutableClock()
        juno = _runtime(tmp_path, clock=clock)
        call, payload = _issue_request(juno)
        kite = _runtime(tmp_path, mode="kite", clock=clock)
        context_id = call["context_id"]
        message = call["message"]
        if case == "wrong_context":
            context_id = "jk-unmapped"
        else:
            payload = dict(payload)
            if case == "forged_identity":
                payload["principal"] = "lucy"
            elif case == "wrong_generation":
                payload["policy_generation"] = "future-policy"
            elif case == "expired":
                clock.value += 31
            if case != "expired":
                unsigned = {k: v for k, v in payload.items() if k != "signature"}
                payload["signature"] = sign_payload(unsigned, os.environ["JK_REQUEST_KEY"].encode())
            guard = call["message"].split(REQUEST_PREFIX, 1)[0]
            message = guard + REQUEST_PREFIX + canonical_json(payload)
        denied = _bind_kite(kite, call, context_id=context_id, message=message)
        assert "DENIED" in denied["context"]

    def test_cross_principal_context_reuse_denies_even_with_resigned_body(self, tmp_path):
        juno = _runtime(tmp_path)
        james_call, payload = _issue_request(juno, user_id="fixture-user-101")
        lucy_mapping = juno.store.resolve("lucy", "conversation-a")
        payload["context_id"] = lucy_mapping.context_id
        payload["correlation_id"] = lucy_mapping.correlation_id
        unsigned = {k: v for k, v in payload.items() if k != "signature"}
        payload["signature"] = sign_payload(unsigned, os.environ["JK_REQUEST_KEY"].encode())
        guard = james_call["message"].split(REQUEST_PREFIX, 1)[0]
        kite = _runtime(tmp_path, mode="kite")
        denied = _bind_kite(
            kite,
            james_call,
            context_id=lucy_mapping.context_id,
            message=guard + REQUEST_PREFIX + canonical_json(payload),
        )
        assert "DENIED" in denied["context"]

    def test_hook_exception_profile_mode_mismatch_and_missing_binding_deny(self, tmp_path, monkeypatch):
        juno = _runtime(tmp_path)
        call, _ = _issue_request(juno)
        kite = _runtime(tmp_path, mode="kite")
        monkeypatch.setattr(kite, "_bind_request", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))
        assert "DENIED" in _bind_kite(kite, call)["context"]

        mismatch_config = _base_config(tmp_path)
        mismatch_config["juno_kite_trusted_principal"].update(
            mode="kite", profile="kite"
        )
        mismatch = TrustedPrincipalRuntime(
            mismatch_config, active_profile="not-kite"
        )
        assert "DENIED" in _bind_kite(mismatch, call, profile="not-kite")["context"]

        no_binding = _run_in_session(
            lambda: kite.transform_llm_output(
                response_text="must never escape raw",
                session_id="kite-session",
                model="m",
                platform="a2a",
            ),
            platform="a2a",
            user_id="juno",
            session_key=f"agent:kite:a2a:dm:{call['context_id']}",
            profile="kite",
            chat_id=call["context_id"],
        )
        assert "must never escape raw" not in no_binding

    def test_output_hook_internal_exception_returns_no_raw_output(self, tmp_path, monkeypatch):
        juno = _runtime(tmp_path)
        call, _ = _issue_request(juno)
        kite = _runtime(tmp_path, mode="kite")

        def turn():
            kite.pre_llm_call(
                user_message=call["message"],
                session_id="kite-session",
                turn_id="kite-turn",
                platform="a2a",
            )
            monkeypatch.setattr(kite, "_leak_reason", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))
            return kite.transform_llm_output(
                "raw content must not escape", session_id="kite-session", platform="a2a"
            )

        denied = _run_in_session(
            turn,
            platform="a2a",
            user_id="juno",
            session_key=f"agent:kite:a2a:dm:{call['context_id']}",
            profile="kite",
            chat_id=call["context_id"],
        )
        assert "raw content must not escape" not in denied


class TestExactToolGate:
    def _bound_runtime(self, tmp_path, *, user_id="fixture-user-101", clock=None):
        juno = _runtime(tmp_path, clock=clock)
        call, _ = _issue_request(juno, user_id=user_id)
        kite = _runtime(tmp_path, mode="kite", clock=clock)

        def bind_and_run(callback):
            def turn():
                assert "policy view" in kite.pre_llm_call(
                    session_id="kite-session",
                    turn_id="kite-turn",
                    user_message=call["message"],
                    conversation_history=[],
                    is_first_turn=True,
                    model="m",
                    platform="a2a",
                )["context"].lower()
                return callback(kite)

            return _run_in_session(
                turn,
                platform="a2a",
                user_id="juno",
                session_key=f"agent:kite:a2a:dm:{call['context_id']}",
                profile="kite",
                chat_id=call["context_id"],
            )

        return bind_and_run

    def test_read_allowlist_and_default_deny(self, tmp_path):
        run = self._bound_runtime(tmp_path)

        def checks(kite):
            assert kite.pre_tool_call(
                "read_file", {"path": "/tmp/public.txt"},
                session_id="kite-session", turn_id="kite-turn",
            ) is None
            blocked = kite.pre_tool_call(
                "unknown_read", {}, session_id="kite-session", turn_id="kite-turn"
            )
            assert blocked["action"] == "block"

        run(checks)

    @pytest.mark.parametrize(
        "tool,args",
        [
            (
                "file_write",
                {
                    "path": "<approved>",
                    "content": "approved fixture content",
                    "encoding": "utf-8",
                },
            ),
            ("write_file", {"path": "<approved>", "content": "approved fixture content"}),
            ("write_file", {"path": "<other>", "content": "approved fixture content", "encoding": "utf-8"}),
            ("write_file", {"path": "<approved>", "content": "changed", "encoding": "utf-8"}),
            (
                "write_file",
                {
                    "path": "<approved>",
                    "content": "approved fixture content",
                    "encoding": "utf-8",
                    "extra": True,
                },
            ),
        ],
    )
    def test_mutation_denies_alias_omission_changes_and_additional_keys(self, tmp_path, tool, args):
        run = self._bound_runtime(tmp_path)
        args = dict(args)
        if args.get("path") == "<approved>":
            args["path"] = str(tmp_path / "approved-write.txt")
        elif args.get("path") == "<other>":
            args["path"] = str(tmp_path / "other-write.txt")
        run(lambda kite: self._assert_block(kite.pre_tool_call(
            tool, args, session_id="kite-session", turn_id="kite-turn"
        )))

    @staticmethod
    def _assert_block(value):
        assert value["action"] == "block"

    def test_exact_action_allowed_once_and_mutation_after_gate_denies(self, tmp_path):
        run = self._bound_runtime(tmp_path)
        exact = {
            "path": str(tmp_path / "approved-write.txt"),
            "content": "approved fixture content",
            "encoding": "utf-8",
        }

        def checks(kite):
            assert kite.pre_tool_call(
                "write_file", exact, session_id="kite-session", turn_id="kite-turn"
            ) is None
            exact["content"] = "post-gate mutation"
            assert kite.pre_tool_call(
                "write_file", exact, session_id="kite-session", turn_id="kite-turn"
            )["action"] == "block"

        run(checks)

    def test_stale_binding_denies_action(self, tmp_path):
        clock = MutableClock()
        run = self._bound_runtime(tmp_path, clock=clock)

        def checks(kite):
            clock.value += 31
            exact = {
                "path": str(tmp_path / "approved-write.txt"),
                "content": "approved fixture content",
                "encoding": "utf-8",
            }
            assert kite.pre_tool_call(
                "write_file", exact, session_id="kite-session", turn_id="kite-turn"
            )["action"] == "block"

        run(checks)

    @pytest.mark.parametrize(
        "session_id,turn_id",
        [
            ("nested-session", "kite-turn"),
            ("kite-session", "nested-turn"),
        ],
    )
    def test_inherited_binding_cannot_authorize_mismatched_invocation(
        self, tmp_path, session_id, turn_id
    ):
        run = self._bound_runtime(tmp_path)

        def checks(kite):
            nested = copy_context()
            result = nested.run(
                lambda: kite.pre_tool_call(
                    "read_file",
                    {"path": "/tmp/public.txt"},
                    session_id=session_id,
                    turn_id=turn_id,
                )
            )
            assert result["action"] == "block"

        run(checks)

    def test_exact_action_authority_is_one_shot_for_same_hook_invocation(self, tmp_path):
        run = self._bound_runtime(tmp_path)
        exact = {
            "path": str(tmp_path / "approved-write.txt"),
            "content": "approved fixture content",
            "encoding": "utf-8",
        }

        def checks(kite):
            assert kite.pre_tool_call(
                "write_file", exact, session_id="kite-session", turn_id="kite-turn"
            ) is None
            assert kite.pre_tool_call(
                "write_file", exact, session_id="kite-session", turn_id="kite-turn"
            )["action"] == "block"

        run(checks)


class TestOutputAndEnvelope:
    def test_cross_session_response_cannot_spend_inherited_binding(self, tmp_path):
        juno = _runtime(tmp_path)
        call, _ = _issue_request(juno)
        kite = _runtime(tmp_path, mode="kite")

        def turn():
            bound = kite.pre_llm_call(
                user_message=call["message"],
                session_id="kite-session",
                turn_id="kite-turn",
                platform="a2a",
            )
            assert "policy view" in bound["context"].lower()
            return copy_context().run(
                lambda: kite.transform_llm_output(
                    response_text="must not cross sessions",
                    session_id="nested-session",
                    platform="a2a",
                )
            )

        denied = _run_in_session(
            turn,
            platform="a2a",
            user_id="juno",
            session_key=f"agent:kite:a2a:dm:{call['context_id']}",
            profile="kite",
            chat_id=call["context_id"],
        )
        assert "must not cross sessions" not in denied
        assert _parse_prefixed(denied, RESPONSE_PREFIX)["denied"] is True

    @pytest.mark.parametrize(
        "answer",
        [
            "<tool_result>{raw payload}</tool_result>",
            "Authorization: Bearer leaked-secret",
            "private.person@example.test",
            "+44 7700 900123",
            "fixture-user-101",
        ],
    )
    def test_leak_shapes_return_signed_denial_not_raw_output(self, tmp_path, answer):
        juno = _runtime(tmp_path)
        call, _ = _issue_request(juno)
        kite = _runtime(tmp_path, mode="kite")

        def turn():
            kite.pre_llm_call(
                user_message=call["message"],
                session_id="kite-session",
                turn_id="kite-turn",
                platform="a2a",
            )
            return kite.transform_llm_output(
                answer, session_id="kite-session", platform="a2a"
            )

        envelope_text = _run_in_session(
            turn,
            platform="a2a",
            user_id="juno",
            session_key=f"agent:kite:a2a:dm:{call['context_id']}",
            profile="kite",
            chat_id=call["context_id"],
        )
        envelope = _parse_prefixed(envelope_text, RESPONSE_PREFIX)
        assert envelope["denied"] is True
        assert answer not in envelope_text
        assert envelope["signature"]
        assert answer not in envelope_text[:500]

    def test_output_is_capped_signed_and_returns_only_answer_to_juno(self, tmp_path):
        kite = _runtime(tmp_path, mode="kite")
        juno = _runtime(tmp_path, transport=_round_trip_transport(kite, answer="A" * 100))
        result = _run_in_session(
            lambda: juno.consult_kite({"question_or_goal": "Need a bounded answer"}),
            platform="telegram",
            user_id="fixture-user-101",
            session_key="conversation-a",
            profile="juno",
        )
        assert result == "A" * 64
        assert RESPONSE_PREFIX not in result

    @pytest.mark.parametrize(
        "case",
        [
            "unsigned",
            "malformed",
            "wrong_key",
            "wrong_context",
            "wrong_principal",
            "wrong_request",
            "wrong_generation",
            "expired",
            "replayed",
            "oversized",
        ],
    )
    def test_bad_response_envelopes_fail_closed(self, tmp_path, case):
        clock = MutableClock()
        kite = _runtime(tmp_path, mode="kite", clock=clock)
        good_transport = _round_trip_transport(kite, answer="ordinary approved result")

        if case == "replayed":
            captured = {}

            def replay_transport(*args):
                if "value" not in captured:
                    captured["value"] = good_transport(*args)
                return captured["value"]

            transport = replay_transport
        else:
            def transport(peer_name, peer, message, context_id):
                raw, returned_context, state = good_transport(peer_name, peer, message, context_id)
                if case == "unsigned":
                    return "ordinary approved result", returned_context, state
                guard = raw.split(RESPONSE_PREFIX, 1)[0]
                if case == "malformed":
                    return guard + RESPONSE_PREFIX + "{broken", returned_context, state
                payload = _parse_prefixed(raw, RESPONSE_PREFIX)
                if case == "wrong_key":
                    payload["signature"] = sign_payload(
                        {k: v for k, v in payload.items() if k != "signature"},
                        b"wrong-key-with-at-least-thirty-two-bytes",
                    )
                else:
                    field = {
                        "wrong_context": "context_id",
                        "wrong_principal": "correlation_id",
                        "wrong_request": "request_id",
                        "wrong_generation": "policy_generation",
                    }.get(case)
                    if field:
                        payload[field] = "wrong"
                    elif case == "expired":
                        payload["expires_at"] = int(clock()) - 1
                    elif case == "oversized":
                        payload["answer"] = "x" * 2000
                    unsigned = {k: v for k, v in payload.items() if k != "signature"}
                    payload["signature"] = sign_payload(unsigned, os.environ["JK_RESPONSE_KEY"].encode())
                return guard + RESPONSE_PREFIX + canonical_json(payload), returned_context, state

        juno = _runtime(tmp_path, transport=transport, clock=clock)

        def invoke(conversation):
            return _run_in_session(
                lambda: juno.consult_kite({"question_or_goal": "Need approved context"}),
                platform="telegram",
                user_id="fixture-user-101",
                session_key=conversation,
                profile="juno",
            )

        if case == "replayed":
            assert invoke("conversation-a") == "ordinary approved result"
            second = invoke("conversation-a")
            assert second.startswith("BLOCKED:")
        else:
            assert invoke("conversation-a").startswith("BLOCKED:")


class TestRegistrationAndGuidance:
    def test_plugin_registers_only_consult_surface_in_juno_mode(self, tmp_path, monkeypatch):
        from plugins.juno_kite_trusted_principal import register
        import plugins.juno_kite_trusted_principal as plugin

        runtime = _runtime(tmp_path)
        monkeypatch.setattr(plugin, "runtime_from_host", lambda _profile: runtime)

        class Context:
            profile_name = "juno"

            def __init__(self):
                self.tools = []
                self.hooks = []
                self.direct_tools = {"web_search", "web_extract", "read_file"}

            def register_tool(self, **kwargs):
                self.tools.append(kwargs)

            def register_hook(self, name, callback):
                self.hooks.append((name, callback))

        ctx = Context()
        register(ctx)
        assert [item["name"] for item in ctx.tools] == ["consult_kite"]
        assert ctx.tools[0]["toolset"] == "juno_kite"
        schema = ctx.tools[0]["schema"]["function"]
        assert set(schema["parameters"]["properties"]) == {"question_or_goal", "relevant_context"}
        assert "session" in schema["description"].lower()
        assert "local" in schema["description"].lower()
        assert "private authority" in schema["description"].lower()
        assert not {"a2a_call", "a2a_history", "a2a_orchestrate"} & {item["name"] for item in ctx.tools}
        assert ctx.direct_tools == {"web_search", "web_extract", "read_file"}

    def test_documented_config_uses_real_shape_and_narrow_toolset(
        self, tmp_path, monkeypatch
    ):
        from hermes_cli.config import load_config

        readme = (
            Path(__file__).parents[2]
            / "plugins"
            / "juno_kite_trusted_principal"
            / "README.md"
        ).read_text(encoding="utf-8")

        def yaml_after(heading):
            section = readme.split(heading, 1)[1]
            match = re.search(r"```yaml\n(.*?)```", section, re.S)
            assert match is not None
            return yaml.safe_load(match.group(1)), match.group(1)

        def load_documented(name, source):
            hermes_home = tmp_path / name
            hermes_home.mkdir(mode=0o700)
            (hermes_home / "config.yaml").write_text(source, encoding="utf-8")
            monkeypatch.setenv("HERMES_HOME", str(hermes_home))
            return load_config()

        parsed_juno, juno_source = yaml_after("## Juno profile configuration")
        juno = load_documented("juno-home", juno_source)
        assert juno["juno_kite_trusted_principal"] == parsed_juno[
            "juno_kite_trusted_principal"
        ]
        assert "juno_kite_trusted_principal" in juno["plugins"]["enabled"]
        assert "juno_kite" in juno["tools"]["enabled"]
        assert "a2a" not in juno["tools"]["enabled"]
        whatsapp_toolsets = juno["platform_toolsets"]["whatsapp"]
        assert "juno_kite" in whatsapp_toolsets
        assert "web" in whatsapp_toolsets
        assert "a2a" not in whatsapp_toolsets
        assert "file" not in whatsapp_toolsets
        assert "terminal" not in whatsapp_toolsets

        parsed_kite, kite_source = yaml_after("## Kite profile configuration")
        kite = load_documented("kite-home", kite_source)
        assert kite["juno_kite_trusted_principal"] == parsed_kite[
            "juno_kite_trusted_principal"
        ]
        assert set(kite["plugins"]["enabled"]) == {
            "a2a-platform",
            "juno_kite_trusted_principal",
        }
        assert kite["platforms"]["a2a"]["enabled"] is True
        # load_config() adds the standard default gateway section; verify the
        # documented source itself does not use the obsolete nested shape.
        assert "gateway" not in parsed_kite
        assert kite["juno_kite_trusted_principal"]["profile"] == "default"
        policy = kite["juno_kite_trusted_principal"]["policy"]
        assert policy["action_rules"] == []
        assert "action_rules" not in kite
        assert "A2A_HOST=127.0.0.1" in readme
        assert "A2A_PORT=9917" in readme
        assert "A2A_PEER_TOKENS=juno:" in readme
        assert "juno_kite_trusted_principal.policy.action_rules" in readme

    def test_kite_mode_registers_policy_hooks_and_no_model_tool(self, tmp_path, monkeypatch):
        from plugins.juno_kite_trusted_principal import register
        import plugins.juno_kite_trusted_principal as plugin

        runtime = _runtime(tmp_path, mode="kite")
        monkeypatch.setattr(plugin, "runtime_from_host", lambda _profile: runtime)

        class Context:
            profile_name = "kite"

            def __init__(self):
                self.tools = []
                self.hooks = []

            def register_tool(self, **kwargs):
                self.tools.append(kwargs)

            def register_hook(self, name, callback):
                self.hooks.append((name, callback))

        ctx = Context()
        register(ctx)
        assert ctx.tools == []
        assert {name for name, _callback in ctx.hooks} == {
            "pre_llm_call",
            "pre_tool_call",
            "transform_llm_output",
        }

    def test_fixture_principals_are_separate_without_provider_access(self, tmp_path):
        runtime = _runtime(tmp_path)
        james = runtime.store.resolve("james", "conversation-a")
        lucy = runtime.store.resolve("lucy", "conversation-a")
        assert james.principal == "james"
        assert lucy.principal == "lucy"
        assert james.context_id != lucy.context_id
