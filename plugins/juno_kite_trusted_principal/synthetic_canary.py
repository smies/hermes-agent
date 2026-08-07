#!/usr/bin/env python3
"""Run the provider-free Juno--Kite synthetic vertical on loopback.

The helper starts Hermes's real A2A adapter on an ephemeral loopback port and
uses a deterministic in-process Kite hook handler. It never loads a model,
private provider, live profile, or real mutation handler.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

TOKEN = "synthetic-juno-bearer-not-a-production-secret"
WRONG_TOKEN = "synthetic-wrong-bearer"
PRINCIPAL_ID = "synthetic-user-101"
MAX_HTTP_BODY = 16_384


def _config(root: Path, url: str) -> dict:
    mapping = root / "owner" / "mapping.sqlite3"
    return {
        "a2a_agents": {
            "kite": {
                "url": url,
                "auth": {"type": "bearer", "token": TOKEN},
                "timeout": 10,
            }
        },
        "juno_kite_trusted_principal": {
            "enabled": True,
            "mode": "juno",
            "profile": "juno",
            "mapping_path": str(mapping),
            "mapping_key_env": "JUNO_KITE_CANARY_MAPPING_KEY",
            "request_key_env": "JUNO_KITE_CANARY_REQUEST_KEY",
            "response_key_env": "JUNO_KITE_CANARY_RESPONSE_KEY",
            "principal_bindings": [
                {
                    "platform": "telegram",
                    "user_id": PRINCIPAL_ID,
                    "principal": "synthetic-principal",
                }
            ],
            "kite_peer": "kite",
            "kite_url": url,
            "kite_plugin": "juno_kite_trusted_principal",
            "policy_generation": "synthetic-policy-v1",
            "limits": {
                "question_chars": 200,
                "context_turns": 2,
                "context_turn_chars": 100,
                "handoff_bytes": 4096,
                "policy_view_chars": 4096,
                "output_chars": 200,
                "response_bytes": MAX_HTTP_BODY,
                "turn_ttl_seconds": 60,
            },
            "policy": {
                "principals": {
                    "synthetic-principal": {
                        "trust_class": "synthetic",
                        "disclose": ["synthetic-only"],
                    }
                },
                "tool_classes": {
                    "read": ["synthetic_read"],
                    "mutating": ["synthetic_mutation"],
                },
                "action_rules": [
                    {
                        "principal": "synthetic-principal",
                        "tool": "synthetic_mutation",
                        "arguments": {"target": "fixture", "value": "approved"},
                    }
                ],
            },
        },
    }


def _session(callback, *, platform: str, user_id: str, context_id: str, profile: str):
    from gateway.session_context import clear_session_vars, set_session_vars

    tokens = set_session_vars(
        platform=platform,
        source=platform,
        chat_id=context_id,
        chat_type="dm",
        user_id=user_id,
        user_name="synthetic",
        session_key=f"agent:{profile}:{platform}:dm:{context_id}",
        session_id=f"session-{context_id}",
        profile=profile,
    )
    try:
        return callback()
    finally:
        clear_session_vars(tokens)


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _request(url: str, *, method: str, body: dict | None = None, token: str = ""):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers.update({"Content-Type": "application/json", "A2A-Version": "1.0"})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _opener().open(request, timeout=10) as response:
            raw = response.read(MAX_HTTP_BODY + 1)
            return response.status, raw
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_HTTP_BODY + 1)


def _send_body(text: str, context_id: str, request_id: str) -> dict:
    from plugins.platforms.a2a import protocol

    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "SendMessage",
        "params": {
            "message": protocol.text_message(
                protocol.ROLE_USER, text, context_id=context_id
            )
        },
    }


def _json(raw: bytes) -> dict:
    assert len(raw) <= MAX_HTTP_BODY, "response exceeded the 16 KiB canary bound"
    value = json.loads(raw.decode("utf-8"))
    assert isinstance(value, dict)
    return value


async def _run() -> None:
    root = Path(tempfile.mkdtemp(prefix="juno-kite-canary-"))
    synthetic_home = root / "home"
    synthetic_hermes_home = root / "hermes-home"
    synthetic_home.mkdir(mode=0o700)
    synthetic_hermes_home.mkdir(mode=0o700)
    for name, value in {
        "JUNO_KITE_CANARY_MAPPING_KEY": "synthetic-mapping-key-with-at-least-thirty-two-bytes",
        "JUNO_KITE_CANARY_REQUEST_KEY": "synthetic-request-key-with-at-least-thirty-two-bytes",
        "JUNO_KITE_CANARY_RESPONSE_KEY": "synthetic-response-key-with-at-least-thirty-two-bytes",
        "A2A_HOST": "127.0.0.1",
        "A2A_PORT": "0",
        "A2A_PEER_TOKENS": f"juno:{TOKEN}",
        "A2A_TRUSTED_PEERS": "juno",
        "HOME": str(synthetic_home),
        "HERMES_HOME": str(synthetic_hermes_home),
    }.items():
        os.environ[name] = value

    import model_tools
    from gateway.config import PlatformConfig
    from hermes_cli.plugins import get_plugin_manager
    from plugins.platforms.a2a.adapter import A2AAdapter
    from plugins.platforms.a2a.tools import _reply_text_from_result
    from tools.registry import registry

    from .runtime import RESPONSE_PREFIX, TrustedPrincipalRuntime

    adapter = A2AAdapter(PlatformConfig(enabled=True))
    if not await adapter.connect():
        shutil.rmtree(root)
        raise AssertionError("real A2A adapter did not bind loopback")
    assert adapter._httpd is not None
    base_url = f"http://127.0.0.1:{adapter._httpd.server_port}"
    config = _config(root, base_url)
    juno = TrustedPrincipalRuntime(config, active_profile="juno")
    kite_config = copy.deepcopy(config)
    kite_config["juno_kite_trusted_principal"].update(mode="kite", profile="kite")
    kite = TrustedPrincipalRuntime(kite_config, active_profile="kite")
    action_effects: list[dict[str, Any]] = []
    policy_checks: list[str] = []

    registry.register(
        name="synthetic_mutation",
        toolset="synthetic_canary",
        schema={"description": "synthetic", "parameters": {"type": "object"}},
        handler=lambda args, **_kwargs: action_effects.append(dict(args)) or "mutated",
    )
    manager = get_plugin_manager()
    saved_pre = list(manager._hooks.get("pre_tool_call", []))
    saved_final = list(manager._hooks.get("pre_tool_dispatch", []))
    saved_tool_execution = list(manager._middleware.get("tool_execution", []))

    def later_mutation(**kwargs):
        if kwargs.get("tool_name") == "synthetic_mutation":
            kwargs["args"]["value"] = "changed-after-policy"

    manager._hooks["pre_tool_call"] = [kite.pre_tool_call, later_mutation]
    manager._hooks["pre_tool_dispatch"] = [kite.pre_tool_dispatch]
    manager._middleware["tool_execution"] = []

    async def synthetic_kite_handler(event):
        def turn():
            turn_id = str(event.message_id)
            binding = kite.pre_llm_call(
                user_message=event.text,
                session_id="synthetic-kite-session",
                turn_id=turn_id,
                platform="a2a",
            )
            if "DENIED" in str(binding.get("context")):
                answer = "wrong context denied"
            elif "synthetic unknown tool" in event.text:
                result = model_tools.handle_function_call(
                    "synthetic_unknown_tool",
                    {},
                    session_id="synthetic-kite-session",
                    turn_id=turn_id,
                )
                assert "tool is not explicitly classified" in result
                policy_checks.append("unknown-tool-blocked")
                answer = "unknown tool denied"
            elif "synthetic changed action" in event.text:
                result = model_tools.handle_function_call(
                    "synthetic_mutation",
                    {"target": "fixture", "value": "approved"},
                    session_id="synthetic-kite-session",
                    turn_id=turn_id,
                )
                assert "final arguments do not match" in result
                policy_checks.append("changed-action-blocked")
                answer = "changed action denied"
            else:
                answer = "synthetic bounded answer"
            return kite.transform_llm_output(
                answer, session_id="synthetic-kite-session", platform="a2a"
            )

        reply = _session(
            turn,
            platform="a2a",
            user_id="juno",
            context_id=event.source.chat_id,
            profile="kite",
        )
        await adapter.send(event.source.chat_id, reply, metadata={"notify": True})

    adapter.handle_message = synthetic_kite_handler  # type: ignore[method-assign]
    adapter._message_handler = object()

    def consult(question: str, conversation: str) -> str:
        return _session(
            lambda: juno.consult_kite({"question_or_goal": question}),
            platform="telegram",
            user_id=PRINCIPAL_ID,
            context_id=conversation,
            profile="juno",
        )

    class CaptureTransport:
        call: tuple[str, dict, str, str] | None = None

        def __call__(self, peer_name, peer, message, context_id):
            self.call = (peer_name, peer, message, context_id)
            return "unsigned synthetic capture", context_id, "completed"

    try:
        status, raw = await asyncio.to_thread(_request, base_url + "/health", method="GET")
        health = _json(raw)
        assert status == 200 and health.get("status") == "ok"
        print("PASS health: GET /health -> 200, JSON status=ok, body<=16384")

        wrong_body = _send_body(
            "synthetic wrong bearer body", "canary-wrong-bearer", "wrong-bearer"
        )
        status, raw = await asyncio.to_thread(
            _request,
            base_url + "/",
            method="POST",
            body=wrong_body,
            token=WRONG_TOKEN,
        )
        wrong = _json(raw)
        assert status == 401 and isinstance(wrong.get("error"), dict)
        print("PASS wrong bearer: POST / SendMessage -> 401 JSON-RPC error, no dispatch")

        answer = await asyncio.to_thread(
            consult, "synthetic authenticated request", "conversation-001"
        )
        assert answer == "synthetic bounded answer"
        print("PASS authenticated Juno request: POST / SendMessage -> signed bounded answer")

        capture = CaptureTransport()
        juno.transport = capture
        await asyncio.to_thread(
            consult, "synthetic wrong context", "conversation-002"
        )
        assert capture.call is not None
        _peer_name, _peer, message, context_id = capture.call
        wrong_context_body = _send_body(message, context_id + "-changed", "wrong-context")
        status, raw = await asyncio.to_thread(
            _request,
            base_url + "/",
            method="POST",
            body=wrong_context_body,
            token=TOKEN,
        )
        response = _json(raw)
        reply = _reply_text_from_result(response["result"])
        assert status == 200 and RESPONSE_PREFIX in reply and '"denied":true' in reply
        print("PASS wrong context: POST / SendMessage -> 200 signed denial envelope")
        juno.transport = juno._a2a_transport

        unknown = await asyncio.to_thread(
            consult, "synthetic unknown tool", "conversation-003"
        )
        changed = await asyncio.to_thread(
            consult, "synthetic changed action", "conversation-004"
        )
        assert unknown == "unknown tool denied"
        assert changed == "changed action denied"
        assert policy_checks == ["unknown-tool-blocked", "changed-action-blocked"]
        assert action_effects == []
        print("PASS unknown tool: exact plugin gate blocked; signed bounded response")
        print("PASS changed action argument: final dispatch blocked; handler effects=0")
    finally:
        manager._hooks["pre_tool_call"] = saved_pre
        manager._hooks["pre_tool_dispatch"] = saved_final
        manager._middleware["tool_execution"] = saved_tool_execution
        try:
            registry.deregister("synthetic_mutation")
        except Exception:
            pass
        juno.store.close()
        kite.store.close()
        await adapter.disconnect()
        shutil.rmtree(root)
        print("PASS cleanup: adapter stopped; synthetic DB and directory removed")


def main() -> int:
    asyncio.run(_run())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
