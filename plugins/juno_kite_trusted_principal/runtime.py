"""Host-bound Juno--Kite consultation and Kite policy hooks.

This module deliberately composes existing Hermes primitives: the A2A plugin's
JSON-RPC transport helpers, gateway session ContextVars, plugin hooks, and one
SQLite mapping/replay store.  It adds no agent, gateway, session, or A2A
protocol semantics.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import urllib.request
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from gateway.session_context import NON_MESSAGING_SESSION_SURFACES, get_session_env

from .mapping_store import MappingRecord, MappingStore, RequestRecord


logger = logging.getLogger(__name__)

REQUEST_PREFIX = "JUNO_KITE_REQUEST_V1 "
RESPONSE_PREFIX = "JUNO_KITE_RESPONSE_V1 "
DENIAL_PREFIX = "JUNO_KITE_DENIAL_V1 "
AUDIT_PREFIX = "JUNO_KITE_AUDIT_V1 "
_A2A_AUDIT_SUMMARY_CHARS = 500

_REQUEST_FIELDS = frozenset(
    {
        "context_id",
        "correlation_id",
        "request_id",
        "policy_generation",
        "expires_at",
        "question_or_goal",
        "relevant_context",
        "signature",
    }
)
_RESPONSE_FIELDS = frozenset(
    {
        "context_id",
        "correlation_id",
        "request_id",
        "policy_generation",
        "expires_at",
        "answer",
        "denied",
        "reason",
        "signature",
    }
)
_CREDENTIAL_PATTERNS = (
    re.compile(r"(?i)authorization\s*:\s*bearer\s+\S+"),
    re.compile(r"(?i)\b(?:api[_ -]?key|access[_ -]?token|password|secret)\s*[:=]\s*\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)
_EMAIL_PATTERN = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I)
_PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\d .()\-]{7,}\d)(?!\w)")
_PRIVATE_ID_PATTERN = re.compile(
    r"(?i)\b(?:account|chat|conversation|customer|principal|subject|user)[_-]?id\s*[:=]"
)
_UUID_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])"
)
_RAW_RESULT_PATTERNS = (
    re.compile(r"(?i)<\/?tool[_ -]?result>"),
    re.compile(r"(?i)\[tool(?:_result)?\]"),
    re.compile(r'(?i)"(?:raw_)?tool_result"\s*:'),
)
_PROMPT_PATTERNS = (
    re.compile(r"(?i)<\/?system[_ -]?prompt>"),
    re.compile(r"(?i)\bbegin system prompt\b"),
    re.compile(r'(?i)"role"\s*:\s*"system"'),
)


def canonical_json(value: Any) -> str:
    """Deterministic UTF-8 JSON form used by every exact binding."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sign_payload(payload: dict, key: bytes) -> str:
    return hmac.new(key, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def _verify_signature(payload: dict, key: bytes) -> bool:
    signature = payload.get("signature")
    if not isinstance(signature, str) or len(signature) != 64:
        return False
    unsigned = {name: value for name, value in payload.items() if name != "signature"}
    return hmac.compare_digest(signature, sign_payload(unsigned, key))


def _contains_wildcard(value: Any) -> bool:
    if isinstance(value, str):
        return "*" in value
    if isinstance(value, dict):
        return any(_contains_wildcard(k) or _contains_wildcard(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_wildcard(item) for item in value)
    return False


def _truncate_chars(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit]


def _audit_guard(correlation_id: str, request_id: str, context_id: str) -> str:
    """Keep existing A2A's 500-char audit summary opaque and data-free."""
    head = (
        f"{AUDIT_PREFIX}correlation={correlation_id} request={request_id} "
        f"context={context_id} "
    )
    return head + "." * max(0, _A2A_AUDIT_SUMMARY_CHARS + 1 - len(head)) + "\n"


@dataclass(frozen=True)
class Limits:
    question_chars: int
    context_turns: int
    context_turn_chars: int
    handoff_bytes: int
    policy_view_chars: int
    output_chars: int
    response_bytes: int
    turn_ttl_seconds: int


@dataclass(frozen=True)
class TurnBinding:
    valid: bool
    reason: str
    mapping: Optional[MappingRecord] = None
    request: Optional[RequestRecord] = None
    session_id: str = ""
    turn_id: str = ""


_ACTIVE_BINDING: ContextVar[Optional[TurnBinding]] = ContextVar(
    "juno_kite_active_binding", default=None
)


Transport = Callable[[str, dict, str, str], tuple[str, str, str]]


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class TrustedPrincipalRuntime:
    """The generic plugin runtime, configured as either Juno or Kite."""

    def __init__(
        self,
        host_config: dict,
        *,
        active_profile: str,
        transport: Optional[Transport] = None,
        clock: Optional[Callable[[], float]] = None,
    ):
        section = host_config.get("juno_kite_trusted_principal")
        if not isinstance(section, dict):
            raise ValueError("juno_kite_trusted_principal config is required")
        self.host_config = host_config
        self.config = section
        self.enabled = section.get("enabled") is True
        self.mode = str(section.get("mode") or "").strip().lower()
        self.configured_profile = str(section.get("profile") or "").strip()
        self.active_profile = str(active_profile or "default")
        self.policy_generation = str(section.get("policy_generation") or "").strip()
        self.clock = clock or time.time
        self.transport = transport or self._a2a_transport
        self.limits = self._load_limits(section.get("limits"))
        self._validate_static_config()
        self.mapping_key = self._load_key("mapping_key_env")
        self.request_key = self._load_key("request_key_env")
        self.response_key = self._load_key("response_key_env")
        key_refs = {
            str(self.config.get(name) or "").strip()
            for name in ("mapping_key_env", "request_key_env", "response_key_env")
        }
        if len(key_refs) != 3 or len({self.mapping_key, self.request_key, self.response_key}) != 3:
            raise ValueError("mapping, request, and response keys must be independent")
        self.secret_values = {
            value.decode("utf-8", errors="ignore")
            for value in (self.mapping_key, self.request_key, self.response_key)
        }
        self.principal_bindings = self._load_principal_bindings()
        self.private_identifiers = {
            user_id for _platform, user_id, _principal in self.principal_bindings
        }
        self.policy = section.get("policy")
        if not isinstance(self.policy, dict):
            raise ValueError("policy must be a mapping")
        self._validate_policy()
        if self.mode == "juno":
            self.peer = self._resolve_fixed_peer()
            self.secret_values.add(str(self.peer["auth"]["token"]))
        else:
            self.peer_name = str(self.config.get("kite_peer") or "kite").strip()
            self.peer = {}
        # Open durable state only after the entire behavior/authority config
        # validates, so a malformed profile cannot create partial state.
        self.store = MappingStore(Path(str(section["mapping_path"])), self.mapping_key)

    @staticmethod
    def _load_limits(raw: Any) -> Limits:
        if not isinstance(raw, dict):
            raise ValueError("limits must be configured")
        values = {
            "question_chars": int(raw.get("question_chars", 0)),
            "context_turns": int(raw.get("context_turns", 0)),
            "context_turn_chars": int(raw.get("context_turn_chars", 0)),
            "handoff_bytes": int(raw.get("handoff_bytes", 0)),
            "policy_view_chars": int(raw.get("policy_view_chars", 0)),
            "output_chars": int(raw.get("output_chars", 0)),
            "response_bytes": int(raw.get("response_bytes", 0)),
            "turn_ttl_seconds": int(raw.get("turn_ttl_seconds", 0)),
        }
        if any(value <= 0 for value in values.values()):
            raise ValueError("all handoff/output limits must be positive")
        return Limits(**values)

    def _validate_static_config(self) -> None:
        if not self.enabled:
            raise ValueError("plugin is disabled")
        if self.mode not in {"juno", "kite"}:
            raise ValueError("mode must be exactly 'juno' or 'kite'")
        if not self.configured_profile:
            raise ValueError("profile must be configured")
        mapping_path = Path(str(self.config.get("mapping_path") or ""))
        if not mapping_path.is_absolute():
            raise ValueError("mapping_path must be absolute")
        if not self.policy_generation:
            raise ValueError("policy_generation is required")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", self.policy_generation):
            raise ValueError("policy_generation must be a bounded opaque label")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", self.configured_profile):
            raise ValueError("profile must be a bounded profile name")
        if self.mode == "juno" and self.config.get("kite_plugin") != "juno_kite_trusted_principal":
            raise ValueError("the expected Kite policy plugin must be pinned")

    def _load_key(self, config_name: str) -> bytes:
        env_name = str(self.config.get(config_name) or "").strip()
        if not env_name:
            raise ValueError(f"{config_name} must name an environment variable")
        value = os.environ.get(env_name, "").encode("utf-8")
        if len(value) < 32:
            raise ValueError(f"{env_name} must contain at least 32 bytes")
        return value

    def _load_principal_bindings(self) -> tuple[tuple[str, str, str], ...]:
        raw = self.config.get("principal_bindings")
        if not isinstance(raw, list) or not raw:
            raise ValueError("principal_bindings must be a non-empty list")
        bindings = []
        for entry in raw:
            if not isinstance(entry, dict) or set(entry) != {"platform", "user_id", "principal"}:
                raise ValueError("each principal binding requires only platform, user_id, principal")
            platform = str(entry["platform"] or "").strip().lower()
            user_id = str(entry["user_id"] or "").strip()
            principal = str(entry["principal"] or "").strip()
            if not platform or not user_id or not principal:
                raise ValueError("principal binding values cannot be empty")
            if platform in NON_MESSAGING_SESSION_SURFACES or platform in {"a2a", "cron"}:
                raise ValueError("principal bindings must name human messaging platforms")
            bindings.append((platform, user_id, principal))
        return tuple(bindings)

    def _validate_policy(self) -> None:
        principals = self.policy.get("principals")
        classes = self.policy.get("tool_classes")
        rules = self.policy.get("action_rules", [])
        if not isinstance(principals, dict) or not isinstance(classes, dict):
            raise ValueError("policy principals and tool_classes are required")
        bound_principals = {principal for _platform, _user_id, principal in self.principal_bindings}
        if not bound_principals.issubset(principals):
            raise ValueError("every bound principal must have an explicit policy")
        if any(not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(name)) for name in principals):
            raise ValueError("policy principal names must be bounded opaque labels")
        for principal_name, principal_policy in principals.items():
            if not isinstance(principal_policy, dict):
                raise ValueError("each principal policy must be a semantic mapping")
            if self._leak_reason(canonical_json(principal_policy), output=False):
                raise ValueError(
                    f"principal policy {principal_name!r} contains non-semantic private data"
                )
        read_tools = classes.get("read")
        mutating_tools = classes.get("mutating")
        if not isinstance(read_tools, list) or not isinstance(mutating_tools, list):
            raise ValueError("read and mutating tool classes must be lists")
        self.read_tools = frozenset(str(name) for name in read_tools if str(name))
        self.mutating_tools = frozenset(str(name) for name in mutating_tools if str(name))
        if any(
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
            for name in self.read_tools | self.mutating_tools
        ):
            raise ValueError("tool classifications require bounded canonical names")
        if self.read_tools & self.mutating_tools:
            raise ValueError("a tool cannot be both read and mutating")
        if _contains_wildcard(read_tools) or _contains_wildcard(mutating_tools):
            raise ValueError("wildcard tool classes are forbidden")
        if not isinstance(rules, list):
            raise ValueError("action_rules must be a list")
        normalized = []
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {"principal", "tool", "arguments"}:
                raise ValueError("action rules require principal, tool, and complete arguments")
            if rule["tool"] not in self.mutating_tools or not isinstance(rule["arguments"], dict):
                raise ValueError("action rule tool must be classified as mutating")
            if str(rule["principal"]) not in principals:
                raise ValueError("action rule principal must have a policy")
            if _contains_wildcard(rule):
                raise ValueError("wildcard mutation rules are forbidden")
            normalized.append(
                (
                    str(rule["principal"]),
                    str(rule["tool"]),
                    canonical_json(rule["arguments"]),
                )
            )
        self.action_rules = frozenset(normalized)

    def _resolve_fixed_peer(self) -> dict:
        name = str(self.config.get("kite_peer") or "").strip()
        expected_url = str(self.config.get("kite_url") or "").strip().rstrip("/")
        peers = self.host_config.get("a2a_agents")
        entry = peers.get(name) if isinstance(peers, dict) else None
        if not name or not isinstance(entry, dict):
            raise ValueError("the configured Kite A2A peer is missing")
        actual_url = str(entry.get("url") or "").strip().rstrip("/")
        parsed = urlparse(actual_url)
        if (
            actual_url != expected_url
            or parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.query)
            or bool(parsed.fragment)
        ):
            raise ValueError("Kite peer URL must exactly match the configured localhost URL")
        auth = entry.get("auth")
        if not isinstance(auth, dict) or auth.get("type") != "bearer" or not auth.get("token"):
            raise ValueError("Kite peer must use configured bearer authentication")
        timeout = int(entry.get("timeout", 120))
        if timeout <= 0:
            raise ValueError("Kite peer timeout must be positive")
        self.peer_name = name
        return {"url": actual_url, "auth": dict(auth), "timeout": timeout}

    def juno_available(self) -> bool:
        return self.enabled and self.mode == "juno" and self.active_profile == self.configured_profile

    def _profile_matches(self) -> bool:
        contextual = str(get_session_env("HERMES_SESSION_PROFILE") or "").strip()
        return (
            self.active_profile == self.configured_profile
            and (not contextual or contextual == self.configured_profile)
        )

    def _derive_juno_principal(self) -> tuple[str, str]:
        if not self.juno_available() or not self._profile_matches():
            raise ValueError("profile/mode mismatch")
        platform = str(get_session_env("HERMES_SESSION_PLATFORM") or "").strip().lower()
        source = str(get_session_env("HERMES_SESSION_SOURCE") or "").strip().lower()
        user_id = str(get_session_env("HERMES_SESSION_USER_ID") or "").strip()
        conversation_key = str(get_session_env("HERMES_SESSION_KEY") or "").strip()
        if get_session_env("HERMES_CRON_SESSION"):
            raise ValueError("cron context is not a human principal")
        if platform == "a2a" or source == "a2a":
            raise ValueError("A2A loop context is forbidden")
        if not platform or platform in NON_MESSAGING_SESSION_SURFACES:
            raise ValueError("a human messaging platform is required")
        if source and source != platform:
            raise ValueError("conflicting platform/source context")
        if not user_id or not conversation_key:
            raise ValueError("authenticated user and canonical conversation are required")
        matches = {
            principal
            for bound_platform, bound_user_id, principal in self.principal_bindings
            if bound_platform == platform and hmac.compare_digest(bound_user_id, user_id)
        }
        if len(matches) != 1:
            raise ValueError("principal binding is missing or ambiguous")
        return next(iter(matches)), conversation_key

    def _leak_reason(self, text: str, *, output: bool) -> str:
        value = str(text or "")
        for pattern in _CREDENTIAL_PATTERNS:
            if pattern.search(value):
                return "credential-shaped content"
        if any(secret and secret in value for secret in getattr(self, "secret_values", ())):
            return "configured credential value"
        if _EMAIL_PATTERN.search(value):
            return "email-shaped private identifier"
        if _PHONE_PATTERN.search(value):
            return "phone-shaped private identifier"
        if _PRIVATE_ID_PATTERN.search(value):
            return "labelled private identifier"
        if _UUID_PATTERN.search(value):
            return "UUID-shaped private identifier"
        if any(identifier and identifier in value for identifier in self.private_identifiers):
            return "configured private identifier"
        if any(pattern.search(value) for pattern in _RAW_RESULT_PATTERNS):
            return "raw tool-result marker"
        if not output and any(pattern.search(value) for pattern in _PROMPT_PATTERNS):
            return "prompt-shaped content"
        return ""

    def _bounded_context(self, raw: Any) -> list[dict[str, str]]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise ValueError("relevant_context must be a list of turns")
        bounded = []
        for item in raw[: self.limits.context_turns]:
            if not isinstance(item, dict) or set(item) != {"role", "text"}:
                raise ValueError("context turns require only role and text")
            role = str(item["role"] or "")
            text = str(item["text"] or "")
            if role not in {"user", "assistant"}:
                raise ValueError("context role must be user or assistant")
            if self._leak_reason(text, output=False):
                raise ValueError("relevant context contains private or credential-shaped data")
            bounded.append({"role": role, "text": _truncate_chars(text, self.limits.context_turn_chars)})
        return bounded

    def consult_kite(self, args: dict, **_: Any) -> str:
        """Tool handler: derive authority from ContextVars and call fixed Kite."""
        try:
            principal, conversation_key = self._derive_juno_principal()
            question = str((args or {}).get("question_or_goal") or "").strip()
            if not question or len(question) > self.limits.question_chars:
                raise ValueError("question_or_goal is empty or over its configured limit")
            if self._leak_reason(question, output=False):
                raise ValueError("question contains private or credential-shaped data")
            session_private_values = {
                str(get_session_env(name) or "").strip()
                for name in (
                    "HERMES_SESSION_USER_ID",
                    "HERMES_SESSION_CHAT_ID",
                    "HERMES_SESSION_THREAD_ID",
                    "HERMES_SESSION_KEY",
                    "HERMES_SESSION_ID",
                )
            }
            if any(value and value in question for value in session_private_values):
                raise ValueError("question contains a raw authenticated session identifier")
            relevant_context = self._bounded_context((args or {}).get("relevant_context"))
            if any(
                value and value in turn["text"]
                for value in session_private_values
                for turn in relevant_context
            ):
                raise ValueError("relevant context contains a raw authenticated session identifier")
            mapping = self.store.resolve(principal, conversation_key)
            request_id = "req-" + secrets.token_urlsafe(18)
            expires_at = int(self.clock()) + self.limits.turn_ttl_seconds
            unsigned = {
                "context_id": mapping.context_id,
                "correlation_id": mapping.correlation_id,
                "request_id": request_id,
                "policy_generation": self.policy_generation,
                "expires_at": expires_at,
                "question_or_goal": question,
                "relevant_context": relevant_context,
            }
            payload = {**unsigned, "signature": sign_payload(unsigned, self.request_key)}
            guard = _audit_guard(mapping.correlation_id, request_id, mapping.context_id)
            message = guard + REQUEST_PREFIX + canonical_json(payload)
            while len(message.encode("utf-8")) > self.limits.handoff_bytes and relevant_context:
                relevant_context.pop()
                unsigned["relevant_context"] = relevant_context
                payload = {**unsigned, "signature": sign_payload(unsigned, self.request_key)}
                message = guard + REQUEST_PREFIX + canonical_json(payload)
            if len(message.encode("utf-8")) > self.limits.handoff_bytes:
                raise ValueError("bounded handoff exceeds its byte limit")
            self.store.issue_request(mapping, request_id, self.policy_generation, expires_at)
            logger.info("Juno--Kite dispatch correlation=%s", mapping.correlation_id)
            raw, returned_context, state = self.transport(
                self.peer_name, dict(self.peer), message, mapping.context_id
            )
            if returned_context != mapping.context_id or state.lower() not in {
                "completed",
                "task-state-completed",
                "task_state_completed",
            }:
                raise ValueError("Kite returned a mismatched context or incomplete task")
            return self._verify_response(raw, mapping, request_id)
        except Exception as exc:
            logger.warning("Juno--Kite consultation blocked: %s", type(exc).__name__)
            return f"BLOCKED: consult_kite denied ({self._public_reason(exc)})."

    @staticmethod
    def _public_reason(exc: Exception) -> str:
        if isinstance(exc, ValueError):
            return str(exc)
        return "internal fail-closed error"

    def _extract_request(self, user_message: str) -> dict:
        if user_message.count(REQUEST_PREFIX) != 1:
            raise ValueError("missing or ambiguous signed request")
        guard, encoded = user_message.split(REQUEST_PREFIX, 1)
        if not guard.startswith(AUDIT_PREFIX) or len(guard) <= _A2A_AUDIT_SUMMARY_CHARS:
            raise ValueError("request is missing its opaque audit guard")
        encoded = encoded.strip()
        payload = json.loads(encoded)
        if not isinstance(payload, dict) or set(payload) != _REQUEST_FIELDS:
            raise ValueError("malformed or authority-bearing request body")
        if not _verify_signature(payload, self.request_key):
            raise ValueError("invalid request signature")
        question = payload.get("question_or_goal")
        context = payload.get("relevant_context")
        if (
            not isinstance(question, str)
            or not question.strip()
            or len(question) > self.limits.question_chars
            or self._leak_reason(question, output=False)
        ):
            raise ValueError("request question violates bounded handoff policy")
        if context != self._bounded_context(context):
            raise ValueError("request context violates bounded handoff policy")
        return payload

    def _a2a_lane(self) -> tuple[str, str, str]:
        platform = str(get_session_env("HERMES_SESSION_PLATFORM") or "").strip().lower()
        peer = str(get_session_env("HERMES_SESSION_USER_ID") or "").strip()
        context_id = str(get_session_env("HERMES_SESSION_CHAT_ID") or "").strip()
        return platform, peer, context_id

    def _bind_request(self, user_message: str, session_id: str, turn_id: str) -> TurnBinding:
        if self.mode != "kite" or not self._profile_matches():
            raise ValueError("profile/mode mismatch")
        platform, peer, context_id = self._a2a_lane()
        if platform != "a2a" or peer != "juno" or not context_id:
            raise ValueError("request is not on the authenticated Juno A2A lane")
        session_id = str(session_id or "")
        turn_id = str(turn_id or "")
        if not session_id or not turn_id:
            raise ValueError("real session and turn identifiers are required")
        # The adapter always adds this exact peer-specific frame after bearer
        # authentication.  Strip no other prefix and derive no peer identity
        # from message text.
        from plugins.platforms.a2a.security import PRIVACY_PREFIX

        privacy_frame = PRIVACY_PREFIX.format(peer="juno")
        if user_message.startswith(privacy_frame):
            user_message = user_message[len(privacy_frame):]
        payload = self._extract_request(user_message)
        if payload["context_id"] != context_id:
            raise ValueError("request context does not match authenticated A2A context")
        if payload["policy_generation"] != self.policy_generation:
            raise ValueError("request policy generation is stale or unknown")
        now = int(self.clock())
        if not isinstance(payload["expires_at"], int) or payload["expires_at"] <= now:
            raise ValueError("request expired")
        mapping = self.store.get_by_context(context_id)
        if mapping is None or payload["correlation_id"] != mapping.correlation_id:
            raise ValueError("request mapping does not match authenticated context")
        if mapping.principal not in self.policy.get("principals", {}):
            raise ValueError("principal has no policy")
        request = self.store.claim_request(
            str(payload["request_id"]),
            context_id,
            mapping.correlation_id,
            self.policy_generation,
            now,
        )
        if request is None:
            raise ValueError("request is unissued, replayed, stale, or cross-bound")
        return TurnBinding(True, "", mapping, request, session_id, turn_id)

    def _policy_view(self, binding: TurnBinding) -> str:
        assert binding.mapping is not None and binding.request is not None
        principal_policy = self.policy["principals"][binding.mapping.principal]
        view = {
            "policy_generation": self.policy_generation,
            "mapped_scope": binding.mapping.correlation_id,
            "request_correlation": binding.request.request_id,
            "authenticated_peer": "juno",
            "principal": binding.mapping.principal,
            "principal_policy": principal_policy,
            "data_class": "operator-configured semantic classes",
            "subject": binding.mapping.principal,
            "purpose": "answer the current bounded consultation",
            "requested_disclosure": "one minimized policy-compliant answer",
            "recipient": "the authenticated originating principal",
            "destination": "the mapped originating Juno conversation",
            "action": {
                "risk": "operator-classified exact rules only",
                "timing": "same non-stale turn",
                "reversibility": "operator-classified before rule creation",
                "tool_and_arguments": "canonical and complete",
            },
            "read_tools": sorted(self.read_tools),
            "mutating_tools": sorted(self.mutating_tools),
            "rule": (
                "Return only a minimized answer; raw sources, tool results, "
                "credentials, and private identifiers stay in Kite."
            ),
        }
        rendered = (
            "Juno--Kite source-agnostic policy view (host generated):\n"
            + canonical_json(view)
        )
        if len(rendered) > self.limits.policy_view_chars:
            raise ValueError("generated policy view exceeds its deterministic limit")
        return rendered

    def pre_llm_call(
        self,
        user_message: str = "",
        session_id: str = "",
        turn_id: str = "",
        **_: Any,
    ) -> Optional[dict]:
        platform, _peer, _context_id = self._a2a_lane()
        if platform != "a2a":
            _ACTIVE_BINDING.set(None)
            return None
        try:
            binding = self._bind_request(
                str(user_message or ""), str(session_id or ""), str(turn_id or "")
            )
            _ACTIVE_BINDING.set(binding)
            return {"context": self._policy_view(binding)}
        except Exception as exc:
            _ACTIVE_BINDING.set(
                TurnBinding(
                    False,
                    self._public_reason(exc),
                    session_id=str(session_id or ""),
                    turn_id=str(turn_id or ""),
                )
            )
            logger.warning("Kite policy binding denied: %s", type(exc).__name__)
            return {
                "context": (
                    "JUNO--KITE POLICY: DENIED. "
                    "Do not use tools or release response content."
                )
            }

    def _current_valid_binding(
        self, *, session_id: str, turn_id: Optional[str] = None
    ) -> TurnBinding:
        binding = _ACTIVE_BINDING.get()
        if (
            binding is None
            or not binding.valid
            or binding.mapping is None
            or binding.request is None
        ):
            raise ValueError("missing valid same-turn policy binding")
        if self.mode != "kite" or not self._profile_matches():
            raise ValueError("profile/mode mismatch")
        if not session_id or not hmac.compare_digest(binding.session_id, str(session_id)):
            raise ValueError("hook session does not match same-turn policy binding")
        if turn_id is not None and (
            not turn_id or not hmac.compare_digest(binding.turn_id, str(turn_id))
        ):
            raise ValueError("hook turn does not match same-turn policy binding")
        platform, peer, context_id = self._a2a_lane()
        if platform != "a2a" or peer != "juno" or context_id != binding.mapping.context_id:
            raise ValueError("authenticated A2A lane changed after policy binding")
        now = int(self.clock())
        request = self.store.get_request(binding.request.request_id)
        if (
            request is None
            or request.state != "bound"
            or request.expires_at <= now
            or request.policy_generation != self.policy_generation
        ):
            raise ValueError("same-turn binding is stale, replayed, or mismatched")
        return binding

    @staticmethod
    def _block(message: str) -> dict[str, str]:
        return {"action": "block", "message": "Juno--Kite policy blocked tool call: " + message}

    def pre_tool_call(
        self,
        tool_name: str = "",
        args: Any = None,
        session_id: str = "",
        turn_id: str = "",
        **_: Any,
    ) -> Optional[dict]:
        platform, _peer, _context = self._a2a_lane()
        if platform != "a2a":
            return None
        try:
            binding = self._current_valid_binding(
                session_id=str(session_id or ""), turn_id=str(turn_id or "")
            )
            if not isinstance(args, dict):
                return self._block("arguments must be a complete object")
            if tool_name in self.read_tools:
                return None
            if tool_name not in self.mutating_tools:
                return self._block("tool is not explicitly classified")
            assert binding.mapping is not None and binding.request is not None
            canonical_args = canonical_json(args)
            rule = (binding.mapping.principal, str(tool_name), canonical_args)
            if rule not in self.action_rules:
                return self._block("no exact canonical tool-and-arguments rule")
            fingerprint = hashlib.sha256(
                f"{tool_name}\0{canonical_args}".encode("utf-8")
            ).hexdigest()
            if not self.store.claim_action(
                binding.request.request_id, fingerprint, int(self.clock())
            ):
                return self._block("action binding is stale or already consumed")
            return None
        except Exception as exc:
            logger.warning("Kite tool gate blocked: %s", type(exc).__name__)
            return self._block("internal or missing policy binding")

    def _signed_response(
        self,
        binding: Optional[TurnBinding],
        *,
        answer: str,
        denied: bool,
        reason: str,
    ) -> str:
        mapping = binding.mapping if binding else None
        request = binding.request if binding else None
        unsigned = {
            "context_id": mapping.context_id if mapping else "",
            "correlation_id": mapping.correlation_id if mapping else "",
            "request_id": request.request_id if request else "",
            "policy_generation": self.policy_generation,
            "expires_at": request.expires_at if request else int(self.clock()),
            "answer": answer,
            "denied": bool(denied),
            "reason": reason,
        }
        payload = {**unsigned, "signature": sign_payload(unsigned, self.response_key)}
        return (
            _audit_guard(
                mapping.correlation_id if mapping else "corr-denied",
                request.request_id if request else "req-denied",
                mapping.context_id if mapping else "ctx-denied",
            )
            + RESPONSE_PREFIX
            + canonical_json(payload)
        )

    def transform_llm_output(
        self, response_text: str = "", session_id: str = "", **_: Any
    ) -> Optional[str]:
        platform, _peer, _context = self._a2a_lane()
        if platform != "a2a":
            return None
        binding = _ACTIVE_BINDING.get()
        try:
            binding = self._current_valid_binding(session_id=str(session_id or ""))
            answer = str(response_text or "")
            leak_reason = self._leak_reason(answer, output=True)
            denied = bool(leak_reason)
            if denied:
                answer = ""
            else:
                answer = _truncate_chars(answer, self.limits.output_chars)
            assert binding.request is not None
            if not self.store.release_request(binding.request.request_id, int(self.clock())):
                raise ValueError("response binding could not be released")
            envelope = self._signed_response(
                binding,
                answer=answer,
                denied=denied,
                reason=("output minimized by deterministic leak policy" if denied else ""),
            )
            while len(envelope.encode("utf-8")) > self.limits.response_bytes and answer:
                answer = answer[:-1]
                envelope = self._signed_response(binding, answer=answer, denied=denied, reason="")
            if len(envelope.encode("utf-8")) > self.limits.response_bytes:
                raise ValueError("response envelope exceeds byte limit")
            return envelope
        except Exception as exc:
            logger.warning("Kite output release denied: %s", type(exc).__name__)
            try:
                return self._signed_response(
                    binding if binding and binding.valid else None,
                    answer="",
                    denied=True,
                    reason="missing, stale, mismatched, or internal policy binding",
                )
            except Exception:
                return DENIAL_PREFIX + "no releasable envelope"

    def _verify_response(self, raw: str, mapping: MappingRecord, request_id: str) -> str:
        encoded = str(raw or "")
        if len(encoded.encode("utf-8")) > self.limits.response_bytes:
            raise ValueError("Kite response exceeds configured byte limit")
        if encoded.count(RESPONSE_PREFIX) != 1:
            raise ValueError("Kite response is unsigned")
        guard, encoded_payload = encoded.split(RESPONSE_PREFIX, 1)
        if not guard.startswith(AUDIT_PREFIX) or len(guard) <= _A2A_AUDIT_SUMMARY_CHARS:
            raise ValueError("Kite response is missing its opaque audit guard")
        try:
            payload = json.loads(encoded_payload)
        except (TypeError, ValueError) as exc:
            raise ValueError("Kite response is malformed") from exc
        if not isinstance(payload, dict) or set(payload) != _RESPONSE_FIELDS:
            raise ValueError("Kite response has an invalid envelope")
        if not _verify_signature(payload, self.response_key):
            raise ValueError("Kite response signature is invalid")
        expected = {
            "context_id": mapping.context_id,
            "correlation_id": mapping.correlation_id,
            "request_id": request_id,
            "policy_generation": self.policy_generation,
        }
        if any(payload.get(name) != value for name, value in expected.items()):
            raise ValueError("Kite response scope or correlation is mismatched")
        now = int(self.clock())
        request = self.store.get_request(request_id)
        if (
            request is None
            or not isinstance(payload.get("expires_at"), int)
            or payload["expires_at"] != request.expires_at
            or payload["expires_at"] <= now
        ):
            raise ValueError("Kite response is stale or expired")
        answer = payload.get("answer")
        if not isinstance(answer, str) or len(answer) > self.limits.output_chars:
            raise ValueError("Kite response answer exceeds its minimized limit")
        if self._leak_reason(answer, output=True):
            raise ValueError("Kite response contains leak-shaped data")
        if not self.store.consume_response(
            request_id,
            mapping.context_id,
            mapping.correlation_id,
            self.policy_generation,
            now,
        ):
            raise ValueError("Kite response is replayed or not releasable")
        if payload.get("denied") is not False:
            raise ValueError("Kite denied release under current policy")
        return answer

    @staticmethod
    def _a2a_transport(
        peer_name: str, peer: dict, message: str, context_id: str
    ) -> tuple[str, str, str]:
        """Use A2A's existing protocol/HTTP helpers without card URL redirect."""
        from plugins.platforms.a2a import protocol, security
        from plugins.platforms.a2a.tools import _auth_header, _reply_text_from_result

        safe_message = security.redact_outbound(message)
        if safe_message != message:
            raise ValueError("A2A redaction changed the signed bounded handoff")
        task_id = protocol.new_task_id()
        body = {
            "jsonrpc": "2.0",
            "id": task_id,
            "method": "SendMessage",
            "params": {
                "message": protocol.text_message(
                    protocol.ROLE_USER, message, context_id=context_id
                )
            },
        }
        security.audit("outbound", peer_name, task_id, "opaque trusted-principal consultation")
        protocol.persist_message(context_id, "user", message, task_id)
        data = json.dumps(body).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "A2A-Version": protocol.PROTOCOL_VERSION,
            **_auth_header(peer["auth"]),
        }
        request = urllib.request.Request(
            str(peer["url"]).rstrip("/"), data=data, headers=headers, method="POST"
        )

        opener = urllib.request.build_opener(_RefuseRedirects())
        with opener.open(request, timeout=int(peer["timeout"])) as http_response:
            response = json.loads(http_response.read().decode("utf-8"))
        if "error" in response:
            raise ValueError("Kite A2A peer returned an error")
        payload = protocol.unwrap_send_message_response(response.get("result", {}))
        reply = _reply_text_from_result(payload)
        reply_context = context_id
        state = ""
        if isinstance(payload, dict):
            reply_context = str(payload.get("contextId") or context_id)
            state = str((payload.get("status") or {}).get("state") or "")
        protocol.persist_message(reply_context, "agent", reply, task_id)
        return reply, reply_context, state


class FailClosedRuntime:
    """Keeps A2A output and tools closed when configured plugin startup fails."""

    def __init__(self, error: Exception, *, mode: str, active_profile: str):
        self.error = error
        self.mode = mode
        self.active_profile = active_profile
        self.enabled = False
        self.limits = Limits(1, 1, 1, 1, 1, 1, 1, 1)

    def juno_available(self) -> bool:
        return False

    def consult_kite(self, _args: dict, **_: Any) -> str:
        return "BLOCKED: consult_kite configuration is unavailable."

    def pre_llm_call(self, **_: Any) -> Optional[dict]:
        if str(get_session_env("HERMES_SESSION_PLATFORM") or "").lower() == "a2a":
            return {"context": "JUNO--KITE POLICY: DENIED. Plugin configuration is unavailable."}
        return None

    def pre_tool_call(self, **_: Any) -> Optional[dict]:
        if str(get_session_env("HERMES_SESSION_PLATFORM") or "").lower() == "a2a":
            return {"action": "block", "message": "Juno--Kite policy configuration is unavailable"}
        return None

    def transform_llm_output(self, **_: Any) -> Optional[str]:
        if str(get_session_env("HERMES_SESSION_PLATFORM") or "").lower() == "a2a":
            return DENIAL_PREFIX + "no releasable envelope"
        return None


def runtime_from_host(active_profile: str) -> TrustedPrincipalRuntime | FailClosedRuntime:
    host_config: dict = {}
    try:
        from hermes_cli.config import load_config

        host_config = load_config() or {}
        return TrustedPrincipalRuntime(host_config, active_profile=active_profile)
    except Exception as exc:
        logger.warning("Juno--Kite plugin initialized fail-closed: %s", type(exc).__name__)
        section = host_config.get("juno_kite_trusted_principal", {})
        if not isinstance(section, dict):
            section = {}
        return FailClosedRuntime(
            exc,
            mode=str(section.get("mode") or "").strip().lower(),
            active_profile=active_profile,
        )
