"""Host-bound Juno--Kite consultation and Kite policy hooks.

This module deliberately composes existing Hermes primitives: the A2A plugin's
JSON-RPC transport helpers, gateway session ContextVars, plugin hooks, and one
SQLite mapping/replay store.  It adds no agent, gateway, session, or A2A
protocol semantics.
"""

from __future__ import annotations

import asyncio
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

REQUEST_PREFIX = "JUNO_KITE_REQUEST_V2 "
RESPONSE_PREFIX = "JUNO_KITE_RESPONSE_V2 "
DENIAL_PREFIX = "JUNO_KITE_DENIAL_V2 "
AUDIT_PREFIX = "JUNO_KITE_AUDIT_V2 "
_A2A_AUDIT_SUMMARY_CHARS = 500

_REQUEST_FIELDS = frozenset(
    {
        "context_id",
        "version",
        "correlation_id",
        "request_id",
        "policy_generation",
        "expires_at",
        "question_or_goal",
        "relevant_context",
        "audience_digest",
        "conversation_binding",
        "effective_read_capability_ids",
        "effective_action_capability_ids",
        "roster_generation",
        "signature",
    }
)
_RESPONSE_FIELDS = frozenset(
    {
        "context_id",
        "version",
        "correlation_id",
        "request_id",
        "policy_generation",
        "expires_at",
        "answer",
        "denied",
        "reason",
        "audience_digest",
        "conversation_binding",
        "effective_read_capability_ids",
        "effective_action_capability_ids",
        "roster_generation",
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
    roster_timeout_seconds: int


@dataclass(frozen=True)
class AudienceBinding:
    """Opaque host-derived authority for one current conversation audience."""

    principal: str
    conversation_kind: str
    conversation_binding: str
    audience_digest: str
    roster_generation: str
    effective_read_capability_ids: tuple[str, ...]
    effective_action_capability_ids: tuple[str, ...]
    private_eligible: bool
    policy_generation: str
    revalidate: Optional[Callable[[], dict]] = None


@dataclass(frozen=True)
class PreparedRequest:
    """One signed, durably issued request ready for the fixed A2A transport."""

    mapping: MappingRecord
    request_id: str
    message: str
    audience: AudienceBinding


@dataclass(frozen=True)
class TurnBinding:
    valid: bool
    reason: str
    mapping: Optional[MappingRecord] = None
    request: Optional[RequestRecord] = None
    session_id: str = ""
    turn_id: str = ""
    effective_read_capability_ids: tuple[str, ...] = ()
    effective_action_capability_ids: tuple[str, ...] = ()


_ACTIVE_BINDING: ContextVar[Optional[TurnBinding]] = ContextVar(
    "juno_kite_active_binding", default=None
)
_ACTIVE_AUDIENCE: ContextVar[Optional[AudienceBinding]] = ContextVar(
    "juno_kite_active_audience", default=None
)
_ACTIVE_INGRESS_TOKEN: ContextVar[Any] = ContextVar(
    "juno_kite_active_ingress_token", default=None
)

CRITICAL_INGRESS_SCOPE = "juno-trusted-principal-v2"


Transport = Callable[[str, dict, str, str], tuple[str, str, str]]


def critical_ingress_satisfied(token: Any) -> bool:
    """Prove the trusted callback completed for this exact dispatch event."""
    return token is not None and _ACTIVE_INGRESS_TOKEN.get() is token


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
        self.allowed_group_conversations = self._load_allowed_group_conversations()
        self.private_identifiers.update(
            chat_id for _platform, chat_id in self.allowed_group_conversations
        )
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
            "roster_timeout_seconds": int(raw.get("roster_timeout_seconds", 0)),
        }
        if any(value <= 0 for value in values.values()):
            raise ValueError("all handoff/output limits must be positive")
        if values["roster_timeout_seconds"] > 5:
            raise ValueError("roster timeout must remain short and bounded")
        return Limits(**values)

    def _validate_static_config(self) -> None:
        if self.config.get("version") != 2:
            raise ValueError("trusted-principal config version must be exactly 2")
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
            if platform == "whatsapp" and re.fullmatch(
                r"\d{1,32}@(s\.whatsapp\.net|lid)", user_id
            ) is None:
                raise ValueError("WhatsApp principal bindings require canonical JID/LID values")
            bindings.append((platform, user_id, principal))
        return tuple(bindings)

    def _load_allowed_group_conversations(self) -> frozenset[tuple[str, str]]:
        raw = self.config.get("allowed_group_conversations")
        if not isinstance(raw, list):
            raise ValueError("allowed_group_conversations must be an explicit list")
        groups: set[tuple[str, str]] = set()
        for entry in raw:
            if not isinstance(entry, dict) or set(entry) != {"platform", "chat_id"}:
                raise ValueError("group allowlist entries require only platform and chat_id")
            platform = str(entry.get("platform") or "").strip().lower()
            chat_id = str(entry.get("chat_id") or "").strip()
            if platform != "whatsapp" or re.fullmatch(r"\d{1,32}@g\.us", chat_id) is None:
                raise ValueError("Slice A group allowlists require canonical WhatsApp group IDs")
            if (platform, chat_id) in groups:
                raise ValueError("duplicate allowed group conversation")
            groups.add((platform, chat_id))
        return frozenset(groups)

    def _validate_policy(self) -> None:
        if set(self.policy) != {"principals", "tool_classes", "action_rules"}:
            raise ValueError("policy requires the exact audience-policy fields")
        principals = self.policy.get("principals")
        classes = self.policy.get("tool_classes")
        rules = self.policy.get("action_rules", [])
        if not isinstance(principals, dict) or not isinstance(classes, dict):
            raise ValueError("policy principals and tool_classes are required")
        if set(classes) != {"read", "mutating"}:
            raise ValueError("tool_classes requires exact read and mutating fields")
        bound_principals = {principal for _platform, _user_id, principal in self.principal_bindings}
        if not bound_principals.issubset(principals):
            raise ValueError("every bound principal must have an explicit policy")
        if any(not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(name)) for name in principals):
            raise ValueError("policy principal names must be bounded opaque labels")
        expected_principal_fields = {
            "conversation_eligibility",
            "required_group_co_principals",
            "read_capability_ids",
            "action_capability_ids",
            "semantic_policy",
        }
        self.conversation_eligibility: dict[str, dict[str, bool]] = {}
        self.required_group_co_principals: dict[str, frozenset[str]] = {}
        self.principal_read_capabilities: dict[str, frozenset[str]] = {}
        self.principal_action_capabilities: dict[str, frozenset[str]] = {}
        capability_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
        for principal_name, principal_policy in principals.items():
            if not isinstance(principal_policy, dict) or set(principal_policy) != expected_principal_fields:
                raise ValueError("each principal policy requires the exact audience-policy fields")
            eligibility = principal_policy.get("conversation_eligibility")
            if (
                not isinstance(eligibility, dict)
                or set(eligibility) != {"dm", "group"}
                or type(eligibility.get("dm")) is not bool
                or type(eligibility.get("group")) is not bool
            ):
                raise ValueError("conversation eligibility requires exact DM/group booleans")
            required = principal_policy.get("required_group_co_principals")
            read_caps = principal_policy.get("read_capability_ids")
            action_caps = principal_policy.get("action_capability_ids")
            semantic_policy = principal_policy.get("semantic_policy")
            if not isinstance(required, list) or not isinstance(read_caps, list) or not isinstance(action_caps, list):
                raise ValueError("principal group requirements and capabilities must be lists")
            if not isinstance(semantic_policy, dict):
                raise ValueError("principal semantic_policy must be a mapping")
            if len(set(map(str, required))) != len(required):
                raise ValueError("required co-principals must be unique")
            if any(str(name) not in principals or str(name) == str(principal_name) for name in required):
                raise ValueError("required co-principals must name other configured principals")
            for values in (read_caps, action_caps):
                if len(set(map(str, values))) != len(values) or any(
                    capability_pattern.fullmatch(str(value)) is None for value in values
                ):
                    raise ValueError("semantic capability IDs must be unique bounded labels")
            if eligibility["dm"] is False and action_caps:
                raise ValueError("group-only principals cannot have action capabilities")
            if set(map(str, semantic_policy)) != set(map(str, read_caps)):
                raise ValueError(
                    "semantic_policy must map every read capability ID exactly once"
                )
            if self._leak_reason(canonical_json(semantic_policy), output=False):
                raise ValueError(
                    f"principal policy {principal_name!r} contains non-semantic private data"
                )
            name = str(principal_name)
            self.conversation_eligibility[name] = {
                "dm": eligibility["dm"], "group": eligibility["group"]
            }
            self.required_group_co_principals[name] = frozenset(map(str, required))
            self.principal_read_capabilities[name] = frozenset(map(str, read_caps))
            self.principal_action_capabilities[name] = frozenset(map(str, action_caps))
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
            if not self.principal_action_capabilities[str(rule["principal"])]:
                raise ValueError("action rule principal has no semantic action capability")
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

    @staticmethod
    def _capability_fingerprint(values: tuple[str, ...] | list[str]) -> str:
        return hashlib.sha256(canonical_json(list(values)).encode("utf-8")).hexdigest()

    def _opaque_digest(self, label: str, value: Any) -> str:
        material = label.encode("ascii") + b"\0" + canonical_json(value).encode("utf-8")
        return hmac.new(self.mapping_key, material, hashlib.sha256).hexdigest()

    def _principal_for_transport_identity(self, platform: str, identity: str) -> set[str]:
        return {
            principal
            for bound_platform, bound_identity, principal in self.principal_bindings
            if bound_platform == platform and hmac.compare_digest(bound_identity, identity)
        }

    def _audience_from_roster(
        self,
        *,
        initiating_principal: str,
        platform: str,
        chat_id: str,
        roster: dict,
        revalidate: Callable[[], dict],
    ) -> AudienceBinding:
        if not isinstance(roster, dict) or set(roster) != {
            "group_id", "participants", "bot_identities", "generation"
        }:
            raise ValueError("authenticated roster evidence is malformed")
        if roster.get("group_id") != chat_id:
            raise ValueError("authenticated roster group is mismatched")
        generation = roster.get("generation")
        if not isinstance(generation, str) or re.fullmatch(r"[a-f0-9]{64}", generation) is None:
            raise ValueError("authenticated roster generation is malformed")
        participants = roster.get("participants")
        bot_identities = roster.get("bot_identities")
        if not isinstance(participants, list) or not participants:
            raise ValueError("authenticated roster is empty")
        if not isinstance(bot_identities, list) or not bot_identities:
            raise ValueError("authenticated bot identity evidence is missing")
        identity_pattern = re.compile(r"\d{1,32}@(s\.whatsapp\.net|lid)")
        if len(set(bot_identities)) != len(bot_identities) or any(
            not isinstance(value, str) or identity_pattern.fullmatch(value) is None
            for value in bot_identities
        ):
            raise ValueError("authenticated bot identity evidence is malformed")
        bot_set = frozenset(bot_identities)
        canonical_members: list[tuple[str, ...]] = []
        seen_transport_ids: set[str] = set()
        human_principals: list[str] = []
        audience_unknown = False
        for raw_member in participants:
            if not isinstance(raw_member, list) or not raw_member:
                raise ValueError("authenticated roster member is malformed")
            if len(set(raw_member)) != len(raw_member) or any(
                not isinstance(value, str) or identity_pattern.fullmatch(value) is None
                for value in raw_member
            ):
                raise ValueError("authenticated roster identity is malformed")
            member = tuple(sorted(raw_member))
            if any(value in seen_transport_ids for value in member):
                raise ValueError("authenticated roster contains duplicate identities")
            seen_transport_ids.update(member)
            canonical_members.append(member)
            bot_overlap = bot_set.intersection(member)
            if bot_overlap:
                if not set(member).issubset(bot_set):
                    raise ValueError("bot and human identities are ambiguously combined")
                continue
            matches: set[str] = set()
            for identity in member:
                matches.update(self._principal_for_transport_identity(platform, identity))
            if len(matches) != 1:
                audience_unknown = True
                continue
            human_principals.append(next(iter(matches)))
        if not human_principals and not audience_unknown:
            raise ValueError("authenticated roster has no human members")
        if len(set(human_principals)) != len(human_principals):
            # Separate roster records cannot be collapsed merely because two
            # configured aliases name the same principal. Only aliases carried
            # together by one transport participant record prove equivalence.
            audience_unknown = True
        proved_principals = frozenset(human_principals)
        if initiating_principal not in proved_principals:
            raise PermissionError("initiating-principal-unproved")
        required = self.required_group_co_principals[initiating_principal]
        if not required.issubset(proved_principals):
            raise PermissionError("required-co-principal-unproved")
        if audience_unknown:
            read_caps: tuple[str, ...] = ()
            action_caps: tuple[str, ...] = ()
        else:
            read_sets = [self.principal_read_capabilities[name] for name in proved_principals]
            read_caps = tuple(sorted(set.intersection(*(set(values) for values in read_sets))))
            # Mixed/group conversations intentionally expose no actions in
            # Slice A. Later action handlers require their own final audience
            # revalidation seam before this can be non-empty.
            action_caps = ()
        conversation_binding = self._opaque_digest(
            "conversation-v2", {"platform": platform, "kind": "group", "chat": chat_id}
        )
        audience_digest = self._opaque_digest(
            "audience-v2",
            {
                "conversation": conversation_binding,
                "members": sorted(canonical_members),
                "bots": sorted(bot_set),
                "generation": generation,
            },
        )
        return AudienceBinding(
            principal=initiating_principal,
            conversation_kind="group",
            conversation_binding=conversation_binding,
            audience_digest=audience_digest,
            roster_generation=generation,
            effective_read_capability_ids=read_caps,
            effective_action_capability_ids=action_caps,
            private_eligible=bool(read_caps),
            policy_generation=self.policy_generation,
            revalidate=revalidate,
        )

    def _single_principal_audience(
        self, principal: str, platform: str, destination: str
    ) -> AudienceBinding:
        if not self.conversation_eligibility[principal]["dm"]:
            raise ValueError("conversation is not eligible")
        conversation_binding = self._opaque_digest(
            "conversation-v2",
            {"platform": platform, "kind": "dm", "chat": destination},
        )
        return AudienceBinding(
            principal=principal,
            conversation_kind="dm",
            conversation_binding=conversation_binding,
            audience_digest=self._opaque_digest(
                "audience-v2", {"conversation": conversation_binding, "principal": principal}
            ),
            roster_generation=self._opaque_digest(
                "roster-v2", {"kind": "single-principal", "principal": principal}
            ),
            effective_read_capability_ids=tuple(
                sorted(self.principal_read_capabilities[principal])
            ),
            effective_action_capability_ids=tuple(
                sorted(self.principal_action_capabilities[principal])
            ),
            private_eligible=bool(self.principal_read_capabilities[principal]),
            policy_generation=self.policy_generation,
        )

    def current_audience_binding(self) -> AudienceBinding:
        binding = _ACTIVE_AUDIENCE.get()
        if binding is None:
            raise ValueError("no active authenticated audience")
        return binding

    @staticmethod
    def _ingress_skip(reason: str) -> dict:
        return {"action": "skip", "reason": reason, "redact_scope": True}

    @staticmethod
    def _ingress_allow(critical_ingress_token: Any) -> dict:
        _ACTIVE_INGRESS_TOKEN.set(critical_ingress_token)
        return {
            "action": "critical_allow",
            "scope": CRITICAL_INGRESS_SCOPE,
            "redact_scope": True,
        }

    async def pre_gateway_dispatch(
        self,
        event: Any = None,
        gateway: Any = None,
        critical_ingress_token: Any = None,
        **_: Any,
    ) -> Optional[dict]:
        """Bind eligible Juno audience authority before auth/session/model work."""
        if self.mode != "juno" or not self.juno_available():
            return None
        _ACTIVE_AUDIENCE.set(None)
        _ACTIVE_INGRESS_TOKEN.set(None)
        source = getattr(event, "source", None)
        platform_value = getattr(getattr(source, "platform", None), "value", None)
        platform = str(platform_value or getattr(source, "platform", "") or "").lower()
        user_id = str(getattr(source, "user_id", "") or "")
        matches = self._principal_for_transport_identity(platform, user_id)
        if not matches:
            return None
        # Ambiguous configured identities are protected and therefore skipped,
        # never passed through to pairing/auth/model behavior.
        if len(matches) != 1:
            return self._ingress_skip("protected-principal-ambiguous")
        principal = next(iter(matches))
        try:
            chat_type = str(getattr(source, "chat_type", "") or "").lower()
            chat_id = str(getattr(source, "chat_id", "") or "")
            eligibility = self.conversation_eligibility[principal]
            if chat_type not in {"dm", "group"} or not eligibility[chat_type]:
                return self._ingress_skip("conversation-ineligible")
            if chat_type == "dm":
                _ACTIVE_AUDIENCE.set(
                    self._single_principal_audience(principal, platform, chat_id)
                )
                return self._ingress_allow(critical_ingress_token)
            if (
                platform != "whatsapp"
                or (platform, chat_id) not in self.allowed_group_conversations
            ):
                return self._ingress_skip("conversation-ineligible")
            metadata = getattr(event, "metadata", None) or {}
            if metadata.get("whatsapp_inbound_provenance") != (
                "messages.upsert:registered-emitting-socket:v1"
            ):
                raise ValueError("authenticated inbound socket provenance is missing")
            inbound_runtime_id = metadata.get("whatsapp_inbound_runtime_id")
            inbound_socket_generation = metadata.get(
                "whatsapp_inbound_socket_generation"
            )
            if (
                not isinstance(inbound_runtime_id, str)
                or re.fullmatch(r"[a-f0-9]{64}", inbound_runtime_id) is None
                or not isinstance(inbound_socket_generation, int)
                or isinstance(inbound_socket_generation, bool)
                or inbound_socket_generation <= 0
            ):
                raise ValueError("authenticated inbound socket generation is missing")
            adapters = getattr(gateway, "adapters", None) or {}
            adapter = adapters.get(getattr(source, "platform", None))
            fetch = getattr(adapter, "authenticated_group_roster", None)
            if not callable(fetch):
                raise ValueError("authenticated managed roster provider is unavailable")

            def provider() -> dict:
                return fetch(
                    self.configured_profile,
                    chat_id,
                    timeout=self.limits.roster_timeout_seconds,
                    expected_runtime_id=inbound_runtime_id,
                    expected_socket_generation=inbound_socket_generation,
                )

            roster = await asyncio.wait_for(
                asyncio.to_thread(provider), timeout=self.limits.roster_timeout_seconds + 0.5
            )
            _ACTIVE_AUDIENCE.set(
                self._audience_from_roster(
                    initiating_principal=principal,
                    platform=platform,
                    chat_id=chat_id,
                    roster=roster,
                    revalidate=provider,
                )
            )
            return self._ingress_allow(critical_ingress_token)
        except asyncio.CancelledError:
            raise
        except PermissionError:
            return self._ingress_skip("required-co-principal-unproved")
        except Exception as exc:
            logger.warning("Juno audience ingress blocked: %s", type(exc).__name__)
            # Group-only principals must remain silent when roster/co-member
            # proof is unavailable. Other protected group principals are also
            # skipped: allowing on hook failure would bypass the pre-model gate.
            return self._ingress_skip("audience-authority-unavailable")

    def _revalidate_audience(self, binding: AudienceBinding) -> AudienceBinding:
        if binding.policy_generation != self.policy_generation:
            raise ValueError("audience policy generation changed")
        if binding.conversation_kind == "dm":
            return binding
        if binding.revalidate is None:
            raise ValueError("group audience cannot be revalidated")
        roster = binding.revalidate()
        current = self._audience_from_roster(
            initiating_principal=binding.principal,
            platform="whatsapp",
            chat_id=next(
                chat_id
                for platform, chat_id in self.allowed_group_conversations
                if platform == "whatsapp"
                and self._opaque_digest(
                    "conversation-v2",
                    {"platform": platform, "kind": "group", "chat": chat_id},
                ) == binding.conversation_binding
            ),
            roster=roster,
            revalidate=binding.revalidate,
        )
        expected = (
            binding.conversation_binding,
            binding.audience_digest,
            binding.roster_generation,
            binding.effective_read_capability_ids,
            binding.effective_action_capability_ids,
            binding.private_eligible,
        )
        observed = (
            current.conversation_binding,
            current.audience_digest,
            current.roster_generation,
            current.effective_read_capability_ids,
            current.effective_action_capability_ids,
            current.private_eligible,
        )
        if not hmac.compare_digest(
            hashlib.sha256(canonical_json(expected).encode()).digest(),
            hashlib.sha256(canonical_json(observed).encode()).digest(),
        ):
            raise ValueError("authenticated audience changed")
        return current

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

    def _prepare_request(self, args: dict) -> PreparedRequest:
        """Validate current host authority and durably issue one signed request."""
        principal, conversation_key = self._derive_juno_principal()
        audience = _ACTIVE_AUDIENCE.get()
        chat_type = str(get_session_env("HERMES_SESSION_CHAT_TYPE") or "").lower()
        platform = str(get_session_env("HERMES_SESSION_PLATFORM") or "").lower()
        chat_id = str(get_session_env("HERMES_SESSION_CHAT_ID") or "")
        if audience is None:
            if chat_type != "dm":
                raise ValueError("group audience was not authenticated at ingress")
            audience = self._single_principal_audience(principal, platform, chat_id)
            _ACTIVE_AUDIENCE.set(audience)
        if audience.principal != principal:
            raise ValueError("audience principal does not match authenticated sender")
        if audience.conversation_kind != chat_type:
            raise ValueError("audience conversation classification changed")
        expected_conversation_binding = self._opaque_digest(
            "conversation-v2",
            {"platform": platform, "kind": chat_type, "chat": chat_id},
        )
        if not hmac.compare_digest(
            audience.conversation_binding, expected_conversation_binding
        ):
            raise ValueError("audience destination binding changed")
        if audience.policy_generation != self.policy_generation:
            raise ValueError("audience policy generation is stale")
        if not audience.private_eligible or not audience.effective_read_capability_ids:
            raise ValueError("effective audience is public-only")
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
        # First live group recheck. This happens before mapping or request
        # creation, so a changed/missing audience cannot leave authority state
        # or issue an A2A call.
        audience = self._revalidate_audience(audience)
        mapping = self.store.resolve(principal, conversation_key)
        request_id = "req-" + secrets.token_urlsafe(18)
        expires_at = int(self.clock()) + self.limits.turn_ttl_seconds
        unsigned = {
            "version": 2,
            "context_id": mapping.context_id,
            "correlation_id": mapping.correlation_id,
            "request_id": request_id,
            "policy_generation": self.policy_generation,
            "expires_at": expires_at,
            "question_or_goal": question,
            "relevant_context": relevant_context,
            "audience_digest": audience.audience_digest,
            "conversation_binding": audience.conversation_binding,
            "effective_read_capability_ids": list(audience.effective_read_capability_ids),
            "effective_action_capability_ids": list(audience.effective_action_capability_ids),
            "roster_generation": audience.roster_generation,
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
        self.store.issue_request(
            mapping,
            request_id,
            self.policy_generation,
            expires_at,
            audience.audience_digest,
            audience.conversation_binding,
            self._capability_fingerprint(audience.effective_read_capability_ids),
            self._capability_fingerprint(audience.effective_action_capability_ids),
            audience.roster_generation,
        )
        logger.info("Juno--Kite dispatch correlation=%s", mapping.correlation_id)
        return PreparedRequest(mapping, request_id, message, audience)

    def consult_kite(self, args: dict, **_: Any) -> str:
        """Tool handler: derive authority from ContextVars and call fixed Kite."""
        request_id = ""
        try:
            prepared = self._prepare_request(args)
            mapping = prepared.mapping
            request_id = prepared.request_id
            audience = prepared.audience
            raw, returned_context, state = self.transport(
                self.peer_name, dict(self.peer), prepared.message, mapping.context_id
            )
            if returned_context != mapping.context_id or state.lower() not in {
                "completed",
                "task-state-completed",
                "task_state_completed",
            }:
                raise ValueError("Kite returned a mismatched context or incomplete task")
            payload = self._validate_response(raw, mapping, request_id)
            # Verify the signed response first, then acquire a second live
            # roster immediately before private content can return to Juno.
            self._revalidate_audience(audience)
            if not self.store.consume_response(
                request_id,
                mapping.context_id,
                mapping.correlation_id,
                self.policy_generation,
                int(self.clock()),
            ):
                raise ValueError("Kite response is replayed or not releasable")
            return str(payload["answer"])
        except Exception as exc:
            if request_id:
                try:
                    self.store.abort_request(request_id)
                except Exception:
                    logger.warning("Juno--Kite request abort failed closed")
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
        if payload.get("version") != 2:
            raise ValueError("unsupported trusted-principal envelope version")
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
        for name in ("audience_digest", "conversation_binding", "roster_generation"):
            if not isinstance(payload.get(name), str) or re.fullmatch(
                r"[a-f0-9]{64}", payload[name]
            ) is None:
                raise ValueError("request audience binding is malformed")
        capability_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
        for name in (
            "effective_read_capability_ids", "effective_action_capability_ids"
        ):
            values = payload.get(name)
            if (
                not isinstance(values, list)
                or values != sorted(set(values))
                or any(
                    not isinstance(value, str)
                    or capability_pattern.fullmatch(value) is None
                    for value in values
                )
            ):
                raise ValueError("request effective capabilities are malformed")
        if not payload["effective_read_capability_ids"]:
            raise ValueError("public-only audience cannot request private consultation")
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
        read_caps = tuple(payload["effective_read_capability_ids"])
        action_caps = tuple(payload["effective_action_capability_ids"])
        if not set(read_caps).issubset(
            self.principal_read_capabilities[mapping.principal]
        ) or not set(action_caps).issubset(
            self.principal_action_capabilities[mapping.principal]
        ):
            raise ValueError("requested semantic policy exceeds principal audience authority")
        request = self.store.claim_request(
            str(payload["request_id"]),
            context_id,
            mapping.correlation_id,
            self.policy_generation,
            now,
            str(payload["audience_digest"]),
            str(payload["conversation_binding"]),
            self._capability_fingerprint(read_caps),
            self._capability_fingerprint(action_caps),
            str(payload["roster_generation"]),
        )
        if request is None:
            raise ValueError("request is unissued, replayed, stale, or cross-bound")
        return TurnBinding(
            True,
            "",
            mapping,
            request,
            session_id,
            turn_id,
            read_caps,
            action_caps,
        )

    def _policy_view(self, binding: TurnBinding) -> str:
        assert binding.mapping is not None and binding.request is not None
        configured_semantic_policy = self.policy["principals"][
            binding.mapping.principal
        ]["semantic_policy"]
        principal_policy = {
            capability_id: configured_semantic_policy[capability_id]
            for capability_id in binding.effective_read_capability_ids
        }
        view = {
            "policy_generation": self.policy_generation,
            "mapped_scope": binding.mapping.correlation_id,
            "request_correlation": binding.request.request_id,
            "authenticated_peer": "juno",
            "principal": binding.mapping.principal,
            "principal_policy": principal_policy,
            "effective_read_capability_ids": list(
                binding.effective_read_capability_ids
            ),
            "effective_action_capability_ids": list(
                binding.effective_action_capability_ids
            ),
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
        binding: Optional[TurnBinding] = None
        try:
            binding = self._bind_request(
                str(user_message or ""), str(session_id or ""), str(turn_id or "")
            )
            _ACTIVE_BINDING.set(binding)
            return {"context": self._policy_view(binding)}
        except Exception as exc:
            if binding and binding.request:
                try:
                    self.store.abort_request(binding.request.request_id)
                except Exception:
                    logger.warning("Kite bind abort failed closed")
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
            if not binding.effective_action_capability_ids:
                return self._block("effective audience has no action capability")
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

    def pre_tool_dispatch(
        self,
        tool_name: str = "",
        args: Any = None,
        session_id: str = "",
        turn_id: str = "",
        **_: Any,
    ) -> Optional[dict]:
        """Recheck exact mutation authority at the real handler boundary."""
        platform, _peer, _context = self._a2a_lane()
        if platform != "a2a":
            return None
        try:
            binding = self._current_valid_binding(
                session_id=str(session_id or ""), turn_id=str(turn_id or "")
            )
            if not isinstance(args, dict):
                return self._block("final arguments must be a complete object")
            if tool_name in self.read_tools:
                return None
            if tool_name not in self.mutating_tools:
                return self._block("tool is not explicitly classified at dispatch")
            if not binding.effective_action_capability_ids:
                return self._block("effective audience has no final action capability")
            assert binding.mapping is not None and binding.request is not None
            canonical_args = canonical_json(args)
            rule = (binding.mapping.principal, str(tool_name), canonical_args)
            if rule not in self.action_rules:
                return self._block("final arguments do not match the exact action rule")
            fingerprint = hashlib.sha256(
                f"{tool_name}\0{canonical_args}".encode("utf-8")
            ).hexdigest()
            if not self.store.verify_action(
                binding.request.request_id, fingerprint, int(self.clock())
            ):
                return self._block("final action does not match claimed authority")
            return None
        except Exception as exc:
            logger.warning("Kite final tool gate blocked: %s", type(exc).__name__)
            return self._block("internal or missing final policy binding")

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
            "version": 2,
            "context_id": mapping.context_id if mapping else "",
            "correlation_id": mapping.correlation_id if mapping else "",
            "request_id": request.request_id if request else "",
            "policy_generation": self.policy_generation,
            "expires_at": request.expires_at if request else int(self.clock()),
            "answer": answer,
            "denied": bool(denied),
            "reason": reason,
            "audience_digest": request.audience_digest if request else "",
            "conversation_binding": request.conversation_binding if request else "",
            "effective_read_capability_ids": (
                list(binding.effective_read_capability_ids) if binding else []
            ),
            "effective_action_capability_ids": (
                list(binding.effective_action_capability_ids) if binding else []
            ),
            "roster_generation": request.roster_generation if request else "",
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
            if binding and binding.request:
                try:
                    self.store.abort_request(binding.request.request_id)
                except Exception:
                    logger.warning("Kite request abort failed closed")
            try:
                return self._signed_response(
                    binding if binding and binding.valid else None,
                    answer="",
                    denied=True,
                    reason="missing, stale, mismatched, or internal policy binding",
                )
            except Exception:
                return DENIAL_PREFIX + "no releasable envelope"

    def _validate_response(self, raw: str, mapping: MappingRecord, request_id: str) -> dict:
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
        if payload.get("version") != 2:
            raise ValueError("Kite response has an unsupported envelope version")
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
        authority_expected = {
            "audience_digest": request.audience_digest,
            "conversation_binding": request.conversation_binding,
            "roster_generation": request.roster_generation,
            "effective_read_capability_ids": payload.get(
                "effective_read_capability_ids"
            ),
            "effective_action_capability_ids": payload.get(
                "effective_action_capability_ids"
            ),
        }
        if any(
            payload.get(name) != authority_expected[name]
            for name in ("audience_digest", "conversation_binding", "roster_generation")
        ):
            raise ValueError("Kite response audience scope is mismatched")
        if any(
            not isinstance(authority_expected[name], str)
            or re.fullmatch(r"[a-f0-9]{64}", authority_expected[name]) is None
            for name in ("audience_digest", "conversation_binding", "roster_generation")
        ):
            raise ValueError("Kite response audience binding is malformed")
        read_caps = authority_expected["effective_read_capability_ids"]
        action_caps = authority_expected["effective_action_capability_ids"]
        if (
            not isinstance(read_caps, list)
            or read_caps != sorted(set(read_caps))
            or not isinstance(action_caps, list)
            or action_caps != sorted(set(action_caps))
            or self._capability_fingerprint(tuple(read_caps))
            != request.read_capability_fingerprint
            or self._capability_fingerprint(tuple(action_caps))
            != request.action_capability_fingerprint
        ):
            raise ValueError("Kite response effective capabilities are mismatched")
        answer = payload.get("answer")
        if not isinstance(answer, str) or len(answer) > self.limits.output_chars:
            raise ValueError("Kite response answer exceeds its minimized limit")
        if self._leak_reason(answer, output=True):
            raise ValueError("Kite response contains leak-shaped data")
        if payload.get("denied") is not False:
            raise ValueError("Kite denied release under current policy")
        return payload

    def _verify_response(self, raw: str, mapping: MappingRecord, request_id: str) -> str:
        """Compatibility helper: verify and consume one already released response."""
        payload = self._validate_response(raw, mapping, request_id)
        if not self.store.consume_response(
            request_id,
            mapping.context_id,
            mapping.correlation_id,
            self.policy_generation,
            int(self.clock()),
        ):
            raise ValueError("Kite response is replayed or not releasable")
        return str(payload["answer"])

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

        # Supplying an explicit empty ProxyHandler prevents build_opener() from
        # importing HTTP(S)/ALL_PROXY from the ambient environment. Redirects
        # remain disabled so the bearer and signed body can reach only the
        # configured loopback origin.
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _RefuseRedirects()
        )
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


def valid_juno_gateway_activation_config(raw: Any, active_profile: str) -> bool:
    """Purely validate the config needed to activate Juno's adapter fence.

    This deliberately performs no environment reads and opens no mapping
    store. Plugin initialization remains authoritative for secrets, the fixed
    A2A peer entry, and durable state.
    """
    try:
        if (
            type(raw) is not dict
            or active_profile != "juno"
            or raw.get("version") != 2
            or raw.get("enabled") is not True
            or raw.get("mode") != "juno"
            or raw.get("profile") != "juno"
        ):
            return False
        validator = object.__new__(TrustedPrincipalRuntime)
        validator.config = raw
        validator.enabled = raw.get("enabled") is True
        validator.mode = str(raw.get("mode") or "").strip().lower()
        validator.configured_profile = str(raw.get("profile") or "").strip()
        validator.policy_generation = str(raw.get("policy_generation") or "").strip()
        validator.secret_values = set()
        validator._validate_static_config()
        validator.limits = validator._load_limits(raw.get("limits"))
        key_refs = [
            str(raw.get(name) or "").strip()
            for name in (
                "mapping_key_env",
                "request_key_env",
                "response_key_env",
            )
        ]
        if any(not value for value in key_refs) or len(set(key_refs)) != 3:
            return False
        validator.principal_bindings = validator._load_principal_bindings()
        if not any(
            platform == "whatsapp"
            for platform, _user_id, _principal in validator.principal_bindings
        ):
            return False
        validator.private_identifiers = {
            user_id for _platform, user_id, _principal in validator.principal_bindings
        }
        validator.allowed_group_conversations = (
            validator._load_allowed_group_conversations()
        )
        if not validator.allowed_group_conversations:
            return False
        validator.private_identifiers.update(
            chat_id for _platform, chat_id in validator.allowed_group_conversations
        )
        validator.policy = raw.get("policy")
        if not isinstance(validator.policy, dict):
            return False
        validator._validate_policy()
        peer_name = str(raw.get("kite_peer") or "").strip()
        peer_url = str(raw.get("kite_url") or "").strip().rstrip("/")
        parsed = urlparse(peer_url)
        return bool(
            peer_name
            and raw.get("kite_plugin") == "juno_kite_trusted_principal"
            and parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
        )
    except (TypeError, ValueError):
        return False


class FailClosedRuntime:
    """Keeps A2A output and tools closed when configured plugin startup fails."""

    def __init__(
        self,
        error: Exception,
        *,
        mode: str,
        active_profile: str,
        configured_profile: str,
    ):
        self.error = error
        self.mode = mode
        self.active_profile = active_profile
        self.configured_profile = configured_profile
        self.enabled = False
        self.limits = Limits(1, 1, 1, 1, 1, 1, 1, 1, 1)

    def juno_available(self) -> bool:
        return False

    def consult_kite(self, _args: dict, **_: Any) -> str:
        return "BLOCKED: consult_kite configuration is unavailable."

    def pre_gateway_dispatch(self, **_: Any) -> Optional[dict]:
        if (
            self.mode == "juno"
            and bool(self.configured_profile)
            and self.active_profile == self.configured_profile
        ):
            return {
                "action": "skip",
                "reason": "audience-policy-unavailable",
                "redact_scope": True,
            }
        return None

    def pre_llm_call(self, **_: Any) -> Optional[dict]:
        if str(get_session_env("HERMES_SESSION_PLATFORM") or "").lower() == "a2a":
            return {"context": "JUNO--KITE POLICY: DENIED. Plugin configuration is unavailable."}
        return None

    def pre_tool_call(self, **_: Any) -> Optional[dict]:
        if str(get_session_env("HERMES_SESSION_PLATFORM") or "").lower() == "a2a":
            return {"action": "block", "message": "Juno--Kite policy configuration is unavailable"}
        return None

    def pre_tool_dispatch(self, **_: Any) -> Optional[dict]:
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
            configured_profile=str(section.get("profile") or "").strip(),
        )
