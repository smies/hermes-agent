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
from datetime import datetime, timezone
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

_REQUEST_FIELDS = frozenset({
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
    "host_output_tier",
    "host_informational",
    "signature",
})
_RESPONSE_FIELDS = frozenset({
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
})
_CREDENTIAL_PATTERNS = (
    re.compile(r"(?i)authorization\s*:\s*bearer\s+\S+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)\b(?:api[_ -]?key|access[_ -]?token|refresh[_ -]?token|password|secret)\s*[:=]\s*\S+"
    ),
    re.compile(r"(?i)\b(?:session[_ -]?cookie|set-cookie|cookie)\s*[:=]\s*\S+"),
    re.compile(
        r"(?i)\b(?:otp|one[- ]time|verification|authentication|signup|recovery|pairing)"
        r"(?:\s+(?:password|code))?\s*[:=]\s*[A-Za-z0-9-]{4,64}\b"
    ),
    # "verification code 8f3k2a" is a secret; "verification that the document
    # is his" is a sentence. Without a qualifier, require the token to look
    # like a code rather than the next English word -- this rule refused
    # "Send me my British passport" before it ever left Juno.
    re.compile(
        r"(?i)\b(?:otp|one[- ]time|login|verification|authentication|signup|recovery|pairing)"
        r"\s+(?:password|code)\s+(?:is\s+)?[A-Za-z0-9-]{4,64}\b"
    ),
    re.compile(
        r"(?i)\b(?:otp|one[- ]time|login|verification|authentication|signup|recovery|pairing)"
        r"\s+(?:is\s+)?(?=[A-Za-z0-9-]{4,64}\b)[A-Za-z-]*\d[A-Za-z0-9-]*\b"
    ),
    re.compile(
        r"(?i)\b(?:cvv|cvc|card pin|banking pin|online banking passcode)\s*[:=]\s*\d{3,12}\b"
    ),
    re.compile(
        r"(?i)https?://\S{0,512}(?:magic|login|signin|reset|recover|token|auth)[^\s]*[?&](?:token|code|key|secret)=\S+"
    ),
    re.compile(
        r"(?i)https?://\S{0,512}/(?:magic|login|signin|reset|recover|auth)(?:/|\?)[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{8,}"
    ),
    re.compile(
        r"(?i)https?://\S{0,512}[?&](?:access_token|auth_token|refresh_token|"
        r"session_token|token|api_key|secret)=\S+"
    ),
    re.compile(r"(?i)\b(?:qr|pairing)\s+(?:code|payload|material)\s*[:=]\s*\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)
_EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.I
)
_ISO_DATE_PATTERN = re.compile(
    r"(?<!\d)\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?(?!\d)"
)
_PHONE_CANDIDATE = re.compile(r"(?<!\w)\+?\d[\d .()\-]{5,}\d(?!\w)")


def _is_phone_shaped(token: str) -> bool:
    """Whether a run of digits looks like someone's phone number.

    Length alone does not say. Four family passport numbers written as a
    plain list -- "Alex Morgan Reed - 900000001 - 4 March 2032" -- were
    each read as a phone number and the whole answer was withheld, because
    the only carve-out was for a value written directly after the words
    "passport number", which a list does not do. Nothing in that answer even
    said "passport", so no rule about surrounding words could have saved it.

    What actually distinguishes a phone number is its shape: a country code,
    a trunk zero, grouping, or enough digits to be dialled. A bare nine-digit
    run with none of those is a reference of some kind, and this filter is
    the backstop for contact details leaking in by accident -- what may be
    disclosed on purpose is decided by the tier and the capability.
    """
    digits = re.sub(r"\D", "", token)
    if not 9 <= len(digits) <= 15:
        return False
    if token.lstrip().startswith("+") or digits.startswith("0"):
        return True
    groups = [part for part in re.split(r"[ .()\-]+", token.strip()) if part]
    if len(groups) > 1:
        # A number is dialled in short groups. A nine-digit run standing next
        # to something else -- "900000002 - 31 January" -- is a reference and
        # a date, which the separators alone cannot tell from a dialled
        # number.
        return all(len(part) <= 6 for part in groups)
    return len(digits) >= 10
# Emphasis is formatting, and formatting must not decide a security verdict.
# A model writes "Passport number: **900000001**", the bold broke the passport
# carve-out below, and the number underneath was read as a phone number -- the
# answer was refused for containing the thing it had been asked for. The same
# gap runs the other way: cred**ential** would slip a pattern that the flat
# text catches, so the scan sees both forms and either one is enough.
_EMPHASIS_PATTERN = re.compile(r"[*_`~]+")
_PASSPORT_CONTEXT_PATTERN = re.compile(
    r"(?i)\bpassport\s+(?:number|no\.?|identifier)\s*[:#-]?\s*"
    r"[A-Z0-9][A-Z0-9 -]{4,18}[A-Z0-9]\b"
)
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
_OUTPUT_INTERNAL_PATTERNS = (
    re.compile(r"(?i)(?:^|\s)/Users/[^\s]+"),
    re.compile(r"(?i)(?:^|\s)(?:~|\$HOME)/\.hermes(?:/|\b)"),
    re.compile(r"(?i)\b(?:oauth|client)[_-]?id\s*[:=]"),
    re.compile(r"(?i)\b(?:platform|connector|raw)[_-]?session[_-]?id\s*[:=]"),
)
_RAW_EMAIL_HEADER_PATTERN = re.compile(
    r"(?im)^(?:from|to|cc|bcc|subject|date|message-id|in-reply-to|mime-version):\s*.+$"
)
_RAW_EMAIL_JSON_PATTERNS = (
    re.compile(r'(?i)"headers"\s*:\s*[\[{]'),
    re.compile(r'(?i)"(?:raw|body|payload)"\s*:\s*"'),
)
_PROPERTY_CAPABILITY_ID = "juno.shared.property_intel"
_PROPERTY_OUTPUT_MAX_CHARS = 4000
_PROPERTY_OUTPUT_MAX_BYTES = 12_000
_PROPERTY_OUTPUT_MAX_LINES = 40
_PROPERTY_OUTPUT_MAX_BULLETS = 30
_PROPERTY_OUTPUT_INTERNAL_PATTERNS = (
    re.compile(r"(?i)(?:^|\s)/Users/[^\s]+"),
    re.compile(r"(?i)(?:^|\s)(?:~|\$HOME)/\.hermes(?:/|\b)"),
    re.compile(r"(?i)\b(?:connector|oauth)[_-]?client[_-]?id\s*[:=]"),
    re.compile(r"(?i)\b(?:platform|connector|raw)[_-]?session[_-]?id\s*[:=]"),
)
_PROPERTY_TABLE_SEPARATOR_PATTERN = re.compile(
    r"\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*"
)

_PRIVATE_SOURCE_FRAGMENT_CHARS = 48
_PRIVATE_SOURCE_MAX_RECORDED_FRAGMENTS = 128
_MINIMIZED_PROVENANCE_MAX_DISTINCT_FRAGMENTS = 12
_MINIMIZED_PROVENANCE_MAX_TOTAL_CHARS = 480
_PROVENANCE_IDENTITY_FIELDS = frozenset({
    "author", "authorname", "bcc", "canonicaltitle", "cc", "date",
    "datetime", "documenttitle", "filename", "from", "sender",
    "sendername", "subject", "time", "timestamp", "title", "to",
})
_CONTENT_FIELDS = frozenset({
    "attachmenttext", "body", "content", "description", "extractedtext",
    "html", "htmlbody", "message", "notes", "plaintext", "snippet",
    "text", "transcript",
})


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
    return hmac.new(
        key, canonical_json(payload).encode("utf-8"), hashlib.sha256
    ).hexdigest()


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
        return any(
            _contains_wildcard(k) or _contains_wildcard(v) for k, v in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_wildcard(item) for item in value)
    return False


def _truncate_chars(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[:limit]


def _normalized_payload_field(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _provenance_identity_path(path: tuple[str, ...]) -> bool:
    """Classify source text from its payload field path, never answer text."""
    fields = tuple(_normalized_payload_field(part) for part in path)
    return bool(
        fields
        and fields[-1] in _PROVENANCE_IDENTITY_FIELDS
        and not _CONTENT_FIELDS.intersection(fields)
    )


def _contains_json_container(value: str) -> bool:
    """Detect a complete or embedded JSON object/list deterministically."""
    stripped = value.strip()
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, (dict, list)):
            return True
    decoder = json.JSONDecoder()
    for index, character in enumerate(value):
        if character not in "[{":
            continue
        try:
            parsed, _end = decoder.raw_decode(value, index)
        except (TypeError, ValueError):
            continue
        if isinstance(parsed, (dict, list)):
            return True
    return False


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
    human_principals: tuple[str, ...] = ()
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
    output_tier: str = "minimized_answer"


_ACTIVE_BINDING: ContextVar[Optional[TurnBinding]] = ContextVar(
    "juno_kite_active_binding", default=None
)
_ACTIVE_AUDIENCE: ContextVar[Optional[AudienceBinding]] = ContextVar(
    "juno_kite_active_audience", default=None
)
_ACTIVE_INGRESS_TOKEN: ContextVar[Any] = ContextVar(
    "juno_kite_active_ingress_token", default=None
)
_ACTIVE_PRIVATE_READS: ContextVar[Optional[dict[str, set[str]]]] = ContextVar(
    "juno_kite_active_private_reads", default=None
)
# The authentic inbound message, captured at ingress before any model sees it.
# The output tier is a security control and must not be derived from a string
# the Juno model wrote: its paraphrase varies per turn, and an under-classified
# document request would skip the staging and approval gates entirely.
_ACTIVE_INBOUND_TEXT: ContextVar[str] = ContextVar(
    "juno_kite_active_inbound_text", default=""
)
# The authenticated delivery seam and destination for this turn, captured at
# ingress so an auto-released document is dispatched by the host rather than by
# anything the model says or does.
_ACTIVE_DELIVERY: ContextVar[Optional[tuple[Any, str]]] = ContextVar(
    "juno_kite_active_delivery", default=None
)
# The gateway's own event loop. An async tool handler is run by _run_async on a
# fresh loop in a disposable thread, and the platform adapter's HTTP session is
# bound to the loop that created it, so a document dispatched from the tool's
# loop fails in the transport. Delivery is scheduled back onto this loop.
_ACTIVE_LOOP: ContextVar[Optional[Any]] = ContextVar(
    "juno_kite_active_loop", default=None
)

CRITICAL_INGRESS_SCOPE = "juno-trusted-principal-v2"
# How long a document request stays resolvable by a bare follow-up.
_DOCUMENT_FOLLOWUP_TTL_SECONDS = 300
# The closed vocabulary of a host-built release descriptor. Juno recognises the
# shape by these, so nothing outside them can wear it.
_RELEASE_SOURCE_CLASSES = frozenset({"personal files", "personal Gmail attachment"})
# Readers whose source has no capability of its own, bound to named principals.
_PRINCIPAL_BOUND_READS = {"kite_session_search": frozenset({"james"})}
_RELEASE_PURPOSES = frozenset({
    "personal administration",
    "family administration",
    "travel administration",
    "property administration",
})


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
        private_read_backends: Optional[dict[str, Any]] = None,
        private_read_command_runner: Optional[Callable[..., Any]] = None,
        private_read_url_opener: Any = None,
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
        if (
            len(key_refs) != 3
            or len({self.mapping_key, self.request_key, self.response_key}) != 3
        ):
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
        from .private_reads import PrivateReadService, TOOL_NAMES

        self.private_reads = PrivateReadService(
            section.get("private_reads"),
            backends=private_read_backends,
            command_runner=private_read_command_runner,
            url_opener=private_read_url_opener,
            secret_values=self.secret_values,
        )
        self.private_read_tool_names = frozenset(self.private_reads.tool_names)
        if self.private_reads.enabled:
            configured_reads = frozenset(
                str(name) for name in self.policy["tool_classes"]["read"]
            )
            prohibited_reads = configured_reads - frozenset(TOOL_NAMES)
            if prohibited_reads:
                raise ValueError(
                    "Slice B private reads cannot classify generic or non-plugin read tools"
                )
            if self.mutating_tools or self.action_rules:
                raise ValueError(
                    "Slice B private-read mode cannot enable mutating tools or rules"
                )
            self.read_tools = frozenset(TOOL_NAMES)
        if self.mode == "juno":
            self.peer = self._resolve_fixed_peer()
            self.secret_values.add(str(self.peer["auth"]["token"]))
        else:
            self.peer_name = str(self.config.get("kite_peer") or "kite").strip()
            self.peer = {}
        # Open durable state only after the entire behavior/authority config
        # validates, so a malformed profile cannot create partial state.
        self.store = MappingStore(Path(str(section["mapping_path"])), self.mapping_key)
        # Turns whose document the host already delivered, so the model's
        # redundant confirmation can be dropped. Bounded: each entry is
        # consumed by the transform for that same turn.
        self._auto_delivered: set[str] = set()
        # Conversations whose last request was a document request, so a bare
        # "send it again" can be resolved. Keyed by the opaque conversation
        # binding, never a raw chat id, and short-lived.
        self._recent_document_turns: dict[str, int] = {}
        from .document_release import DocumentReleaseService

        self.document_releases = DocumentReleaseService(
            section.get("document_release"),
            store=self.store,
            mapping_key=self.mapping_key,
            clock=self.clock,
        )
        if self.document_releases.enabled:
            # Only the staging side needs typed readers: it is the read that
            # produces the artifact.  The Juno side carries the same
            # document_release config to run the other half -- claiming one
            # APPROVE code, revalidating the staged inode, and delivering it --
            # and must never be given private-read backends to do that.  Any
            # mode other than juno is still required to have them, so an
            # unrecognized mode stays fail-closed.
            if self.mode != "juno" and not self.private_reads.enabled:
                raise ValueError("document release requires Slice B private reads")
            james_caps = self.principal_read_capabilities.get("james")
            if not james_caps or "juno.private.james" not in james_caps:
                raise ValueError("document release requires the exact James private capability")
            if any(
                name != "james" and "juno.private.james" in capabilities
                for name, capabilities in self.principal_read_capabilities.items()
            ):
                raise ValueError("the James-only document phase cannot be shared")

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
        if (
            self.mode == "juno"
            and self.config.get("kite_plugin") != "juno_kite_trusted_principal"
        ):
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
            if not isinstance(entry, dict) or set(entry) != {
                "platform",
                "user_id",
                "principal",
            }:
                raise ValueError(
                    "each principal binding requires only platform, user_id, principal"
                )
            platform = str(entry["platform"] or "").strip().lower()
            user_id = str(entry["user_id"] or "").strip()
            principal = str(entry["principal"] or "").strip()
            if not platform or not user_id or not principal:
                raise ValueError("principal binding values cannot be empty")
            if platform in NON_MESSAGING_SESSION_SURFACES or platform in {
                "a2a",
                "cron",
            }:
                raise ValueError(
                    "principal bindings must name human messaging platforms"
                )
            if (
                platform == "whatsapp"
                and re.fullmatch(r"\d{1,32}@(s\.whatsapp\.net|lid)", user_id) is None
            ):
                raise ValueError(
                    "WhatsApp principal bindings require canonical JID/LID values"
                )
            bindings.append((platform, user_id, principal))
        return tuple(bindings)

    def _load_allowed_group_conversations(self) -> frozenset[tuple[str, str]]:
        raw = self.config.get("allowed_group_conversations")
        if not isinstance(raw, list):
            raise ValueError("allowed_group_conversations must be an explicit list")
        groups: set[tuple[str, str]] = set()
        for entry in raw:
            if not isinstance(entry, dict) or set(entry) != {"platform", "chat_id"}:
                raise ValueError(
                    "group allowlist entries require only platform and chat_id"
                )
            platform = str(entry.get("platform") or "").strip().lower()
            chat_id = str(entry.get("chat_id") or "").strip()
            if (
                platform != "whatsapp"
                or re.fullmatch(r"\d{1,32}@g\.us", chat_id) is None
            ):
                raise ValueError(
                    "Slice A group allowlists require canonical WhatsApp group IDs"
                )
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
        bound_principals = {
            principal for _platform, _user_id, principal in self.principal_bindings
        }
        if not bound_principals.issubset(principals):
            raise ValueError("every bound principal must have an explicit policy")
        if any(
            not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(name)) for name in principals
        ):
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
            if (
                not isinstance(principal_policy, dict)
                or set(principal_policy) != expected_principal_fields
            ):
                raise ValueError(
                    "each principal policy requires the exact audience-policy fields"
                )
            eligibility = principal_policy.get("conversation_eligibility")
            if (
                not isinstance(eligibility, dict)
                or set(eligibility) != {"dm", "group"}
                or type(eligibility.get("dm")) is not bool
                or type(eligibility.get("group")) is not bool
            ):
                raise ValueError(
                    "conversation eligibility requires exact DM/group booleans"
                )
            required = principal_policy.get("required_group_co_principals")
            read_caps = principal_policy.get("read_capability_ids")
            action_caps = principal_policy.get("action_capability_ids")
            semantic_policy = principal_policy.get("semantic_policy")
            if (
                not isinstance(required, list)
                or not isinstance(read_caps, list)
                or not isinstance(action_caps, list)
            ):
                raise ValueError(
                    "principal group requirements and capabilities must be lists"
                )
            if not isinstance(semantic_policy, dict):
                raise ValueError("principal semantic_policy must be a mapping")
            if len(set(map(str, required))) != len(required):
                raise ValueError("required co-principals must be unique")
            if any(
                str(name) not in principals or str(name) == str(principal_name)
                for name in required
            ):
                raise ValueError(
                    "required co-principals must name other configured principals"
                )
            for values in (read_caps, action_caps):
                if len(set(map(str, values))) != len(values) or any(
                    capability_pattern.fullmatch(str(value)) is None for value in values
                ):
                    raise ValueError(
                        "semantic capability IDs must be unique bounded labels"
                    )
            if eligibility["dm"] is False and action_caps:
                raise ValueError(
                    "group-only principals cannot have action capabilities"
                )
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
                "dm": eligibility["dm"],
                "group": eligibility["group"],
            }
            self.required_group_co_principals[name] = frozenset(map(str, required))
            self.principal_read_capabilities[name] = frozenset(map(str, read_caps))
            self.principal_action_capabilities[name] = frozenset(map(str, action_caps))
        read_tools = classes.get("read")
        mutating_tools = classes.get("mutating")
        if not isinstance(read_tools, list) or not isinstance(mutating_tools, list):
            raise ValueError("read and mutating tool classes must be lists")
        self.read_tools = frozenset(str(name) for name in read_tools if str(name))
        self.mutating_tools = frozenset(
            str(name) for name in mutating_tools if str(name)
        )
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
            if not isinstance(rule, dict) or set(rule) != {
                "principal",
                "tool",
                "arguments",
            }:
                raise ValueError(
                    "action rules require principal, tool, and complete arguments"
                )
            if rule["tool"] not in self.mutating_tools or not isinstance(
                rule["arguments"], dict
            ):
                raise ValueError("action rule tool must be classified as mutating")
            if str(rule["principal"]) not in principals:
                raise ValueError("action rule principal must have a policy")
            if not self.principal_action_capabilities[str(rule["principal"])]:
                raise ValueError(
                    "action rule principal has no semantic action capability"
                )
            if _contains_wildcard(rule):
                raise ValueError("wildcard mutation rules are forbidden")
            normalized.append((
                str(rule["principal"]),
                str(rule["tool"]),
                canonical_json(rule["arguments"]),
            ))
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
            raise ValueError(
                "Kite peer URL must exactly match the configured localhost URL"
            )
        auth = entry.get("auth")
        if (
            not isinstance(auth, dict)
            or auth.get("type") != "bearer"
            or not auth.get("token")
        ):
            raise ValueError("Kite peer must use configured bearer authentication")
        timeout = int(entry.get("timeout", 120))
        if timeout <= 0:
            raise ValueError("Kite peer timeout must be positive")
        self.peer_name = name
        return {"url": actual_url, "auth": dict(auth), "timeout": timeout}

    def juno_available(self) -> bool:
        return (
            self.enabled
            and self.mode == "juno"
            and self.active_profile == self.configured_profile
        )

    def private_reads_available(self) -> bool:
        """Static schema availability; same-turn authority is checked at dispatch."""
        return bool(
            self.enabled
            and self.mode == "kite"
            and self._profile_matches()
            and self.private_reads.enabled
        )

    def _profile_matches(self) -> bool:
        contextual = str(get_session_env("HERMES_SESSION_PROFILE") or "").strip()
        return self.active_profile == self.configured_profile and (
            not contextual or contextual == self.configured_profile
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
            raise ValueError(
                "authenticated user and canonical conversation are required"
            )
        matches = {
            principal
            for bound_platform, bound_user_id, principal in self.principal_bindings
            if bound_platform == platform
            and hmac.compare_digest(bound_user_id, user_id)
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

    def _principal_for_transport_identity(
        self, platform: str, identity: str
    ) -> set[str]:
        return {
            principal
            for bound_platform, bound_identity, principal in self.principal_bindings
            if bound_platform == platform
            and hmac.compare_digest(bound_identity, identity)
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
            "group_id",
            "participants",
            "bot_identities",
            "generation",
        }:
            raise ValueError("authenticated roster evidence is malformed")
        if roster.get("group_id") != chat_id:
            raise ValueError("authenticated roster group is mismatched")
        generation = roster.get("generation")
        if (
            not isinstance(generation, str)
            or re.fullmatch(r"[a-f0-9]{64}", generation) is None
        ):
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
                    raise ValueError(
                        "bot and human identities are ambiguously combined"
                    )
                continue
            matches: set[str] = set()
            for identity in member:
                matches.update(
                    self._principal_for_transport_identity(platform, identity)
                )
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
            read_sets = [
                self.principal_read_capabilities[name] for name in proved_principals
            ]
            read_caps = tuple(
                sorted(set.intersection(*(set(values) for values in read_sets)))
            )
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
            human_principals=tuple(sorted(proved_principals)),
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
                "audience-v2",
                {"conversation": conversation_binding, "principal": principal},
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
            human_principals=(principal,),
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

    @staticmethod
    def _is_document_approval_text(value: Any) -> bool:
        text = str(value or "").strip()
        return text == "APPROVE" or text.startswith("APPROVE ")

    @staticmethod
    async def _send_document_receipt(adapter: Any, chat_id: str, text: str) -> None:
        send = getattr(adapter, "send", None)
        if not callable(send):
            return
        try:
            await send(chat_id=chat_id, content=text)
        except Exception:
            logger.warning("Juno document receipt transport failed closed")

    async def _handle_document_approval(
        self,
        *,
        event: Any,
        adapter: Any,
        audience: AudienceBinding,
    ) -> dict:
        """Consume and dispatch one exact approval without invoking the model."""
        chat_id = str(getattr(getattr(event, "source", None), "chat_id", "") or "")
        denied = "Document release denied."
        text = str(getattr(event, "text", "") or "").strip()
        match = re.fullmatch(r"APPROVE (C7-[A-Z2-9]{16})", text)
        if match is None:
            await self._send_document_receipt(adapter, chat_id, denied)
            return self._ingress_skip("document-release-handled")
        await self._consume_and_deliver(
            match.group(1), audience=audience, adapter=adapter, chat_id=chat_id
        )
        return self._ingress_skip("document-release-handled")

    async def _consume_and_deliver(
        self,
        code: str,
        *,
        audience: AudienceBinding,
        adapter: Any,
        chat_id: str,
        send_receipt: bool = True,
        title: Any = "",
        caption: str = "",
    ) -> str:
        """Claim one authority, revalidate everything, and dispatch once.

        Shared by the typed APPROVE path and by auto-release, so removing the
        human confirmation step removes only that step: the one-use claim, the
        live roster recheck, the destination binding, and the staged-artifact
        identity check all still run here, in this order, before any byte
        reaches transport.
        """
        denied = "Document release denied."
        if (
            audience.principal.casefold() != "james"
            or audience.human_principals != ("james",)
            or "juno.private.james" not in audience.effective_read_capability_ids
        ):
            if send_receipt:
                await self._send_document_receipt(adapter, chat_id, denied)
            return "denied"

        record = None
        try:
            self.document_releases.cleanup()
            record = self.document_releases.claim(
                code,
                principal=audience.principal,
                policy_generation=self.policy_generation,
                audience_digest=audience.audience_digest,
                conversation_binding=audience.conversation_binding,
                roster_generation=audience.roster_generation,
            )
            if record is None or record.state != "dispatching":
                if record is not None:
                    self.document_releases.unlink_record(record)
                if send_receipt:
                    await self._send_document_receipt(adapter, chat_id, denied)
                return "denied"

            # A second managed-roster read sits immediately at the final effect
            # boundary. No staged bytes are handed to transport before it and
            # the artifact identity check both succeed.
            await asyncio.to_thread(self._revalidate_audience, audience)
            expected_destination = self._opaque_digest(
                "conversation-v2",
                {"platform": "whatsapp", "kind": audience.conversation_kind, "chat": chat_id},
            )
            if not hmac.compare_digest(
                expected_destination, record.conversation_binding
            ):
                raise ValueError("document destination changed")
            path = self.document_releases.revalidate(record)
            send_document = getattr(adapter, "send_document", None)
            if not callable(send_document):
                raise ValueError("authenticated document delivery seam is unavailable")
            from .document_release import ALLOWED_MIME_EXTENSIONS

            extension = ALLOWED_MIME_EXTENSIONS.get(record.artifact_mime)
            if extension is None:
                raise ValueError("document MIME is unsupported")
        except Exception as exc:
            logger.warning("Juno document dispatch denied: %s", type(exc).__name__)
            if record is not None and record.state == "dispatching":
                self.document_releases.terminalize(record, "denied")
                self.document_releases.unlink_record(record)
            if send_receipt:
                await self._send_document_receipt(adapter, chat_id, denied)
            return "denied"

        try:
            result = await send_document(
                chat_id=chat_id,
                file_path=str(path),
                file_name=self._delivery_file_name(title, extension),
                caption=caption or None,
            )
            success = getattr(result, "success", None)
            message_id = getattr(result, "message_id", None)
            if success is True and isinstance(message_id, str) and message_id:
                terminal = "delivered"
                receipt_text = "Document delivered. Receipt: delivered."
                provider_receipt = message_id
            elif success is False:
                # The transport reports a loop/session/bridge fault only as a
                # failed send, so record its class here rather than leaving the
                # cause to be reconstructed from a ledger row.
                logger.warning(
                    "Juno document transport failed: %s",
                    str(getattr(result, "error", "") or "unspecified")[:200],
                )
                terminal = "failed"
                receipt_text = "Document delivery failed. Receipt: failed."
                provider_receipt = ""
            else:
                terminal = "uncertain"
                receipt_text = (
                    "Document delivery uncertain. Receipt: uncertain; no retry will occur."
                )
                provider_receipt = ""
        except Exception:
            terminal = "uncertain"
            receipt_text = (
                "Document delivery uncertain. Receipt: uncertain; no retry will occur."
            )
            provider_receipt = ""

        if not self.document_releases.terminalize(
            record, terminal, provider_receipt=provider_receipt
        ):
            terminal = "uncertain"
            receipt_text = (
                "Document delivery uncertain. Receipt: uncertain; no retry will occur."
            )
        if terminal != "uncertain":
            self.document_releases.unlink_record(record)
        if terminal == "delivered" and not send_receipt:
            # The file is the whole reply, and the model's follow-up is dropped,
            # so nothing more will be sent. Without this the indicator keeps
            # refreshing until the turn ends, leaving Juno apparently typing at
            # a conversation that already has its answer.
            await self._quiet_typing(adapter, chat_id)
        if send_receipt:
            await self._send_document_receipt(adapter, chat_id, receipt_text)
        return terminal

    @staticmethod
    async def _quiet_typing(adapter: Any, chat_id: str) -> None:
        """Settle the typing indicator. Cosmetic only; never fails a delivery.

        pause_typing_for_chat keeps the refresh loop from re-asserting it; the
        gateway clears that pause in its own end-of-turn finally.
        """
        try:
            pause = getattr(adapter, "pause_typing_for_chat", None)
            if callable(pause):
                pause(chat_id)
            stop = getattr(adapter, "stop_typing", None)
            if callable(stop):
                await stop(chat_id)
        except Exception:
            logger.debug("Juno typing indicator did not settle after delivery")

    def _is_juno_lane_request(self, event: Any) -> bool:
        """An inbound signed request from the authenticated Juno peer."""
        source = getattr(event, "source", None)
        platform_value = getattr(getattr(source, "platform", None), "value", None)
        platform = str(platform_value or getattr(source, "platform", "") or "").lower()
        return bool(
            platform == "a2a"
            and str(getattr(source, "user_id", "") or "") == "juno"
            and REQUEST_PREFIX in str(getattr(event, "text", "") or "")
        )

    def _reset_lane_session(self, event: Any, session_store: Any) -> None:
        """Start every Juno request from a clean Kite session.

        Each request is self-contained and independently authorized, so history
        buys nothing here -- but it accumulates stale tool schemas and stale
        failures, and the model reasons from those instead of retrying. It
        reported an attachment id as "still" overlength on a build where the
        limit had already been raised, and never called the reader at all.
        """
        reset = getattr(session_store, "reset_session", None)
        listing = getattr(session_store, "list_sessions", None)
        chat_id = str(getattr(getattr(event, "source", None), "chat_id", "") or "")
        if not callable(reset) or not callable(listing) or not chat_id:
            return
        suffix = f":a2a:dm:{chat_id}"
        try:
            for entry in listing():
                key = str(getattr(entry, "session_key", "") or "")
                if key.endswith(suffix):
                    reset(key)
        except Exception:
            logger.warning("Juno--Kite lane session reset failed; continuing")

    async def pre_gateway_dispatch(
        self,
        event: Any = None,
        gateway: Any = None,
        session_store: Any = None,
        critical_ingress_token: Any = None,
        **_: Any,
    ) -> Optional[dict]:
        """Bind eligible Juno audience authority before auth/session/model work."""
        if self.mode == "kite":
            if self.enabled and self._is_juno_lane_request(event):
                self._reset_lane_session(event, session_store)
            return None
        if self.mode != "juno" or not self.juno_available():
            return None
        _ACTIVE_AUDIENCE.set(None)
        _ACTIVE_INGRESS_TOKEN.set(None)
        _ACTIVE_DELIVERY.set(None)
        _ACTIVE_INBOUND_TEXT.set(str(getattr(event, "text", "") or ""))
        try:
            _ACTIVE_LOOP.set(asyncio.get_running_loop())
        except RuntimeError:
            _ACTIVE_LOOP.set(None)
        source = getattr(event, "source", None)
        platform_value = getattr(getattr(source, "platform", None), "value", None)
        platform = str(platform_value or getattr(source, "platform", "") or "").lower()
        user_id = str(getattr(source, "user_id", "") or "")
        is_document_approval = bool(
            self.document_releases.enabled
            and platform == "whatsapp"
            and self._is_document_approval_text(getattr(event, "text", ""))
        )
        matches = self._principal_for_transport_identity(platform, user_id)
        if not matches:
            if is_document_approval:
                return self._ingress_skip("document-release-handled")
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
                audience = self._single_principal_audience(principal, platform, chat_id)
                _ACTIVE_AUDIENCE.set(audience)
                _ACTIVE_DELIVERY.set(
                    ((getattr(gateway, "adapters", None) or {}).get(
                        getattr(source, "platform", None)
                    ), chat_id)
                )
                if (
                    self.document_releases.enabled
                    and platform == "whatsapp"
                    and self._is_document_approval_text(getattr(event, "text", ""))
                ):
                    adapters = getattr(gateway, "adapters", None) or {}
                    adapter = adapters.get(getattr(source, "platform", None))
                    return await self._handle_document_approval(
                        event=event, adapter=adapter, audience=audience
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
                asyncio.to_thread(provider),
                timeout=self.limits.roster_timeout_seconds + 0.5,
            )
            audience = self._audience_from_roster(
                initiating_principal=principal,
                platform=platform,
                chat_id=chat_id,
                roster=roster,
                revalidate=provider,
            )
            _ACTIVE_AUDIENCE.set(audience)
            _ACTIVE_DELIVERY.set((adapter, chat_id))
            if (
                self.document_releases.enabled
                and self._is_document_approval_text(getattr(event, "text", ""))
            ):
                return await self._handle_document_approval(
                    event=event, adapter=adapter, audience=audience
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
                )
                == binding.conversation_binding
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
            binding.human_principals,
        )
        observed = (
            current.conversation_binding,
            current.audience_digest,
            current.roster_generation,
            current.effective_read_capability_ids,
            current.effective_action_capability_ids,
            current.private_eligible,
            current.human_principals,
        )
        if not hmac.compare_digest(
            hashlib.sha256(canonical_json(expected).encode()).digest(),
            hashlib.sha256(canonical_json(observed).encode()).digest(),
        ):
            raise ValueError("authenticated audience changed")
        return current

    def _leak_reason(self, text: str, *, output: bool) -> str:
        value = str(text or "")
        flattened = _EMPHASIS_PATTERN.sub("", value)
        for pattern in _CREDENTIAL_PATTERNS:
            if pattern.search(value) or pattern.search(flattened):
                return "credential-shaped content"
        if any(
            secret and secret in value for secret in getattr(self, "secret_values", ())
        ):
            return "configured credential value"
        if _EMAIL_PATTERN.search(value) or _EMAIL_PATTERN.search(flattened):
            return "email-shaped private identifier"
        identifier_scan = flattened
        if output:
            for origin in getattr(
                getattr(self, "private_reads", None), "public_property_origins", ()
            ):
                identifier_scan = re.sub(
                    re.escape(origin) + r"/[^\s<>()]+",
                    "<approved-property-public-link>",
                    identifier_scan,
                )
        if _PRIVATE_ID_PATTERN.search(identifier_scan):
            return "labelled private identifier"
        if _UUID_PATTERN.search(identifier_scan):
            return "UUID-shaped private identifier"
        # A date is not a contact detail, and "2026-08-10 15:37" is otherwise
        # ten digits in short groups -- indistinguishable from a number.
        phone_scan = _ISO_DATE_PATTERN.sub(" ", identifier_scan)
        phone_scan = _PASSPORT_CONTEXT_PATTERN.sub("", phone_scan)
        if any(
            _is_phone_shaped(match.group(0))
            for match in _PHONE_CANDIDATE.finditer(phone_scan)
        ):
            return "phone-shaped private identifier"
        if any(
            identifier and identifier in value
            for identifier in self.private_identifiers
        ):
            return "configured private identifier"
        if any(pattern.search(value) for pattern in _RAW_RESULT_PATTERNS):
            return "raw tool-result marker"
        if output and any(
            pattern.search(value) for pattern in _OUTPUT_INTERNAL_PATTERNS
        ):
            return "internal connector identifier or path"
        if output and (
            len(_RAW_EMAIL_HEADER_PATTERN.findall(value)) >= 3
            or sum(bool(pattern.search(value)) for pattern in _RAW_EMAIL_JSON_PATTERNS)
            >= 2
        ):
            return "raw email or thread dump"
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
                raise ValueError(
                    "relevant context contains private or credential-shaped data"
                )
            bounded.append({
                "role": role,
                "text": _truncate_chars(text, self.limits.context_turn_chars),
            })
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
        handoff_reason = self._leak_reason(question, output=False)
        if handoff_reason:
            # Name what matched. A generic rejection here is undiagnosable: the
            # payload is only persisted once it is sent, so a question refused
            # at this line leaves no record of itself anywhere.
            raise ValueError(
                "question contains private or credential-shaped data "
                f"({handoff_reason})"
            )
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
            raise ValueError(
                "relevant context contains a raw authenticated session identifier"
            )
        # First live group recheck. This happens before mapping or request
        # creation, so a changed/missing audience cannot leave authority state
        # or issue an A2A call.
        audience = self._revalidate_audience(audience)
        # Auto-release consumes the authority issued against exactly this
        # revalidated audience, so publish it rather than the ingress copy.
        _ACTIVE_AUDIENCE.set(audience)
        from .disclosure import _DOCUMENT_INFORMATIONAL, classify_output_tier

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
            "effective_read_capability_ids": list(
                audience.effective_read_capability_ids
            ),
            "effective_action_capability_ids": list(
                audience.effective_action_capability_ids
            ),
            "roster_generation": audience.roster_generation,
            # Classified from the authentic inbound message captured at ingress,
            # never from the model-authored question_or_goal.
            "host_output_tier": self._host_output_tier(
                _ACTIVE_INBOUND_TEXT.get(), audience.conversation_binding
            ),
            # Whether James asked *about* a document rather than *for* one,
            # tested against his own words before any model rewrote them.
            "host_informational": bool(
                _DOCUMENT_INFORMATIONAL.search(_ACTIVE_INBOUND_TEXT.get() or "")
            ),
        }
        payload = {**unsigned, "signature": sign_payload(unsigned, self.request_key)}
        guard = _audit_guard(mapping.correlation_id, request_id, mapping.context_id)
        message = guard + REQUEST_PREFIX + canonical_json(payload)
        while (
            len(message.encode("utf-8")) > self.limits.handoff_bytes
            and relevant_context
        ):
            relevant_context.pop()
            unsigned["relevant_context"] = relevant_context
            payload = {
                **unsigned,
                "signature": sign_payload(unsigned, self.request_key),
            }
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
                raise ValueError(
                    "Kite returned a mismatched context or incomplete task"
                )
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

    async def consult_kite_delivering(self, args: dict, **kwargs: Any) -> str:
        """Registered handler: consult Kite, then dispatch any released document.

        consult_kite stays synchronous because the whole authority path and its
        tests are built around it. Delivery is the only part that must await a
        transport, so it hangs off this thin wrapper instead of turning the
        request path async.
        """
        answer = self.consult_kite(args, **kwargs)
        audience = _ACTIVE_AUDIENCE.get()
        if audience is None:
            return answer
        # A tool handler is not given the host's session/turn identifiers --
        # handler_kwargs is whatever the caller passed -- so keying the delivery
        # flag off kwargs produced an empty key that never matched the hook.
        # The session environment does reach this thread, so key off that and
        # let transform_llm_output match on either identifier it is handed.
        return await self._auto_release(
            answer, audience, self._delivery_turn_keys(kwargs)
        )

    @staticmethod
    def _delivery_turn_keys(kwargs: dict) -> frozenset[str]:
        """Every identifier this turn might be recognised by downstream."""
        return frozenset(
            value
            for value in (
                str(kwargs.get("session_id") or ""),
                str(get_session_env("HERMES_SESSION_ID") or ""),
                str(get_session_env("HERMES_SESSION_KEY") or ""),
            )
            if value
        )

    @classmethod
    def _delivery_caption(cls, descriptor: dict) -> str:
        """Describe the artifact on the file itself, not in a second message.

        Host-generated from the staged descriptor only, and reduced the same
        way the filename is, so nothing crossing the boundary reaches the chat
        unfiltered.
        """
        title = cls._safe_delivery_text(descriptor.get("title"))
        kind = {
            "application/pdf": "PDF",
            "image/jpeg": "JPEG",
            "image/png": "PNG",
        }.get(str(descriptor.get("mime_type") or ""), "")
        pages = descriptor.get("page_count")
        parts = [part for part in (title, kind) if part]
        if isinstance(pages, int) and not isinstance(pages, bool) and pages > 1:
            parts.append(f"{pages} pages")
        return " · ".join(parts)

    @staticmethod
    def _safe_delivery_text(value: Any, limit: int = 80) -> str:
        text = re.sub(r"[^A-Za-z0-9 ()_.-]+", " ", str(value or ""))
        return re.sub(r"\s+", " ", text).strip(" ._-")[:limit].strip(" ._-")

    @staticmethod
    def _delivery_file_name(title: Any, extension: str) -> str:
        """Name the delivered file after the document, not after the plumbing.

        The title crosses the A2A boundary inside the signed envelope and was
        already reduced to a safe form when it was staged, but it lands here as
        a filename, so it is re-reduced on this side rather than trusted.
        """
        text = re.sub(r"[^A-Za-z0-9 ()_.-]+", " ", str(title or ""))
        text = re.sub(r"\s+", " ", text).strip(" ._-")[:80].strip(" ._-")
        return (text or "requested-document") + extension

    @staticmethod
    async def _on_gateway_loop(coro: Any) -> Any:
        """Await a coroutine on the gateway's loop, wherever we are now.

        An async tool handler runs on a disposable loop in its own thread, but
        the platform adapter's HTTP session belongs to the gateway's loop and
        raises if touched from another one -- which the transport reports only
        as a failed send. Delivery therefore runs where the adapter lives.
        """
        loop = _ACTIVE_LOOP.get()
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if loop is None or loop is running or loop.is_closed():
            return await coro
        return await asyncio.wrap_future(
            asyncio.run_coroutine_threadsafe(coro, loop)
        )

    async def _auto_release(
        self,
        answer: str,
        audience: AudienceBinding,
        turn_keys: frozenset[str] = frozenset(),
    ) -> str:
        """Consume an approval the host just issued, without asking the owner.

        The code is a host-internal one-use authority, not a password: it was
        minted, carried, and consumed inside this turn and never shown to
        anyone. Every gate it binds still runs in _consume_and_deliver. Only
        the owner-confirmation step is removed, so a routine request from the
        owner for his own document does not have to be re-typed back.
        """
        if not self.document_releases.enabled:
            return answer
        try:
            parsed = json.loads(answer)
            if (
                not isinstance(parsed, dict)
                or parsed.get("outcome") != "approval_required"
            ):
                return answer
            code = str((parsed.get("approval") or {}).get("code") or "")
            document = parsed.get("document")
            delivery = _ACTIVE_DELIVERY.get()
            if not code or delivery is None:
                return answer
            adapter, chat_id = delivery
        except (TypeError, ValueError):
            return answer

        descriptor = document if isinstance(document, dict) else {}
        outcome = await self._on_gateway_loop(
            self._consume_and_deliver(
                code, audience=audience, adapter=adapter, chat_id=chat_id,
                send_receipt=False,
                title=descriptor.get("title"),
                caption=self._delivery_caption(descriptor),
            )
        )
        if outcome == "delivered":
            # Normally consumed by this turn's transform. If a turn dies before
            # then, keep the residue bounded so one stale key cannot sit there
            # swallowing a later reply indefinitely.
            if len(self._auto_delivered) > 16:
                self._auto_delivered.clear()
            self._auto_delivered |= turn_keys
            return canonical_json({"outcome": "delivered", "document": document})
        return canonical_json({
            "outcome": "delivery_" + outcome,
            "document": document,
            "reason": (
                "the document was located but the host could not complete "
                "delivery in this conversation"
            ),
        })

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
            if (
                not isinstance(payload.get(name), str)
                or re.fullmatch(r"[a-f0-9]{64}", payload[name]) is None
            ):
                raise ValueError("request audience binding is malformed")
        capability_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
        for name in (
            "effective_read_capability_ids",
            "effective_action_capability_ids",
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

    def _bind_request(
        self, user_message: str, session_id: str, turn_id: str
    ) -> TurnBinding:
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
        from plugins.platforms.a2a.security import inbound_prefix

        privacy_frame = inbound_prefix("juno")
        if user_message.startswith(privacy_frame):
            user_message = user_message[len(privacy_frame) :]
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
            raise ValueError(
                "requested semantic policy exceeds principal audience authority"
            )
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
        from .disclosure import (
            BOUNDED_EXCERPT,
            DOCUMENT_DESCRIPTOR,
            classify_output_tier,
            strongest_output_tier,
        )

        # The peer's question_or_goal is model-authored and reworded every turn,
        # so it cannot be the sole source of the tier: one live paraphrase said
        # "release the actual document" (document tier) and the next said
        # "return a releasable file reference" (minimized), for the same request.
        # Take the most restrictive of the host-classified inbound message, the
        # paraphrase, and the quoted context, so an untrusted rewording can only
        # add gates, never remove them.
        # Only what is being asked now: the host's reading of the authentic
        # message, and the peer's paraphrase of it. Quoted history is context
        # for understanding the request, not a statement of it -- counting it
        # turned "what is Lucy's passport number" into a file release, because
        # the previous turn had been "send me Frankie's passport".
        candidates = [
            str(payload.get("host_output_tier") or ""),
            classify_output_tier(str(payload["question_or_goal"])),
        ]
        tier = strongest_output_tier(candidates)
        # A question about a document is not a request for one. The host tested
        # that against James's own words, so a paraphrase cannot promote it.
        if payload.get("host_informational") is True and tier == DOCUMENT_DESCRIPTOR:
            tier = BOUNDED_EXCERPT
        return TurnBinding(
            True,
            "",
            mapping,
            request,
            session_id,
            turn_id,
            read_caps,
            action_caps,
            tier,
        )

    def _host_output_tier(self, inbound_text: str, conversation_binding: str) -> str:
        """Classify the authentic message, resolving a bare follow-up.

        "retrieve and send it again" names no document, so on its own it is an
        ordinary minimized turn. It is only a document request in the light of
        the turn before it, which the host knows and the message does not. The
        inheritance is deliberately narrow: same conversation, recent, and only
        for a delivery verb with an anaphoric object.
        """
        from .disclosure import (
            DOCUMENT_DESCRIPTOR,
            classify_output_tier,
            is_document_followup,
        )

        tier = classify_output_tier(inbound_text)
        now = int(self.clock())
        key = str(conversation_binding or "")
        cutoff = now - _DOCUMENT_FOLLOWUP_TTL_SECONDS
        self._recent_document_turns = {
            binding: seen
            for binding, seen in self._recent_document_turns.items()
            if seen > cutoff
        }
        if tier == DOCUMENT_DESCRIPTOR:
            if key:
                self._recent_document_turns[key] = now
        elif key and key in self._recent_document_turns and is_document_followup(
            inbound_text
        ):
            tier = DOCUMENT_DESCRIPTOR
            self._recent_document_turns[key] = now
        return tier

    def _policy_view(self, binding: TurnBinding) -> str:
        assert binding.mapping is not None and binding.request is not None
        configured_semantic_policy = self.policy["principals"][
            binding.mapping.principal
        ]["semantic_policy"]
        principal_policy = {
            capability_id: configured_semantic_policy[capability_id]
            for capability_id in binding.effective_read_capability_ids
        }
        semantic_disclosure = None
        if self.private_reads.enabled:
            from .disclosure import generated_semantic_guidance

            semantic_disclosure = generated_semantic_guidance(
                principal=binding.mapping.principal,
                effective_capability_ids=binding.effective_read_capability_ids,
                configured_policy=configured_semantic_policy,
                output_tier=binding.output_tier,
            )
        # The top-level rule is the most imperative line in this view, so it has
        # to agree with the tier.  Stating "return only a minimized answer" on a
        # document turn told the model to answer from context, and it did: one
        # API call, no typed read, nothing staged, and a host denial every time.
        staging_turn = (
            self.private_reads.enabled
            and self.document_releases.enabled
            and binding.output_tier == "specific_full_document_descriptor"
        )
        if staging_turn:
            requested_disclosure = (
                "one staged document candidate plus its semantic capability id"
            )
            rule = (
                "Do not answer this turn from context or memory, and do not send "
                "a prose answer: prose releases nothing here. First call an "
                "approved typed reader and let it succeed, so the host stages the "
                "artifact. Then return only the JSON object "
                "{\"capability_id\": \"<one effective capability id>\"} and no "
                "other text. Raw sources, tool results, credentials, and private "
                "identifiers still stay in Kite."
            )
        else:
            requested_disclosure = "one minimized policy-compliant answer"
            rule = (
                "Return only a minimized answer; raw sources, tool results, "
                "credentials, and private identifiers stay in Kite. The sole expanded "
                "form is bounded prose/bullets containing any sanitized Property Intel "
                "facts when the host verifies James, the exact Property capability, "
                "and only successful kite_property_read provenance."
            )
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
            "requested_disclosure": requested_disclosure,
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
            "semantic_disclosure": semantic_disclosure,
            "rule": rule,
        }
        rendered = (
            "Juno--Kite source-agnostic policy view (host generated):\n"
            + canonical_json(view)
        )
        if len(rendered) > self.limits.policy_view_chars:
            raise ValueError("generated policy view exceeds its deterministic limit")
        return rendered

    def _juno_turn_context(self) -> Optional[dict]:
        """Put the document instruction in the turn, not in a tool description.

        Twice now Juno has refused a document request outright -- "I can't
        access or send another person's passport" for the principal's own
        children -- with one API call and no consultation at all. The tool
        description already forbade exactly that, and was not enough: a static
        description is skimmed, while a line in the turn is read.

        This says nothing about entitlement, which remains the host's to
        decide. It says only that this particular turn is a document request
        and must be asked, so that a refusal can come from a gate rather than
        from a guess.
        """
        if self.mode != "juno" or not self.juno_available():
            return None
        from .disclosure import DOCUMENT_DESCRIPTOR, classify_output_tier

        inbound = _ACTIVE_INBOUND_TEXT.get()
        if not inbound or classify_output_tier(inbound) != DOCUMENT_DESCRIPTOR:
            return None
        return {
            "context": (
                "JUNO--KITE: this turn is a request for a specific document. "
                "Call consult_kite before answering. Whether it exists, and "
                "whose it is, and whether it may be released, are the host's "
                "decisions and not yours -- household and children's documents "
                "are routinely in scope. Do not answer that you cannot provide "
                "or access it without having asked; if the host denies it, "
                "report the reason it gave."
            )
        }

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
            _ACTIVE_PRIVATE_READS.set(None)
            return self._juno_turn_context()
        binding: Optional[TurnBinding] = None
        try:
            binding = self._bind_request(
                str(user_message or ""), str(session_id or ""), str(turn_id or "")
            )
            _ACTIVE_BINDING.set(binding)
            _ACTIVE_PRIVATE_READS.set({
                "authorized": set(),
                "dispatched": set(),
                "failures": set(),
                "gmail_messages": set(),
                "gmail_attachments": set(),
                "personal_files": set(),
                "content_fragments": set(),
                "provenance_fragments": set(),
                "successful_tools": set(),
                "document_candidates": [],
            })
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
            _ACTIVE_PRIVATE_READS.set(None)
            # The message is an internal policy string, not user content, and
            # without it a binding failure is undiagnosable after the fact.
            logger.warning(
                "Kite policy binding denied: %s: %s",
                type(exc).__name__, str(exc)[:200],
            )
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
        if not session_id or not hmac.compare_digest(
            binding.session_id, str(session_id)
        ):
            raise ValueError("hook session does not match same-turn policy binding")
        if turn_id is not None and (
            not turn_id or not hmac.compare_digest(binding.turn_id, str(turn_id))
        ):
            raise ValueError("hook turn does not match same-turn policy binding")
        platform, peer, context_id = self._a2a_lane()
        if (
            platform != "a2a"
            or peer != "juno"
            or context_id != binding.mapping.context_id
        ):
            raise ValueError("authenticated A2A lane changed after policy binding")
        now = int(self.clock())
        request = self.store.get_request(binding.request.request_id)
        if (
            request is None
            or request.state != "bound"
            or request.expires_at <= now
            or request.policy_generation != self.policy_generation
            or request.context_id != binding.mapping.context_id
            or request.correlation_id != binding.mapping.correlation_id
            or request.audience_digest != binding.request.audience_digest
            or request.conversation_binding != binding.request.conversation_binding
            or request.roster_generation != binding.request.roster_generation
            or request.read_capability_fingerprint
            != self._capability_fingerprint(binding.effective_read_capability_ids)
            or request.action_capability_fingerprint
            != self._capability_fingerprint(binding.effective_action_capability_ids)
        ):
            raise ValueError("same-turn binding is stale, replayed, or mismatched")
        return binding

    @staticmethod
    def _block(message: str) -> dict[str, str]:
        return {
            "action": "block",
            "message": "Juno--Kite policy blocked tool call: " + message,
        }

    @staticmethod
    def _private_read_fingerprint(tool_name: str, args: dict[str, Any]) -> str:
        return hashlib.sha256(
            f"{tool_name}\0{canonical_json(args)}".encode("utf-8")
        ).hexdigest()

    def _private_read_state(self) -> dict[str, Any]:
        state = _ACTIVE_PRIVATE_READS.get()
        if (
            not isinstance(state, dict)
            or set(state)
            != {
                "authorized",
                "dispatched",
                "failures",
                "gmail_messages",
                "gmail_attachments",
                "personal_files",
                "content_fragments",
                "provenance_fragments",
                "successful_tools",
                "document_candidates",
            }
            or not isinstance(state["authorized"], set)
            or not isinstance(state["dispatched"], set)
            or not isinstance(state["failures"], set)
            or not isinstance(state["content_fragments"], set)
            or not isinstance(state["provenance_fragments"], set)
            or not isinstance(state["successful_tools"], set)
            or not isinstance(state["personal_files"], set)
            or not isinstance(state["document_candidates"], list)
        ):
            raise ValueError("private read authorization state is missing")
        return state

    def execute_private_read(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        session_id: str = "",
        turn_id: str = "",
        **_: Any,
    ) -> str:
        """Handler-bound defense: require the final-dispatch fingerprint."""
        source = tool_name.removeprefix("kite_").split("_", 1)[0]
        try:
            binding = self._current_valid_binding(session_id=str(session_id or ""))
            if tool_name not in self.private_read_tool_names or not isinstance(
                args, dict
            ):
                raise ValueError("private read tool or arguments are invalid")
            digest = self._private_read_fingerprint(tool_name, args)
            state = self._private_read_state()
            if digest not in state["dispatched"]:
                raise ValueError("private read did not pass exact final dispatch")
            state["dispatched"].remove(digest)
            candidate_source = None
            if (
                binding.output_tier == "specific_full_document_descriptor"
                and self.document_releases.enabled
                and tool_name
                in {
                    "kite_personal_files_read",
                    "kite_gmail_attachment_extract",
                }
                and (
                    tool_name == "kite_gmail_attachment_extract"
                    or args.get("operation") == "read"
                )
            ):
                result, candidate_source = self.private_reads.resolve_document_candidate(
                    tool_name, args
                )
            else:
                result = self.private_reads.execute(tool_name, args)
            try:
                parsed = json.loads(result)
                if isinstance(parsed, dict) and parsed.get("status") == "error":
                    error = (
                        parsed.get("error")
                        if isinstance(parsed.get("error"), dict)
                        else {}
                    )
                    state["failures"].add(
                        f"{str(parsed.get('source') or source)[:32]}:"
                        f"{str(error.get('code') or 'source_failure')[:48]}"
                    )
                elif isinstance(parsed, dict) and parsed.get("status") == "ok":
                    state["successful_tools"].add(tool_name)
                    data = parsed.get("data")
                    if candidate_source is not None:
                        try:
                            if "path" in candidate_source:
                                candidate = self.document_releases.stage_path(
                                    candidate_source["path"],
                                    source_class=candidate_source["source_class"],
                                    display_name=candidate_source["display_name"],
                                    expected_identity=candidate_source.get(
                                        "expected_identity"
                                    ),
                                    inspection_text=candidate_source.get(
                                        "inspection_text", ""
                                    ),
                                )
                            else:
                                candidate = self.document_releases.stage_bytes(
                                    candidate_source["bytes"],
                                    source_class=candidate_source["source_class"],
                                    display_name=candidate_source["display_name"],
                                    inspection_text=candidate_source.get(
                                        "inspection_text", ""
                                    ),
                                )
                            if (
                                candidate.mime_type != candidate_source["expected_mime"]
                                or candidate.size_bytes != candidate_source["expected_size"]
                            ):
                                self.document_releases.discard_candidate(candidate)
                                raise ValueError("typed source descriptor mismatched artifact")
                            state["document_candidates"].append(candidate)
                        except Exception as exc:
                            # DocumentReleaseDenied messages are written to be
                            # non-sensitive on purpose -- they name the gate,
                            # not the document. Withholding them made a
                            # refused artifact undiagnosable: "failed the
                            # release gate" cannot distinguish an oversized
                            # scan from a mismatched type.
                            from .document_release import DocumentReleaseDenied

                            detail = (
                                str(exc)[:120]
                                if isinstance(exc, (DocumentReleaseDenied, ValueError))
                                else ""
                            )
                            state["failures"].add(f"{source}:release_denied")
                            logger.warning(
                                "Juno--Kite release gate refused a candidate: %s",
                                detail or type(exc).__name__,
                            )
                            return canonical_json({
                                "status": "error",
                                "source": source,
                                "complete": False,
                                "error": {
                                    "code": "release_denied",
                                    "message": (
                                        "document candidate failed the release gate"
                                        + (f": {detail}" if detail else "")
                                    ),
                                    "retryable": False,
                                },
                            })
                    stack: list[tuple[Any, tuple[str, ...]]] = [(data, ())]
                    while stack and (
                        len(state["content_fragments"])
                        + len(state["provenance_fragments"])
                        < _PRIVATE_SOURCE_MAX_RECORDED_FRAGMENTS
                    ):
                        current, path = stack.pop()
                        if isinstance(current, dict):
                            for key in sorted(current, key=str, reverse=True):
                                stack.append((current[key], (*path, str(key))))
                        elif isinstance(current, list):
                            stack.extend((item, path) for item in reversed(current))
                        elif (
                            isinstance(current, str)
                            and len(current) >= _PRIVATE_SOURCE_FRAGMENT_CHARS
                        ):
                            fragment_class = (
                                "provenance_fragments"
                                if _provenance_identity_path(path)
                                else "content_fragments"
                            )
                            for offset in range(
                                0,
                                len(current) - _PRIVATE_SOURCE_FRAGMENT_CHARS + 1,
                                _PRIVATE_SOURCE_FRAGMENT_CHARS,
                            ):
                                state[fragment_class].add(current[
                                    offset : offset + _PRIVATE_SOURCE_FRAGMENT_CHARS
                                ])
                                if (
                                    len(state["content_fragments"])
                                    + len(state["provenance_fragments"])
                                    >= _PRIVATE_SOURCE_MAX_RECORDED_FRAGMENTS
                                ):
                                    break
                    account = str(args.get("account") or "")
                    if tool_name == "kite_gmail_search" and isinstance(data, list):
                        for item in data:
                            if isinstance(item, dict):
                                message_id = item.get("id") or item.get("message_id")
                                if isinstance(message_id, str) and message_id:
                                    state["gmail_messages"].add(
                                        f"{account}\0{message_id}"
                                    )
                    elif (
                        tool_name == "kite_personal_files_read"
                        and args.get("operation") == "search"
                        and isinstance(data, list)
                    ):
                        for item in data:
                            if isinstance(item, dict):
                                root = item.get("root")
                                relative = item.get("relative_path")
                                if isinstance(root, str) and isinstance(relative, str):
                                    state["personal_files"].add(
                                        f"{root}\0{relative}"
                                    )
                    elif tool_name == "kite_gmail_get" and isinstance(data, dict):
                        message_id = str(args.get("message_id") or "")
                        attachments = data.get("attachments")
                        if isinstance(attachments, list):
                            for item in attachments:
                                if isinstance(item, dict):
                                    attachment_id = item.get(
                                        "attachment_id"
                                    ) or item.get("attachmentId")
                                    if isinstance(attachment_id, str) and attachment_id:
                                        state["gmail_attachments"].add(
                                            f"{account}\0{message_id}\0{attachment_id}"
                                        )
            except (TypeError, ValueError):
                state["failures"].add(f"{source}:malformed_result")
            return result
        except Exception:
            return canonical_json({
                "status": "error",
                "source": source,
                "complete": False,
                "error": {
                    "code": "authority_denied",
                    "message": "current trusted private-read authority is unavailable",
                    "retryable": False,
                },
            })

    def private_read_handlers(self) -> dict[str, Callable[..., str]]:
        handlers: dict[str, Callable[..., str]] = {}
        for name in sorted(self.private_read_tool_names):

            def handler(
                args: dict[str, Any],
                *,
                session_id: str = "",
                turn_id: str = "",
                _name: str = name,
                **kwargs: Any,
            ) -> str:
                return self.execute_private_read(
                    _name,
                    args,
                    session_id=session_id,
                    turn_id=turn_id,
                    **kwargs,
                )

            handler.__name__ = f"handle_{name}"
            handlers[name] = handler
        return handlers

    def _authorize_private_read(
        self,
        binding: TurnBinding,
        tool_name: str,
        args: dict[str, Any],
    ) -> Optional[dict]:
        """Bind one exact typed private read to the final handler dispatch."""
        if binding.output_tier == "bulk_raw_export":
            return self._block(
                "bulk/raw private-source requests cannot invoke connectors"
            )
        # Past conversation is not a typed source with a capability of its own,
        # so it is bound to the principal whose conversations they are, here,
        # rather than left to the model to remember. Adding another principal
        # is then an explicit decision instead of an inherited one.
        if tool_name in _PRINCIPAL_BOUND_READS:
            principal = (
                binding.mapping.principal if binding.mapping is not None else ""
            )
            if str(principal).casefold() not in _PRINCIPAL_BOUND_READS[tool_name]:
                return self._block(
                    "session recall is bound to the principal whose "
                    "conversations these are"
                )
        from .private_reads import validate_tool_arguments

        if not validate_tool_arguments(tool_name, args):
            return self._block(
                "arguments do not match the selected private-read schema"
            )
        state = self._private_read_state()
        if tool_name == "kite_gmail_get":
            reference = (
                f"{str(args.get('account') or '')}\0"
                f"{str(args.get('message_id') or '')}"
            )
            if reference not in state["gmail_messages"]:
                return self._block(
                    "Gmail message ID was not returned by this bounded source turn"
                )
        if tool_name == "kite_gmail_attachment_extract":
            reference = (
                f"{str(args.get('account') or '')}\0"
                f"{str(args.get('message_id') or '')}\0"
                f"{str(args.get('attachment_id') or '')}"
            )
            if reference not in state["gmail_attachments"]:
                return self._block(
                    "Gmail attachment ID was not returned by this exact message read"
                )
        if (
            binding.output_tier == "specific_full_document_descriptor"
            and self.document_releases.enabled
            and tool_name == "kite_personal_files_read"
            and args.get("operation") == "read"
        ):
            reference = (
                f"{str(args.get('root') or '')}\0"
                f"{str(args.get('relative_path') or '')}"
            )
            if reference not in state["personal_files"]:
                return self._block(
                    "personal file was not returned by this exact bounded search"
                )
        digest = self._private_read_fingerprint(tool_name, args)
        state["authorized"].add(digest)
        return None

    def pre_tool_call(
        self,
        tool_name: str = "",
        args: Any = None,
        session_id: str = "",
        turn_id: str = "",
        **_: Any,
    ) -> Optional[dict]:
        platform, _peer, _context = self._a2a_lane()
        brokered_private_read = (
            self.mode == "kite"
            and tool_name in {"tool_describe", "tool_call"}
        )
        if platform != "a2a" and not brokered_private_read:
            return None
        try:
            binding = self._current_valid_binding(
                session_id=str(session_id or ""), turn_id=str(turn_id or "")
            )
            if not isinstance(args, dict):
                return self._block("arguments must be a complete object")
            if tool_name == "tool_describe":
                if (
                    set(args) != {"name"}
                    or not isinstance(args.get("name"), str)
                    or args["name"] not in self.private_read_tool_names
                ):
                    return self._block(
                        "broker target is not an exact Slice B private-read tool"
                    )
                return None
            if tool_name == "tool_call":
                if set(args) != {"name", "arguments"}:
                    return self._block(
                        "broker call must contain only name and arguments"
                    )
                target = args.get("name")
                nested_args = args.get("arguments")
                if (
                    not isinstance(target, str)
                    or target not in self.private_read_tool_names
                    or not isinstance(nested_args, dict)
                ):
                    return self._block(
                        "broker target is not an exact Slice B private-read tool"
                    )
                return self._authorize_private_read(binding, target, nested_args)
            if tool_name in self.private_read_tool_names:
                return self._authorize_private_read(binding, str(tool_name), args)
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
            if tool_name in self.private_read_tool_names:
                digest = self._private_read_fingerprint(str(tool_name), args)
                state = self._private_read_state()
                if digest not in state["authorized"]:
                    return self._block(
                        "private read arguments changed after authorization"
                    )
                state["authorized"].remove(digest)
                state["dispatched"].add(digest)
                return None
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

    def _property_output_authorized(
        self, binding: TurnBinding, state: dict[str, set[str]]
    ) -> bool:
        """Select the expanded Property prose mode from host-bound facts only."""
        if state["successful_tools"] != {"kite_property_read"}:
            return False
        if binding.mapping is None or binding.request is None:
            return False
        if binding.mapping.principal != "james":
            return False
        if _PROPERTY_CAPABILITY_ID not in binding.effective_read_capability_ids:
            return False
        principal_policy = self.policy.get("principals", {}).get("james")
        if not isinstance(principal_policy, dict):
            return False
        configured_caps = self.principal_read_capabilities.get("james", frozenset())
        semantic_policy = principal_policy.get("semantic_policy")
        if (
            _PROPERTY_CAPABILITY_ID not in configured_caps
            or not isinstance(semantic_policy, dict)
            or _PROPERTY_CAPABILITY_ID not in semantic_policy
        ):
            return False
        request = self.store.get_request(binding.request.request_id)
        return bool(
            request is not None
            and request.state == "bound"
            and request.policy_generation == self.policy_generation
            and request.roster_generation == binding.request.roster_generation
            and request.read_capability_fingerprint
            == self._capability_fingerprint(binding.effective_read_capability_ids)
        )

    def _property_output_leak_reason(self, answer: str) -> str:
        """Gate form and absolute secrets without inspecting Property fields.

        The connector has already sanitized the complete payload.  This check
        deliberately does not reconstruct a field allowlist or compare output
        fragments with source text; it enforces only credentials, containers,
        and deterministic response bounds.
        """
        value = str(answer or "")
        if len(value) > min(self.limits.output_chars, _PROPERTY_OUTPUT_MAX_CHARS):
            return "Property answer exceeds its character limit"
        if len(value.encode("utf-8")) > min(
            self.limits.response_bytes, _PROPERTY_OUTPUT_MAX_BYTES
        ):
            return "Property answer exceeds its byte limit"
        lines = value.splitlines()
        if len(lines) > _PROPERTY_OUTPUT_MAX_LINES:
            return "Property answer exceeds its line limit"
        if sum(
            bool(re.match(r"^\s*(?:[-*+] |\d{1,3}[.)] )", line))
            for line in lines
        ) > _PROPERTY_OUTPUT_MAX_BULLETS:
            return "Property answer exceeds its item limit"
        if "```" in value:
            return "Property answer is not bounded prose or bullets"
        if (
            sum(line.count("|") >= 2 for line in lines) >= 2
            and any(
                _PROPERTY_TABLE_SEPARATOR_PATTERN.fullmatch(line)
                for line in lines
            )
        ):
            return "Property table/container dump"
        for pattern in _CREDENTIAL_PATTERNS:
            if pattern.search(value):
                return "credential-shaped content"
        if any(
            secret and secret in value for secret in getattr(self, "secret_values", ())
        ):
            return "configured credential value"
        if any(pattern.search(value) for pattern in _RAW_RESULT_PATTERNS):
            return "raw tool-result marker"
        if any(pattern.search(value) for pattern in _PROPERTY_OUTPUT_INTERNAL_PATTERNS):
            return "internal connector identifier or path"

        stripped = value.strip()
        decoder = json.JSONDecoder()
        if stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(stripped)
            except (TypeError, ValueError):
                parsed = None
            if isinstance(parsed, (dict, list)):
                return "Property JSON/container dump"
        for index, character in enumerate(value):
            if character not in "[{":
                continue
            try:
                parsed, _end = decoder.raw_decode(value, index)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, (dict, list)):
                return "Property JSON/container dump"
        return ""

    @staticmethod
    def _release_descriptor(answer: str) -> Optional[dict]:
        """Return the host's closed release descriptor, or None for prose.

        Juno cannot tell a host-built descriptor from model text by signature
        alone -- both are signed by Kite -- so it is recognised by exact shape.
        Every field is constrained to a host-generated value except the title,
        which the caller checks separately, so nothing can smuggle prose
        through by wearing this shape.
        """
        from .document_release import ALLOWED_MIME_EXTENSIONS

        try:
            parsed = json.loads(str(answer or ""))
        except (TypeError, ValueError):
            return None
        if (
            not isinstance(parsed, dict)
            or set(parsed) != {"outcome", "document", "audience", "purpose", "approval"}
            or parsed.get("outcome") != "approval_required"
            or parsed.get("audience") != "James only in this WhatsApp conversation"
            or parsed.get("purpose") not in _RELEASE_PURPOSES
        ):
            return None
        document = parsed.get("document")
        approval = parsed.get("approval")
        if (
            not isinstance(document, dict)
            or set(document) != {
                "title", "source_class", "mime_type", "size_bytes", "page_count"
            }
            or not isinstance(document.get("title"), str)
            or len(document["title"]) > 96
            or document.get("source_class") not in _RELEASE_SOURCE_CLASSES
            or document.get("mime_type") not in ALLOWED_MIME_EXTENSIONS
            or not isinstance(document.get("size_bytes"), int)
            or isinstance(document.get("size_bytes"), bool)
            or not isinstance(document.get("page_count"), int)
            or isinstance(document.get("page_count"), bool)
        ):
            return None
        if (
            not isinstance(approval, dict)
            or set(approval) != {"code", "instruction", "expires_at"}
            or not isinstance(approval.get("code"), str)
            or re.fullmatch(r"C7-[A-Z2-9]{16}", approval["code"]) is None
            or approval.get("instruction") != "APPROVE " + approval["code"]
            or not isinstance(approval.get("expires_at"), str)
            or len(approval["expires_at"]) > 40
        ):
            return None
        return parsed

    def _safe_release_title(self, title: Any) -> str:
        """Keep a real document title unless it carries something that must not ship.

        The full output scan is written for model prose and false-positives on
        ordinary document names: "EL MS 07 08 2026" is a date, and it reads as a
        phone number, which blanked the whole release. The title is already
        reduced to a bounded character allowlist at staging, so what is left to
        check is the small set of things that genuinely cannot leave Kite --
        configured secrets, configured private identifiers, an address, or
        credential-shaped text -- and anything matching is replaced rather than
        allowed to deny the document.
        """
        value = str(title or "").strip()
        if not value:
            return "Requested document"
        if any(
            secret and secret in value
            for secret in getattr(self, "secret_values", ())
        ):
            return "Requested document"
        if any(
            identifier and identifier in value
            for identifier in self.private_identifiers
        ):
            return "Requested document"
        if _EMAIL_PATTERN.search(value) or any(
            pattern.search(value) for pattern in _CREDENTIAL_PATTERNS
        ):
            return "Requested document"
        return value

    def _document_release_answer(
        self, binding: TurnBinding, model_text: str, state: dict[str, Any]
    ) -> str:
        """Convert one staged candidate into a deterministic approval preview."""
        candidates = list(state["document_candidates"])
        stage = "release"
        try:
            if state["failures"]:
                stage = "typed-read"
                # Carry the gate's own words outward. "a required private
                # source failed" cannot tell James whether his scan was too
                # large, the wrong type, or simply absent.
                self._typed_read_failures = sorted(state["failures"])[:3]
                raise ValueError("a required private source failed or was incomplete")
            if not candidates:
                # Name the sources that were never searched. A model that
                # searched one source, found nothing and stopped looks identical
                # to one that refused, unless the denial says which reader never
                # ran -- and a document lives in exactly one source.
                unsearched = sorted(
                    {"kite_personal_files_read", "kite_gmail_attachment_extract"}
                    - set(state["successful_tools"])
                )
                stage = "search-incomplete" if unsearched else "staging"
                self._unsearched_document_sources = unsearched
                raise ValueError(
                    "no document was staged, because no approved typed reader ran "
                    "and succeeded in this turn"
                )
            if len(candidates) != 1:
                stage = "staging"
                raise ValueError("exactly one staged document is required")
            if (
                binding.mapping is None
                or binding.request is None
                or binding.mapping.principal.casefold() != "james"
                or "juno.private.james"
                not in binding.effective_read_capability_ids
            ):
                stage = "binding"
                raise ValueError("the phase-one James-only binding is unavailable")
            stage = "selection"
            selection = json.loads(str(model_text or ""))
            if not isinstance(selection, dict) or set(selection) != {"capability_id"}:
                raise ValueError("release selection must choose one semantic capability")
            capability_id = selection.get("capability_id")
            purpose_by_capability = {
                "juno.private.james": "personal administration",
                "juno.shared.family": "family administration",
                "juno.shared.children": "family administration",
                "juno.shared.mauritius": "travel administration",
                "juno.shared.property_intel": "property administration",
                "juno.shared.villa_lena": "property administration",
            }
            if (
                not isinstance(capability_id, str)
                or capability_id not in purpose_by_capability
                or capability_id not in binding.effective_read_capability_ids
            ):
                stage = "policy"
                raise ValueError("document domain is outside the effective policy")
            candidate = candidates[0]
            title = self._safe_release_title(candidate.title)
            stage = "approval-issue"
            code, expires_at = self.document_releases.issue(
                candidate,
                request=binding.request,
                principal=binding.mapping.principal,
            )
            return canonical_json({
                "outcome": "approval_required",
                "document": {
                    "title": title,
                    "source_class": candidate.source_class,
                    "mime_type": candidate.mime_type,
                    "size_bytes": candidate.size_bytes,
                    "page_count": candidate.page_count,
                },
                "audience": "James only in this WhatsApp conversation",
                "purpose": purpose_by_capability[capability_id],
                "approval": {
                    "code": code,
                    "instruction": f"APPROVE {code}",
                    "expires_at": datetime.fromtimestamp(
                        expires_at, tz=timezone.utc
                    ).isoformat(),
                },
            })
        except Exception:
            for candidate in candidates:
                self.document_releases.discard_candidate(candidate)
            # Name the stage that actually denied.  A single generic reason sent
            # earlier debugging toward deployment and config when the real stage
            # was staging.  These strings are fixed and stage-only: the caught
            # exception text is never echoed outward.
            reason_by_stage = {
                "typed-read": (
                    "a required private source failed or was incomplete, so no "
                    "document could be staged: "
                    + "; ".join(getattr(self, "_typed_read_failures", ()) or ["unspecified"])
                ),
                "staging": (
                    "no approved typed reader ran and succeeded in this turn, so "
                    "no document was staged for release"
                ),
                "search-incomplete": (
                    "no approved typed reader staged a document, and these "
                    "document sources were never searched successfully in this "
                    "turn: "
                    + ", ".join(getattr(self, "_unsearched_document_sources", ()))
                ),
                "binding": (
                    "the phase-one James-only document binding is unavailable"
                ),
                "selection": (
                    "the response did not select exactly one semantic capability "
                    "for the staged document"
                ),
                "policy": (
                    "the selected document domain is outside the effective policy"
                ),
                "approval-issue": (
                    "the staged document could not be bound to a one-use approval"
                ),
            }
            return canonical_json({
                "outcome": "denied",
                "stage": stage,
                "reason": reason_by_stage.get(
                    stage,
                    "specific document release is unavailable under the current "
                    "exact binding",
                ),
            })

    @staticmethod
    def _private_source_overlap_leak_reason(
        answer: str,
        output_tier: str,
        state: dict[str, Any],
    ) -> str:
        """Allow only bounded path-tagged provenance in minimized answers."""
        content_overlaps = {
            fragment for fragment in state["content_fragments"] if fragment in answer
        }
        provenance_overlaps = {
            fragment
            for fragment in state["provenance_fragments"]
            if fragment in answer
        }
        if not content_overlaps and not provenance_overlaps:
            return ""
        if output_tier == "bounded_excerpt" and len(answer) <= 400:
            return ""
        if content_overlaps or output_tier != "minimized_answer":
            return "raw private-source overlap"
        if _contains_json_container(answer):
            return "raw private-source overlap"
        provenance_characters = sum(
            answer.count(fragment) * len(fragment)
            for fragment in provenance_overlaps
        )
        if (
            len(provenance_overlaps)
            > _MINIMIZED_PROVENANCE_MAX_DISTINCT_FRAGMENTS
            or provenance_characters > _MINIMIZED_PROVENANCE_MAX_TOTAL_CHARS
        ):
            return "raw private-source overlap"
        return ""

    def transform_llm_output(
        self,
        response_text: str = "",
        session_id: str = "",
        turn_id: Optional[str] = None,
        **_: Any,
    ) -> Optional[str]:
        # The document itself is the answer. When the host already delivered it
        # in this exact turn, drop the model's follow-up sentence: the gateway
        # strips the returned whitespace to empty and then sends nothing, while
        # returning "" here would mean "leave unchanged".
        delivered = self._auto_delivered & frozenset(
            value
            for value in (
                str(session_id or ""),
                str(get_session_env("HERMES_SESSION_ID") or ""),
                str(get_session_env("HERMES_SESSION_KEY") or ""),
            )
            if value
        )
        if delivered:
            self._auto_delivered -= delivered
            return " "
        platform, _peer, _context = self._a2a_lane()
        if platform != "a2a":
            return None
        binding = _ACTIVE_BINDING.get()
        try:
            binding = self._current_valid_binding(
                session_id=str(session_id or ""),
                turn_id=None if turn_id is None else str(turn_id),
            )
            answer = str(response_text or "")
            property_mode = False
            property_provenance = False
            host_authored = False
            if self.private_reads.enabled:
                if binding.output_tier == "bulk_raw_export":
                    answer = canonical_json({
                        "outcome": "denied",
                        "reason": "bulk/raw private-source export is not permitted",
                    })
                elif binding.output_tier == "specific_full_document_descriptor":
                    if self.document_releases.enabled:
                        state = self._private_read_state()
                        answer = self._document_release_answer(binding, answer, state)
                        # The model's text was discarded above; what remains is
                        # the host's own closed descriptor.
                        host_authored = True
                    else:
                        answer = canonical_json({
                            "outcome": "unavailable_next_gate",
                            "reason": "specific document delivery is unavailable until Slice C",
                        })
                else:
                    state = self._private_read_state()
                    failures = sorted(state["failures"])
                    if failures:
                        answer = canonical_json({
                            "outcome": "unverifiable",
                            "reason": "one or more required private sources failed or were incomplete",
                            "source_failures": failures[:8],
                        })
                    else:
                        property_provenance = (
                            "kite_property_read" in state["successful_tools"]
                        )
                        property_mode = self._property_output_authorized(binding, state)
            if property_provenance and not property_mode:
                leak_reason = "Property output authority or provenance is unavailable"
            elif property_mode:
                leak_reason = self._property_output_leak_reason(answer)
            elif host_authored:
                # A closed host-built descriptor, not prose. Its only free field
                # is the title, already reduced at staging and checked again by
                # _safe_release_title against what actually cannot ship.
                leak_reason = ""
            else:
                leak_reason = self._leak_reason(answer, output=True)
            # The overlap check exists to stop the model echoing raw source
            # text. On a document turn the answer is the host's own descriptor,
            # so running it there checks the host against itself -- and it must
            # fail: the document's title is derived from the artifact's
            # filename, which the reader that found it recorded as provenance.
            if not leak_reason and self.private_reads.enabled and not host_authored:
                if not property_mode:
                    leak_reason = self._private_source_overlap_leak_reason(
                        answer,
                        binding.output_tier,
                        self._private_read_state(),
                    )
            denied = bool(leak_reason)
            if denied:
                answer = ""
            else:
                output_limit = self.limits.output_chars
                if (
                    self.private_reads.enabled
                    and binding.output_tier == "bounded_excerpt"
                ):
                    output_limit = min(output_limit, 1200)
                answer = _truncate_chars(answer, output_limit)
            assert binding.request is not None
            if not self.store.release_request(
                binding.request.request_id, int(self.clock())
            ):
                raise ValueError("response binding could not be released")
            envelope = self._signed_response(
                binding,
                answer=answer,
                denied=denied,
                reason=(
                    f"output withheld by leak policy ({leak_reason})"
                    if denied
                    else ""
                ),
            )
            if (
                property_mode
                and len(envelope.encode("utf-8")) > self.limits.response_bytes
            ):
                answer = ""
                denied = True
                envelope = self._signed_response(
                    binding,
                    answer="",
                    denied=True,
                    reason="Property output exceeds the signed response byte limit",
                )
            while len(envelope.encode("utf-8")) > self.limits.response_bytes and answer:
                answer = answer[:-1]
                envelope = self._signed_response(
                    binding, answer=answer, denied=denied, reason=""
                )
            if len(envelope.encode("utf-8")) > self.limits.response_bytes:
                raise ValueError("response envelope exceeds byte limit")
            return envelope
        except Exception as exc:
            logger.warning(
                "Kite output release denied: %s: %s",
                type(exc).__name__, str(exc)[:200],
            )
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

    def _validate_response(
        self, raw: str, mapping: MappingRecord, request_id: str
    ) -> dict:
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
        if self._release_descriptor(answer) is None:
            if self._leak_reason(answer, output=True):
                raise ValueError("Kite response contains leak-shaped data")
        elif self._safe_release_title(
            json.loads(answer)["document"]["title"]
        ) == "Requested document" and json.loads(answer)["document"]["title"]:
            raise ValueError("Kite response contains leak-shaped data")
        if payload.get("denied") is not False:
            # Say which gate refused. A bare "denied under current policy"
            # is indistinguishable from a missing file, an unreadable scan
            # and a policy that genuinely does not cover the request, and
            # every one of those has cost a round trip to tell apart. The
            # reason names the category the host itself computed, never the
            # content that tripped it.
            detail = str(payload.get("reason") or "").strip()
            raise ValueError(
                "Kite denied release under current policy"
                + (f": {detail[:160]}" if detail else "")
            )
        return payload

    def _verify_response(
        self, raw: str, mapping: MappingRecord, request_id: str
    ) -> str:
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
        security.audit(
            "outbound", peer_name, task_id, "opaque trusted-principal consultation"
        )
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

    async def consult_kite_delivering(self, _args: dict, **_: Any) -> str:
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
            return {
                "context": "JUNO--KITE POLICY: DENIED. Plugin configuration is unavailable."
            }
        return None

    def pre_tool_call(self, **_: Any) -> Optional[dict]:
        if str(get_session_env("HERMES_SESSION_PLATFORM") or "").lower() == "a2a":
            return {
                "action": "block",
                "message": "Juno--Kite policy configuration is unavailable",
            }
        return None

    def pre_tool_dispatch(self, **_: Any) -> Optional[dict]:
        if str(get_session_env("HERMES_SESSION_PLATFORM") or "").lower() == "a2a":
            return {
                "action": "block",
                "message": "Juno--Kite policy configuration is unavailable",
            }
        return None

    def transform_llm_output(self, **_: Any) -> Optional[str]:
        if str(get_session_env("HERMES_SESSION_PLATFORM") or "").lower() == "a2a":
            return DENIAL_PREFIX + "no releasable envelope"
        return None


def runtime_from_host(
    active_profile: str,
) -> TrustedPrincipalRuntime | FailClosedRuntime:
    host_config: dict = {}
    try:
        from hermes_cli.config import load_config

        host_config = load_config() or {}
        return TrustedPrincipalRuntime(host_config, active_profile=active_profile)
    except Exception as exc:
        logger.warning(
            "Juno--Kite plugin initialized fail-closed: %s", type(exc).__name__
        )
        section = host_config.get("juno_kite_trusted_principal", {})
        if not isinstance(section, dict):
            section = {}
        return FailClosedRuntime(
            exc,
            mode=str(section.get("mode") or "").strip().lower(),
            active_profile=active_profile,
            configured_profile=str(section.get("profile") or "").strip(),
        )
