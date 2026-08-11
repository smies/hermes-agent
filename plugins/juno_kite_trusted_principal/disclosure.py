"""Deterministic semantic-disclosure guidance for trusted private reads.

Identity and audience authority are supplied by :mod:`runtime`.  This module
does not infer either from text; it only turns the already-intersected
capability IDs into a compact, stable policy view for Kite.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable


MINIMIZED = "minimized_answer"
BOUNDED_EXCERPT = "bounded_excerpt"
DOCUMENT_DESCRIPTOR = "specific_full_document_descriptor"
BULK_RAW = "bulk_raw_export"

CAPABILITY_DOMAINS: dict[str, tuple[str, ...]] = {
    "juno.private.james": (
        "personal communications and email",
        "personal or family calendar and travel",
        "personal Things tasks",
        "personal notes and documents",
        "personal finances, purchases, receipts, memberships, and health",
    ),
    "juno.shared.family": (
        "authenticated Lucy submissions",
        "household-shared information and ordinary family logistics",
    ),
    "juno.shared.children": (
        "children's school, family, medical, passport, identity, and travel information",
    ),
    "juno.shared.mauritius": (
        "Mauritius plans, bookings, costs, traveller details, requirements, and correspondence",
    ),
    "juno.shared.property_intel": ("all Property Intel information",),
    "juno.shared.villa_lena": (
        "Villa Lena purchase financial, legal, survey, inventory, adviser, and acquisition information",
    ),
    "juno.public": ("public and non-private agent-operational information",),
}

_RAW_PATTERNS = (
    re.compile(
        r"(?i)\b(?:bulk|entire|whole|all)\b.{0,28}\b(?:mailbox|emails?|threads?|headers?|attachments?|archive|dump|export)\b"
    ),
    re.compile(
        r"(?i)\b(?:raw|verbatim)\b.{0,24}\b(?:email|thread|headers?|mailbox|source|records?|messages?)\b"
    ),
    re.compile(r"(?i)\bmailbox\s+(?:dump|export)\b"),
    re.compile(
        r"(?i)\b(?:bulk|entire|whole|all)\b.{0,32}\b(?:portal|property(?: Intel)?)\s+"
        r"(?:database|records?|rows?|export|dump)\b"
    ),
    re.compile(
        r"(?i)\b(?:dump|export)\b.{0,32}\b(?:Property Intel|property records?|portal records?)\b"
    ),
)
_DOCUMENT_DELIVERY = (
    r"(?:send|resend|re-send|forward|attach|share|deliver|upload|download|"
    r"retrieve|give\s+me|email\s+me|whatsapp\s+me|text\s+me|i\s+need|"
    r"show\s+me|let\s+me\s+see|pull\s+up)"
)
# Plurals count. "Send me the passports" classified as a minimized answer
# because \b would not close after "passport", so asking for more than one
# document quietly asked for none.
_DOCUMENT_ARTIFACT = (
    r"(?:document|scan|passport|pdf|file|attachment|copy|copies)(?:e?s)?"
)
# Real-world document names people actually use.  A request rarely says "PDF";
# it says "the engagement letter" or "Albie's boarding pass".
_DOCUMENT_NOUN = (
    r"(?:letter|certificate|agreement|contract|invoice|statement|report|pass|"
    r"ticket|licence|license|deed|policy|form|receipt|itinerary|permit|record)"
    r"(?:e?s)?"
)
# Informational intent, which must never escalate into a file release even when
# it sits next to a delivery verb ("send me a summary of the engagement letter").
# A field printed on a document is not the document. "Give me the whole
# family's passport numbers and expiries" asks for four numbers, and answering
# it by sending four passports is both wrong and irreversible. Read as a
# question this needs no question word, so nothing else here catches it.
_DOCUMENT_ATTRIBUTE = (
    # "reference" is deliberately absent: "return a releasable file reference"
    # means a handle to the document, not a field printed on it.
    r"(?:numbers?|no\.|expir(?:y|ies|ation|es|ing)|issue\s+dates?|"
    r"serial|details)"
)
_DOCUMENT_INFORMATIONAL = re.compile(
    r"(?i)(?:\b(?:summary|summarise|summarize|update|note|gist|overview|"
    r"tell\s+me|remind|what|when|who|how|why|which|where)\b"
    # A leading auxiliary makes it a question about a document, not a request
    # for one ("did nacho send the agreement").
    r"|^\s*(?:did|do|does|has|have|had|is|are|was|were|will|can|could|should)\b"
    r"(?!\s+you\s+" + _DOCUMENT_DELIVERY + r"\b)"
    # "the passport number", either order. A details *page* is the document
    # itself, so it keeps its release tier.
    r"|\b" + _DOCUMENT_ARTIFACT + r"\b[^.?!]{0,24}?\b" + _DOCUMENT_ATTRIBUTE
    + r"\b(?!\s+(?:page|scan|copy))"
    r"|\b" + _DOCUMENT_ATTRIBUTE + r"\b[^.?!]{0,24}?\b(?:of|on|in|for|from)\b"
    r"[^.?!]{0,24}?\b" + _DOCUMENT_ARTIFACT + r"\b"
    r")"
)
_DOCUMENT_PATTERNS = (
    re.compile(
        r"(?i)\b" + _DOCUMENT_DELIVERY + r"\b.{0,40}\b" + _DOCUMENT_ARTIFACT + r"\b"
    ),
    re.compile(
        r"(?i)\b(?:full|actual|original)\s+" + _DOCUMENT_ARTIFACT + r"\b"
    ),
    # Delivery of a definite or possessive named document.
    re.compile(
        r"(?i)\b" + _DOCUMENT_DELIVERY + r"\b[^.?!]{0,40}?"
        r"(?:\b(?:the|my|our|his|her|their|this|that)\b\s+|\b[a-z]+['\u2019]s\s+)"
        r"(?:[a-z0-9'\u2019\-]+\s+){0,3}" + _DOCUMENT_NOUN + r"\b"
    ),
)
_EXCERPT_PATTERNS = (
    re.compile(r"(?i)\b(?:quote|excerpt|exact wording|verbatim sentence)\b"),
)


# A follow-up that names no document at all: a delivery verb pointing at
# something the previous turn already identified ("retrieve and send it again").
# It carries no subject of its own, so it can only be resolved against the
# conversation, never from the message alone.
_DOCUMENT_FOLLOWUP_OBJECT = re.compile(
    r"(?i)\b(?:it|that|this|them|those|these|again|one|copy)\b"
)
_DOCUMENT_FOLLOWUP_SUBJECT = re.compile(
    r"(?i)\b(?:about|regarding|instead|summar\w+|status|update)\b"
)
_DOCUMENT_FOLLOWUP_MAX_CHARS = 80


def is_document_followup(question: str) -> bool:
    """True when this asks again for whatever the last turn produced.

    Deliberately narrow: it must be short, carry a delivery verb and an
    anaphoric object, introduce no subject of its own, and not already
    classify as something else. The caller still has to prove that the
    previous turn in this same conversation was a document turn -- on its own
    this text says nothing about documents.
    """
    value = str(question or "")
    if not value or len(value) > _DOCUMENT_FOLLOWUP_MAX_CHARS:
        return False
    if classify_output_tier(value) != MINIMIZED:
        return False
    if _DOCUMENT_FOLLOWUP_SUBJECT.search(value) or _DOCUMENT_INFORMATIONAL.search(
        value
    ):
        return False
    return bool(
        re.search(r"(?i)\b" + _DOCUMENT_DELIVERY + r"\b", value)
        and _DOCUMENT_FOLLOWUP_OBJECT.search(value)
    )


def classify_output_tier(question: str) -> str:
    """Classify only the requested output form, never its principal/domain."""
    value = str(question or "")
    if any(pattern.search(value) for pattern in _RAW_PATTERNS):
        return BULK_RAW
    if not _DOCUMENT_INFORMATIONAL.search(value) and any(
        pattern.search(value) for pattern in _DOCUMENT_PATTERNS
    ):
        return DOCUMENT_DESCRIPTOR
    if any(pattern.search(value) for pattern in _EXCERPT_PATTERNS):
        return BOUNDED_EXCERPT
    return MINIMIZED


# Ordered least to most restrictive. Escalating adds gates (an approval flow, or
# an outright denial for bulk/raw), so combining tiers by taking the maximum is
# the fail-closed direction: an unrecognized value scores highest of all.
_TIER_RESTRICTIVENESS = {
    MINIMIZED: 0,
    BOUNDED_EXCERPT: 1,
    DOCUMENT_DESCRIPTOR: 2,
    BULK_RAW: 3,
}


def strongest_output_tier(tiers: Iterable[str]) -> str:
    """Return the most restrictive tier among the candidates.

    Used where more than one description of the same request is available and
    only some of them are trustworthy. An unknown or empty tier must never
    silently relax the outcome, so it is treated as maximally restrictive.
    """
    strongest = MINIMIZED
    for tier in tiers:
        value = str(tier or "")
        if not value:
            continue
        if value not in _TIER_RESTRICTIVENESS:
            return BULK_RAW
        if _TIER_RESTRICTIVENESS[value] > _TIER_RESTRICTIVENESS[strongest]:
            strongest = value
    return strongest


_DOCUMENT_RELEASABLE_CAPABILITIES = frozenset({
    # James's own personal documents, released only back to James.
    "juno.private.james",
    "juno.shared.family",
    "juno.shared.children",
    "juno.shared.mauritius",
    "juno.shared.property_intel",
    "juno.shared.villa_lena",
})


def _releasable_document_capabilities(
    principal: str, capabilities: Iterable[str]
) -> list[str]:
    """Document classes this principal may release, in stable order.

    Capability, not name. A principal releases what their audience actually
    holds, and in a group that is the intersection of everyone present -- so
    juno.private.james leaves the set the moment anyone else is in the room,
    without a rule here having to say so. A shared class survives, which is
    what lets a family document reach a family conversation.
    """
    return sorted(
        set(map(str, capabilities)) & _DOCUMENT_RELEASABLE_CAPABILITIES
    )


@dataclass(frozen=True)
class DisclosureDecision:
    allowed: bool
    outcome: str
    reason: str


def disclosure_decision(
    *,
    principal: str,
    effective_capability_ids: Iterable[str],
    capability_id: str,
    output_tier: str = MINIMIZED,
    contains_credentials: bool = False,
    source_complete: bool = True,
) -> DisclosureDecision:
    """A small deterministic oracle used by tests and output-tier handling.

    Semantic topic matching remains the model's job.  The caller supplies the
    capability selected for that topic; this function verifies that it is in
    the host-computed intersection and applies non-semantic absolute rules.
    """
    effective = frozenset(map(str, effective_capability_ids))
    if contains_credentials:
        return DisclosureDecision(False, "denied", "credentials are never disclosable")
    if not source_complete:
        return DisclosureDecision(
            False, "unverifiable", "required live source is incomplete"
        )
    if str(capability_id) not in effective:
        return DisclosureDecision(
            False, "denied", "domain is outside the effective audience intersection"
        )
    if output_tier == BULK_RAW:
        return DisclosureDecision(
            False, "denied", "bulk or raw private-source export is unavailable"
        )
    if str(principal).lower() == "lucy" and capability_id == "juno.private.james":
        return DisclosureDecision(
            False, "denied", "James-exclusive information is unavailable to Lucy"
        )
    if output_tier == DOCUMENT_DESCRIPTOR:
        if capability_id not in _releasable_document_capabilities(
            principal, effective_capability_ids
        ):
            return DisclosureDecision(
                False,
                "denied",
                "specific document release is unavailable under the phase-one binding",
            )
        return DisclosureDecision(
            True,
            DOCUMENT_DESCRIPTOR,
            "host-bound Slice C proposal and approval gates are required",
        )
    if output_tier not in {MINIMIZED, BOUNDED_EXCERPT}:
        return DisclosureDecision(False, "denied", "unknown output tier")
    return DisclosureDecision(
        True, output_tier, "effective audience capability permits this minimized form"
    )


# Readers bound to one principal because of whose data they read, not whose
# question it is. Session recall searches a principal's own conversation
# transcripts; locate walks where they keep documents. The runtime imports
# this so the guidance and the gate cannot drift: recommending a tool the
# caller may not use costs a turn and reads to them as a dead end.
PRINCIPAL_BOUND_READS = {
    # Empty on purpose. Every entry that was here cost a real answer to
    # someone James trusts, and none of them ever stopped a disclosure: what
    # may be said is decided by the capabilities in force for the room, and
    # judged against them before anything is returned. A reader bound by name
    # only decides who has to ask him instead.
    # Recall is deliberately NOT here. James's decision, and the reasoning is
    # his: Kite may look with its full power, and then judge what came back
    # against the request and the capabilities this turn actually has, and
    # return only what is both relevant and permitted. Binding recall by name
    # instead cost a real answer -- a follow-up about a passport she had just
    # been told the number of -- and would keep costing them.
    #
    # What this does not do, stated plainly: the store holds every
    # conversation, and nothing in it is tagged by owner, so there is no
    # mechanical filter separating a private thread from a shared one. The
    # judgment step is the filter. When sessions carry a principal, that
    # becomes a real boundary and should be added here.
}


def _may_recall(principal: str) -> bool:
    permitted = PRINCIPAL_BOUND_READS.get("kite_session_search")
    return permitted is None or str(principal).casefold() in permitted


def generated_semantic_guidance(
    *,
    principal: str,
    effective_capability_ids: Iterable[str],
    configured_policy: dict[str, Any],
    output_tier: str,
) -> dict[str, Any]:
    """Return byte-stable guidance selected from host-bound authority only."""
    capabilities = tuple(sorted(set(map(str, effective_capability_ids))))
    allowed_domains = [
        domain
        for capability_id in capabilities
        for domain in CAPABILITY_DOMAINS.get(capability_id, ())
    ]
    principal_name = str(principal).lower()
    releasable_documents = _releasable_document_capabilities(
        principal, capabilities
    )
    work_boundary = {
        "gmail": "work Gmail is absent",
        "calendar": (
            "work calendar may disclose only busy/free intervals, timezone, "
            "and coarse timing constraints"
        ),
        "forbidden_work_fields": [
            "title",
            "attendees",
            "description",
            "location",
            "links",
            "ids",
            "organizer",
            "conference",
            "attachments",
            "company context",
        ],
    }
    denials = [
        "credentials and authentication material",
        "bulk/raw private-source dumps",
        "data outside the effective audience capability intersection",
        "claims of absence from a failed, truncated, stale, or incomplete source",
    ]
    if principal_name == "lucy":
        denials.extend([
            "unrelated James email or private correspondence",
            "unrelated banking, tax, investments, or finances",
            "James private health, Things, notes, or documents",
            "work information and other-principal private data",
        ])
    return {
        "authority": "host-authenticated principal plus signed effective audience intersection",
        "principal": principal,
        "effective_capability_ids": list(capabilities),
        "configured_capability_guidance": {
            capability_id: configured_policy[capability_id]
            for capability_id in capabilities
        },
        "frozen_allowed_domains": allowed_domains,
        "work_boundary": work_boundary,
        "always_denied": denials,
        "output_tier": output_tier,
        "document_release_mode": {
            "available": bool(releasable_documents),
            "releasable_capability_ids": releasable_documents,
            "authority": (
                "the host decides document release through the Slice C proposal "
                "and exact APPROVE gates; entitlement is already intersected here"
            ),
            "required_steps": (
                "1) call an approved typed reader and let it succeed, so the host "
                "stages exactly one artifact from that live read; 2) only then "
                "return {\"capability_id\": \"<one effective capability id>\"} as "
                "the entire response. Step 1 is what creates the release; skipping "
                "it always produces a host denial and James receives nothing"
            ),
            "self_refusal": (
                "do not refuse a document request that falls inside these "
                "capability IDs, and never invent a privacy or authorization "
                "reason of your own: attempt the typed read and let the host "
                "gates allow or deny it, then report the host's actual reason"
            ),
        },
        "property_output_mode": {
            "available": (
                principal_name == "james"
                and "juno.shared.property_intel" in capabilities
            ),
            "authority": (
                "exact current James turn, current signed roster/policy, exact "
                "juno.shared.property_intel capability, and only successful "
                "kite_property_read provenance"
            ),
            "form": (
                "bounded prose or bullets may use any sanitized Property Intel facts, "
                "including future fields, nested values, ordinary IDs, URLs, notes, "
                "history, and document metadata; there is no per-field allowlist"
            ),
            "denied": (
                "JSON/container records, bulk/raw exports, binary documents, over-limit "
                "answers, credentials, mixed-source provenance, and non-James release"
            ),
        },
        "output_tier_rule": {
            MINIMIZED: (
                "answer with necessary facts, status, synthesis, blockers, next "
                "steps, and bounded provenance. "
                + (
                    "When the request refers to something already discussed, "
                    "decided or filed, kite_session_search recalls it rather "
                    "than re-deriving it from live sources. What it returns is "
                    "raw recall from every stored conversation, not an answer: "
                    "read it, keep only what actually bears on this request, "
                    "and only what the effective semantic domains above permit "
                    "for THIS audience. A transcript carries no capability of "
                    "its own, so nothing found in one may be repeated here "
                    "unless a capability in force this turn covers it. "
                    if _may_recall(principal)
                    else "Answer from the typed readers: this principal cannot "
                    "search stored conversations, so a question about "
                    "something already discussed is answered by reading the "
                    "source again. "
                )
                + "No document staging or approval "
                "gate runs on this tier, so never explain a document you did not "
                "return by inventing one: if a binary was wanted and this turn "
                "did not ask for one, say exactly that"
            ),
            BOUNDED_EXCERPT: "quote only a short necessary excerpt when the effective semantic domain permits it",
            DOCUMENT_DESCRIPTOR: (
                "Two acts in this turn, not an output format.\n"
                "1. Find it. "
                + (
                    "If it has come up before, kite_session_search "
                    "recalls where it was filed. Then read it with a typed reader "
                    if _may_recall(principal)
                    else "Read it with a typed reader "
                )
                + 
                "-- kite_personal_files_read (bounded search, then the exact "
                "read) or the exact Gmail message read then "
                "kite_gmail_attachment_extract. Only a real successful read "
                "stages anything. Search BOTH sources before saying a document "
                "is missing: a local file never appears in an email search.\n"
                "2. Check it. The reader returns document_name and "
                "document_preview, text taken from the artifact itself; a "
                "scanner default like \"photo\" identifies nothing and the "
                "surrounding email is not evidence of an image's contents. "
                "Match the contents, not the topic -- a British passport and "
                "an Irish one are both passports. On a mismatch, or an empty "
                "preview, read the next candidate; if none match, name what "
                "you found. A released document cannot be recalled.\n"
                "Then reply with only {\"capability_id\": \"<one effective "
                "capability id>\"}. That JSON without step 1 stages nothing "
                "and is denied, so never answer this tier from memory."
            ),
            BULK_RAW: "deny without invoking a private connector",
        }[output_tier],
        "passport_rule": (
            "passport identifiers are identity documents, not credentials; disclose only under an "
            "effective children/family/Mauritius capability; binary release additionally requires "
            "the host-bound Slice C staging and approval flow"
        ),
        "provenance": (
            "bounded source class, sender/author display label, date, title, and, only in the "
            "James Property output mode, sanitized portal identifiers and URLs; never internal "
            "connector paths, connector client IDs, session IDs, or credentials"
        ),
    }


__all__ = [
    "BOUNDED_EXCERPT",
    "BULK_RAW",
    "CAPABILITY_DOMAINS",
    "DOCUMENT_DESCRIPTOR",
    "MINIMIZED",
    "DisclosureDecision",
    "classify_output_tier",
    "disclosure_decision",
    "strongest_output_tier",
    "generated_semantic_guidance",
]
