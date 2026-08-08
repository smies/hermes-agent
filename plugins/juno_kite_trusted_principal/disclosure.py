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
)
_DOCUMENT_PATTERNS = (
    re.compile(
        r"(?i)\b(?:send|deliver|attach|upload|download|give me)\b.{0,40}\b(?:document|scan|passport|pdf|file|attachment)\b"
    ),
    re.compile(
        r"(?i)\b(?:full|actual|original)\s+(?:document|scan|passport|pdf|file|attachment)\b"
    ),
)
_EXCERPT_PATTERNS = (
    re.compile(r"(?i)\b(?:quote|excerpt|exact wording|verbatim sentence)\b"),
)


def classify_output_tier(question: str) -> str:
    """Classify only the requested output form, never its principal/domain."""
    value = str(question or "")
    if any(pattern.search(value) for pattern in _RAW_PATTERNS):
        return BULK_RAW
    if any(pattern.search(value) for pattern in _DOCUMENT_PATTERNS):
        return DOCUMENT_DESCRIPTOR
    if any(pattern.search(value) for pattern in _EXCERPT_PATTERNS):
        return BOUNDED_EXCERPT
    return MINIMIZED


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
    if output_tier == DOCUMENT_DESCRIPTOR:
        return DisclosureDecision(
            False,
            "unavailable_next_gate",
            "the document may be described but cannot be delivered before Slice C",
        )
    if output_tier not in {MINIMIZED, BOUNDED_EXCERPT}:
        return DisclosureDecision(False, "denied", "unknown output tier")
    if str(principal).lower() == "lucy" and capability_id == "juno.private.james":
        return DisclosureDecision(
            False, "denied", "James-exclusive information is unavailable to Lucy"
        )
    return DisclosureDecision(
        True, output_tier, "effective audience capability permits this minimized form"
    )


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
        "output_tier_rule": {
            MINIMIZED: "answer with necessary facts, status, synthesis, blockers, next steps, and bounded provenance",
            BOUNDED_EXCERPT: "quote only a short necessary excerpt when the effective semantic domain permits it",
            DOCUMENT_DESCRIPTOR: "return an unavailable_next_gate descriptor; binary delivery belongs to Slice C",
            BULK_RAW: "deny without invoking a private connector",
        }[output_tier],
        "passport_rule": (
            "passport identifiers are identity documents, not credentials; disclose only under an "
            "effective children/family/Mauritius capability, never as binary delivery in this slice"
        ),
        "provenance": (
            "bounded source class, sender/author display label, date, title, and Property Intel "
            "public link only; never internal paths, client IDs, session IDs, or credentials"
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
    "generated_semantic_guidance",
]
