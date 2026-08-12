"""Narrow, read-only private-source connectors for Kite.

Every model-facing argument is bounded and source-specific.  Executable paths,
account identities, endpoints, filesystem roots, and credentials are host
configuration; they are never accepted from the model.  External commands use
an argv vector with ``shell=False`` and HTTP uses fixed GET-only routes.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import math
import mimetypes
import os
import re
import sqlite3
import threading
from collections import OrderedDict
from datetime import date, datetime, timedelta, timezone
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

PRIVATE_READ_TOOLSET = "juno_kite_private_reads"
TOOL_NAMES = (
    "kite_gmail_search",
    "kite_gmail_get",
    "kite_gmail_attachment_extract",
    "kite_calendar_read",
    "kite_things_read",
    "kite_property_read",
    "kite_whatsapp_archive_read",
    "kite_personal_files_read",
    "kite_personal_files_locate",
    "kite_personal_files_release_located",
    "kite_session_search",
)

PERSONAL_GMAIL = "smith.js@gmail.com"
KITE_GMAIL = "kite.010.kite@gmail.com"
THINGS_PROJECT_UUID = "QcGAPSj2vVUsf3ad2buNo3"
THINGS_PROJECT_TITLE = "Personal Action List"
THINGS_CLIENT = (
    "/Users/james/projects/personal-ops/runtime/scripts/things_mcp_client.py"
)
THINGS_ENDPOINT = "http://127.0.0.1:8787/mcp"
WHATSAPP_QUERY = (
    "/Users/james/projects/personal-ops/runtime/whatsapp-readonly/scripts/query.mjs"
)
OBSIDIAN_ROOT = "/Users/james/Documents/Obsidian Vault"

# What a property list is for: telling thirty-nine properties apart and
# finding the one that matters. The full record is 4KB of description,
# amenities, legal text and geometry -- 170KB for the list, which crowds out
# the question being asked and sits one growth spurt from the byte cap. Depth
# is what the detail operations are for; this is the index.
_PROPERTY_LIST_FIELDS = (
    "id", "canonicalTitle", "displayArea", "market", "status",
    "interestLevel", "viewingPriority", "propertyType", "transactionType",
    "priceAmount", "priceCurrency", "pricePeriod", "priceQualifier",
    "bedrooms", "bathrooms", "nextAction", "nextActionDueAt", "updatedAt",
)

_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
# Gmail attachment handles are far longer than message ids -- the engagement
# letter's is 319 characters -- and are regenerated per response, so they
# cannot be shortened or cached. A 256 cap silently made every real attachment
# unreachable: the schema rejected the argument before the reader ever ran.
_ATTACHMENT_ID_MAX_CHARS = 1024
# Transport headroom for one base64-encoded artifact plus its metadata. The
# release ceiling is 8MB of decoded bytes, which is ~10.7MB encoded; this caps
# the pipe, not the policy, which is enforced on the decoded size.
_ATTACHMENT_COMMAND_OUTPUT_BYTES = 12 * 1024 * 1024
# The attachment command makes two API round-trips and downloads the document,
# where an ordinary text answer makes one and returns a few KB. The shared 15s
# source timeout killed it mid-download. Bounded well inside the A2A call
# envelope so a slow document cannot strand the whole consultation.
_ATTACHMENT_COMMAND_TIMEOUT_SECONDS = 60
_ATTACHMENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,%d}\Z" % _ATTACHMENT_ID_MAX_CHARS)
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\Z"
)
from .document_release import _EXECUTABLE_SUFFIXES

_DATE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})?)?\Z"
)
# A date argument was one of the readers' most reliable ways to lose an answer.
# "after must be an ISO date" is true and useless: it does not say what an ISO
# date looks like, so the retry is a guess. And the forms being refused were
# the ones anybody writing a mail query reaches for first -- Gmail's own
# YYYY/MM/DD, or "30d" for the last month. The window wanted is unambiguous in
# every one of them.
#
# The regex above also let 2026-13-45 through, which then went to the source as
# a search term nothing could match. Parsing settles that in passing.
_RELATIVE_DATE_RE = re.compile(r"(\d{1,4})\s*([dwmy])\Z", re.IGNORECASE)
_RELATIVE_DAYS = {"d": 1, "w": 7, "m": 31, "y": 366}
_DATE_HELP = (
    "give a date as 2026-08-01 (or 2026/08/01), or a span back from today "
    "as 7d, 3w, 6m, 1y, or today/yesterday"
)


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _normalise_date(value: str, key: str, *, allow_time: bool = False) -> str:
    """Return YYYY-MM-DD for anything that unambiguously names a day.

    With allow_time, a full ISO timestamp is passed through untouched -- a
    calendar window may legitimately want an hour, and rounding it to the day
    would quietly widen the read.
    """

    text = value.strip()
    if allow_time and "T" in text and _DATE_RE.fullmatch(text) is not None:
        try:
            datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            raise SourceFailure(
                "invalid_arguments", f"{key} is not a date I can read -- {_DATE_HELP}"
            ) from None
        return text
    lowered = text.lower()
    if lowered in {"today", "now"}:
        return _today().isoformat()
    if lowered == "yesterday":
        return (_today() - timedelta(days=1)).isoformat()
    relative = _RELATIVE_DATE_RE.fullmatch(lowered)
    if relative is not None:
        span = int(relative.group(1)) * _RELATIVE_DAYS[relative.group(2).lower()]
        if span > 36600:
            raise SourceFailure("invalid_arguments", f"{key} reaches back too far")
        return (_today() - timedelta(days=span)).isoformat()
    calendrical = text.replace("/", "-").replace(".", "-")
    day = calendrical[:10]
    try:
        parsed = date.fromisoformat(day)
    except ValueError:
        raise SourceFailure(
            "invalid_arguments", f"{key} is not a date I can read -- {_DATE_HELP}"
        ) from None
    if len(calendrical) > 10 and _DATE_RE.fullmatch(calendrical) is None:
        raise SourceFailure(
            "invalid_arguments", f"{key} is not a date I can read -- {_DATE_HELP}"
        )
    return parsed.isoformat()
# The release path already settled this argument -- refuse what executes and
# carry everything else -- but reading kept its own allow-list of twelve
# extensions, so a HEIC photo of a document could be released and never found.
# A document does not become dangerous by being a format nobody anticipated,
# and reading one is strictly weaker than sending it: the deny-list is shared
# with release so the two cannot drift apart again.
# Key material is not a document. The path patterns below catch names like
# private_key and token, but not id_rsa.pem, and a documents folder is exactly
# where a stray certificate ends up.
_CREDENTIAL_EXTENSIONS = frozenset({
    ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk",
    ".crt", ".cer", ".der", ".asc", ".gpg", ".pgp", ".kdbx", ".keychain",
    ".env", ".netrc", ".htpasswd",
})
_REFUSED_EXTENSIONS = _EXECUTABLE_SUFFIXES | _CREDENTIAL_EXTENSIONS
_EXTRACTABLE_MIME = frozenset({
    "text/plain",
    "text/csv",
    "text/markdown",
    "application/json",
    "application/pdf",
    "image/jpeg",
    "image/png",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
})
_WORK_FIELDS = frozenset({
    "title",
    "summary",
    "subject",
    "attendees",
    "description",
    "location",
    "htmlLink",
    "link",
    "links",
    "id",
    "eventId",
    "organizer",
    "conferenceData",
    "conference",
    "attachments",
    "company",
    "companyContext",
})

_PROPERTY_MAX_DEPTH = 12
_PROPERTY_MAX_CONTAINER_ITEMS = 1024
_PROPERTY_MAX_TOTAL_ITEMS = 8192
_PROPERTY_REDACTION = "[REDACTED]"
_PROPERTY_OPERATIONAL_CONTEXT_KEYS = frozenset({
    "auth",
    "authentication",
    "backend",
    "config",
    "connector",
    "credential",
    "credentials",
    "http",
    "request",
    "runtime",
    "transport",
})
_PROPERTY_SECRET_KEYS = frozenset({
    "apikey",
    "apisecret",
    "apitoken",
    "auth",
    "authconfig",
    "authenv",
    "authentication",
    "authorization",
    "authorizationheader",
    "bearertoken",
    "clientsecret",
    "cookie",
    "cookieheader",
    "credentialconfig",
    "credentials",
    "credentialsconfig",
    "idtoken",
    "password",
    "passphrase",
    "privatekey",
    "proxyauthorization",
    "refreshtoken",
    "secret",
    "secretconfig",
    "secretconfiguration",
    "secretkey",
    "secrets",
    "sessioncookie",
    "sessiontoken",
    "setcookie",
    "signingkey",
    "signingsecret",
    "token",
})
_PROPERTY_HEADER_KEYS = frozenset({
    "authheaders",
    "connectorheaders",
    "headers",
    "httpheaders",
    "requestheaders",
    "responseheaders",
})
_PROPERTY_SECRET_VALUE_PATTERNS = (
    re.compile(
        r"(?i)(?:\\?[\"'])?\b(?:authorization|proxy[-_ ]?authorization)"
        r"(?:\\?[\"'])?\s*[:=]\s*(?:\\?[\"'])?"
        r"(?:bearer|basic)\s+[^\s,;\"']+"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(
        r"(?i)(?:\\?[\"'])?\b(?:api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|"
        r"session[-_ ]?token|password|passphrase|client[-_ ]?secret|secret[-_ ]?key|"
        r"session[-_ ]?cookie|set-cookie|cookie)(?:\\?[\"'])?\s*[:=]\s*"
        r"(?:\\?[\"'])?[^\s,;\"']+"
    ),
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
        r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*", re.DOTALL),
    re.compile(
        r"(?i)([?&](?:access_token|auth_token|refresh_token|session_token|"
        r"token|api_key|secret)=)[^&#\s]+"
    ),
)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _object_schema(
    properties: dict[str, Any], required: tuple[str, ...]
) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": list(required),
    }


TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "kite_gmail_search": {
        "description": "Search one fixed personal or Kite Gmail account. Work Gmail does not exist here.",
        "parameters": _object_schema(
            {
                "account": {"type": "string", "enum": ["personal", "kite"]},
                "query": {"type": "string", "minLength": 1, "maxLength": 512},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 25},
                "after": {
                    "type": "string", "maxLength": 32, "description": _DATE_HELP,
                },
                "before": {
                    "type": "string", "maxLength": 32, "description": _DATE_HELP,
                },
            },
            ("account", "query", "max_results"),
        ),
    },
    "kite_gmail_get": {
        "description": "Read one exact Gmail message previously identified by bounded search.",
        "parameters": _object_schema(
            {
                "account": {"type": "string", "enum": ["personal", "kite"]},
                "message_id": {"type": "string", "minLength": 1, "maxLength": 256},
            },
            ("account", "message_id"),
        ),
    },
    "kite_gmail_attachment_extract": {
        "description": (
            "Privately extract one exact supported non-executable Gmail attachment. "
            "On a specific-document turn this exact call IS how the host stages the "
            "binary for its approval gate -- the staging is a host side effect of "
            "this call, not a separate flow you have to find or invoke, so make the "
            "call and let the host gate decide. On any other turn the extraction "
            "stays private and nothing is staged."
        ),
        "parameters": _object_schema(
            {
                "account": {"type": "string", "enum": ["personal", "kite"]},
                "message_id": {"type": "string", "minLength": 1, "maxLength": 256},
                "attachment_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": _ATTACHMENT_ID_MAX_CHARS,
                },
            },
            ("account", "message_id", "attachment_id"),
        ),
    },
    "kite_calendar_read": {
        "description": "Read a bounded personal calendar window or a deterministically redacted work free/busy window.",
        "parameters": _object_schema(
            {
                "account": {"type": "string", "enum": ["personal", "work_free_busy"]},
                "start": {
                    "type": "string", "minLength": 2, "maxLength": 40,
                    "description": _DATE_HELP,
                },
                "end": {
                    "type": "string", "minLength": 2, "maxLength": 40,
                    "description": _DATE_HELP,
                },
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50},
            },
            ("account", "start", "end", "max_results"),
        ),
    },
    "kite_things_read": {
        "description": "Read only the pinned Personal Action List project, an exact item, or bounded dedupe evidence.",
        "parameters": _object_schema(
            {
                "operation": {
                    "type": "string",
                    "enum": ["snapshot", "item", "search", "recent_completed"],
                },
                "item_id": {"type": "string", "minLength": 1, "maxLength": 256},
                "query": {"type": "string", "minLength": 1, "maxLength": 200},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 30},
            },
            ("operation",),
        ),
    },
    "kite_property_read": {
        "description": "Read bounded Property Intel records through fixed supported HTTP GET endpoints only.",
        "parameters": _object_schema(
            {
                "operation": {
                    "type": "string",
                    "enum": [
                        "list",
                        "property",
                        "research_notes",
                        "note",
                        "note_entry",
                        "transaction",
                    ],
                },
                "query": {"type": "string", "minLength": 1, "maxLength": 200},
                "property_id": {"type": "string", "minLength": 36, "maxLength": 36},
                "note_id": {"type": "string", "minLength": 36, "maxLength": 36},
                "entry_id": {"type": "string", "minLength": 36, "maxLength": 36},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 30},
            },
            ("operation",),
        ),
    },
    "kite_whatsapp_archive_read": {
        "description": "Query the existing read-only WhatsApp archive with narrow bounded selectors.",
        "parameters": _object_schema(
            {
                "operation": {
                    "type": "string",
                    "enum": ["search", "message", "deleted", "media_metadata"],
                },
                "chat": {"type": "string", "minLength": 1, "maxLength": 128},
                "name": {"type": "string", "minLength": 1, "maxLength": 128},
                "query": {"type": "string", "minLength": 1, "maxLength": 200},
                "message_id": {"type": "string", "minLength": 1, "maxLength": 256},
                "since": {
                    "type": "string", "minLength": 2, "maxLength": 40,
                    "description": _DATE_HELP,
                },
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50},
            },
            ("operation", "max_results"),
        ),
    },
    "kite_session_search": {
        "description": (
            "Search this assistant's own past conversations for what it already "
            "learned or was told. Returns short dated excerpts, never a whole "
            "transcript, and is for recalling facts and locations -- where a "
            "document was filed, what was decided -- not for quoting past "
            "conversation back to the requester."
        ),
        "parameters": _object_schema(
            {
                "query": {"type": "string", "minLength": 2, "maxLength": 120},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 10},
            },
            ("query",),
        ),
    },
    "kite_personal_files_locate": {
        "description": (
            "Find where a document is, anywhere the principal keeps documents, "
            "when it is not under a configured root. Returns names and "
            "locations only -- never contents, never a preview, and never a "
            "releasable reference. A file found this way cannot be read or "
            "sent by this tool or any other: say what was found and where, and "
            "the principal decides whether it may be released."
        ),
        "parameters": _object_schema(
            {
                "query": {"type": "string", "minLength": 2, "maxLength": 200},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 20},
            },
            ("query",),
        ),
    },
    "kite_personal_files_release_located": {
        "description": (
            "Propose a document that kite_personal_files_locate found outside "
            "a configured root. Names the exact directory and file from one "
            "locate match. This does not send anything: it prepares the "
            "document and asks the principal to approve its release, and "
            "only his approval delivers it to whoever asked."
        ),
        "parameters": _object_schema(
            {
                "directory": {"type": "string", "minLength": 1, "maxLength": 512},
                "file_name": {"type": "string", "minLength": 1, "maxLength": 255},
            },
            ("directory", "file_name"),
        ),
    },
    "kite_personal_files_read": {
        "description": (
            "Search or read relative regular files beneath a configured personal "
            "root with containment and type bounds. On a specific-document turn "
            "the read of the exact file found by a prior search IS how the host "
            "stages it for its approval gate -- a host side effect of this call, "
            "not a separate flow to find or invoke."
        ),
        "parameters": _object_schema(
            {
                "operation": {"type": "string", "enum": ["search", "read"]},
                "root": {"type": "string", "minLength": 1, "maxLength": 64},
                "relative_path": {"type": "string", "minLength": 1, "maxLength": 512},
                "query": {
                    "type": "string", "minLength": 1, "maxLength": 200,
                    "description": (
                        "Words to look for in a document's name or, for text "
                        "files, its contents. Word order and punctuation do not "
                        "matter. Files matching every word come first; a file "
                        "matching only some is still returned, marked "
                        "matched_on partial."
                    ),
                },
                "max_results": {"type": "integer", "minimum": 1, "maximum": 30},
                "max_lines": {"type": "integer", "minimum": 1, "maximum": 400},
            },
            ("operation", "root"),
        ),
    },
}


# Areas a personal-file root may live beneath. Naming the area is not enough --
# a root has to be a folder inside one, so that widening reach is always a
# deliberate, visible act rather than an oversight.
def _session_when(stamp: Any) -> str:
    """A date the model can reason about, from whatever the store holds."""
    text = str(stamp or "").strip()
    try:
        return datetime.fromtimestamp(float(text)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return text[:16]


_SESSION_EXCERPT_CHARS = 300

# A file search used to be one literal substring of the path. That is not how
# anyone names a document or asks for one: "holiday itinerary" matched nothing
# in a folder holding Ibiza-Trip-Itinerary.pdf, and five searches in a row came
# back empty on a question the documents could answer. Words are matched
# separately, separators are not punctuation the searcher should have to guess,
# and a file matching some of them is still shown -- ranked below the ones
# matching all of them, and labelled so the model can tell the difference.
_FILE_SEARCH_MAX_SCANNED = 20_000
_FILE_SEARCH_MAX_CONTENT_BYTES = 32 * 1024 * 1024
_SEARCH_SEPARATORS = re.compile(r"[^0-9a-z]+")


# "file search requires query and max_results" was the answer to a call that
# passed both. What it objected to was max_lines -- advertised on the same tool,
# for the other operation -- and it never said so. A refusal that does not name
# the argument it refused costs a round trip to guess at, and the guess is
# often wrong twice.
def _require_args(
    args: Mapping[str, Any], allowed: Iterable[str], required: Iterable[str], label: str
) -> None:
    extra = sorted(set(args) - set(allowed))
    missing = sorted(set(required) - set(args))
    if not extra and not missing:
        return
    complaint = []
    if missing:
        complaint.append("needs " + ", ".join(missing))
    if extra:
        complaint.append("does not take " + ", ".join(extra))
    raise SourceFailure("invalid_arguments", f"{label} " + " and ".join(complaint))


def _searchable(text: str) -> str:
    return " " + _SEARCH_SEPARATORS.sub(" ", text.casefold()).strip() + " "


def _matches(word: str, haystack: str) -> bool:
    """A word matches where a word starts, so passport finds passports.

    Anchoring to the start of a word and not to the end is the difference
    between a search that tolerates a plural and one that matches the middle
    of an unrelated word.
    """
    return f" {word}" in haystack


def _search_tokens(query: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(_searchable(query).split()))



def _session_denied_patterns():
    """Anything secret-shaped is dropped from recall outright.

    A transcript carries no capability of its own, so this does not rely on a
    later check catching it -- it never enters the turn.
    """
    from .document_release import _CREDENTIAL_PATTERNS

    return _CREDENTIAL_PATTERNS


_PERSONAL_ROOT_BASES = (
    "/users/james/documents",
    "/users/james/desktop",
    "/users/james/downloads",
)

# A locate walk is bounded by work done, not by what it finds: a query that
# matches nothing must still terminate over a documents tree of any size.
_LOCATE_MAX_SCANNED = 20_000
# Credential-shaped path components stay invisible to locate for the same
# reason they are unreadable: naming a file called id_rsa discloses that it
# exists and where, which is most of what an attacker wanted.
_LOCATE_DENIED_PART = re.compile(
    r"(?i)(?:^|[._-])(?:credential|credentials|secret|secrets|token|tokens|"
    r"password|passwords|private[-_]?key|keychain|wallet)(?:[._-]|$)"
)

_PREVIEW_MAX_CHARS = 600
_PREVIEW_MAX_PAGES = 2
# A read asks to understand the document, not merely to tell it apart, so it
# is bounded by what it costs rather than by what a preview needs. The result
# envelope caps it at output_bytes regardless, and what may be disclosed from
# it is capped separately at limits.output_chars -- reading more never
# discloses more. 40k characters is roughly a 20-page contract.
_READ_EXTRACT_CHARS = 40_000
_READ_MAX_PAGES = 20
# What an extractor is willing to load, which is not what it returns: a scan
# is megabytes of image data behind a few hundred characters of text.
_EXTRACT_MAX_INPUT_BYTES = 8 * 1024 * 1024
_TEXT_SUFFIXES = frozenset({
    ".txt",
    ".md",
    ".markdown",
    ".csv",
    ".json",
    ".yaml",
    ".yml",
})
_PREVIEW_TIMEOUT_SECONDS = 45
_PDFTOTEXT_CANDIDATES = ("/opt/homebrew/bin/pdftotext", "/usr/local/bin/pdftotext")
_SYSTEM_PYTHON = "/usr/bin/python3"
_MACOS_OCR_SCRIPT = str(Path(__file__).resolve().parent / "macos_ocr.py")


_CONVERTIBLE_IMAGE_MIME = {
    "image/heic": "heic",
    "image/heif": "heif",
    "image/tiff": "tiff",
}
_SIPS = "/usr/bin/sips"

# Identifying one document costs five to nine seconds, nearly all of it fixed:
# a fresh /usr/bin/python3 spends ~1.5s importing the Vision bindings before
# the recogniser has looked at a single pixel, and the first recognition
# request in a cold process pays several seconds more to warm the OS text
# models. The same page recognised again inside an already-warm process takes
# about 1.2s. That cost is paid per candidate, and paid again next turn for the
# same unchanged files -- which is what made weighing four documents take
# minutes.
#
# The extraction is a pure function of (bytes, mime, pages): `limit` only
# truncates the result at the very end, so it is deliberately not part of the
# key. Remembering the extracted text for the life of the process therefore
# makes a second look free without changing one character of what any caller
# sees.
#
# Keyed on a digest of the document's own bytes rather than on (st_dev, st_ino,
# st_size, st_mtime_ns): these callers hand the preview bytes, not a path, so a
# stat tuple would have to be threaded through every call site and would still
# be the weaker key -- a file rewritten inside one mtime_ns tick keeps its stat
# identity and would serve a stale preview of the wrong document. A digest
# cannot. Hashing costs ~12ms at the 8 MiB input cap against a 5-9s extraction.
_PREVIEW_CACHE_MAX_ENTRIES = 64
# Bounds what document text lives in memory. Each entry is capped at
# _READ_EXTRACT_CHARS (40k) and the total at 512k characters, so the cache
# holds at most half a megabyte of extracted text -- a dozen or so full reads,
# or every preview of a large candidate set. It is memory only: nothing here is
# ever written to disk, and it dies with the process.
_PREVIEW_CACHE_MAX_CHARS = 512_000
_PREVIEW_CACHE: "OrderedDict[tuple[str, str, int], str]" = OrderedDict()
_PREVIEW_CACHE_LOCK = threading.Lock()


def _reset_document_preview_cache() -> None:
    """Forget every remembered extraction. For tests, and for a fresh start."""
    with _PREVIEW_CACHE_LOCK:
        _PREVIEW_CACHE.clear()


def _cached_preview(key: tuple[str, str, int]) -> Optional[str]:
    with _PREVIEW_CACHE_LOCK:
        text = _PREVIEW_CACHE.get(key)
        if text is not None:
            _PREVIEW_CACHE.move_to_end(key)
        return text


def _remember_preview(key: tuple[str, str, int], text: str) -> None:
    """Keep the extraction, oldest first out, under both bounds."""
    with _PREVIEW_CACHE_LOCK:
        _PREVIEW_CACHE.pop(key, None)
        _PREVIEW_CACHE[key] = text
        while len(_PREVIEW_CACHE) > _PREVIEW_CACHE_MAX_ENTRIES:
            _PREVIEW_CACHE.popitem(last=False)
        total = sum(len(value) for value in _PREVIEW_CACHE.values())
        while total > _PREVIEW_CACHE_MAX_CHARS and len(_PREVIEW_CACHE) > 1:
            _key, dropped = _PREVIEW_CACHE.popitem(last=False)
            total -= len(dropped)


def _normalise_artifact(data: bytes, mime_type: str) -> tuple[bytes, str]:
    """Turn what a phone or scanner produces into something releasable.

    A photo taken on an iPhone is HEIC and a scan is often TIFF, and neither
    can be released: the inspector only understands PDF, JPEG and PNG. Rather
    than widen what may leave the machine, convert on the way in, locally, so
    the artifact that is inspected, staged and delivered is still a JPEG.
    """
    kind = _CONVERTIBLE_IMAGE_MIME.get(str(mime_type or "").lower())
    if kind is None or not Path(_SIPS).exists():
        return data, mime_type
    source = destination = ""
    try:
        with tempfile.NamedTemporaryFile(suffix="." + kind, delete=False) as handle:
            handle.write(data)
            source = handle.name
        os.chmod(source, 0o600)
        destination = source + ".jpg"
        completed = subprocess.run(
            [_SIPS, "-s", "format", "jpeg", source, "--out", destination],
            shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=_PREVIEW_TIMEOUT_SECONDS, env={"PATH": "/usr/bin:/bin"},
        )
        if completed.returncode != 0:
            return data, mime_type
        converted = Path(destination).read_bytes()
        if not converted.startswith(b"\xff\xd8\xff"):
            return data, mime_type
        return converted, "image/jpeg"
    except (OSError, ValueError, subprocess.SubprocessError):
        return data, mime_type
    finally:
        for path in (source, destination):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass


def _office_preview(data: bytes) -> str:
    """Recover readable text from a Word or Excel container, bounded."""
    import zipfile

    wanted = ("word/document.xml", "xl/sharedStrings.xml", "xl/workbook.xml")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = set(archive.namelist())
            recovered: list[str] = []
            for name in wanted:
                if name not in names:
                    continue
                info = archive.getinfo(name)
                if info.file_size > 4 * 1024 * 1024:
                    continue
                with archive.open(name) as handle:
                    chunk = handle.read(info.file_size)
                recovered.append(
                    re.sub(r"<[^>]+>", " ", chunk.decode("utf-8", errors="replace"))
                )
            return re.sub(r"\s+", " ", " ".join(recovered)).strip()[
                :_PREVIEW_MAX_CHARS
            ]
    except (OSError, ValueError, zipfile.BadZipFile):
        return ""


def _run_preview_reader(argv: list[str], limit: int = _PREVIEW_MAX_CHARS) -> str:
    """Run one local reader and return its bounded, collapsed text.

    The bound is the caller's. This used to impose the preview length on every
    reader, so a read asking for the whole document still got 600 characters:
    enough of a passport to show the number and stop short of the expiry date,
    which reads as a document that cannot be verified rather than one that was
    cut off.
    """
    try:
        completed = subprocess.run(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=_PREVIEW_TIMEOUT_SECONDS,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""
    if completed.returncode != 0:
        return ""
    return re.sub(r"\s+", " ", str(completed.stdout or "")).strip()[:limit]


def _document_preview(
    data: bytes,
    mime_type: str,
    *,
    limit: int = _PREVIEW_MAX_CHARS,
    pages: int = _PREVIEW_MAX_PAGES,
) -> str:
    """A bounded look at what this document actually says.

    The model has to decide whether a candidate is the document that was asked
    for, and a filename frequently cannot answer that: "Epson_07082026151807"
    and "photo" identify nothing, and the surrounding email is not evidence of
    what an image contains. Both readers here run on this machine -- pdftotext
    for a text layer, the OS text recogniser for a scan -- so the artifact is
    never sent anywhere to find out what it is.

    Returns "" when nothing can be read, which is itself informative: it means
    the candidate cannot be identified from its contents.

    Reading the same unchanged document twice returns the remembered
    extraction rather than paying the recogniser again. See _PREVIEW_CACHE.
    """
    if limit > _READ_EXTRACT_CHARS:
        # More than any caller asks for and more than the cache agrees to
        # hold. Extract it fresh rather than remember an unbounded amount of
        # someone's document.
        return _extract_document_text(data, mime_type, pages, limit)
    key = (hashlib.sha256(data).hexdigest(), str(mime_type or ""), int(pages))
    text = _cached_preview(key)
    if text is None:
        text = _extract_document_text(data, mime_type, pages, _READ_EXTRACT_CHARS)
        # Nothing read is not remembered. "" means both "this document has no
        # text in it" and "the recogniser timed out, failed to start, or died
        # under memory pressure" -- the readers cannot tell those apart and
        # return the same empty string for each. Caching it would turn one
        # transient failure into a document that stays unidentifiable for the
        # life of the gateway, reported to whoever asked as an inability to
        # tell what the file is. A genuinely blank page pays the recogniser
        # again next turn, which is much the cheaper of the two mistakes.
        if text:
            _remember_preview(key, text)
    return text[:limit]


def _extract_document_text(
    data: bytes, mime_type: str, pages: int, limit: int
) -> str:
    """Run the local readers once and return what they say, bounded.

    Split out of _document_preview so the expensive half can be memoised on
    the document's identity while the cheap half -- truncating to the caller's
    limit -- stays per call.
    """
    # A phone photo is HEIC and a scan is often TIFF. Release already converts
    # these locally; reading did not, so the formats a family actually
    # photographs documents in came back silent -- indistinguishable here from
    # a genuinely unreadable file.
    data, mime_type = _normalise_artifact(data, mime_type)
    try:
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(data)
            path = handle.name
        os.chmod(path, 0o600)
    except OSError:
        return ""
    try:
        if mime_type == "application/pdf":
            executable = next(
                (item for item in _PDFTOTEXT_CANDIDATES if Path(item).exists()), ""
            )
            extracted = ""
            if executable:
                extracted = _run_preview_reader(
                    [executable, "-l", str(pages), "-q", path, "-"], limit
                )
            if extracted:
                return extracted
            # No text layer: a scanned document. Fall through to reading the
            # rendered page, or it stays unidentifiable -- which is the case
            # the preview exists for.
            argv = [_SYSTEM_PYTHON, _MACOS_OCR_SCRIPT, path, str(pages)]
            if not (Path(_SYSTEM_PYTHON).exists() and Path(_MACOS_OCR_SCRIPT).exists()):
                return ""
        elif mime_type in {
            "text/plain", "text/csv", "text/markdown", "application/json",
        }:
            try:
                return re.sub(r"\s+", " ", data.decode("utf-8")).strip()[:limit]
            except UnicodeDecodeError:
                return ""
        elif mime_type in {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }:
            return _office_preview(data)[:limit]
        elif mime_type in {"image/jpeg", "image/png"}:
            if not Path(_SYSTEM_PYTHON).exists() or not Path(_MACOS_OCR_SCRIPT).exists():
                return ""
            argv = [_SYSTEM_PYTHON, _MACOS_OCR_SCRIPT, path, str(pages)]
        else:
            return ""
        return _run_preview_reader(argv, limit)
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _release_display_name(value: Any) -> str:
    """The candidate's own name, reduced the same way its title will be.

    Without this the model chose a document and was never told which one it
    had picked: the descriptor carried only a MIME type and a byte count. It
    could not check its own choice, could not say what it was about to send,
    and could not notice that "Epson_07082026151807" says nothing about
    whether this is a British passport.
    """
    stem = Path(str(value or "")).stem
    text = re.sub(r"[^A-Za-z0-9 ()_.-]+", " ", stem)
    return re.sub(r"\s+", " ", text).strip(" ._-")[:96] or "untitled"


def validate_tool_arguments(tool_name: str, args: Any) -> bool:
    """Fail-closed validation for brokered private-read arguments.

    Hermes validates model-facing schemas when a tool is listed directly, but
    the deferred ``tool_call`` broker accepts a generic nested object.  Recheck
    the selected Slice B schema here before granting the underlying tool's
    dispatch fingerprint.  This intentionally implements only the schema
    vocabulary used by ``TOOL_SCHEMAS``; source-specific semantic checks remain
    in the real handler immediately before backend access.
    """
    schema = TOOL_SCHEMAS.get(tool_name)
    if not isinstance(schema, dict) or not isinstance(args, dict):
        return False
    parameters = schema.get("parameters")
    if not isinstance(parameters, dict) or parameters.get("type") != "object":
        return False
    properties = parameters.get("properties")
    required = parameters.get("required")
    if not isinstance(properties, dict) or not isinstance(required, list):
        return False
    if parameters.get("additionalProperties") is not False:
        return False
    if set(args) - set(properties) or any(name not in args for name in required):
        return False

    for name, value in args.items():
        field = properties.get(name)
        if not isinstance(field, dict):
            return False
        expected = field.get("type")
        if expected == "string":
            if not isinstance(value, str):
                return False
            if len(value) < int(field.get("minLength", 0)):
                return False
            maximum = field.get("maxLength")
            if isinstance(maximum, int) and len(value) > maximum:
                return False
        elif expected == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                return False
            minimum = field.get("minimum")
            maximum = field.get("maximum")
            if isinstance(minimum, int) and value < minimum:
                return False
            if isinstance(maximum, int) and value > maximum:
                return False
        else:
            return False
        allowed = field.get("enum")
        if isinstance(allowed, list) and value not in allowed:
            return False
    return True


@dataclass(frozen=True)
class SourceFailure(Exception):
    code: str
    message: str
    retryable: bool = False


def _failure(
    source: str, code: str, message: str, *, retryable: bool = False
) -> dict[str, Any]:
    return {
        "status": "error",
        "source": source,
        "complete": False,
        "error": {"code": code, "message": message, "retryable": retryable},
    }


def _success(source: str, data: Any) -> dict[str, Any]:
    return {"status": "ok", "source": source, "complete": True, "data": data}


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class PrivateReadService:
    """Validated source dispatcher with injectable source backends."""

    def __init__(
        self,
        config: Any,
        *,
        backends: Optional[Mapping[str, Any]] = None,
        command_runner: Optional[Callable[..., Any]] = None,
        url_opener: Any = None,
        secret_values: Optional[Iterable[str]] = None,
    ):
        self.config = config if isinstance(config, dict) else {}
        self.enabled = self.config.get("enabled") is True
        self.timeout = int(self.config.get("timeout_seconds", 15))
        self.output_bytes = int(self.config.get("output_bytes", 131_072))
        if self.enabled and not 1 <= self.timeout <= 60:
            raise ValueError("private read timeout_seconds must be between 1 and 60")
        if self.enabled and not 4096 <= self.output_bytes <= 1_048_576:
            raise ValueError(
                "private read output_bytes must be between 4096 and 1048576"
            )
        self.backends = dict(backends or {})
        self.command_runner = command_runner or subprocess.run
        self.url_opener = url_opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirects()
        )
        self.secret_values = tuple(
            sorted(
                {str(value) for value in (secret_values or ()) if str(value)},
                key=len,
                reverse=True,
            )
        )
        self._validate_config()
        prop = self.config.get("property_intel")
        self.public_property_origins = (
            (self._fixed_http_origin({"base_url": prop["public_base_url"]}),)
            if isinstance(prop, dict) and prop.get("public_base_url")
            else ()
        )

    def _validate_config(self) -> None:
        if not self.enabled:
            return
        allowed = {
            "enabled",
            "timeout_seconds",
            "output_bytes",
            "gmail",
            "calendar",
            "things",
            "property_intel",
            "whatsapp",
            "files",
            "sessions",
        }
        if set(self.config) - allowed:
            raise ValueError("private_reads contains unsupported configuration fields")
        sessions = self.config.get("sessions")
        if sessions is not None:
            if (
                not isinstance(sessions, dict)
                or set(sessions) != {"database"}
                or not Path(str(sessions.get("database") or "")).is_absolute()
            ):
                raise ValueError("session recall requires only an absolute database path")
        gmail = self.config.get("gmail")
        if gmail is not None:
            if (
                not isinstance(gmail, dict)
                or set(gmail) != {"executable", "account_aliases"}
                or not Path(str(gmail.get("executable") or "")).is_absolute()
                or gmail.get("account_aliases")
                != {"personal": "personal", "kite": "kite"}
            ):
                raise ValueError(
                    "Gmail reads require only the exact personal and Kite account aliases"
                )
        calendar = self.config.get("calendar")
        if calendar is not None:
            if (
                not isinstance(calendar, dict)
                or set(calendar) != {"executable", "account_aliases", "calendar_ids"}
                or not Path(str(calendar.get("executable") or "")).is_absolute()
                or calendar.get("account_aliases")
                != {"personal": "personal", "work_free_busy": "work"}
                or not isinstance(calendar.get("calendar_ids"), dict)
                or set(calendar["calendar_ids"]) != {"personal", "work_free_busy"}
            ):
                raise ValueError(
                    "calendar reads require exact personal and work-free-busy aliases"
                )
            if any(
                re.fullmatch(r"[A-Za-z0-9._@-]{1,128}", str(value or "")) is None
                for mapping in (calendar["account_aliases"], calendar["calendar_ids"])
                for value in mapping.values()
            ):
                raise ValueError(
                    "calendar aliases and IDs must be bounded fixed values"
                )
        things = self.config.get("things")
        if things is not None:
            if not isinstance(things, dict):
                raise ValueError("things private-read config must be a mapping")
            expected = {
                "client": THINGS_CLIENT,
                "endpoint": THINGS_ENDPOINT,
                "project_uuid": THINGS_PROJECT_UUID,
                "project_title": THINGS_PROJECT_TITLE,
            }
            if set(things) != set(expected) or any(
                str(things.get(key) or "") != value for key, value in expected.items()
            ):
                raise ValueError(
                    "Things reads must use the exact supported personal boundary"
                )
        whatsapp = self.config.get("whatsapp")
        if whatsapp is not None:
            if (
                not isinstance(whatsapp, dict)
                or set(whatsapp) != {"executable", "script", "state_dir"}
                or str(whatsapp.get("script") or "") != WHATSAPP_QUERY
            ):
                raise ValueError(
                    "WhatsApp reads must use the supported read-only archive CLI"
                )
            state_dir = Path(str(whatsapp.get("state_dir") or ""))
            executable = Path(str(whatsapp.get("executable") or ""))
            if not state_dir.is_absolute() or not executable.is_absolute():
                raise ValueError(
                    "WhatsApp executable and archive state must be absolute"
                )
        prop = self.config.get("property_intel")
        if prop is not None:
            if (
                not isinstance(prop, dict)
                or not {"base_url"}.issubset(prop)
                or set(prop) - {"base_url", "public_base_url", "auth_env"}
            ):
                raise ValueError(
                    "Property Intel reads require base_url and optional public_base_url/auth_env"
                )
            self._fixed_http_origin(prop)
            if prop.get("public_base_url"):
                self._fixed_http_origin({"base_url": prop["public_base_url"]})
        files = self.config.get("files")
        if files is not None:
            self._roots(files)

    @property
    def tool_names(self) -> tuple[str, ...]:
        return TOOL_NAMES if self.enabled else ()

    def execute(self, tool_name: str, args: Any) -> str:
        source = tool_name.removeprefix("kite_").split("_", 1)[0]
        try:
            if not self.enabled or tool_name not in TOOL_NAMES:
                raise SourceFailure(
                    "unavailable", "private read source is not configured"
                )
            if not isinstance(args, dict):
                raise SourceFailure("invalid_arguments", "arguments must be an object")
            handler = {
                "kite_gmail_search": self._gmail_search,
                "kite_gmail_get": self._gmail_get,
                "kite_gmail_attachment_extract": self._gmail_attachment,
                "kite_calendar_read": self._calendar,
                "kite_things_read": self._things,
                "kite_property_read": self._property,
                "kite_whatsapp_archive_read": self._whatsapp,
                "kite_personal_files_read": self._files,
                "kite_personal_files_locate": self._locate,
                "kite_personal_files_release_located": self._release_located,
                "kite_session_search": self._sessions,
            }[tool_name]
            result = _success(source, handler(dict(args)))
            encoded = canonical_json(result)
            if len(encoded.encode("utf-8")) > self.output_bytes:
                result = _failure(
                    source,
                    "cap_exceeded",
                    "source result exceeded the configured output cap",
                )
            return canonical_json(result)
        except SourceFailure as exc:
            return canonical_json(
                _failure(source, exc.code, exc.message, retryable=exc.retryable)
            )
        except subprocess.TimeoutExpired:
            return canonical_json(
                _failure(source, "timeout", "source timed out", retryable=True)
            )
        except TimeoutError:
            return canonical_json(
                _failure(source, "timeout", "source timed out", retryable=True)
            )
        except Exception:
            return canonical_json(
                _failure(
                    source,
                    "backend_unavailable",
                    "source backend is unavailable",
                    retryable=True,
                )
            )

    def _injected(self, source: str, operation: str, args: dict[str, Any]) -> Any:
        backend = self.backends.get(source)
        if backend is None:
            raise SourceFailure(
                "backend_unavailable", "source backend is not configured", True
            )
        execute = getattr(backend, "execute", backend)
        if not callable(execute):
            raise SourceFailure("backend_unavailable", "source backend is invalid")
        value = execute(operation, dict(args))
        if isinstance(value, dict) and value.get("status") == "error":
            error = value.get("error") if isinstance(value.get("error"), dict) else {}
            raise SourceFailure(
                str(error.get("code") or "source_failure"),
                str(error.get("message") or "source failed"),
                bool(error.get("retryable")),
            )
        if isinstance(value, dict) and value.get("complete") is False:
            raise SourceFailure("incomplete", "source returned incomplete results")
        if isinstance(value, dict) and value.get("status") == "ok" and "data" in value:
            return value["data"]
        return value

    @staticmethod
    def _require_exact(
        args: dict[str, Any],
        allowed: set[str],
        required: set[str],
        label: str = "this read",
    ) -> None:
        _require_args(args, allowed, required, label)

    @staticmethod
    def _bounded_text(
        value: Any, name: str, maximum: int, *, required: bool = True
    ) -> str:
        text = str(value or "")
        if (required and not text) or len(text) > maximum or "\x00" in text:
            raise SourceFailure(
                "invalid_arguments", f"{name} is missing or out of bounds"
            )
        return text

    @staticmethod
    def _bounded_int(value: Any, name: str, maximum: int) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= maximum
        ):
            raise SourceFailure("invalid_arguments", f"{name} is out of bounds")
        return value

    @staticmethod
    def _account(args: dict[str, Any]) -> tuple[str, str]:
        alias = args.get("account")
        identities = {"personal": PERSONAL_GMAIL, "kite": KITE_GMAIL}
        if alias not in identities:
            raise SourceFailure(
                "account_denied", "only personal and Kite Gmail accounts are available"
            )
        return str(alias), identities[str(alias)]

    def _gmail_search(self, args: dict[str, Any]) -> Any:
        self._require_exact(
            args,
            {"account", "query", "max_results", "after", "before"},
            {"account", "query", "max_results"},
        )
        alias, identity = self._account(args)
        query = self._bounded_text(args["query"], "query", 512)
        maximum = self._bounded_int(args["max_results"], "max_results", 25)
        for key, operator in (("after", "after"), ("before", "before")):
            if key in args:
                value = _normalise_date(
                    self._bounded_text(args[key], key, 32), key
                )
                query += f" {operator}:{value.replace('-', '/')}"
        canonical = {
            "account": alias,
            "account_identity": identity,
            "query": query,
            "max_results": maximum,
        }
        result = self._source_or_google_command("gmail", "search", canonical)
        if not isinstance(result, list):
            raise SourceFailure(
                "malformed_result", "Gmail search did not return a result list"
            )
        # max_results says how many are wanted, not how many there had better
        # be: a source that overshoots is bounded here, not turned into a
        # failed read.
        return result[:maximum]

    def _gmail_get(self, args: dict[str, Any]) -> Any:
        self._require_exact(args, {"account", "message_id"}, {"account", "message_id"})
        alias, identity = self._account(args)
        message_id = self._bounded_text(args["message_id"], "message_id", 256)
        if _ID_RE.fullmatch(message_id) is None:
            raise SourceFailure("invalid_arguments", "message_id is malformed")
        result = self._source_or_google_command(
            "gmail",
            "get",
            {"account": alias, "account_identity": identity, "message_id": message_id},
        )
        if not isinstance(result, dict):
            raise SourceFailure(
                "malformed_result", "Gmail item read returned malformed data"
            )
        observed = result.get("id") or result.get("message_id")
        if observed is not None and observed != message_id:
            raise SourceFailure(
                "malformed_result", "Gmail item ID did not match the exact request"
            )
        return result

    def _gmail_attachment(self, args: dict[str, Any]) -> Any:
        result = self._gmail_attachment_payload(args)
        return {
            key: result[key]
            for key in ("filename", "mime_type", "size_bytes", "text")
            if key in result
        }

    def _gmail_attachment_payload(
        self, args: dict[str, Any], *, release: bool = False
    ) -> dict[str, Any]:
        self._require_exact(
            args,
            {"account", "message_id", "attachment_id"},
            {"account", "message_id", "attachment_id"},
        )
        alias, identity = self._account(args)
        message_id = self._bounded_text(args["message_id"], "message_id", 256)
        attachment_id = self._bounded_text(
            args["attachment_id"], "attachment_id", _ATTACHMENT_ID_MAX_CHARS
        )
        if (
            _ID_RE.fullmatch(message_id) is None
            or _ATTACHMENT_ID_RE.fullmatch(attachment_id) is None
        ):
            raise SourceFailure(
                "invalid_arguments", "message or attachment ID is malformed"
            )
        result = self._source_or_google_command(
            "gmail",
            "attachment_extract",
            {
                "account": alias,
                "account_identity": identity,
                "message_id": message_id,
                "attachment_id": attachment_id,
            },
        )
        if not isinstance(result, dict):
            raise SourceFailure(
                "malformed_result", "attachment extractor returned malformed data"
            )
        mime = str(result.get("mime_type") or "").split(";", 1)[0].lower()
        size = result.get("size_bytes")
        if mime not in _EXTRACTABLE_MIME:
            raise SourceFailure(
                "unsupported_content",
                "attachment type is not safe for private extraction",
            )
        maximum = _EXTRACT_MAX_INPUT_BYTES if release else self.output_bytes
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= maximum
        ):
            raise SourceFailure("cap_exceeded", "attachment exceeds the extraction cap")
        if not isinstance(result.get("text"), str):
            raise SourceFailure(
                "malformed_result", "attachment extraction did not return text"
            )
        return result

    def resolve_document_candidate(
        self, tool_name: str, args: dict[str, Any]
    ) -> tuple[str, Optional[dict[str, Any]]]:
        """Resolve exactly one binary candidate through an approved typed reader.

        The returned source descriptor is internal to Kite and is never JSON
        encoded.  The model receives only the closed, content-free candidate
        descriptor in the first tuple item.
        """
        source = tool_name.removeprefix("kite_").split("_", 1)[0]
        try:
            if not self.enabled or tool_name not in {
                "kite_personal_files_read",
                "kite_personal_files_release_located",
                "kite_gmail_attachment_extract",
            }:
                raise SourceFailure(
                    "operation_denied", "source cannot produce a release candidate"
                )
            if tool_name == "kite_personal_files_release_located":
                # A document found outside every configured root. Reading it
                # here is fine -- what must not happen without the principal
                # saying so is the release to whoever asked -- so it is staged
                # and inspected exactly like any other candidate, and the
                # descriptor is marked so the host asks him rather than
                # delivering it the way an in-root document is delivered.
                path = self._located_path(dict(args))
                source_info = path.lstat()
                guessed = (mimetypes.guess_type(path.name)[0] or "").lower()
                descriptor = {
                    "outcome": "release_candidate",
                    "source_class": "personal files",
                    "document_name": _release_display_name(path.name),
                    "document_preview": _document_preview(path.read_bytes(), guessed),
                    "mime_type": guessed,
                    "size_bytes": source_info.st_size,
                    "requires_owner_approval": True,
                    "found_in": str(path.parent),
                }
                internal = {
                    "path": path,
                    "display_name": path.name,
                    "source_class": "personal files",
                    "expected_mime": guessed,
                    "expected_size": source_info.st_size,
                    "expected_identity": (
                        source_info.st_dev,
                        source_info.st_ino,
                        source_info.st_size,
                        source_info.st_mtime_ns,
                    ),
                    "requires_owner_approval": True,
                }
                return canonical_json(_success(source, descriptor)), internal
            if tool_name == "kite_personal_files_read":
                self._require_exact(
                    args,
                    {"operation", "root", "relative_path", "max_lines"},
                    {"operation", "root", "relative_path"},
                )
                if args.get("operation") != "read":
                    raise SourceFailure(
                        "invalid_arguments", "one exact file read is required"
                    )
                roots = self._roots(self.config.get("files"))
                root_name = str(args.get("root") or "")
                if root_name not in roots:
                    raise SourceFailure("path_denied", "personal file root is unavailable")
                relative = self._bounded_text(
                    args.get("relative_path"), "relative_path", 512
                )
                path = self._safe_file(roots[root_name], relative)
                source_info = path.lstat()
                if source_info.st_size > _EXTRACT_MAX_INPUT_BYTES:
                    raise SourceFailure(
                        "cap_exceeded", "file exceeds the configured byte cap"
                    )
                guessed = (mimetypes.guess_type(path.name)[0] or "").lower()
                descriptor = {
                    "outcome": "release_candidate",
                    "source_class": "personal files",
                    "document_name": _release_display_name(path.name),
                    "document_preview": _document_preview(
                        path.read_bytes(), guessed
                    ),
                    "mime_type": guessed,
                    "size_bytes": source_info.st_size,
                }
                internal = {
                    "path": path,
                    "display_name": path.name,
                    "source_class": "personal files",
                    "expected_mime": guessed,
                    "expected_size": source_info.st_size,
                    "expected_identity": (
                        source_info.st_dev,
                        source_info.st_ino,
                        source_info.st_size,
                        source_info.st_mtime_ns,
                    ),
                }
            else:
                payload = self._gmail_attachment_payload(args, release=True)
                binary_fields = [
                    name
                    for name in ("artifact_bytes", "artifact_base64", "artifact_path")
                    if name in payload
                ]
                if len(binary_fields) != 1:
                    raise SourceFailure(
                        "binary_unavailable",
                        "attachment extractor did not return one exact binary artifact",
                    )
                field = binary_fields[0]
                if field == "artifact_bytes":
                    binary = payload[field]
                    if not isinstance(binary, bytes):
                        raise SourceFailure(
                            "malformed_result", "attachment binary is malformed"
                        )
                    source_value: Any = binary
                elif field == "artifact_base64":
                    encoded = payload[field]
                    if not isinstance(encoded, str):
                        raise SourceFailure(
                            "malformed_result", "attachment binary is malformed"
                        )
                    try:
                        source_value = base64.b64decode(encoded, validate=True)
                    except (ValueError, TypeError) as exc:
                        raise SourceFailure(
                            "malformed_result", "attachment binary is malformed"
                        ) from exc
                else:
                    value = payload[field]
                    if not isinstance(value, str) or not Path(value).is_absolute():
                        raise SourceFailure(
                            "malformed_result", "attachment artifact is unavailable"
                        )
                    source_value = Path(value)
                filename = self._bounded_text(
                    payload.get("filename"), "filename", 255
                )
                if isinstance(source_value, bytes):
                    source_value, payload = (
                        lambda pair: (pair[0], {**payload, "mime_type": pair[1],
                                                "size_bytes": len(pair[0])})
                    )(_normalise_artifact(source_value, str(payload.get("mime_type") or "")))
                descriptor = {
                    "outcome": "release_candidate",
                    "source_class": "personal Gmail attachment",
                    "document_name": _release_display_name(filename),
                    "document_preview": _document_preview(
                        source_value if isinstance(source_value, bytes)
                        else source_value.read_bytes(),
                        str(payload.get("mime_type") or "").lower(),
                    ),
                    "mime_type": str(payload.get("mime_type") or "").lower(),
                    "size_bytes": int(payload.get("size_bytes") or 0),
                }
                internal = {
                    "bytes" if isinstance(source_value, bytes) else "path": source_value,
                    "display_name": filename,
                    "source_class": "personal Gmail attachment",
                    "expected_mime": str(payload.get("mime_type") or "").lower(),
                    "expected_size": int(payload.get("size_bytes") or 0),
                    "inspection_text": payload["text"],
                }
                if isinstance(source_value, Path):
                    source_info = source_value.lstat()
                    internal["expected_identity"] = (
                        source_info.st_dev,
                        source_info.st_ino,
                        source_info.st_size,
                        source_info.st_mtime_ns,
                    )
            return canonical_json(_success(source, descriptor)), internal
        except SourceFailure as exc:
            return canonical_json(
                _failure(source, exc.code, exc.message, retryable=exc.retryable)
            ), None
        except Exception:
            return canonical_json(
                _failure(
                    source,
                    "backend_unavailable",
                    "source backend is unavailable",
                    retryable=True,
                )
            ), None

    def _source_or_google_command(
        self, source: str, operation: str, canonical: dict[str, Any]
    ) -> Any:
        if source in self.backends:
            return self._injected(source, operation, canonical)
        cfg = self.config.get("gmail" if source == "gmail" else "calendar")
        if not isinstance(cfg, dict):
            raise SourceFailure(
                "backend_unavailable", f"{source} backend is not configured", True
            )
        executable = Path(str(cfg.get("executable") or ""))
        aliases = cfg.get("account_aliases")
        alias = str(canonical["account"])
        if not executable.is_absolute() or not isinstance(aliases, dict):
            raise SourceFailure(
                "backend_unavailable", f"{source} command boundary is invalid"
            )
        fixed_alias = str(aliases.get(alias) or "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", fixed_alias):
            raise SourceFailure(
                "account_denied", "configured source account is unavailable"
            )
        if source == "gmail" and operation == "search":
            argv = [
                str(executable),
                fixed_alias,
                "api",
                "gmail",
                "search",
                canonical["query"],
                "--max",
                str(canonical["max_results"]),
            ]
        elif source == "gmail" and operation == "get":
            argv = [
                str(executable),
                fixed_alias,
                "api",
                "gmail",
                "get",
                canonical["message_id"],
            ]
        elif source == "gmail" and operation == "attachment_extract":
            # Previously injected-backend only, which meant no production path
            # at all: every extraction raised backend_unavailable and Slice C
            # could never release a Gmail attachment.
            argv = [
                str(executable),
                fixed_alias,
                "api",
                "gmail",
                "attachment",
                canonical["message_id"],
                canonical["attachment_id"],
            ]
        elif source == "calendar" and operation == "list":
            argv = [
                str(executable),
                fixed_alias,
                "api",
                "calendar",
                "list",
                "--start",
                canonical["start"],
                "--end",
                canonical["end"],
                "--max",
                str(canonical["max_results"]),
                "--calendar",
                str(cfg.get("calendar_ids", {}).get(alias) or "primary"),
            ]
        else:
            raise SourceFailure("operation_denied", "source operation is unavailable")
        if source == "gmail" and operation == "attachment_extract":
            # This command's output legitimately carries a base64 artifact, so
            # the ordinary text-answer cap rejected every real document: a
            # 254KB letter is ~339KB once encoded. The artifact's own size
            # limit is enforced separately, on the decoded bytes, and still
            # decides what may be extracted or released.
            return self._run_json(
                argv,
                max_output_bytes=_ATTACHMENT_COMMAND_OUTPUT_BYTES,
                max_seconds=_ATTACHMENT_COMMAND_TIMEOUT_SECONDS,
            )
        return self._run_json(argv)

    def _run_json(
        self,
        argv: list[str],
        *,
        env: Optional[dict[str, str]] = None,
        max_output_bytes: Optional[int] = None,
        max_seconds: Optional[int] = None,
    ) -> Any:
        completed = self.command_runner(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max_seconds or self.timeout,
            env=env,
        )
        if completed.returncode != 0:
            stdout = str(completed.stdout or "")
            stderr = str(completed.stderr or "")
            try:
                parsed = json.loads(stdout)
            except (TypeError, ValueError):
                parsed = None
            error = str(parsed.get("error") or "") if isinstance(parsed, dict) else ""
            lowered = (error + " " + stderr[:512]).casefold()
            if "ambiguous" in lowered:
                raise SourceFailure("ambiguous", "source selector is ambiguous")
            if "not found" in lowered:
                raise SourceFailure("not_found", "source item was not found")
            if any(
                word in lowered
                for word in (
                    "unauthorized",
                    "not authenticated",
                    "invalid_grant",
                    "missing auth",
                )
            ):
                raise SourceFailure(
                    "missing_auth", "source authentication is unavailable"
                )
            if any(
                word in lowered for word in ("stale", "freshness", "archive health")
            ):
                raise SourceFailure(
                    "stale_archive", "source archive is stale or unhealthy", True
                )
            raise SourceFailure("source_failure", "source command failed", True)
        output = str(completed.stdout or "")
        if len(output.encode("utf-8")) > (max_output_bytes or self.output_bytes):
            raise SourceFailure(
                "cap_exceeded", "source command output exceeded its cap"
            )
        if not output.strip() or output.strip() == "No messages found.":
            return []
        try:
            return json.loads(output)
        except (TypeError, ValueError) as exc:
            raise SourceFailure(
                "malformed_result", "source command returned malformed JSON"
            ) from exc

    def _calendar(self, args: dict[str, Any]) -> Any:
        self._require_exact(
            args,
            {"account", "start", "end", "max_results"},
            {"account", "start", "end", "max_results"},
        )
        account = args.get("account")
        if account not in {"personal", "work_free_busy"}:
            raise SourceFailure("account_denied", "calendar account is unavailable")
        start = _normalise_date(
            self._bounded_text(args["start"], "start", 40), "start", allow_time=True
        )
        end = _normalise_date(
            self._bounded_text(args["end"], "end", 40), "end", allow_time=True
        )
        if start >= end:
            raise SourceFailure(
                "invalid_arguments", "the calendar window ends before it starts"
            )
        maximum = self._bounded_int(args["max_results"], "max_results", 50)
        canonical = {
            "account": account,
            "start": start,
            "end": end,
            "max_results": maximum,
        }
        result = (
            self._injected("calendar", "list", canonical)
            if "calendar" in self.backends
            else self._source_or_google_command("calendar", "list", canonical)
        )
        if not isinstance(result, list):
            raise SourceFailure(
                "malformed_result", "calendar source did not return an event list"
            )
        result = result[:maximum]
        if account == "work_free_busy":
            return self.redact_work_calendar(result)
        return result

    @staticmethod
    def redact_work_calendar(events: list[Any]) -> list[dict[str, Any]]:
        """Project adversarial work events onto the only permitted fields."""
        redacted = []
        for event in events:
            if not isinstance(event, dict):
                raise SourceFailure(
                    "malformed_result", "work calendar event is malformed"
                )
            start = event.get("start")
            end = event.get("end")
            if isinstance(start, dict):
                start = start.get("dateTime") or start.get("date")
            if isinstance(end, dict):
                end = end.get("dateTime") or end.get("date")
            if (
                not isinstance(start, str)
                or not isinstance(end, str)
                or _DATE_RE.fullmatch(start) is None
                or _DATE_RE.fullmatch(end) is None
                or start >= end
            ):
                raise SourceFailure(
                    "malformed_result", "work free/busy interval is malformed"
                )
            timezone = str(event.get("timezone") or event.get("timeZone") or "")
            try:
                if timezone:
                    ZoneInfo(timezone)
            except (ValueError, ZoneInfoNotFoundError):
                timezone = ""
            if not timezone:
                offset = re.search(r"(?:Z|[+-]\d{2}:\d{2})$", start)
                timezone = offset.group(0) if offset else "floating"
            status = (
                "free"
                if str(event.get("status") or "").lower() in {"free", "transparent"}
                else "busy"
            )
            redacted.append({
                "status": status,
                "start": start,
                "end": end,
                "timezone": timezone,
                "constraints": ["all_day"] if len(start) == 10 else [],
            })
        if any(_WORK_FIELDS.intersection(item) for item in redacted):
            raise SourceFailure("redaction_failure", "work calendar redaction failed")
        return redacted

    def _things(self, args: dict[str, Any]) -> Any:
        self._require_exact(
            args, {"operation", "item_id", "query", "max_results"}, {"operation"}
        )
        operation = args.get("operation")
        if operation not in {"snapshot", "item", "search", "recent_completed"}:
            raise SourceFailure("operation_denied", "Things operation is unavailable")
        canonical: dict[str, Any] = {
            "project_uuid": THINGS_PROJECT_UUID,
            "project_title": THINGS_PROJECT_TITLE,
            "operation": operation,
        }
        if operation == "item":
            _require_args(
                args, {"operation", "item_id"}, {"operation", "item_id"},
                "an exact Things item",
            )
            canonical["item_id"] = self._bounded_text(
                args.get("item_id"), "item_id", 256
            )
        elif operation in {"search", "recent_completed"}:
            required = {"operation", "query", "max_results"}
            _require_args(args, required, required, "a Things lookup")
            canonical["query"] = self._bounded_text(args.get("query"), "query", 200)
            canonical["max_results"] = self._bounded_int(
                args.get("max_results"), "max_results", 30
            )
        else:
            _require_args(args, {"operation"}, {"operation"}, "a Things snapshot")
        if "things" in self.backends:
            return self._injected("things", str(operation), canonical)
        cfg = self.config.get("things")
        if not isinstance(cfg, dict):
            raise SourceFailure(
                "backend_unavailable", "Things backend is not configured", True
            )
        client = str(cfg["client"])
        endpoint = str(cfg["endpoint"])
        if operation == "snapshot":
            argv = [
                client,
                "--url",
                endpoint,
                "--timeout",
                str(self.timeout),
                "call",
                "get_todos",
                canonical_json({"project_uuid": THINGS_PROJECT_UUID}),
            ]
        elif operation == "item":
            argv = [
                client,
                "--url",
                endpoint,
                "--timeout",
                str(self.timeout),
                "call",
                "show_item",
                canonical_json({"id": canonical["item_id"]}),
            ]
        else:
            argv = [
                client,
                "--url",
                endpoint,
                "--timeout",
                str(self.timeout),
                "search",
                "--query",
                canonical["query"],
                "--project",
                THINGS_PROJECT_TITLE,
                "--json",
            ]
        result = self._run_text(argv)
        return {
            "project_uuid": THINGS_PROJECT_UUID,
            "project_title": THINGS_PROJECT_TITLE,
            "content": result,
        }

    def _run_text(
        self, argv: list[str], *, env: Optional[dict[str, str]] = None
    ) -> str:
        completed = self.command_runner(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=self.timeout,
            env=env,
        )
        if completed.returncode != 0:
            raise SourceFailure("source_failure", "source command failed", True)
        output = str(completed.stdout or "")
        if len(output.encode("utf-8")) > self.output_bytes:
            raise SourceFailure(
                "cap_exceeded", "source command output exceeded its cap"
            )
        return output

    @staticmethod
    def _fixed_http_origin(config: Any) -> str:
        if not isinstance(config, dict):
            raise ValueError("Property Intel private-read config must be a mapping")
        base_url = str(config.get("base_url") or "").rstrip("/")
        parsed = urllib.parse.urlparse(base_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("Property Intel base_url must be a fixed origin")
        return base_url

    @staticmethod
    def _property_key_name(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.casefold())

    @classmethod
    def _property_secret_key(cls, key: str, *, operational: bool) -> bool:
        normalized = cls._property_key_name(key)
        if normalized in _PROPERTY_SECRET_KEYS:
            return True
        if any(
            marker in normalized
            for marker in (
                "authorizationheader",
                "privatekey",
                "secretconfig",
                "sessioncookie",
            )
        ):
            return True
        if normalized.endswith("password") or normalized.endswith("passphrase"):
            return True
        if normalized.endswith("secret") and normalized.startswith(
            (
                "api",
                "auth",
                "client",
                "connector",
                "database",
                "encryption",
                "oauth",
                "session",
                "signing",
                "webhook",
            )
        ):
            return True
        if normalized.endswith("token") and normalized.startswith(
            ("access", "api", "auth", "bearer", "id", "refresh", "session")
        ):
            return True
        if "connector" in normalized and any(
            marker in normalized
            for marker in ("auth", "config", "env", "header", "secret")
        ):
            return True
        if normalized in _PROPERTY_HEADER_KEYS and (
            operational
            or normalized.startswith(
                ("auth", "connector", "http", "request", "response")
            )
        ):
            return True
        if operational and normalized in {
            "authenv",
            "clientid",
            "connectionid",
            "env",
            "environment",
            "oauthclientid",
            "sessionid",
        }:
            return True
        return False

    @staticmethod
    def _sanitize_property_text(value: str, secret_values: tuple[str, ...]) -> str:
        sanitized = value
        for pattern in _PROPERTY_SECRET_VALUE_PATTERNS:
            sanitized = pattern.sub(_PROPERTY_REDACTION, sanitized)
        for secret in secret_values:
            sanitized = sanitized.replace(secret, _PROPERTY_REDACTION)
        return sanitized

    def _sanitize_property_payload(self, value: Any) -> Any:
        """Remove only operational secrets while preserving the portal schema.

        Property Intel evolves independently of Hermes, so this traversal has
        no field allowlist.  It validates one complete JSON-shaped value and
        fails instead of truncating ordinary portal data when a structural or
        processing bound is exceeded.
        """
        total_items = 0
        processed_bytes = 0
        active_containers: set[int] = set()
        prop = self.config.get("property_intel")
        auth_env = str(prop.get("auth_env") or "") if isinstance(prop, dict) else ""
        dynamic_secrets = list(self.secret_values)
        if auth_env:
            dynamic_secrets.append(auth_env)
            auth_value = os.environ.get(auth_env, "")
            if auth_value:
                dynamic_secrets.append(auth_value)
        secret_values = tuple(sorted(set(dynamic_secrets), key=len, reverse=True))
        auth_env_key = self._property_key_name(auth_env) if auth_env else ""

        def visit(current: Any, depth: int, *, operational: bool = False) -> Any:
            nonlocal processed_bytes, total_items
            if depth > _PROPERTY_MAX_DEPTH:
                raise SourceFailure(
                    "depth_exceeded",
                    "Property Intel result exceeded the maximum nesting depth",
                )
            if current is None or isinstance(current, (bool, int)):
                return current
            if isinstance(current, float):
                if not math.isfinite(current):
                    raise SourceFailure(
                        "malformed_result",
                        "Property Intel result contains a non-finite number",
                    )
                return current
            if isinstance(current, str):
                if len(current) > self.output_bytes:
                    raise SourceFailure(
                        "cap_exceeded",
                        "Property Intel result exceeded its processing byte cap",
                    )
                processed_bytes += len(current.encode("utf-8"))
                if processed_bytes > self.output_bytes:
                    raise SourceFailure(
                        "cap_exceeded",
                        "Property Intel result exceeded its processing byte cap",
                    )
                return self._sanitize_property_text(current, secret_values)
            if not isinstance(current, (dict, list)):
                raise SourceFailure(
                    "malformed_result",
                    "Property Intel result is not valid JSON data",
                )

            identity = id(current)
            if identity in active_containers:
                raise SourceFailure(
                    "malformed_result",
                    "Property Intel result contains a recursive container",
                )
            item_count = len(current)
            if item_count > _PROPERTY_MAX_CONTAINER_ITEMS:
                raise SourceFailure(
                    "cap_exceeded",
                    "Property Intel container exceeded its item cap",
                )
            total_items += item_count
            if total_items > _PROPERTY_MAX_TOTAL_ITEMS:
                raise SourceFailure(
                    "cap_exceeded",
                    "Property Intel result exceeded its processing item cap",
                )

            active_containers.add(identity)
            try:
                if isinstance(current, list):
                    return [
                        visit(item, depth + 1, operational=operational)
                        for item in current
                    ]

                sanitized: dict[str, Any] = {}
                for key, item in current.items():
                    if not isinstance(key, str):
                        raise SourceFailure(
                            "malformed_result",
                            "Property Intel object keys must be strings",
                        )
                    processed_bytes += len(key.encode("utf-8"))
                    if processed_bytes > self.output_bytes:
                        raise SourceFailure(
                            "cap_exceeded",
                            "Property Intel result exceeded its processing byte cap",
                        )
                    if (
                        (auth_env_key and self._property_key_name(key) == auth_env_key)
                        or self._property_secret_key(key, operational=operational)
                    ):
                        # Removed values still count toward every input bound;
                        # a huge/deep secret subtree must not evade processing
                        # limits merely because it will not be disclosed.
                        visit(item, depth + 1, operational=True)
                        continue
                    normalized = self._property_key_name(key)
                    child_operational = operational or normalized in (
                        _PROPERTY_OPERATIONAL_CONTEXT_KEYS
                    ) or any(
                        marker in normalized
                        for marker in ("connector", "credential", "transport")
                    )
                    sanitized[key] = visit(
                        item, depth + 1, operational=child_operational
                    )
                return sanitized
            finally:
                active_containers.remove(identity)

        sanitized = visit(value, 0)
        try:
            encoded = canonical_json(sanitized).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise SourceFailure(
                "malformed_result", "Property Intel result is not valid JSON data"
            ) from exc
        if len(encoded) > self.output_bytes:
            raise SourceFailure(
                "cap_exceeded", "Property Intel sanitized result exceeded its byte cap"
            )
        return sanitized

    def _property(self, args: dict[str, Any]) -> Any:
        self._require_exact(
            args,
            {"operation", "query", "property_id", "note_id", "entry_id", "max_results"},
            {"operation"},
        )
        operation = args.get("operation")
        expected = {
            "list": {"operation", "max_results"},
            "property": {"operation", "property_id"},
            "research_notes": {"operation", "property_id", "max_results"},
            "note": {"operation", "note_id"},
            "note_entry": {"operation", "note_id", "entry_id"},
            "transaction": {"operation", "property_id"},
        }
        if operation not in expected:
            raise SourceFailure(
                "operation_denied", "Property Intel operation is unavailable"
            )
        allowed_args = set(expected[str(operation)]) | (
            {"query"} if operation == "list" else set()
        )
        _require_args(
            args, allowed_args, expected[str(operation)],
            f"the Property Intel {operation} operation",
        )
        canonical = dict(args)
        for key in ("property_id", "note_id", "entry_id"):
            if key in canonical and _UUID_RE.fullmatch(str(canonical[key])) is None:
                raise SourceFailure("invalid_arguments", f"{key} must be an exact UUID")
        if "max_results" in canonical:
            canonical["max_results"] = self._bounded_int(
                canonical["max_results"], "max_results", 30
            )
        if "query" in canonical:
            canonical["query"] = self._bounded_text(canonical["query"], "query", 200)
        if "property_intel" in self.backends:
            data = self._injected("property_intel", str(operation), canonical)
        else:
            cfg = self.config.get("property_intel")
            base = self._fixed_http_origin(cfg)
            quoted = {
                key: urllib.parse.quote(str(value), safe="")
                for key, value in canonical.items()
            }
            path = {
                "list": "/api/properties",
                "property": f"/api/properties/{quoted.get('property_id', '')}",
                "research_notes": f"/api/properties/{quoted.get('property_id', '')}/research-notes",
                "note": f"/api/research-notes/{quoted.get('note_id', '')}",
                "note_entry": f"/api/research-notes/{quoted.get('note_id', '')}/entries/{quoted.get('entry_id', '')}",
                "transaction": f"/api/properties/{quoted.get('property_id', '')}/transaction",
            }[str(operation)]
            data = self._http_get(base + path, cfg)
        data = self._sanitize_property_payload(data)
        if operation in {"list", "research_notes"}:
            if not isinstance(data, list):
                raise SourceFailure(
                    "malformed_result", "Property Intel list result is malformed"
                )
            query = str(canonical.get("query") or "").casefold()
            if query:
                data = [
                    item for item in data if query in canonical_json(item).casefold()
                ]
            total = len(data)
            if operation == "list":
                data = [
                    {
                        key: item[key]
                        for key in _PROPERTY_LIST_FIELDS
                        if isinstance(item, dict) and item.get(key) is not None
                    }
                    for item in data
                ]
            # max_results asked for a number and was answered with a refusal:
            # ask for five of thirty-nine and the whole call failed. It bounds
            # the answer now and says when it did, because a silent cut reads
            # as "that is all there is".
            limit = canonical["max_results"]
            if total > limit:
                return {
                    "matches": data[:limit],
                    "total": total,
                    "truncated": True,
                    "note": (
                        f"{total} matched; showing {limit}. Narrow with query, "
                        "or ask for one property by id."
                    ),
                }
            return {"matches": data, "total": total, "truncated": False}
        return data

    def _http_get(self, url: str, config: dict[str, Any]) -> Any:
        headers = {"Accept": "application/json"}
        auth_env = str(config.get("auth_env") or "")
        if auth_env:
            if re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", auth_env) is None:
                raise SourceFailure(
                    "backend_unavailable", "Property Intel auth reference is invalid"
                )
            token = os.environ.get(auth_env, "")
            if not token:
                raise SourceFailure(
                    "missing_auth", "Property Intel authentication is unavailable"
                )
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with self.url_opener.open(request, timeout=self.timeout) as response:
                raw = response.read(self.output_bytes + 1)
        except urllib.error.HTTPError as exc:
            code = "missing_auth" if exc.code in {401, 403} else "source_failure"
            raise SourceFailure(
                code, "Property Intel source request failed", exc.code >= 500
            ) from exc
        if len(raw) > self.output_bytes:
            raise SourceFailure(
                "cap_exceeded",
                "Property Intel returned more than this reader may hold. "
                "Ask for one property by id, or narrow the list with query"
            )
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise SourceFailure(
                "malformed_result", "Property Intel returned malformed JSON"
            ) from exc

    def _whatsapp(self, args: dict[str, Any]) -> Any:
        self._require_exact(
            args,
            {
                "operation",
                "chat",
                "name",
                "query",
                "message_id",
                "since",
                "max_results",
            },
            {"operation", "max_results"},
        )
        operation = args.get("operation")
        if operation not in {"search", "message", "deleted", "media_metadata"}:
            raise SourceFailure(
                "operation_denied", "WhatsApp archive operation is unavailable"
            )
        maximum = self._bounded_int(args["max_results"], "max_results", 50)
        if "chat" in args and "name" in args:
            raise SourceFailure(
                "invalid_arguments",
                "choose exact chat or uniquely resolved name, not both",
            )
        canonical: dict[str, Any] = {"operation": operation, "max_results": maximum}
        for key, limit in (
            ("chat", 128),
            ("name", 128),
            ("query", 200),
            ("message_id", 256),
            ("since", 40),
        ):
            if key in args:
                canonical[key] = self._bounded_text(args[key], key, limit)
        if operation == "search" and "query" not in canonical:
            raise SourceFailure("invalid_arguments", "WhatsApp search requires a query")
        if operation == "message" and "message_id" not in canonical:
            raise SourceFailure(
                "invalid_arguments", "exact WhatsApp message lookup requires message_id"
            )
        if "since" in canonical:
            canonical["since"] = _normalise_date(
                canonical["since"], "since", allow_time=True
            )
        if "whatsapp" in self.backends:
            data = self._injected("whatsapp", str(operation), canonical)
            return data[:maximum] if isinstance(data, list) else data
        cfg = self.config.get("whatsapp")
        if not isinstance(cfg, dict):
            raise SourceFailure(
                "backend_unavailable",
                "WhatsApp archive backend is not configured",
                True,
            )
        argv = [str(cfg["executable"]), str(cfg["script"]), "--limit", str(maximum)]
        flags = {
            "chat": "--chat",
            "name": "--name",
            "query": "--search",
            "message_id": "--message",
            "since": "--since",
        }
        for key, flag in flags.items():
            if key in canonical:
                argv.extend([flag, canonical[key]])
        if operation == "deleted":
            argv.append("--deleted")
        if operation == "media_metadata":
            argv.append("--media")
        env = dict(os.environ)
        env["WHATSAPP_READONLY_STATE_DIR"] = str(cfg["state_dir"])
        data = self._run_json(argv, env=env)
        if not isinstance(data, list):
            raise SourceFailure(
                "malformed_result", "WhatsApp archive returned malformed data"
            )
        return data[:maximum]

    def root_names(self) -> tuple[str, ...]:
        """Configured personal-file root names, or empty when unavailable."""
        try:
            return tuple(sorted(self._roots(self.config.get("files"))))
        except Exception:
            return ()

    def schema_for(self, tool_name: str) -> dict[str, Any]:
        """Return the model-facing schema with the real root names bound in.

        ``root`` was an unconstrained string, so the model had to guess which
        root existed and every guess failed with "personal file root is
        unavailable". The names are host-configured and not sensitive -- unlike
        their paths, which stay in Kite -- so they belong in the schema exactly
        as the Gmail account aliases already are.
        """
        schema = copy.deepcopy(TOOL_SCHEMAS[tool_name])
        if tool_name == "kite_personal_files_read":
            names = self.root_names()
            if names:
                schema["parameters"]["properties"]["root"]["enum"] = list(names)
                schema["description"] += (
                    " The only selectable root names are: " + ", ".join(names) + "."
                )
        return schema

    @staticmethod
    def _roots(config: Any) -> dict[str, Path]:
        if (
            not isinstance(config, dict)
            or not set(config) <= {"roots", "allowed_bases"}
            or "roots" not in config
            or not isinstance(config["roots"], list)
        ):
            raise ValueError("files private-read config requires only a roots list")
        bases = config.get("allowed_bases", _PERSONAL_ROOT_BASES)
        if not isinstance(bases, (list, tuple)) or not bases:
            raise ValueError("allowed_bases must be a non-empty list when given")
        bases = tuple(str(base).casefold().rstrip("/") for base in bases)
        if any(base in {"", "/"} for base in bases):
            raise ValueError("an allowed base must name a directory, not the root")
        roots: dict[str, Path] = {}
        for item in config["roots"]:
            if not isinstance(item, dict) or set(item) != {"name", "path"}:
                raise ValueError("each personal file root requires only name and path")
            name = str(item["name"] or "")
            path = Path(str(item["path"] or ""))
            if (
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name) is None
                or not path.is_absolute()
            ):
                raise ValueError(
                    "personal file roots require bounded names and absolute paths"
                )
            lowered = str(path).casefold().rstrip("/")
            # An allow-list, not a deny-list. The previous rule blocked the
            # obvious roots -- home, Documents, Hermes' own directories -- but
            # permitted anything it had not thought of, including ~/Library,
            # which holds Keychains and the Messages database. A root now has
            # to sit beneath somewhere explicitly nominated for documents.
            if not any(
                lowered == base or lowered.startswith(base + "/")
                for base in bases
            ):
                raise ValueError(
                    "personal file roots must sit beneath an approved documents area"
                )
            # Still refused inside those areas: Hermes' own state, and anything
            # filed as project or work material.
            if any(
                part in lowered
                for part in ("/.hermes", "/projects/", "/work/", "/workspace/")
            ):
                raise ValueError("Hermes, project, and work roots are forbidden")
            if lowered in bases:
                raise ValueError(
                    "a personal file root must name a folder, not a whole area"
                )
            if name in roots:
                raise ValueError("personal file root names must be unique")
            roots[name] = path
        return roots

    def _safe_file(self, root: Path, relative: str) -> Path:
        candidate_path = Path(relative)
        if (
            candidate_path.is_absolute()
            or not candidate_path.parts
            or any(
                part in {"", ".", ".."} or part.startswith(".")
                for part in candidate_path.parts
            )
        ):
            raise SourceFailure(
                "path_denied",
                "path must be visible and relative beneath the selected root",
            )
        if any(
            re.search(
                r"(?i)(?:^|[._-])(?:credential|credentials|secret|secrets|token|tokens|password|private[-_]?key)(?:[._-]|$)",
                part,
            )
            for part in candidate_path.parts
        ):
            raise SourceFailure("path_denied", "credential-bearing paths are forbidden")
        try:
            if root.is_symlink():
                raise SourceFailure(
                    "path_denied", "configured root cannot be a symlink"
                )
            root_real = root.resolve(strict=True)
            candidate = root_real.joinpath(candidate_path)
            if any(
                stat.S_ISLNK(
                    os.lstat(root_real.joinpath(*candidate_path.parts[:index])).st_mode
                )
                for index in range(1, len(candidate_path.parts) + 1)
            ):
                raise SourceFailure("path_denied", "symlinks are not permitted")
            real = candidate.resolve(strict=True)
            real.relative_to(root_real)
        except SourceFailure:
            raise
        except (OSError, ValueError) as exc:
            raise SourceFailure(
                "path_denied", "path is unavailable or escapes its configured root"
            ) from exc
        mode = real.stat().st_mode
        if not stat.S_ISREG(mode):
            raise SourceFailure("path_denied", "only regular files are readable")
        if real.suffix.casefold() in _REFUSED_EXTENSIONS:
            raise SourceFailure(
                "unsupported_content",
                "executable and credential files are not readable",
            )
        return real

    def _sessions(self, args: dict[str, Any]) -> Any:
        """Recall what this assistant already learned, in bounded excerpts.

        This reads past conversation, which is not a typed source with a
        capability of its own: a transcript line has no domain the way personal
        Gmail does. It is therefore deliberately narrow -- an excerpt, dated,
        with the surface it came from -- so it can answer "where did I put the
        passports" without becoming a way to replay a conversation.

        Its results are returned through the same path as every other reader,
        so the host records them as content fragments and the overlap check
        still governs what may reach Juno.
        """
        self._require_exact(args, {"query", "max_results"}, {"query"})
        config = self.config.get("sessions")
        if not isinstance(config, dict):
            raise SourceFailure(
                "backend_unavailable", "session recall is not configured", True
            )
        database = Path(str(config.get("database") or ""))
        if not database.is_absolute() or not database.exists():
            raise SourceFailure(
                "backend_unavailable", "session store is unavailable", True
            )
        query = self._bounded_text(args["query"], "query", 120)
        maximum = self._bounded_int(args.get("max_results", 5), "max_results", 10)
        # Reduce rather than reject. A real query says "One&Only Mauritius
        # dates"; refusing it taught the model only that recall was broken.
        # Everything outside the safe set becomes a space, which also strips
        # every FTS operator, so the match expression stays ours.
        words = [
            word for word in re.sub(r"[^A-Za-z0-9']+", " ", query).split()
            if len(word) > 1
        ]
        if not words:
            raise SourceFailure("invalid_arguments", "query needs a word to search")
        # OR, not AND. Requiring every word meant a natural request --
        # "Mauritius trip confirmed dates travellers accommodation flights" --
        # matched nothing at all, and the model reported the context missing.
        # bm25 then ranks the messages that match most of them first.
        terms = " OR ".join(f'"{word}"' for word in words[:12])
        found: list[dict[str, Any]] = []
        try:
            connection = sqlite3.connect(
                f"file:{database}?mode=ro", uri=True, timeout=5
            )
            try:
                connection.execute("pragma query_only = on")
                rows = connection.execute(
                    "select m.content, m.timestamp, s.session_key "
                    "from messages_fts f "
                    "join messages m on m.id = f.rowid "
                    "join sessions s on s.id = m.session_id "
                    "where f.messages_fts match ? and m.role in ('user','assistant') "
                    # Best match first, recent as the tie-break. Ordering by
                    # recency alone returned messages that merely contained the
                    # words -- "school term dates" matched a note about
                    # architecture that happened to use all three.
                    "order by bm25(messages_fts), m.rowid desc limit ?",
                    (terms, maximum * 12),
                ).fetchall()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise SourceFailure(
                "source_failure", "session store could not be read", True
            ) from exc

        for content, stamp, key in rows:
            text = re.sub(r"\s+", " ", str(content or "")).strip()
            if len(text) < 24:
                continue
            # A transcript is not a typed source, so anything credential-shaped
            # is dropped here rather than relied on being caught downstream.
            if any(pattern.search(text) for pattern in _session_denied_patterns()):
                continue
            surface = (str(key or "").split(":") + ["", "", ""])[2] or "cli"
            if surface == "a2a":
                continue  # this lane's own traffic, not recall
            found.append({
                "when": _session_when(stamp),
                "surface": surface,
                "excerpt": text[:_SESSION_EXCERPT_CHARS],
            })
            if len(found) >= maximum:
                break
        return found

    def _located_path(self, args: dict[str, Any]) -> Path:
        """The one file a locate match named, re-checked from scratch.

        Locate's output is a description, not a capability. Everything it
        refused to show is refused again here, against the path as it is now
        rather than as it was when the walk saw it, because the two calls are
        separated by a model deciding what to do.
        """
        self._require_exact(args, {"directory", "file_name"}, {"directory", "file_name"})
        directory = self._bounded_text(args["directory"], "directory", 512)
        file_name = self._bounded_text(args["file_name"], "file_name", 255)
        if "/" in file_name or file_name in {".", ".."} or file_name.startswith("."):
            raise SourceFailure("path_denied", "file_name must be one plain name")
        config = self.config.get("files")
        bases = (
            (config or {}).get("allowed_bases", _PERSONAL_ROOT_BASES)
            if isinstance(config, dict)
            else _PERSONAL_ROOT_BASES
        )
        candidate = Path(directory) / file_name
        if not candidate.is_absolute():
            raise SourceFailure("path_denied", "an absolute location is required")
        try:
            real = candidate.resolve(strict=True)
        except OSError as exc:
            raise SourceFailure("path_denied", "the document is unavailable") from exc
        lowered = str(real).casefold()
        if not any(
            lowered == str(base).casefold().rstrip("/")
            or lowered.startswith(str(base).casefold().rstrip("/") + "/")
            for base in bases
        ):
            raise SourceFailure(
                "path_denied", "the document is outside the searchable bases"
            )
        if candidate.is_symlink() or real.is_symlink():
            raise SourceFailure("path_denied", "symlinks are not permitted")
        if real.suffix.casefold() in _REFUSED_EXTENSIONS or any(
            _LOCATE_DENIED_PART.search(part) for part in real.parts
        ):
            raise SourceFailure(
                "unsupported_content", "executable and credential files are not released"
            )
        info = real.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise SourceFailure("path_denied", "only regular files are releasable")
        if info.st_size > _EXTRACT_MAX_INPUT_BYTES:
            raise SourceFailure("cap_exceeded", "file exceeds the configured byte cap")
        return real

    def _release_located(self, args: dict[str, Any]) -> Any:
        """What the model is told about a located document it wants released.

        Content-free, like every candidate descriptor: enough to say which
        document this is and that nothing has been sent, never the document.
        """
        path = self._located_path(dict(args))
        info = path.lstat()
        return {
            "outcome": "approval_required",
            "document_name": _release_display_name(path.name),
            "directory": str(path.parent),
            "size_bytes": info.st_size,
            "note": (
                "Nothing has been sent. The principal has been asked to approve "
                "releasing this document to whoever requested it."
            ),
        }

    def _locate(self, args: dict[str, Any]) -> Any:
        """Say where a document is, without acquiring the right to open it.

        A configured root is a standing grant: everything beneath it may be
        read and released. That is why there are only three of them, and why
        a document kept anywhere else could not be found at all -- the honest
        answer was "I cannot find it" for a file sitting in plain view.

        Finding is not reading. This walks the same bases that bound where a
        root may point, and returns names, locations and sizes only: no
        contents, no preview, no relative_path that any reader here accepts.
        Turning a location into a release needs the principal to say so, which
        is the whole of the approval step and is deliberately not automatable
        from in here.
        """
        self._require_exact(args, {"query", "max_results"}, {"query"})
        query = self._bounded_text(args["query"], "query", 200).casefold()
        maximum = self._bounded_int(args.get("max_results", 10), "max_results", 20)
        config = self.config.get("files")
        bases = [
            Path(base)
            for base in (
                (config or {}).get("allowed_bases", _PERSONAL_ROOT_BASES)
                if isinstance(config, dict)
                else _PERSONAL_ROOT_BASES
            )
        ]
        release_roots = {}
        try:
            release_roots = {
                name: root.resolve(strict=True)
                for name, root in self._roots(config).items()
            }
        except (ValueError, OSError, SourceFailure):
            release_roots = {}

        found: list[dict[str, Any]] = []
        seen: set[str] = set()
        scanned = 0
        for base in bases:
            try:
                base_real = base.expanduser().resolve(strict=True)
            except OSError:
                continue
            # Bases may overlap or nest -- one configured area sitting inside
            # another is ordinary -- and a document listed twice reads as two
            # documents to whoever has to choose between them.
            if any(
                base_real == other or other in base_real.parents
                for other in (Path(item) for item in seen)
            ):
                continue
            seen.add(str(base_real))
            for directory, names, files in os.walk(base_real, followlinks=False):
                names[:] = sorted(
                    item
                    for item in names
                    if not item.startswith(".")
                    and not Path(directory, item).is_symlink()
                )
                for filename in sorted(files):
                    scanned += 1
                    if scanned > _LOCATE_MAX_SCANNED:
                        return self._locate_result(found, truncated=True)
                    if filename.startswith(".") or query not in filename.casefold():
                        continue
                    path = Path(directory, filename)
                    if path.is_symlink() or path.suffix.casefold() in (
                        _REFUSED_EXTENSIONS
                    ):
                        continue
                    if any(
                        pattern.search(part)
                        for part in path.parts
                        for pattern in (_LOCATE_DENIED_PART,)
                    ):
                        continue
                    try:
                        info = path.lstat()
                    except OSError:
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    root_name = next(
                        (
                            name
                            for name, root in release_roots.items()
                            if root in path.parents
                        ),
                        None,
                    )
                    if str(path.resolve()) in seen:
                        continue
                    seen.add(str(path.resolve()))
                    found.append({
                        "document_name": _release_display_name(filename),
                        "file_name": filename,
                        # A directory, not a path a reader would take. The
                        # readers key off (root, relative_path); nothing here
                        # can be handed to one.
                        "directory": str(path.parent),
                        "size_bytes": info.st_size,
                        "modified": _session_when(info.st_mtime),
                        "release_root": root_name,
                        "releasable_now": root_name is not None,
                    })
                    if len(found) >= maximum:
                        return self._locate_result(found, truncated=True)
        return self._locate_result(found, truncated=False)

    @staticmethod
    def _locate_result(found: list[dict[str, Any]], *, truncated: bool) -> Any:
        return {
            "matches": found,
            "truncated": truncated,
            "note": (
                "Locations only. A match with releasable_now false is outside "
                "every configured root: it cannot be read or sent from here, "
                "and releasing it requires the principal's approval."
            ),
        }

    def _files(self, args: dict[str, Any]) -> Any:
        self._require_exact(
            args,
            {"operation", "root", "relative_path", "query", "max_results", "max_lines"},
            {"operation", "root"},
        )
        roots = self._roots(self.config.get("files"))
        name = str(args.get("root") or "")
        if name not in roots:
            raise SourceFailure("path_denied", "personal file root is unavailable")
        operation = args.get("operation")
        if operation == "read":
            _require_args(
                args,
                {"operation", "root", "relative_path", "max_lines"},
                {"operation", "root", "relative_path"},
                "a file read",
            )
            maximum_lines = self._bounded_int(
                args.get("max_lines", 400), "max_lines", 400
            )
            path = self._safe_file(
                roots[name],
                self._bounded_text(args["relative_path"], "relative_path", 512),
            )
            size = path.stat().st_size
            textual = path.suffix.casefold() in _TEXT_SUFFIXES
            # output_bytes caps what a tool returns. For a text file that is
            # also its size on disk, so one gate served for both. An extracted
            # document returns at most _READ_EXTRACT_CHARS however large the
            # scan behind it is, and charging it for the size of its image
            # data made every passport unreadable while the same file
            # previewed and released fine. Bound what it will load instead,
            # at the cap the release path already uses.
            if size > (self.output_bytes if textual else _EXTRACT_MAX_INPUT_BYTES):
                raise SourceFailure(
                    "cap_exceeded", "file exceeds the configured byte cap"
                )
            if not textual:
                # A PDF or a scan is readable even though it is not text, and
                # refusing to read it made an ordinary question unanswerable:
                # "what is Lucy's passport number" could only be answered by
                # sending Lucy's passport. The text is extracted on this
                # machine, and disclosure of what it says is governed by the
                # capability for the turn exactly as any other read is.
                guessed = (
                    mimetypes.guess_type(path.name)[0] or "application/octet-stream"
                )
                # Leave room for the descriptor around it: a configured cap
                # smaller than the extract turns a readable document into an
                # opaque cap error, and a shorter answer beats no answer.
                extracted = _document_preview(
                    path.read_bytes(),
                    guessed,
                    limit=min(_READ_EXTRACT_CHARS, self.output_bytes // 2),
                    pages=_READ_MAX_PAGES,
                )
                return {
                    "outcome": "extracted" if extracted else "unavailable_next_gate",
                    "descriptor": {
                        "root": name,
                        "relative_path": str(path.relative_to(roots[name].resolve())),
                        "mime_type": guessed,
                        "size_bytes": size,
                    },
                    "text": extracted,
                }
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            if len(lines) > maximum_lines:
                raise SourceFailure(
                    "cap_exceeded", "file exceeds the requested line cap"
                )
            return {
                "root": name,
                "relative_path": str(path.relative_to(roots[name].resolve())),
                "line_count": len(lines),
                "text": text,
            }
        if operation != "search":
            raise SourceFailure(
                "operation_denied", "a personal file read is a search or a read"
            )
        _require_args(
            args,
            {"operation", "root", "query", "max_results"},
            {"operation", "root", "query", "max_results"},
            "a file search",
        )
        tokens = _search_tokens(self._bounded_text(args["query"], "query", 200))
        if not tokens:
            raise SourceFailure(
                "invalid_arguments", "file search needs a word to search for"
            )
        maximum = self._bounded_int(args["max_results"], "max_results", 30)
        root_real = roots[name].resolve(strict=True)
        if roots[name].is_symlink():
            raise SourceFailure("path_denied", "configured root cannot be a symlink")
        scored: list[tuple[int, int, str, dict[str, Any]]] = []
        scanned = 0
        content_bytes = 0
        for directory, names, files in os.walk(root_real, followlinks=False):
            names[:] = sorted(
                item
                for item in names
                if not item.startswith(".") and not Path(directory, item).is_symlink()
            )
            for filename in sorted(files):
                if filename.startswith("."):
                    continue
                scanned += 1
                if scanned > _FILE_SEARCH_MAX_SCANNED:
                    break
                relative = str(Path(directory, filename).relative_to(root_real))
                try:
                    path = self._safe_file(root_real, relative)
                except SourceFailure:
                    continue
                haystack = _searchable(relative)
                in_name = {word for word in tokens if _matches(word, haystack)}
                in_text: set[str] = set()
                size = path.stat().st_size
                if (
                    len(in_name) < len(tokens)
                    and size <= self.output_bytes
                    and content_bytes < _FILE_SEARCH_MAX_CONTENT_BYTES
                    and path.suffix.casefold() in _TEXT_SUFFIXES
                ):
                    try:
                        body = _searchable(path.read_text(encoding="utf-8"))
                    except (OSError, UnicodeError):
                        body = ""
                    content_bytes += size
                    in_text = {word for word in tokens if _matches(word, body)}
                hit = in_name | in_text
                if not hit:
                    continue
                # Everything in the name is the strongest thing a search can
                # say; everything, somewhere, is next; some of it is still
                # worth showing, because a partly-remembered name is the
                # ordinary case and returning nothing teaches nothing.
                if len(in_name) == len(tokens):
                    rank, why = 0, "name"
                elif len(hit) == len(tokens):
                    rank, why = 1, "contents"
                else:
                    rank, why = 2, "partial"
                scored.append((rank, -len(hit), relative, {
                    "root": name,
                    "relative_path": relative,
                    "size_bytes": size,
                    "matched_on": why,
                }))
            if scanned > _FILE_SEARCH_MAX_SCANNED:
                break
        scored.sort(key=lambda item: item[:3])
        return [item[3] for item in scored[:maximum]]


def handlers_for(service: PrivateReadService) -> dict[str, Callable[..., str]]:
    """Build stable per-tool handlers without exposing a generic dispatch tool."""
    handlers: dict[str, Callable[..., str]] = {}
    for tool_name in service.tool_names:

        def handler(
            args: dict[str, Any], *, _tool_name: str = tool_name, **_: Any
        ) -> str:
            return service.execute(_tool_name, args)

        handler.__name__ = f"handle_{tool_name}"
        handlers[tool_name] = handler
    return handlers


__all__ = [
    "KITE_GMAIL",
    "OBSIDIAN_ROOT",
    "PERSONAL_GMAIL",
    "PRIVATE_READ_TOOLSET",
    "THINGS_CLIENT",
    "THINGS_ENDPOINT",
    "THINGS_PROJECT_TITLE",
    "THINGS_PROJECT_UUID",
    "TOOL_NAMES",
    "TOOL_SCHEMAS",
    "WHATSAPP_QUERY",
    "PrivateReadService",
    "SourceFailure",
    "handlers_for",
]
