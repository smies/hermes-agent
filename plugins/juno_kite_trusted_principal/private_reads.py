"""Narrow, read-only private-source connectors for Kite.

Every model-facing argument is bounded and source-specific.  Executable paths,
account identities, endpoints, filesystem roots, and credentials are host
configuration; they are never accepted from the model.  External commands use
an argv vector with ``shell=False`` and HTTP uses fixed GET-only routes.
"""

from __future__ import annotations

import base64
import copy
import json
import math
import mimetypes
import os
import re
import stat
import subprocess
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
_ATTACHMENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,%d}\Z" % _ATTACHMENT_ID_MAX_CHARS)
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\Z"
)
_DATE_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})?)?\Z"
)
_SAFE_EXTENSIONS = frozenset({
    ".txt",
    ".md",
    ".markdown",
    ".csv",
    ".json",
    ".yaml",
    ".yml",
    ".pdf",
    ".docx",
    ".jpg",
    ".jpeg",
    ".png",
})
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
                "after": {"type": "string", "maxLength": 32},
                "before": {"type": "string", "maxLength": 32},
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
                "start": {"type": "string", "minLength": 10, "maxLength": 40},
                "end": {"type": "string", "minLength": 10, "maxLength": 40},
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
                "since": {"type": "string", "minLength": 10, "maxLength": 40},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50},
            },
            ("operation", "max_results"),
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
                "query": {"type": "string", "minLength": 1, "maxLength": 200},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 30},
                "max_lines": {"type": "integer", "minimum": 1, "maximum": 400},
            },
            ("operation", "root"),
        ),
    },
}


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
        }
        if set(self.config) - allowed:
            raise ValueError("private_reads contains unsupported configuration fields")
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
        args: dict[str, Any], allowed: set[str], required: set[str]
    ) -> None:
        if set(args) - allowed or not required.issubset(args):
            raise SourceFailure(
                "invalid_arguments", "arguments do not match the typed operation"
            )

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
                value = self._bounded_text(args[key], key, 32)
                if _DATE_RE.fullmatch(value) is None:
                    raise SourceFailure(
                        "invalid_arguments", f"{key} must be an ISO date"
                    )
                query += f" {operator}:{value[:10].replace('-', '/')}"
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
        if len(result) > maximum:
            raise SourceFailure(
                "cap_exceeded", "Gmail search exceeded the requested result cap"
            )
        return result

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
        maximum = 8 * 1024 * 1024 if release else self.output_bytes
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
                "kite_gmail_attachment_extract",
            }:
                raise SourceFailure(
                    "operation_denied", "source cannot produce a release candidate"
                )
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
                guessed = (mimetypes.guess_type(path.name)[0] or "").lower()
                descriptor = {
                    "outcome": "release_candidate",
                    "source_class": "personal files",
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
                descriptor = {
                    "outcome": "release_candidate",
                    "source_class": "personal Gmail attachment",
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
                argv, max_output_bytes=_ATTACHMENT_COMMAND_OUTPUT_BYTES
            )
        return self._run_json(argv)

    def _run_json(
        self,
        argv: list[str],
        *,
        env: Optional[dict[str, str]] = None,
        max_output_bytes: Optional[int] = None,
    ) -> Any:
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
        start = self._bounded_text(args["start"], "start", 40)
        end = self._bounded_text(args["end"], "end", 40)
        if (
            _DATE_RE.fullmatch(start) is None
            or _DATE_RE.fullmatch(end) is None
            or start >= end
        ):
            raise SourceFailure("invalid_arguments", "calendar window is malformed")
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
        if len(result) > maximum:
            raise SourceFailure(
                "cap_exceeded", "calendar source exceeded the requested result cap"
            )
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
            if set(args) != {"operation", "item_id"}:
                raise SourceFailure(
                    "invalid_arguments", "exact Things item requires only item_id"
                )
            canonical["item_id"] = self._bounded_text(
                args.get("item_id"), "item_id", 256
            )
        elif operation in {"search", "recent_completed"}:
            required = {"operation", "query", "max_results"}
            if set(args) != required:
                raise SourceFailure(
                    "invalid_arguments", "Things lookup requires query and max_results"
                )
            canonical["query"] = self._bounded_text(args.get("query"), "query", 200)
            canonical["max_results"] = self._bounded_int(
                args.get("max_results"), "max_results", 30
            )
        elif set(args) != {"operation"}:
            raise SourceFailure(
                "invalid_arguments", "Things snapshot accepts no selectors"
            )
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
        if set(args) != allowed_args and not (
            operation == "list" and set(args) == expected["list"]
        ):
            raise SourceFailure(
                "invalid_arguments",
                "Property Intel arguments do not match the operation",
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
            if len(data) > canonical["max_results"]:
                raise SourceFailure(
                    "cap_exceeded", "Property Intel result exceeded the requested cap"
                )
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
                "cap_exceeded", "Property Intel response exceeded its cap"
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
        if "since" in canonical and _DATE_RE.fullmatch(canonical["since"]) is None:
            raise SourceFailure(
                "invalid_arguments", "WhatsApp since must be an ISO date"
            )
        if "whatsapp" in self.backends:
            return self._injected("whatsapp", str(operation), canonical)
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
        if len(data) > maximum:
            raise SourceFailure(
                "cap_exceeded", "WhatsApp archive exceeded the requested cap"
            )
        return data

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
            or set(config) != {"roots"}
            or not isinstance(config["roots"], list)
        ):
            raise ValueError("files private-read config requires only a roots list")
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
            lowered = str(path).casefold()
            forbidden_prefixes = (
                "/etc",
                "/var",
                "/system",
                "/library",
                "/applications",
                "/usr",
                "/bin",
                "/sbin",
                "/opt",
            )
            if (
                lowered in {"/", "/users/james", "/users/james/documents"}
                or lowered.startswith(forbidden_prefixes)
                or any(
                    part in lowered
                    for part in ("/.hermes", "/projects/", "/work/", "/workspace/")
                )
            ):
                raise ValueError("Hermes, project, and work roots are forbidden")
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
        if real.suffix.casefold() not in _SAFE_EXTENSIONS:
            raise SourceFailure(
                "unsupported_content", "file extension is not allowlisted"
            )
        return real

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
            if (
                set(args) - {"operation", "root", "relative_path", "max_lines"}
                or "relative_path" not in args
            ):
                raise SourceFailure(
                    "invalid_arguments", "file read requires one relative_path"
                )
            maximum_lines = self._bounded_int(
                args.get("max_lines", 400), "max_lines", 400
            )
            path = self._safe_file(
                roots[name],
                self._bounded_text(args["relative_path"], "relative_path", 512),
            )
            size = path.stat().st_size
            if size > self.output_bytes:
                raise SourceFailure(
                    "cap_exceeded", "file exceeds the configured byte cap"
                )
            if path.suffix.casefold() not in {
                ".txt",
                ".md",
                ".markdown",
                ".csv",
                ".json",
                ".yaml",
                ".yml",
            }:
                return {
                    "outcome": "unavailable_next_gate",
                    "descriptor": {
                        "root": name,
                        "relative_path": str(path.relative_to(roots[name].resolve())),
                        "mime_type": mimetypes.guess_type(path.name)[0]
                        or "application/octet-stream",
                        "size_bytes": size,
                    },
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
        if operation != "search" or set(args) != {
            "operation",
            "root",
            "query",
            "max_results",
        }:
            raise SourceFailure(
                "invalid_arguments", "file search requires query and max_results"
            )
        query = self._bounded_text(args["query"], "query", 200).casefold()
        maximum = self._bounded_int(args["max_results"], "max_results", 30)
        root_real = roots[name].resolve(strict=True)
        if roots[name].is_symlink():
            raise SourceFailure("path_denied", "configured root cannot be a symlink")
        matches: list[dict[str, Any]] = []
        for directory, names, files in os.walk(root_real, followlinks=False):
            names[:] = sorted(
                item
                for item in names
                if not item.startswith(".") and not Path(directory, item).is_symlink()
            )
            for filename in sorted(files):
                if filename.startswith("."):
                    continue
                relative = str(Path(directory, filename).relative_to(root_real))
                try:
                    path = self._safe_file(root_real, relative)
                except SourceFailure:
                    continue
                content_match = False
                if (
                    path.stat().st_size <= self.output_bytes
                    and path.suffix.casefold()
                    in {".txt", ".md", ".markdown", ".csv", ".json", ".yaml", ".yml"}
                ):
                    try:
                        content_match = (
                            query in path.read_text(encoding="utf-8").casefold()
                        )
                    except (OSError, UnicodeError):
                        content_match = False
                if query in relative.casefold() or content_match:
                    matches.append({
                        "root": name,
                        "relative_path": relative,
                        "size_bytes": path.stat().st_size,
                    })
                    if len(matches) > maximum:
                        raise SourceFailure(
                            "cap_exceeded",
                            "file search exceeded the requested result cap",
                        )
        return matches


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
