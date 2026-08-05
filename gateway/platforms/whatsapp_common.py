"""
Transport-agnostic WhatsApp behavior shared by the Baileys bridge adapter
and the official WhatsApp Cloud API adapter.

The mixin provides:
- Allow-list / DM / group gating
- Mention detection (explicit @-mentions + configurable regex patterns)
- Quoted-reply-to-bot detection
- Broadcast / Channel / Newsletter filtering
- WhatsApp-flavored markdown conversion
- Outgoing chunk length budgeting

It is the *behavior layer*. Transport-specific concerns (subprocess management,
HTTP webhooks, Graph API calls, media upload protocols) live in each adapter.

Mixin contract — the adapter must set these on ``self`` before any of the
mixin's methods are called (typically in ``__init__``):

    self.config        # gateway.config.PlatformConfig
    self.name          # str — adapter name (used in log lines)
    self._dm_policy             # str: "open" | "allowlist" | "disabled"
    self._allow_from            # set[str]
    self._group_policy          # str: "open" | "allowlist" | "disabled"
    self._group_allow_from      # set[str]
    self._mention_patterns      # list[re.Pattern]
    self._reply_prefix          # Optional[str]

Class attributes ``MAX_MESSAGE_LENGTH`` and ``DEFAULT_REPLY_PREFIX`` are
defined on the mixin and may be overridden per-adapter if needed.
"""

from __future__ import annotations

import json
import logging
import os
import hashlib
import hmac
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

from agent.secret_scope import UnscopedSecretError as _UnscopedSecretError
from agent.secret_scope import get_secret as _scoped_get_secret


def _get_wsecret(name, default=None):
    """Scope-aware WHATSAPP_* read with the default-profile startup fallback.

    Secondary profiles run under ``_profile_runtime_scope`` -- the scope is
    authoritative and a scoped miss returns ``default`` (no cross-profile
    borrow). The DEFAULT profile's adapter constructs and sends *unscoped*
    under multiplexing, where a bare ``get_secret`` would raise
    ``UnscopedSecretError`` and crash its WhatsApp path; there ``os.environ``
    is that profile's own value, so fall back to it. Same pattern as the
    Slack ``SLACK_APP_TOKEN`` read (#59739).
    """
    try:
        val = _scoped_get_secret(name, default)
    except _UnscopedSecretError:
        val = os.getenv(name)
    return val if val is not None else default

logger = logging.getLogger(__name__)

ORDINARY_VERIFIED_LAUNCHER_SHA256 = "bbcdb784049d04784d835cc3f1f53b1e32242d34c82d347d0b1226ea8d8fffb4"
ORDINARY_VERIFIED_MANIFEST_SHA256 = "9368ac8903723594786666fa141a5e5715396244b2c4e477b0aef95a8cbd10ce"
ORDINARY_VERIFIED_PACKAGE_SHA256 = "c7593a5e4456c6133a0d5a8827d752771b1220c925d5ef4464198773106e40dc"
ORDINARY_VERIFIED_LOCK_SHA256 = "2e62d7c1fe53747fd3148e374b639e23af120cdad295ca57a426d38384f72913"
ORDINARY_VERIFIED_VERIFIER_SHA256 = "12d82b98216afefa516fcc4b1d077787d7c8396ea826e29bdedceee960f0cca9"
ORDINARY_VERIFIED_SOURCE_SHA256 = "d1f5b626f7e8cb373ce299d467292c14b3ac9e9c4a1345ce621c1b5f733c5543"
_ORDINARY_SOURCE_FILES = (
    "allowlist.js", "bridge.js", "bridge_helpers.js", "inbound_producer.js",
    "lid_bootstrap.js", "outbound_ids.js", "owner_message_gate.js",
)
_ORDINARY_MIRROR_FILES = (
    "launcher.js", "transport-manifest.json", "transport_identity.js",
    "package.json", "package-lock.json", *_ORDINARY_SOURCE_FILES,
)
_ORDINARY_MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024


def verify_ordinary_launcher(path: Path) -> bool:
    """Bind the manifest-anchor launcher to the trusted Python host source."""
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            return False
        digest = hashlib.sha256(_read_regular_file(path)).hexdigest()
    except OSError:
        return False
    return hmac.compare_digest(digest, ORDINARY_VERIFIED_LAUNCHER_SHA256)


def _read_regular_file(path: Path) -> bytes:
    """Read one non-replaceable regular file through a checked descriptor."""
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o022
        or before.st_size > _ORDINARY_MAX_SOURCE_FILE_BYTES
    ):
        raise OSError("unsafe ordinary bridge source")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise OSError("replaceable ordinary bridge source")
        chunks: list[bytes] = []
        remaining = _ORDINARY_MAX_SOURCE_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        value = b"".join(chunks)
        if len(value) > _ORDINARY_MAX_SOURCE_FILE_BYTES:
            raise OSError("oversized ordinary bridge source")
        return value
    finally:
        os.close(descriptor)


def _framed_source_digest(files: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in _ORDINARY_SOURCE_FILES:
        file_digest = hashlib.sha256(files[name]).hexdigest()
        name_bytes = name.encode("utf-8")
        digest.update(f"{len(name_bytes)}:".encode())
        digest.update(name_bytes)
        digest.update(f":{len(file_digest)}:{file_digest}\n".encode())
    return digest.hexdigest()


def _reviewed_bridge_files(root: Path) -> dict[str, bytes]:
    """Return an independently anchored snapshot of the reviewed source."""
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_IMODE(root_info.st_mode) & 0o022:
        raise OSError("unsafe ordinary bridge source directory")
    values = {name: _read_regular_file(root / name) for name in _ORDINARY_MIRROR_FILES}
    observed = {
        "launcher": hashlib.sha256(values["launcher.js"]).hexdigest(),
        "manifest": hashlib.sha256(values["transport-manifest.json"]).hexdigest(),
        "package": hashlib.sha256(values["package.json"]).hexdigest(),
        "lock": hashlib.sha256(values["package-lock.json"]).hexdigest(),
        "verifier": hashlib.sha256(values["transport_identity.js"]).hexdigest(),
        "source": _framed_source_digest(values),
    }
    expected = {
        "launcher": ORDINARY_VERIFIED_LAUNCHER_SHA256,
        "manifest": ORDINARY_VERIFIED_MANIFEST_SHA256,
        "package": ORDINARY_VERIFIED_PACKAGE_SHA256,
        "lock": ORDINARY_VERIFIED_LOCK_SHA256,
        "verifier": ORDINARY_VERIFIED_VERIFIER_SHA256,
        "source": ORDINARY_VERIFIED_SOURCE_SHA256,
    }
    if any(not hmac.compare_digest(observed[name], expected[name]) for name in expected):
        raise OSError("ordinary bridge source identity mismatch")
    try:
        manifest = json.loads(values["transport-manifest.json"])
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise OSError("ordinary bridge manifest is invalid") from None
    if (
        type(manifest) is not dict
        or set(manifest) != {
            "version", "package_name", "package_version", "package_sha256",
            "lock_sha256", "verifier_sha256", "source_sha256",
            "node_modules_tree_sha256", "baileys",
        }
        or manifest.get("version") != 3
        or manifest.get("package_sha256") != expected["package"]
        or manifest.get("lock_sha256") != expected["lock"]
        or manifest.get("verifier_sha256") != expected["verifier"]
        or manifest.get("source_sha256") != expected["source"]
    ):
        raise OSError("ordinary bridge manifest identity mismatch")
    return values


def _reviewed_bridge_identity() -> str:
    value = (
        "hermes-whatsapp-bridge-mirror-v1\0"
        + ORDINARY_VERIFIED_LAUNCHER_SHA256 + "\0"
        + ORDINARY_VERIFIED_MANIFEST_SHA256
    )
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _safe_owned_directory(path: Path, *, create: bool = False, private: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700 if private else 0o755, parents=False, exist_ok=True)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) & 0o022
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
    ):
        raise OSError("unsafe ordinary bridge mirror parent")
    if private and stat.S_IMODE(info.st_mode) != 0o700:
        os.chmod(path, 0o700)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_staged_bridge(stage: Path, files: dict[str, bytes]) -> None:
    for name in _ORDINARY_MIRROR_FILES:
        destination = stage / name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(destination, flags, 0o700 if name == "launcher.js" else 0o600)
        try:
            view = memoryview(files[name])
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("ordinary bridge mirror write failed")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    _fsync_directory(stage)


def _remove_exact_mirror_entry(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
        shutil.rmtree(path, ignore_errors=True)
    else:
        try:
            path.unlink()
        except OSError:
            pass


def _install_bridge_is_writable(path: Path) -> bool:
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".hermes-write-test-", dir=path)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                return False
        finally:
            os.close(descriptor)
        return True
    except OSError:
        return False
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _publish_reviewed_bridge_mirror(install_bridge: Path, hermes_home: Path) -> Path:
    files = _reviewed_bridge_files(install_bridge)
    _safe_owned_directory(hermes_home)
    scripts_dir = hermes_home / "scripts"
    _safe_owned_directory(scripts_dir, create=True)
    mirror_root = scripts_dir / ".whatsapp-bridge-mirrors"
    _safe_owned_directory(mirror_root, create=True, private=True)
    identity = _reviewed_bridge_identity()
    destination = mirror_root / identity
    if os.path.lexists(destination):
        try:
            _reviewed_bridge_files(destination)
            return destination
        except OSError:
            pass

    stage = Path(tempfile.mkdtemp(prefix=f".{identity}.stage-", dir=mirror_root))
    os.chmod(stage, 0o700)
    quarantine: Path | None = None
    try:
        _write_staged_bridge(stage, files)
        _reviewed_bridge_files(stage)
        try:
            os.rename(stage, destination)
        except FileExistsError:
            _reviewed_bridge_files(destination)
        except OSError:
            try:
                _reviewed_bridge_files(destination)
                return destination
            except OSError:
                pass
            # A corrupt entry at the content-addressed name is never selected.
            # Move that exact entry aside, then atomically publish the complete
            # staged directory. Concurrent readers either verify or fail closed.
            if not os.path.lexists(destination):
                raise
            quarantine = mirror_root / (
                f".{identity}.rejected-{os.getpid()}-{stage.name.rsplit('-', 1)[-1]}"
            )
            os.rename(destination, quarantine)
            os.rename(stage, destination)
        _fsync_directory(mirror_root)
        _reviewed_bridge_files(destination)
        return destination
    finally:
        _remove_exact_mirror_entry(stage)
        if quarantine is not None:
            _remove_exact_mirror_entry(quarantine)


class WhatsAppBehaviorMixin:
    """Shared behavior for all WhatsApp adapters (Baileys + Cloud API).

    See module docstring for the attribute contract the host adapter must
    satisfy. This mixin owns no state of its own — every value it touches
    is either a class attribute or set by the adapter's ``__init__``.
    """

    # WhatsApp message limits — practical UX limit, not protocol max.
    # WhatsApp allows ~65K but long messages are unreadable on mobile.
    MAX_MESSAGE_LENGTH: int = 4096
    supports_code_blocks = True  # WhatsApp renders fenced code blocks (monospace)

    DEFAULT_REPLY_PREFIX: str = "⚕ *Hermes Agent*\n────────────\n"

    _OUTBOUND_INVISIBLE_CHARS_RE = re.compile(r"[\u200b\u2060\u2063\ufeff]")
    _OUTBOUND_ODD_SPACE_RE = re.compile(r"[\u00a0\u1680\u180e\u2000-\u200a\u202f\u205f\u3000]")

    @classmethod
    def _sanitize_outbound_text(cls, content: str) -> str:
        """Remove invisible formatting chars that leak badly in WhatsApp.

        Some provider/gateway formatting paths can emit unicode like WORD
        JOINER (U+2060) plus NARROW NO-BREAK SPACE (U+202F). WhatsApp may
        render those as mojibake-looking prefixes (``⁠ text``) instead of
        invisible spacing. Keep normal text and emoji joiners intact, but
        strip known zero-width format chars and normalize odd unicode spaces.
        """
        if not content:
            return content
        content = cls._OUTBOUND_INVISIBLE_CHARS_RE.sub("", content)
        return cls._OUTBOUND_ODD_SPACE_RE.sub(" ", content)

    @property
    def enforces_own_access_policy(self) -> bool:
        """WhatsApp gates DM/group access at intake via dm_policy/group_policy."""
        return True

    # ------------------------------------------------------------------ config
    def _effective_reply_prefix(self) -> str:
        """Return the prefix to add to outgoing replies in self-chat mode.

        Subclasses that don't have a self-chat concept (the Cloud API
        adapter) can override this to always return ``""`` or apply a
        different policy.
        """
        whatsapp_mode = _get_wsecret("WHATSAPP_MODE", default="self-chat") or "self-chat"
        if whatsapp_mode != "self-chat":
            return ""
        if self._reply_prefix is not None:
            return self._reply_prefix.replace("\\n", "\n")
        env_prefix = _get_wsecret("WHATSAPP_REPLY_PREFIX")
        if env_prefix is not None:
            return env_prefix.replace("\\n", "\n")
        return self.DEFAULT_REPLY_PREFIX

    def _outgoing_chunk_limit(self) -> int:
        """Reserve room for the reply prefix so the final message fits."""
        prefix_len = len(self._effective_reply_prefix())
        # Keep enough space for truncate_message's pagination indicator and
        # code-fence repair even if a user configures a very long prefix.
        return max(1024, self.MAX_MESSAGE_LENGTH - prefix_len)

    def _whatsapp_require_mention(self) -> bool:
        configured = self.config.extra.get("require_mention")
        if configured is not None:
            if isinstance(configured, str):
                return configured.lower() in {"true", "1", "yes", "on"}
            return bool(configured)
        return (_get_wsecret("WHATSAPP_REQUIRE_MENTION", default="false") or "false").lower() in {
            "true",
            "1",
            "yes",
            "on",
        }

    def _whatsapp_free_response_chats(self) -> set[str]:
        raw = self.config.extra.get("free_response_chats")
        if raw is None:
            raw = _get_wsecret("WHATSAPP_FREE_RESPONSE_CHATS", default="") or ""
        if isinstance(raw, list):
            return {str(part).strip() for part in raw if str(part).strip()}
        return {part.strip() for part in str(raw).split(",") if part.strip()}

    @staticmethod
    def _coerce_allow_list(raw) -> set[str]:
        """Parse allow_from / group_allow_from from config or env var."""
        if raw is None:
            return set()
        if isinstance(raw, list):
            return {str(part).strip() for part in raw if str(part).strip()}
        return {part.strip() for part in str(raw).split(",") if part.strip()}

    def _live_dm_allow_from(self) -> set[str]:
        """Allowlist currently enforced for DM intake / strict DM auth.

        Source precedence matches construction: explicit config wins over any
        env carrier. When the adapter was seeded from an env var, re-read that
        same key so pairing approve/revoke takes effect without restart
        (including an empty value while the key is still present). When the key
        is absent — sole-entry revoke calls ``remove_env_value`` — treat the
        allowlist as empty instead of falling back to the construction-time
        snapshot. Config-seeded adapters keep the in-memory snapshot, which
        pairing revoke purges in place — a lower-precedence or stale env value
        must not broaden access.
        """
        source = getattr(self, "_dm_allowlist_source", None)
        if isinstance(source, str) and source != "config":
            if source in os.environ:
                return self._coerce_allow_list(os.environ.get(source, ""))
            # Key removed (e.g. sole-entry pairing revoke) — do not revive the
            # stale construction snapshot.
            return set()
        return set(self._allow_from or ())

    # ------------------------------------------------------------------ JID helpers
    @staticmethod
    def _normalize_whatsapp_id(value: Optional[str]) -> str:
        if not value:
            return ""
        normalized = str(value).strip()
        if ":" in normalized and "@" in normalized:
            normalized = normalized.replace(":", "@", 1)
        return normalized

    @staticmethod
    def _is_broadcast_chat(chat_id: str) -> bool:
        """True for WhatsApp pseudo-chats that aren't real conversations.

        Covers Status updates (Stories) and Channel/Newsletter broadcasts.
        These show up as inbound messages on Baileys but the agent should
        never reply — answering a Story update spams the contact's status
        feed, and Channel posts aren't addressable in the first place.
        """
        if not chat_id:
            return False
        cid = chat_id.strip().lower()
        if cid == "status@broadcast":
            return True
        # @broadcast suffix covers status@broadcast plus any future
        # broadcast-list variants. @newsletter is the Channel JID suffix.
        if cid.endswith("@broadcast") or cid.endswith("@newsletter"):
            return True
        return False

    # ------------------------------------------------------------------ gating
    def _open_dm_opted_in(self) -> bool:
        if os.getenv("GATEWAY_ALLOW_ALL_USERS", "").lower() in {"true", "1", "yes"}:
            return True
        return (_get_wsecret("WHATSAPP_ALLOW_ALL_USERS", default="") or "").lower() in {"true", "1", "yes"}

    @staticmethod
    def _matches_whatsapp_allowlist(candidate: str, allow_from) -> bool:
        """Match a WhatsApp identifier against an allowlist across phone/LID forms.

        WhatsApp delivers inbound senders in LID form (``<id>@lid``) while
        operators usually configure allowlists with phone numbers, and vice
        versa. A raw set-membership check therefore never matches a known
        contact. Resolve both the candidate and each allowlist entry through
        the bridge's ``lid-mapping-*.json`` files (the shared
        ``gateway.whatsapp_identity`` helper that the gateway authz and
        session-key paths already use) so either configured form resolves to
        the inbound form.
        """
        if not allow_from:
            return False
        # Fast path: exact match against the raw configured value (e.g. a full
        # ``@g.us`` group JID or an entry that already matches verbatim).
        if candidate in allow_from:
            return True

        from gateway.whatsapp_identity import (
            expand_whatsapp_aliases,
            normalize_whatsapp_identifier,
        )

        candidate_aliases = expand_whatsapp_aliases(candidate)
        if not candidate_aliases:
            return False
        for entry in allow_from:
            if entry == "*":
                return True
            if normalize_whatsapp_identifier(entry) in candidate_aliases:
                return True
            # Entry may itself be an unmapped form; expand it too so a phone
            # allowlist entry resolves when the inbound sender arrived as a LID.
            if expand_whatsapp_aliases(entry) & candidate_aliases:
                return True
        return False

    def _is_dm_allowed(self, sender_id: str) -> bool:
        """Strict DM authorization — pairing does not imply access."""
        if self._dm_policy == "disabled":
            return False
        if self._dm_policy == "allowlist":
            return self._matches_whatsapp_allowlist(sender_id, self._live_dm_allow_from())
        if self._dm_policy == "open":
            return self._open_dm_opted_in()
        return False

    def _is_dm_intake_allowed(self, sender_id: str) -> bool:
        """Whether a DM may reach the gateway intake (pairing handshake path)."""
        principal = str(sender_id or "").strip()
        if not principal:
            return False
        if self._dm_policy == "disabled":
            return False
        if self._dm_policy == "allowlist":
            return self._matches_whatsapp_allowlist(principal, self._live_dm_allow_from())
        if self._dm_policy == "pairing":
            return True
        if self._dm_policy == "open":
            return self._open_dm_opted_in()
        return False

    def _is_group_allowed(self, chat_id: str) -> bool:
        """Check whether a group chat should be processed."""
        if self._group_policy == "disabled":
            return False
        if self._group_policy == "allowlist":
            return self._matches_whatsapp_allowlist(chat_id, self._group_allow_from)
        if self._group_policy == "pairing":
            return False
        if self._group_policy == "open":
            return True
        return False

    def _compile_mention_patterns(self):
        patterns = self.config.extra.get("mention_patterns")
        if patterns is None:
            raw = (_get_wsecret("WHATSAPP_MENTION_PATTERNS", default="") or "").strip()
            if raw:
                try:
                    patterns = json.loads(raw)
                except Exception:
                    patterns = [
                        part.strip() for part in raw.splitlines() if part.strip()
                    ]
                    if not patterns:
                        patterns = [
                            part.strip() for part in raw.split(",") if part.strip()
                        ]
        if patterns is None:
            return []
        if isinstance(patterns, str):
            patterns = [patterns]
        if not isinstance(patterns, list):
            logger.warning(
                "[%s] whatsapp mention_patterns must be a list or string; got %s",
                self.name,
                type(patterns).__name__,
            )
            return []

        compiled = []
        for pattern in patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                continue
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error as exc:
                logger.warning(
                    "[%s] Invalid WhatsApp mention pattern %r: %s",
                    self.name,
                    pattern,
                    exc,
                )
        if compiled:
            logger.info(
                "[%s] Loaded %d WhatsApp mention pattern(s)", self.name, len(compiled)
            )
        return compiled

    def _bot_ids_from_message(self, data: Dict[str, Any]) -> set[str]:
        bot_ids = set()
        for candidate in data.get("botIds") or []:
            normalized = self._normalize_whatsapp_id(candidate)
            if normalized:
                bot_ids.add(normalized)
        return bot_ids

    def _message_is_reply_to_bot(self, data: Dict[str, Any]) -> bool:
        quoted_participant = self._normalize_whatsapp_id(data.get("quotedParticipant"))
        if not quoted_participant:
            return False
        return quoted_participant in self._bot_ids_from_message(data)

    def _message_mentions_bot(self, data: Dict[str, Any]) -> bool:
        bot_ids = self._bot_ids_from_message(data)
        if not bot_ids:
            return False
        mentioned_ids = {
            nid
            for candidate in (data.get("mentionedIds") or [])
            if (nid := self._normalize_whatsapp_id(candidate))
        }
        if mentioned_ids & bot_ids:
            return True

        body = str(data.get("body") or "")
        lower_body = body.lower()
        for bot_id in bot_ids:
            bare_id = bot_id.split("@", 1)[0].lower()
            if bare_id and (f"@{bare_id}" in lower_body or bare_id in lower_body):
                return True
        return False

    def _message_matches_mention_patterns(self, data: Dict[str, Any]) -> bool:
        if not self._mention_patterns:
            return False
        body = str(data.get("body") or "")
        return any(pattern.search(body) for pattern in self._mention_patterns)

    def _clean_bot_mention_text(self, text: str, data: Dict[str, Any]) -> str:
        if not text:
            return text
        bot_ids = self._bot_ids_from_message(data)
        cleaned = text
        for bot_id in bot_ids:
            bare_id = bot_id.split("@", 1)[0]
            if bare_id:
                cleaned = re.sub(
                    rf"@{re.escape(bare_id)}\b[,:\-]*\s*", "", cleaned
                )
        return cleaned.strip() or text

    def _should_process_message(self, data: Dict[str, Any]) -> bool:
        chat_id_raw = str(data.get("chatId") or "")
        # WhatsApp uses pseudo-chats for Status updates (Stories) and
        # Channel/Newsletter broadcasts. These are not real conversations
        # and the agent should never reply to them — even in self-chat mode
        # where the bridge may surface them as "fromMe" events.
        if self._is_broadcast_chat(chat_id_raw):
            return False
        is_group = data.get("isGroup", False)
        if is_group:
            chat_id = chat_id_raw
            if not self._is_group_allowed(chat_id):
                return False
        else:
            sender_id = str(data.get("senderId") or data.get("from") or "")
            if not self._is_dm_intake_allowed(sender_id):
                return False
            # DMs that pass the policy gate are always processed
            return True
        # Group messages: check mention / free-response settings
        chat_id = str(data.get("chatId") or "")
        if chat_id in self._whatsapp_free_response_chats():
            return True
        if not self._whatsapp_require_mention():
            return True
        body = str(data.get("body") or "").strip()
        if body.startswith("/"):
            return True
        if self._message_is_reply_to_bot(data):
            return True
        if self._message_mentions_bot(data):
            return True
        return self._message_matches_mention_patterns(data)

    # ------------------------------------------------------------------ formatting
    def format_message(self, content: str) -> str:
        """Convert standard markdown to WhatsApp-compatible formatting.

        WhatsApp supports: *bold*, _italic_, ~strikethrough~, ```code```,
        and monospaced `inline`. Standard markdown uses different syntax
        for bold/italic/strikethrough, so we convert here.

        Code blocks (``` fenced) and inline code (`) are protected from
        conversion via placeholder substitution.
        """
        if not content:
            return content

        content = self._sanitize_outbound_text(content)

        # --- 1. Protect fenced code blocks from formatting changes ---
        _FENCE_PH = "\x00FENCE"
        fences: list[str] = []

        def _save_fence(m: re.Match) -> str:
            fences.append(m.group(0))
            return f"{_FENCE_PH}{len(fences) - 1}\x00"

        result = re.sub(r"```[\s\S]*?```", _save_fence, content)

        # --- 2. Protect inline code ---
        _CODE_PH = "\x00CODE"
        codes: list[str] = []

        def _save_code(m: re.Match) -> str:
            codes.append(m.group(0))
            return f"{_CODE_PH}{len(codes) - 1}\x00"

        result = re.sub(r"`[^`\n]+`", _save_code, result)

        # --- 3. Convert markdown formatting to WhatsApp syntax ---
        # Italic: standard Markdown *text* → WhatsApp _text_.  Do this before
        # bold conversion so **bold** does not become italic by accident.  The
        # lookarounds avoid list bullets and bold delimiters.
        result = re.sub(
            r"(?<!\*)\*(?!\s|\*)([^*\n]*?\S[^*\n]*?)\*(?!\*)",
            r"_\1_",
            result,
        )
        # Bold: **text** or __text__ → *text*
        result = re.sub(r"\*\*(.+?)\*\*", r"*\1*", result)
        result = re.sub(r"__(.+?)__", r"*\1*", result)
        # Strikethrough: ~~text~~ → ~text~
        result = re.sub(r"~~(.+?)~~", r"~\1~", result)
        # _text_ is already WhatsApp italic — leave as-is

        # --- 4. Convert markdown headers to bold text ---
        # # Header → *Header*. Strip any *...* wrapping already produced
        # by step 3 (e.g. "# **Title**" → "*Title*", not "**Title**",
        # which WhatsApp renders with literal asterisks).
        def _header_to_bold(m: re.Match) -> str:
            inner = m.group(1).strip()
            while len(inner) > 1 and inner.startswith("*") and inner.endswith("*"):
                inner = inner[1:-1].strip()
            return f"*{inner}*"

        result = re.sub(
            r"^#{1,6}\s+(.+)$", _header_to_bold, result, flags=re.MULTILINE
        )

        # --- 5. Convert markdown links: [text](url) → text (url) ---
        result = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1 (\2)", result)

        # --- 6. Restore protected sections ---
        for i, fence in enumerate(fences):
            result = result.replace(f"{_FENCE_PH}{i}\x00", fence)
        for i, code in enumerate(codes):
            result = result.replace(f"{_CODE_PH}{i}\x00", code)

        return result


# ---------------------------------------------------------------------------
# Shared bridge directory resolution for CLI and adapter
# ---------------------------------------------------------------------------

def resolve_whatsapp_bridge_dir() -> Path:
    """Resolve only a reviewed writable source or its atomic verified mirror."""
    from pathlib import Path as _Path

    # Default location in install tree (may be read-only)
    from hermes_constants import get_hermes_home
    install_bridge = _Path(__file__).resolve().parents[2] / "scripts" / "whatsapp-bridge"

    hermes_home = get_hermes_home()

    # Snapshot and verify the complete reviewed source before either returning
    # it or using its bytes to construct a writable mirror.
    _reviewed_bridge_files(install_bridge)

    install_writable = _install_bridge_is_writable(install_bridge)

    if install_writable:
        return install_bridge
    # Never fall back to a stale static mirror or to a read-only tree that the
    # adapter may need to mutate with npm ci. Synchronization failures are
    # explicit fail-closed startup failures.
    return _publish_reviewed_bridge_mirror(install_bridge, hermes_home)
