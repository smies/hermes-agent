"""Incremental normalization from model Markdown to phone-friendly speech."""

from __future__ import annotations

import html
import re


_FENCED = re.compile(r"```[\s\S]*?```", re.MULTILINE)
_URL = re.compile(
    r"(?:(?:https?://|www\.)\S+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?)",
    re.IGNORECASE,
)
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\((?:[^)]+)\)")
_INLINE_CODE = re.compile(r"`([^`]+)`")
_HEADING_OR_LIST = re.compile(r"(?m)^\s{0,3}(?:#{1,6}|[-*+] |\d+[.)] )\s*")
_EMPHASIS = re.compile(r"[*_~]{1,3}")
_SPACE = re.compile(r"\s+")


def phone_friendly_text(text: str) -> str:
    """Remove presentation syntax that sounds bad or unsafe over TTS."""
    text = html.unescape(str(text or ""))
    text = _FENCED.sub(" Code omitted for the phone conversation. ", text)
    text = _MARKDOWN_LINK.sub(r"\1, a link", text)
    text = _URL.sub("a link", text)
    text = _INLINE_CODE.sub(r"\1", text)
    text = _HEADING_OR_LIST.sub("", text)
    text = _EMPHASIS.sub("", text)
    text = text.replace("|", ", ").replace(">", "")
    return _SPACE.sub(" ", text).strip()


class StreamingSpeech:
    """Buffer partial tokens until a safe phrase boundary before speaking."""

    def __init__(self, max_buffer: int = 160):
        self._raw_seen = ""
        self._pending = ""
        self._lex_tail = ""
        self._in_fence = False
        self.max_buffer = max(48, int(max_buffer))

    def update(self, accumulated: str, *, final: bool = False) -> list[str]:
        accumulated = str(accumulated or "")
        if accumulated.startswith(self._raw_seen):
            delta = accumulated[len(self._raw_seen) :]
        else:
            # A provider correction/reset must never replay already spoken
            # text or expose a partially rewritten URL/code span.
            delta = ""
        self._raw_seen = accumulated
        self._ingest(delta, final=final)

        chunks: list[str] = []
        while self._pending:
            boundary = self._boundary(final=final)
            if boundary <= 0:
                break
            raw = self._pending[:boundary]
            self._pending = self._pending[boundary:]
            normalized = phone_friendly_text(raw)
            if normalized:
                chunks.append(normalized + (" " if not final else ""))
        return chunks

    def _ingest(self, delta: str, *, final: bool) -> None:
        """Remove fenced code incrementally, even when delimiters split."""
        source = self._lex_tail + delta
        self._lex_tail = ""
        while source:
            marker = source.find("```")
            if marker < 0:
                if final:
                    if not self._in_fence:
                        self._pending += source
                    elif source:
                        self._pending += " Code omitted for the phone conversation. "
                    self._in_fence = False
                elif len(source) <= 2:
                    self._lex_tail = source
                else:
                    stable, self._lex_tail = source[:-2], source[-2:]
                    if not self._in_fence:
                        self._pending += stable
                return
            before, source = source[:marker], source[marker + 3 :]
            if not self._in_fence:
                self._pending += before
                self._in_fence = True
            else:
                self._pending += " Code omitted for the phone conversation. "
                self._in_fence = False

    def _boundary(self, *, final: bool) -> int:
        if final:
            return len(self._pending)
        # Punctuation followed by whitespace is safe for URLs and Markdown.
        match = re.search(r"[.!?;:]\s", self._pending)
        if match:
            return match.end()
        if len(self._pending) >= self.max_buffer:
            index = self._pending.rfind(" ", 0, self.max_buffer + 1)
            if index > 0:
                return index + 1
            return self.max_buffer
        return 0
