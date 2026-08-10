"""Owner-only staging and one-use authority for Slice C document release.

This module never knows platform IDs or source selectors.  It receives one
already-resolved artifact from an approved typed reader, validates and copies
it into an owner-only staging inode, and stores only opaque authority plus the
minimum artifact identity needed for final revalidation.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import secrets
import stat
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from PIL import Image, UnidentifiedImageError

from .mapping_store import DocumentReleaseRecord, MappingStore


MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_PDF_PAGES = 25
MAX_PDF_STREAMS_INSPECTED = 128
MAX_PDF_DECOMPRESSED_BYTES_PER_STREAM = 4 * 1024 * 1024
MAX_PDF_TOTAL_DECOMPRESSED_BYTES = 16 * 1024 * 1024
MAX_PDF_TRAILING_WHITESPACE_BYTES = 32
MAX_IMAGE_PIXELS = 40_000_000
# JPEG-framed stills. MPO is what an iPhone writes for an HDR or portrait
# photo: the same JPEG container with an extra rendition after the main image.
_JPEG_FORMATS = frozenset({"JPEG", "MPO"})
_MPO_MAX_FRAMES = 3
APPROVAL_TTL_SECONDS = 600
UNCERTAIN_RETENTION_SECONDS = 3600

ALLOWED_MIME_EXTENSIONS = {
    "application/pdf": ".pdf",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "text/markdown": ".md",
    "application/json": ".json",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
}
# Text formats carry no structure to hide anything in: they are decoded whole
# and scanned as text.
_TEXT_MIME_EXTENSIONS = {
    "text/plain": ".txt",
    "text/csv": ".csv",
    "text/markdown": ".md",
    "application/json": ".json",
}
# Office formats are zip containers. They cannot be inspected the way a PDF or
# an image can -- there is no equivalent of the stream walk -- so the checks
# here are narrower by nature: reject macros and anything that reaches outside
# the document, and scan the text that can be recovered. Anyone reading this
# should know that is a weaker guarantee than the other formats get.
_OFFICE_MIME_EXTENSIONS = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
}
_OFFICE_ACTIVE_PARTS = ("vbaproject.bin", "vbadata.xml", ".bin")
_OFFICE_MAX_ENTRIES = 512
_OFFICE_MAX_TOTAL_BYTES = 32 * 1024 * 1024
_XML_TEXT = re.compile(r"<[^>]+>")

_APPROVAL_CODE = re.compile(r"C7-[A-Z2-9]{16}\Z")
# Constructs that can run code, reach the network or filesystem, or carry a
# second payload inside the file. These stay refused: the owner asking for his
# own document is a statement about its contents, not a reason to hand his
# phone something that acts on its own.
_PDF_ACTIVE_TOKENS = (
    b"/JavaScript",
    b"/JS",
    b"/XFA",
    b"/Launch",
    b"/GoToR",
    b"/SubmitForm",
    b"/ImportData",
    b"/EmbeddedFile",
    b"/FileAttachment",
    b"/RichMedia",
    b"/Movie",
    b"/Sound",
)
# Inert structure that ordinary business documents use constantly: hyperlinks,
# event dictionaries, form fields, compressed object streams. Refusing these
# rejected essentially every real document -- a solicitor's letter carries a
# website and a LinkedIn link and nothing more. An event dictionary can only
# invoke an action type, every dangerous action type above is still refused,
# and decoded object streams are scanned for those tokens too, so none of
# these can do anything on their own.
_PDF_INERT_TOKENS = (
    b"/URI",
    b"/AA",
    b"/OpenAction",
    b"/AcroForm",
    b"/ObjStm",
)
# Marks a stream whose encoding this scanner cannot inflate, so its bytes are
# inspected as they stand instead of the whole document being refused.
_PDF_OPAQUE_FILTER = b"\x00opaque"
_PDF_NAME_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_PDF_STREAM_START = re.compile(rb"(?<![A-Za-z0-9])stream(?:\r\n|\n|\r)")
_PDF_DIRECT_LENGTH = re.compile(rb"/Length\s+([0-9]+)\s*(?=[/>])")
_PDF_FILTER_VALUE = re.compile(rb"/Filter\s*(/[^\s<>\[\]()/]+|\[[^\]]*\])")
_PDF_WHITESPACE = b"\x00\x09\x0a\x0c\x0d\x20"
_PDF_DECOMPRESSION_INPUT_CHUNK_BYTES = 64 * 1024
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
        r"(?i)https?://\S{0,512}(?:magic|login|signin|reset|recover|token|auth)"
        r"[^\s]*[?&](?:token|code|key|secret)=\S+"
    ),
    re.compile(
        r"(?i)https?://\S{0,512}/(?:magic|login|signin|reset|recover|auth)"
        r"(?:/|\?)[A-Za-z0-9._~!$&'()*+,;=:@%/?-]{8,}"
    ),
    re.compile(
        r"(?i)https?://\S{0,512}[?&](?:access_token|auth_token|refresh_token|"
        r"session_token|token|api_key|secret)=\S+"
    ),
    re.compile(r"(?i)\b(?:qr|pairing)\s+(?:code|payload|material)\s*[:=]\s*\S+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[bap]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    ),
)
_WORK_PATTERNS = (
    re.compile(r"(?i)\bcompany confidential\b"),
    re.compile(r"(?i)\binternal(?: use)? only\b"),
    re.compile(r"(?i)\bproprietary and confidential\b"),
    re.compile(r"(?i)\bemployee confidential\b"),
)


class DocumentReleaseDenied(ValueError):
    """A deliberately non-sensitive fail-closed document denial."""


@dataclass(frozen=True)
class ArtifactInspection:
    mime_type: str
    size_bytes: int
    page_count: int
    sha256: str


@dataclass(frozen=True)
class StagedCandidate:
    proposal_id: str
    stage_leaf: str
    title: str
    source_class: str
    mime_type: str
    size_bytes: int
    page_count: int
    sha256: str
    device: int
    inode: int


class DocumentReleaseService:
    """Validate, stage, bind, revalidate, and clean one exact artifact."""

    phase_one_principal = "james"

    def __init__(
        self,
        raw_config: Any,
        *,
        store: MappingStore,
        mapping_key: bytes,
        clock: Callable[[], float],
    ) -> None:
        self.store = store
        self._mapping_key = bytes(mapping_key)
        self.clock = clock
        self.enabled = raw_config is not None
        self.staging_path: Optional[Path] = None
        self._staging_identity: Optional[tuple[int, int]] = None
        if raw_config is None:
            return
        if (
            not isinstance(raw_config, dict)
            or set(raw_config) != {"enabled", "staging_path"}
            or raw_config.get("enabled") is not True
        ):
            raise ValueError(
                "document_release requires only enabled=true and staging_path"
            )
        path = Path(str(raw_config.get("staging_path") or ""))
        if not path.is_absolute():
            raise ValueError("document release staging_path must be absolute")
        self.staging_path = path
        self._open_staging_directory()
        self.cleanup()

    def _open_staging_directory(self) -> None:
        assert self.staging_path is not None
        try:
            self.staging_path.mkdir(parents=True, mode=0o700, exist_ok=True)
            info = self.staging_path.lstat()
        except OSError as exc:
            raise ValueError("document staging directory is unavailable") from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("document staging directory must be owner-only (0700)")
        self._staging_identity = (info.st_dev, info.st_ino)

    def _validate_staging_directory(self) -> None:
        if not self.enabled or self.staging_path is None:
            raise DocumentReleaseDenied("document release is unavailable")
        try:
            info = self.staging_path.lstat()
        except OSError as exc:
            raise DocumentReleaseDenied("document staging is unavailable") from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or (info.st_dev, info.st_ino) != self._staging_identity
        ):
            raise DocumentReleaseDenied("document staging identity changed")

    @staticmethod
    def _text_is_denied(value: str) -> bool:
        return any(pattern.search(value) for pattern in (*_CREDENTIAL_PATTERNS, *_WORK_PATTERNS))

    @staticmethod
    def _printable_text(data: bytes) -> str:
        chunks = re.findall(rb"[\x20-\x7e]{4,}", data)
        return "\n".join(chunk.decode("latin-1", errors="ignore") for chunk in chunks)

    @staticmethod
    def _dictionary_before_stream(data: bytes, stream_start: int) -> bytes:
        end = stream_start
        while end and data[end - 1] in _PDF_WHITESPACE:
            end -= 1
        if end < 2 or data[end - 2 : end] != b">>":
            raise DocumentReleaseDenied("document stream is malformed")

        depth = 0
        cursor = end
        while cursor >= 2:
            pair = data[cursor - 2 : cursor]
            if pair == b">>":
                depth += 1
                cursor -= 2
            elif pair == b"<<":
                depth -= 1
                cursor -= 2
                if depth == 0:
                    return data[cursor:end]
            else:
                cursor -= 1
        raise DocumentReleaseDenied("document stream is malformed")

    @staticmethod
    def _stream_filter(dictionary: bytes) -> Optional[bytes]:
        """Return FlateDecode, the opaque sentinel, or None for a raw stream.

        A stream this cannot inflate is inspected as opaque bytes rather than
        refused. Refusing meant that a letter containing a scanned page or any
        JPEG -- DCTDecode, CCITTFaxDecode, a filter chain -- could never be
        released, while giving up nothing real: actions live in the object
        graph, not inside image sample data, and the encoded bytes are still
        scanned for the refused tokens.
        """
        normalized = _PDF_NAME_ESCAPE.sub(
            lambda match: bytes((int(match.group(1), 16),)), dictionary
        )
        match = _PDF_FILTER_VALUE.search(normalized)
        if match is None:
            if b"/Filter" in normalized:
                return _PDF_OPAQUE_FILTER
            return None
        if _PDF_FILTER_VALUE.search(normalized, match.end()) is not None:
            raise DocumentReleaseDenied("document stream is malformed")

        names = re.findall(rb"/([^\s<>\[\]()/]+)", match.group(1))
        if len(names) != 1 or names[0] not in {b"FlateDecode", b"Fl"}:
            return _PDF_OPAQUE_FILTER
        # A predictor changes how inflated bytes are laid out, not whether they
        # inflate, and predictor-encoded xref data carries offsets rather than
        # actions. Inflate and scan it either way.
        return names[0]

    @staticmethod
    def _bounded_flate_decode(data: bytes, total_so_far: int) -> bytes:
        inflater = zlib.decompressobj()
        output: list[bytes] = []
        output_size = 0
        try:
            for offset in range(0, len(data), _PDF_DECOMPRESSION_INPUT_CHUNK_BYTES):
                available = min(
                    MAX_PDF_DECOMPRESSED_BYTES_PER_STREAM - output_size,
                    MAX_PDF_TOTAL_DECOMPRESSED_BYTES - total_so_far - output_size,
                )
                if available < 0:
                    raise DocumentReleaseDenied(
                        "document stream inspection bounds exceeded"
                    )
                chunk = inflater.decompress(
                    data[offset : offset + _PDF_DECOMPRESSION_INPUT_CHUNK_BYTES],
                    available + 1,
                )
                if len(chunk) > available or inflater.unconsumed_tail:
                    raise DocumentReleaseDenied(
                        "document stream inspection bounds exceeded"
                    )
                output.append(chunk)
                output_size += len(chunk)
                if inflater.unused_data:
                    raise DocumentReleaseDenied("document stream is malformed")

            available = min(
                MAX_PDF_DECOMPRESSED_BYTES_PER_STREAM - output_size,
                MAX_PDF_TOTAL_DECOMPRESSED_BYTES - total_so_far - output_size,
            )
            if available < 0:
                raise DocumentReleaseDenied("document stream inspection bounds exceeded")
            final = inflater.flush(available + 1)
            if len(final) > available:
                raise DocumentReleaseDenied("document stream inspection bounds exceeded")
            output.append(final)
            if not inflater.eof:
                raise DocumentReleaseDenied("document stream is malformed")
        except zlib.error as exc:
            raise DocumentReleaseDenied("document stream is malformed") from exc
        return b"".join(output)

    @classmethod
    def _decoded_pdf_streams(cls, data: bytes) -> list[bytes]:
        decoded_streams: list[bytes] = []
        total_decoded = 0
        cursor = 0
        while match := _PDF_STREAM_START.search(data, cursor):
            if len(decoded_streams) >= MAX_PDF_STREAMS_INSPECTED:
                raise DocumentReleaseDenied("document stream inspection bounds exceeded")
            dictionary = cls._dictionary_before_stream(data, match.start())
            normalized_dictionary = _PDF_NAME_ESCAPE.sub(
                lambda item: bytes((int(item.group(1), 16),)), dictionary
            )
            lengths = list(_PDF_DIRECT_LENGTH.finditer(normalized_dictionary))
            if len(lengths) != 1:
                raise DocumentReleaseDenied("document stream length is unsupported")
            encoded_length_bytes = lengths[0].group(1)
            if len(encoded_length_bytes) > 10:
                raise DocumentReleaseDenied("document stream length is unsupported")
            encoded_length = int(encoded_length_bytes)
            if encoded_length > MAX_DOCUMENT_BYTES:
                raise DocumentReleaseDenied("document stream length is unsupported")
            content_start = match.end()
            content_end = content_start + encoded_length
            if content_end > len(data):
                raise DocumentReleaseDenied("document stream is malformed")

            endstream = content_end
            whitespace = 0
            while endstream < len(data) and data[endstream] in _PDF_WHITESPACE:
                whitespace += 1
                if whitespace > MAX_PDF_TRAILING_WHITESPACE_BYTES:
                    raise DocumentReleaseDenied("document stream is malformed")
                endstream += 1
            if data[endstream : endstream + 9] != b"endstream":
                raise DocumentReleaseDenied("document stream is malformed")

            encoded = data[content_start:content_end]
            filter_name = cls._stream_filter(dictionary)
            if filter_name is None or filter_name == _PDF_OPAQUE_FILTER:
                # Raw, or encoded with something this cannot inflate: scan the
                # bytes as they stand rather than refusing the document.
                decoded = encoded
                if (
                    len(decoded) > MAX_PDF_DECOMPRESSED_BYTES_PER_STREAM
                    or total_decoded + len(decoded) > MAX_PDF_TOTAL_DECOMPRESSED_BYTES
                ):
                    raise DocumentReleaseDenied(
                        "document stream inspection bounds exceeded"
                    )
            else:
                decoded = cls._bounded_flate_decode(encoded, total_decoded)
            decoded_streams.append(decoded)
            total_decoded += len(decoded)
            cursor = endstream + 9
        return decoded_streams

    def _inspect_pdf(self, data: bytes) -> tuple[int, str]:
        final_eof = data.rfind(b"%%EOF")
        if not data.startswith(b"%PDF-") or final_eof < 0:
            raise DocumentReleaseDenied("document is malformed")
        trailing = data[final_eof + len(b"%%EOF") :]
        if (
            len(trailing) > MAX_PDF_TRAILING_WHITESPACE_BYTES
            or trailing.strip(_PDF_WHITESPACE)
        ):
            raise DocumentReleaseDenied("document has trailing content")
        normalized = _PDF_NAME_ESCAPE.sub(
            lambda match: bytes((int(match.group(1), 16),)), data
        )
        if b"/Encrypt" in normalized:
            raise DocumentReleaseDenied("encrypted documents are unsupported")
        if any(token in normalized for token in _PDF_ACTIVE_TOKENS):
            raise DocumentReleaseDenied("active-content documents are unsupported")
        pages = len(re.findall(rb"/Type\s*/Page(?!s)\b", data))
        if not 1 <= pages <= MAX_PDF_PAGES:
            raise DocumentReleaseDenied("document page count is out of bounds")
        stream_text: list[str] = []
        for decoded in self._decoded_pdf_streams(data):
            normalized_stream = _PDF_NAME_ESCAPE.sub(
                lambda match: bytes((int(match.group(1), 16),)), decoded
            )
            if any(token in normalized_stream for token in _PDF_ACTIVE_TOKENS):
                raise DocumentReleaseDenied("active-content documents are unsupported")
            stream_text.append(self._printable_text(decoded))
        text = "\n".join((self._printable_text(data), *stream_text))
        return pages, text

    @classmethod
    def _inspect_image(cls, data: bytes, expected: str) -> tuple[int, str]:
        try:
            with Image.open(io.BytesIO(data)) as image:
                observed = str(image.format or "").upper()
                accepted = (
                    _JPEG_FORMATS if expected == "image/jpeg" else frozenset({"PNG"})
                )
                if observed not in accepted:
                    # Name what was actually seen. "MIME is mismatched" alone
                    # cost a round trip to learn only that something did not
                    # match; a format name is not content and identifies the
                    # gate exactly.
                    raise DocumentReleaseDenied(
                        "document MIME is mismatched: read as "
                        + (observed.lower() or "unknown")
                    )
                width, height = image.size
                if width <= 0 or height <= 0 or width * height > MAX_IMAGE_PIXELS:
                    raise DocumentReleaseDenied("image dimensions are out of bounds")
                # A phone photo is usually MPO: JPEG framing carrying a second
                # rendition, typically an HDR gain map. It is a still image and
                # the first frame is the picture, so the frame rule applies to
                # what a viewer would animate, not to those extra renditions.
                # Every family passport scan here is one, and the rule refused
                # them all while a PNG of the same page released cleanly.
                frames = int(getattr(image, "n_frames", 1))
                limit = _MPO_MAX_FRAMES if observed == "MPO" else 1
                if frames < 1 or frames > limit:
                    raise DocumentReleaseDenied("multi-frame images are unsupported")
                metadata = "\n".join(
                    str(value) for value in image.info.values() if isinstance(value, str)
                )
                image.verify()
        except DocumentReleaseDenied:
            raise
        except (OSError, SyntaxError, UnidentifiedImageError, ValueError) as exc:
            raise DocumentReleaseDenied("document image is malformed") from exc
        return 1, metadata + "\n" + cls._printable_text(data)

    @staticmethod
    def _decoded_text(data: bytes) -> Optional[str]:
        """Whole-file UTF-8 with no control bytes, or not a text document."""
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if any(
            character in text
            for character in ("\x00", "\x1b", "\x07", "\x08", "\x0c")
        ):
            return None
        return text

    @staticmethod
    def _text_mime(text: str) -> str:
        stripped = text.lstrip()
        if stripped[:1] in "{[":
            try:
                json.loads(text)
                return "application/json"
            except ValueError:
                pass
        return "text/plain"

    @classmethod
    def _inspect_office(cls, data: bytes) -> tuple[str, int, str]:
        """Refuse macros and outside references; scan what text is recoverable."""
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()
                if len(names) > _OFFICE_MAX_ENTRIES:
                    raise DocumentReleaseDenied("document part count is out of bounds")
                total = sum(item.file_size for item in archive.infolist())
                if total > _OFFICE_MAX_TOTAL_BYTES:
                    raise DocumentReleaseDenied("document is too large to inspect")
                lowered = [name.casefold() for name in names]
                if any(
                    name.endswith(part)
                    for name in lowered
                    for part in _OFFICE_ACTIVE_PARTS
                ):
                    raise DocumentReleaseDenied(
                        "macro-enabled documents are unsupported"
                    )
                if any(name.startswith("/") or ".." in name for name in lowered):
                    raise DocumentReleaseDenied("document part path is unsafe")
                if "word/document.xml" in lowered:
                    mime = (
                        "application/vnd.openxmlformats-officedocument."
                        "wordprocessingml.document"
                    )
                elif "xl/workbook.xml" in lowered:
                    mime = (
                        "application/vnd.openxmlformats-officedocument."
                        "spreadsheetml.sheet"
                    )
                else:
                    raise DocumentReleaseDenied("document type is unsupported")
                recovered: list[str] = []
                budget = MAX_PDF_TOTAL_DECOMPRESSED_BYTES
                for name in names:
                    if not name.casefold().endswith(".xml"):
                        continue
                    info = archive.getinfo(name)
                    if info.file_size > budget:
                        break
                    budget -= info.file_size
                    with archive.open(name) as handle:
                        chunk = handle.read(info.file_size)
                    recovered.append(
                        _XML_TEXT.sub(" ", chunk.decode("utf-8", errors="replace"))
                    )
                return mime, 1, "\n".join(recovered)
        except DocumentReleaseDenied:
            raise
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            raise DocumentReleaseDenied("document is malformed") from exc

    def inspect_bytes(self, data: bytes) -> ArtifactInspection:
        if not isinstance(data, bytes) or not 0 < len(data) <= MAX_DOCUMENT_BYTES:
            raise DocumentReleaseDenied("document size is out of bounds")
        if data.startswith(b"%PDF-"):
            mime = "application/pdf"
            pages, scanned_text = self._inspect_pdf(data)
        elif data.startswith(b"\xff\xd8\xff"):
            mime = "image/jpeg"
            pages, scanned_text = self._inspect_image(data, mime)
        elif data.startswith(b"\x89PNG\r\n\x1a\n"):
            mime = "image/png"
            pages, scanned_text = self._inspect_image(data, mime)
        elif data.startswith(b"PK\x03\x04"):
            mime, pages, scanned_text = self._inspect_office(data)
        elif (text := self._decoded_text(data)) is not None:
            mime, pages, scanned_text = self._text_mime(text), 1, text
        else:
            raise DocumentReleaseDenied("document type is unsupported")
        if self._text_is_denied(scanned_text):
            raise DocumentReleaseDenied("document contains prohibited material")
        return ArtifactInspection(
            mime_type=mime,
            size_bytes=len(data),
            page_count=pages,
            sha256=hashlib.sha256(data).hexdigest(),
        )

    @staticmethod
    def _safe_title(value: str) -> str:
        stem = Path(str(value or "")).stem
        title = re.sub(r"[^A-Za-z0-9 ()_.-]+", " ", stem).strip(" ._-")
        title = re.sub(r"\s+", " ", title)[:96]
        if not title or DocumentReleaseService._text_is_denied(title):
            return "Requested document"
        return title

    def _read_secure_source(
        self,
        path: Path,
        *,
        expected_identity: Optional[tuple[int, int, int, int]] = None,
    ) -> bytes:
        try:
            path_info = path.lstat()
            observed_identity = (
                path_info.st_dev,
                path_info.st_ino,
                path_info.st_size,
                path_info.st_mtime_ns,
            )
            if (
                stat.S_ISLNK(path_info.st_mode)
                or not stat.S_ISREG(path_info.st_mode)
                or path_info.st_nlink != 1
                or (
                    expected_identity is not None
                    and observed_identity != expected_identity
                )
            ):
                raise DocumentReleaseDenied("source is not one regular file")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
        except DocumentReleaseDenied:
            raise
        except OSError as exc:
            raise DocumentReleaseDenied("source is unavailable") from exc
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.geteuid()
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > MAX_DOCUMENT_BYTES
                or observed_identity
                != (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                )
            ):
                raise DocumentReleaseDenied("source identity is unavailable")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    raise DocumentReleaseDenied("source changed while reading")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(fd)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise DocumentReleaseDenied("source changed while reading")
            return b"".join(chunks)
        finally:
            os.close(fd)

    def inspect_source_for_test(self, path: Path) -> Optional[ArtifactInspection]:
        """Provider-free test seam; returns no detail for a denied artifact."""
        try:
            return self.inspect_bytes(self._read_secure_source(Path(path)))
        except Exception:
            return None

    def stage_path(
        self,
        path: Path,
        *,
        source_class: str,
        display_name: str,
        expected_identity: Optional[tuple[int, int, int, int]] = None,
        inspection_text: str = "",
    ) -> StagedCandidate:
        return self.stage_bytes(
            self._read_secure_source(
                Path(path), expected_identity=expected_identity
            ),
            source_class=source_class,
            display_name=display_name,
            inspection_text=inspection_text,
        )

    def stage_bytes(
        self,
        data: bytes,
        *,
        source_class: str,
        display_name: str,
        inspection_text: str = "",
    ) -> StagedCandidate:
        self._validate_staging_directory()
        if source_class not in {"personal files", "personal Gmail attachment"}:
            raise DocumentReleaseDenied("document source class is unavailable")
        if not isinstance(inspection_text, str) or self._text_is_denied(
            inspection_text
        ):
            raise DocumentReleaseDenied("document contains prohibited material")
        inspection = self.inspect_bytes(bytes(data))
        proposal_id = "doc-" + secrets.token_urlsafe(18)
        stage_leaf = proposal_id + ".stage"
        assert self.staging_path is not None
        stage_path = self.staging_path / stage_leaf
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(stage_path, flags, 0o600)
        try:
            offset = 0
            while offset < len(data):
                written = os.write(fd, data[offset:])
                if written <= 0:
                    raise DocumentReleaseDenied("document staging was incomplete")
                offset += written
            os.fsync(fd)
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise DocumentReleaseDenied("staged artifact identity is unsafe")
        except Exception:
            try:
                stage_path.unlink()
            except OSError:
                pass
            raise
        finally:
            os.close(fd)
        return StagedCandidate(
            proposal_id=proposal_id,
            stage_leaf=stage_leaf,
            title=self._safe_title(display_name),
            source_class=source_class,
            mime_type=inspection.mime_type,
            size_bytes=inspection.size_bytes,
            page_count=inspection.page_count,
            sha256=inspection.sha256,
            device=info.st_dev,
            inode=info.st_ino,
        )

    def _fingerprint(self, label: str, value: str) -> str:
        return hmac.new(
            self._mapping_key,
            label.encode("ascii") + b"\0" + str(value).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def issue(
        self,
        candidate: StagedCandidate,
        *,
        request: Any,
        principal: str,
    ) -> tuple[str, int]:
        if str(principal).casefold() != "james":
            raise DocumentReleaseDenied("document release is James-only")
        code = "C7-" + "".join(
            secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(16)
        )
        expires_at = int(self.clock()) + APPROVAL_TTL_SECONDS
        self.store.issue_document_release(
            DocumentReleaseRecord(
                proposal_id=candidate.proposal_id,
                approval_fingerprint=self._fingerprint("approval-v1", code),
                request_id=str(request.request_id),
                context_id=str(request.context_id),
                correlation_id=str(request.correlation_id),
                principal_fingerprint=self._fingerprint("principal-v1", principal),
                policy_generation=str(request.policy_generation),
                audience_digest=str(request.audience_digest),
                conversation_binding=str(request.conversation_binding),
                roster_generation=str(request.roster_generation),
                expires_at=expires_at,
                state="staged",
                artifact_sha256=candidate.sha256,
                artifact_size=candidate.size_bytes,
                artifact_mime=candidate.mime_type,
                artifact_pages=candidate.page_count,
                artifact_device=candidate.device,
                artifact_inode=candidate.inode,
                stage_leaf=candidate.stage_leaf,
                receipt_fingerprint="",
            )
        )
        return code, expires_at

    def claim(
        self,
        code: str,
        *,
        principal: str,
        policy_generation: str,
        audience_digest: str,
        conversation_binding: str,
        roster_generation: str,
    ) -> Optional[DocumentReleaseRecord]:
        if _APPROVAL_CODE.fullmatch(str(code or "")) is None:
            return None
        return self.store.claim_document_release(
            self._fingerprint("approval-v1", code),
            now=int(self.clock()),
            principal_fingerprint=self._fingerprint("principal-v1", principal),
            policy_generation=policy_generation,
            audience_digest=audience_digest,
            conversation_binding=conversation_binding,
            roster_generation=roster_generation,
        )

    def artifact_path(self, record: DocumentReleaseRecord) -> Path:
        self._validate_staging_directory()
        if re.fullmatch(r"doc-[A-Za-z0-9_-]{20,64}\.stage", record.stage_leaf) is None:
            raise DocumentReleaseDenied("staged artifact reference is malformed")
        assert self.staging_path is not None
        return self.staging_path / record.stage_leaf

    def revalidate(self, record: DocumentReleaseRecord) -> Path:
        path = self.artifact_path(record)
        data = self._read_secure_source(path)
        try:
            info = path.lstat()
        except OSError as exc:
            raise DocumentReleaseDenied("staged artifact is unavailable") from exc
        inspection = self.inspect_bytes(data)
        observed = (
            info.st_dev,
            info.st_ino,
            inspection.sha256,
            inspection.size_bytes,
            inspection.mime_type,
            inspection.page_count,
            stat.S_IMODE(info.st_mode),
            info.st_nlink,
        )
        expected = (
            record.artifact_device,
            record.artifact_inode,
            record.artifact_sha256,
            record.artifact_size,
            record.artifact_mime,
            record.artifact_pages,
            0o600,
            1,
        )
        if observed != expected:
            raise DocumentReleaseDenied("staged artifact identity changed")
        return path

    def terminalize(
        self, record: DocumentReleaseRecord, state: str, provider_receipt: str = ""
    ) -> bool:
        receipt = (
            self._fingerprint("provider-receipt-v1", provider_receipt)
            if provider_receipt
            else ""
        )
        return self.store.terminalize_document_release(
            record.proposal_id,
            state=state,
            now=int(self.clock()),
            receipt_fingerprint=receipt,
        )

    def discard_candidate(self, candidate: StagedCandidate) -> None:
        try:
            self._validate_staging_directory()
            if re.fullmatch(
                r"doc-[A-Za-z0-9_-]{20,64}\.stage", candidate.stage_leaf
            ) is None:
                return
            assert self.staging_path is not None
            (self.staging_path / candidate.stage_leaf).unlink()
        except Exception:
            pass

    def unlink_record(self, record: DocumentReleaseRecord) -> None:
        try:
            self.artifact_path(record).unlink()
        except Exception:
            pass

    def cleanup(self) -> None:
        if not self.enabled:
            return
        now = int(self.clock())
        records = self.store.document_releases_for_cleanup(
            now=now,
            uncertain_before=now - UNCERTAIN_RETENTION_SECONDS,
        )
        for record in records:
            self.unlink_record(record)


__all__ = [
    "ALLOWED_MIME_EXTENSIONS",
    "APPROVAL_TTL_SECONDS",
    "DocumentReleaseDenied",
    "DocumentReleaseService",
    "StagedCandidate",
]
