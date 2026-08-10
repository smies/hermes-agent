"""Slice C secure, audience-bound specific-document release tests.

All documents, transport identifiers, and provider results are synthetic. The
suite never contacts a provider and never uses the ordinary ``MEDIA:`` path.
"""

from __future__ import annotations

import copy
import io
import json
import zlib
from contextvars import copy_context
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image, PngImagePlugin

from gateway.config import Platform
from gateway.platforms.base import MessageEvent, SendResult
from gateway.session import SessionSource
from gateway.session_context import clear_session_vars, set_session_vars
from plugins.juno_kite_trusted_principal.disclosure import (
    DOCUMENT_DESCRIPTOR,
    disclosure_decision,
)
from plugins.juno_kite_trusted_principal.document_release import (
    DocumentReleaseDenied,
    MAX_PDF_DECOMPRESSED_BYTES_PER_STREAM,
)
from plugins.juno_kite_trusted_principal.runtime import TrustedPrincipalRuntime
from tests.plugins.test_juno_kite_slice_b import _slice_b_config


JAMES_PHONE = "14444444444@s.whatsapp.net"
JAMES_LID = "24444444444@lid"
UNKNOWN_PHONE = "15555555555@s.whatsapp.net"
BOT_PHONE = "19999999999@s.whatsapp.net"
BOT_LID = "29999999999@lid"
GROUP = "300000000000999@g.us"
OTHER_GROUP = "300000000000998@g.us"
RUNTIME_ID = "a" * 64


class Clock:
    def __init__(self) -> None:
        self.value = 1_900_000_000

    def __call__(self) -> float:
        return float(self.value)


class MutableRoster:
    def __init__(self) -> None:
        self.participants = [[JAMES_PHONE, JAMES_LID]]
        self.generation = "b" * 64
        self.missing = False
        self.calls = 0
        self.change_on_call: int | None = None

    def __call__(
        self,
        _profile="juno",
        chat_id=GROUP,
        *,
        timeout=2,
        expected_runtime_id=None,
        expected_socket_generation=None,
    ):
        self.calls += 1
        assert chat_id == GROUP
        assert timeout <= 2
        assert expected_runtime_id == RUNTIME_ID
        assert expected_socket_generation == 1
        if self.missing:
            raise RuntimeError("synthetic roster unavailable")
        if self.change_on_call == self.calls:
            self.participants.append([UNKNOWN_PHONE])
            self.generation = "c" * 64
        return {
            "group_id": GROUP,
            "participants": copy.deepcopy(self.participants),
            "bot_identities": [BOT_PHONE, BOT_LID],
            "generation": self.generation,
        }


class RecordingWhatsAppAdapter:
    def __init__(self, roster: MutableRoster) -> None:
        self.authenticated_group_roster = roster
        self.document_calls: list[dict] = []
        self.receipts: list[str] = []
        self.result = SendResult(success=True, message_id="provider-message-1")
        self.raise_on_send: Exception | None = None
        self.before_send = None

    async def send_document(self, **kwargs):
        if self.before_send is not None:
            self.before_send(kwargs)
        path = Path(kwargs["file_path"])
        self.document_calls.append({
            **kwargs,
            "bytes": path.read_bytes(),
            "mode": path.stat().st_mode & 0o777,
        })
        if self.raise_on_send is not None:
            raise self.raise_on_send
        return self.result

    async def send(self, *, chat_id, content, **_kwargs):
        assert chat_id == GROUP
        self.receipts.append(content)
        return SendResult(success=True, message_id="receipt-message")


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setenv("JK_MAPPING_KEY", "mapping-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_REQUEST_KEY", "request-key-with-at-least-thirty-two-bytes")
    monkeypatch.setenv("JK_RESPONSE_KEY", "response-key-with-at-least-thirty-two-bytes")


@pytest.fixture(autouse=True)
def _fresh_preview_cache():
    """No test inherits another's extraction.

    The document preview cache is process-global on purpose -- it exists so a
    later turn does not pay the recogniser again -- which means a test that
    stubs the reader would otherwise be answered by whatever an earlier test
    stubbed for the same bytes.
    """
    from plugins.juno_kite_trusted_principal import private_reads as pr

    pr._reset_document_preview_cache()
    yield
    pr._reset_document_preview_cache()


def _png_bytes(*, text: str = "family travel document") -> bytes:
    image = Image.new("RGB", (8, 8), color=(20, 40, 60))
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Description", text)
    output = io.BytesIO()
    image.save(output, format="PNG", pnginfo=metadata)
    return output.getvalue()


def _jpeg_bytes(*, comment: bytes = b"family property document") -> bytes:
    image = Image.new("RGB", (8, 8), color=(60, 40, 20))
    output = io.BytesIO()
    image.save(output, format="JPEG", comment=comment)
    return output.getvalue()


def _pdf_with_stream(
    payload: bytes,
    *,
    filter_name: bytes | None = b"FlateDecode",
    encoded_payload: bytes | None = None,
) -> bytes:
    encoded = (
        zlib.compress(payload)
        if encoded_payload is None and filter_name is not None
        else payload if encoded_payload is None else encoded_payload
    )
    filter_entry = b"" if filter_name is None else b"/Filter /" + filter_name + b" "
    return (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 10 10]"
        b"/Contents 4 0 R>>endobj\n"
        b"4 0 obj<<"
        + filter_entry
        + b"/Length "
        + str(len(encoded)).encode("ascii")
        + b">>\nstream\n"
        + encoded
        + b"\nendstream\nendobj\n%%EOF\n"
    )


def _config(tmp_path: Path, personal_root: Path, *, mode: str) -> dict:
    config = _slice_b_config(tmp_path, mode=mode)
    section = config["juno_kite_trusted_principal"]
    section["policy_generation"] = "slice-c-policy-v1"
    section["mapping_path"] = str(tmp_path / "authority" / "mapping.sqlite3")
    section["principal_bindings"] = [
        {"platform": "whatsapp", "user_id": JAMES_PHONE, "principal": "james"},
        {"platform": "whatsapp", "user_id": JAMES_LID, "principal": "james"},
    ]
    section["allowed_group_conversations"] = [
        {"platform": "whatsapp", "chat_id": GROUP}
    ]
    section["private_reads"]["files"] = {
        "roots": [{"name": "family", "path": str(personal_root)}],
        # Tests live under the OS temp area, which is deliberately not one of
        # the production document areas.
        "allowed_bases": [str(tmp_path), str(personal_root.parent)],
    }
    section["document_release"] = {
        "enabled": True,
        "staging_path": str(tmp_path / "authority" / "document-staging"),
    }
    return config


def _runtime(
    tmp_path: Path,
    personal_root: Path,
    *,
    mode: str,
    clock: Clock,
    backends=None,
) -> TrustedPrincipalRuntime:
    return TrustedPrincipalRuntime(
        _config(tmp_path, personal_root, mode=mode),
        active_profile=mode,
        clock=clock,
        private_read_backends=backends,
    )


def _event(text: str, *, sender=JAMES_PHONE, chat_id=GROUP) -> MessageEvent:
    return MessageEvent(
        text=text,
        message_id="opaque-inbound-message",
        source=SessionSource(
            platform=Platform.WHATSAPP,
            user_id=sender,
            chat_id=chat_id,
            user_name="untrusted display name",
            chat_type="group",
        ),
        metadata={
            "whatsapp_inbound_provenance": "messages.upsert:registered-emitting-socket:v1",
            "whatsapp_inbound_runtime_id": RUNTIME_ID,
            "whatsapp_inbound_socket_generation": 1,
        },
    )


def _session(callback, *, mode: str, context_id="", sender=JAMES_PHONE):
    def run():
        platform = "a2a" if mode == "kite" else "whatsapp"
        tokens = set_session_vars(
            platform=platform,
            source=platform,
            chat_id=context_id if mode == "kite" else GROUP,
            chat_type="dm" if mode == "kite" else "group",
            user_id="juno" if mode == "kite" else sender,
            session_key=(
                f"agent:kite:a2a:dm:{context_id}"
                if mode == "kite"
                else "agent:juno:whatsapp:group:opaque"
            ),
            session_id="kite-session" if mode == "kite" else "juno-session",
            profile=mode,
            cron_session="",
        )
        try:
            return callback()
        finally:
            clear_session_vars(tokens)

    return copy_context().run(run)


def _invoke(kite: TrustedPrincipalRuntime, name: str, args: dict):
    assert kite.pre_tool_call(
        name,
        args,
        session_id="kite-session",
        turn_id="kite-turn",
        tool_call_id="tool-call",
    ) is None
    assert kite.pre_tool_dispatch(
        name,
        args,
        session_id="kite-session",
        turn_id="kite-turn",
        tool_call_id="tool-call",
    ) is None
    return json.loads(
        kite.execute_private_read(
            name,
            args,
            session_id="kite-session",
            turn_id="kite-turn",
        )
    )


async def _propose(
    tmp_path: Path,
    root: Path,
    clock: Clock,
    roster: MutableRoster,
    adapter: RecordingWhatsAppAdapter,
    *,
    question="Send me the actual child passport scan",
    relative_path="child-passport.png",
    capability_id="juno.shared.children",
    purpose="family administration",
    search_query="passport",
):
    juno = _runtime(tmp_path, root, mode="juno", clock=clock)
    gateway = SimpleNamespace(adapters={Platform.WHATSAPP: adapter})
    ingress = await juno.pre_gateway_dispatch(
        event=_event(question), gateway=gateway, critical_ingress_token=object()
    )
    assert ingress["action"] == "critical_allow"
    prepared = _session(
        lambda: juno._prepare_request({"question_or_goal": question}), mode="juno"
    )

    kite = _runtime(tmp_path, root, mode="kite", clock=clock)

    def kite_turn():
        policy = kite.pre_llm_call(
            user_message=prepared.message,
            session_id="kite-session",
            turn_id="kite-turn",
        )
        assert "specific" in policy["context"]
        found = _invoke(
            kite,
            "kite_personal_files_read",
            {
                "operation": "search",
                "root": "family",
                "query": search_query,
                "max_results": 1,
            },
        )
        assert len(found["data"]) == 1
        candidate = _invoke(
            kite,
            "kite_personal_files_read",
            {
                "operation": "read",
                "root": "family",
                "relative_path": relative_path,
                "max_lines": 1,
            },
        )
        assert candidate["status"] == "ok"
        return kite.transform_llm_output(
            response_text=json.dumps({"capability_id": capability_id}),
            session_id="kite-session",
            turn_id="kite-turn",
        )

    envelope = _session(
        kite_turn, mode="kite", context_id=prepared.mapping.context_id
    )
    answer = _session(
        lambda: juno._verify_response(
            envelope, prepared.mapping, prepared.request_id
        ),
        mode="juno",
    )
    preview = json.loads(answer)
    assert preview["outcome"] == "approval_required"
    assert set(preview["document"]) == {
        "title",
        "source_class",
        "mime_type",
        "size_bytes",
        "page_count",
    }
    assert preview["audience"] == "James only in this WhatsApp conversation"
    assert preview["purpose"] == purpose
    assert preview["approval"]["instruction"] == (
        "APPROVE " + preview["approval"]["code"]
    )
    return juno, gateway, preview


@pytest.mark.asyncio
async def test_james_own_private_document_releases_on_a_display_verb(tmp_path):
    """James's own documents release back to James on natural phrasing.

    Two live defects met here: "Show me ..." had to reach the document tier,
    and juno.private.james had to be a releasable purpose in the runtime
    gate, not only in the disclosure oracle.
    """
    artifact = _png_bytes()
    root = tmp_path / "family"
    root.mkdir()
    (root / "engagement-letter.png").write_bytes(artifact)
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)

    juno, gateway, preview = await _propose(
        tmp_path,
        root,
        clock,
        roster,
        adapter,
        question="Show me the nacho engagement letter",
        relative_path="engagement-letter.png",
        capability_id="juno.private.james",
        purpose="personal administration",
        search_query="engagement",
    )
    code = preview["approval"]["code"]
    decision = await juno.pre_gateway_dispatch(
        event=_event(f"APPROVE {code}"), gateway=gateway
    )
    assert decision == {
        "action": "skip",
        "reason": "document-release-handled",
        "redact_scope": True,
    }
    assert len(adapter.document_calls) == 1
    assert adapter.document_calls[0]["bytes"] == artifact


@pytest.mark.asyncio
async def test_one_typed_artifact_stages_approves_and_delivers_once(tmp_path, caplog):
    artifact = _png_bytes()
    root = tmp_path / "family"
    root.mkdir()
    source = root / "child-passport.png"
    source.write_bytes(artifact)
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)

    juno, gateway, preview = await _propose(tmp_path, root, clock, roster, adapter)
    code = preview["approval"]["code"]
    decision = await juno.pre_gateway_dispatch(
        event=_event(f"APPROVE {code}"), gateway=gateway
    )
    assert decision == {
        "action": "skip",
        "reason": "document-release-handled",
        "redact_scope": True,
    }
    assert len(adapter.document_calls) == 1
    call = adapter.document_calls[0]
    assert call["chat_id"] == GROUP
    assert call["bytes"] == artifact
    assert call["mode"] == 0o600
    assert call["file_name"] == "requested-document.png"
    assert not Path(call["file_path"]).exists()
    assert adapter.receipts == ["Document delivered. Receipt: delivered."]

    replay = await juno.pre_gateway_dispatch(
        event=_event(f"APPROVE {code}"), gateway=gateway
    )
    assert replay["action"] == "skip"
    assert len(adapter.document_calls) == 1
    assert adapter.receipts[-1] == "Document release denied."

    visible = json.dumps(preview) + caplog.text + json.dumps(adapter.receipts)
    assert str(source) not in visible
    assert artifact.hex() not in visible
    assert "child-passport.png" not in caplog.text
    audit_bytes = (tmp_path / "authority" / "mapping.sqlite3").read_bytes()
    assert str(source).encode() not in audit_bytes
    assert source.name.encode() not in audit_bytes
    assert artifact not in audit_bytes


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    ["principal", "chat", "audience", "policy", "code", "expiry", "artifact", "destination"],
)
async def test_binding_mismatch_denies_before_document_transport(tmp_path, mutation):
    artifact = _png_bytes()
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(artifact)
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)
    juno, gateway, preview = await _propose(tmp_path, root, clock, roster, adapter)
    code = preview["approval"]["code"]
    event = _event(f"APPROVE {code}")

    if mutation == "principal":
        event = _event(f"APPROVE {code}", sender=UNKNOWN_PHONE)
    elif mutation == "chat":
        event = _event(f"APPROVE {code}", chat_id=OTHER_GROUP)
    elif mutation == "audience":
        roster.participants.append([UNKNOWN_PHONE])
        roster.generation = "c" * 64
    elif mutation == "policy":
        juno.policy_generation = "changed-policy"
    elif mutation == "code":
        event = _event("APPROVE C7-WRONGCODE99")
    elif mutation == "expiry":
        clock.value += 601
    elif mutation == "artifact":
        staged = next((tmp_path / "authority" / "document-staging").glob("*.stage"))
        staged.write_bytes(_png_bytes(text="changed artifact"))
    elif mutation == "destination":
        juno.allowed_group_conversations = frozenset()

    decision = await juno.pre_gateway_dispatch(event=event, gateway=gateway)
    assert decision["action"] == "skip"
    assert adapter.document_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("boundary", ["approval", "final_dispatch"])
async def test_membership_change_at_approval_or_final_dispatch_blocks_bytes(
    tmp_path, boundary
):
    artifact = _png_bytes()
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(artifact)
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)
    juno, gateway, preview = await _propose(tmp_path, root, clock, roster, adapter)
    roster.change_on_call = roster.calls + (1 if boundary == "approval" else 2)

    await juno.pre_gateway_dispatch(
        event=_event(f"APPROVE {preview['approval']['code']}"), gateway=gateway
    )
    assert adapter.document_calls == []


@pytest.mark.asyncio
async def test_membership_change_at_proposal_blocks_before_source_or_staging(tmp_path):
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)
    juno = _runtime(tmp_path, root, mode="juno", clock=clock)
    gateway = SimpleNamespace(adapters={Platform.WHATSAPP: adapter})
    result = await juno.pre_gateway_dispatch(
        event=_event("Send the actual child passport scan"), gateway=gateway
    )
    assert result["action"] == "critical_allow"
    roster.change_on_call = roster.calls + 1
    with pytest.raises(ValueError, match="audience changed"):
        _session(
            lambda: juno._prepare_request(
                {"question_or_goal": "Send the actual child passport scan"}
            ),
            mode="juno",
        )
    assert adapter.document_calls == []
    staging = tmp_path / "authority" / "document-staging"
    assert not staging.exists() or not list(staging.glob("*.stage"))


@pytest.mark.asyncio
async def test_ambiguous_provider_outcome_is_terminal_and_non_retrying(tmp_path):
    artifact = _png_bytes()
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(artifact)
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)
    adapter.raise_on_send = TimeoutError("synthetic uncertain outcome")
    juno, gateway, preview = await _propose(tmp_path, root, clock, roster, adapter)
    approval = _event(f"APPROVE {preview['approval']['code']}")

    await juno.pre_gateway_dispatch(event=approval, gateway=gateway)
    await juno.pre_gateway_dispatch(event=approval, gateway=gateway)
    assert len(adapter.document_calls) == 1
    assert adapter.receipts[0] == (
        "Document delivery uncertain. Receipt: uncertain; no retry will occur."
    )
    assert adapter.receipts[1] == "Document release denied."
    assert list((tmp_path / "authority" / "document-staging").glob("*.stage"))


def test_typed_resolver_has_one_closed_candidate_and_no_arbitrary_selectors(tmp_path):
    artifact = _png_bytes()
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(artifact)
    clock = Clock()
    gmail = SimpleNamespace(
        execute=lambda operation, _args: {
            "filename": "trip-confirmation.png",
            "mime_type": "image/png",
            "size_bytes": len(artifact),
            "text": "family travel confirmation",
            "artifact_bytes": artifact,
        }
        if operation == "attachment_extract"
        else []
    )
    runtime = _runtime(tmp_path, root, mode="kite", clock=clock, backends={"gmail": gmail})
    encoded, internal = runtime.private_reads.resolve_document_candidate(
        "kite_gmail_attachment_extract",
        {"account": "personal", "message_id": "message-1", "attachment_id": "attachment-1"},
    )
    candidate = json.loads(encoded)
    assert candidate["status"] == "ok"
    assert set(candidate["data"]) == {
        "outcome",
        "source_class",
        "document_name",
        "document_preview",
        "mime_type",
        "size_bytes",
    }
    # The name is the artifact's own, reduced; still no selector, path or bytes.
    assert candidate["data"]["document_name"]
    assert "/" not in candidate["data"]["document_name"]
    assert internal["bytes"] == artifact
    assert "message-1" not in encoded and "attachment-1" not in encoded

    blocked_gmail = SimpleNamespace(
        execute=lambda _operation, _args: {
            "filename": "trip-confirmation.png",
            "mime_type": "image/png",
            "size_bytes": len(artifact),
            "text": "OTP code: 123456",
            "artifact_bytes": artifact,
        }
    )
    blocked_runtime = _runtime(
        tmp_path / "blocked",
        root,
        mode="kite",
        clock=clock,
        backends={"gmail": blocked_gmail},
    )
    _blocked, blocked_internal = blocked_runtime.private_reads.resolve_document_candidate(
        "kite_gmail_attachment_extract",
        {
            "account": "personal",
            "message_id": "message-1",
            "attachment_id": "attachment-1",
        },
    )
    assert blocked_internal is not None
    with pytest.raises(DocumentReleaseDenied):
        blocked_runtime.document_releases.stage_bytes(
            blocked_internal["bytes"],
            source_class=blocked_internal["source_class"],
            display_name=blocked_internal["display_name"],
            inspection_text=blocked_internal["inspection_text"],
        )

    for tool, args in (
        ("kite_personal_files_read", {"operation": "search", "root": "family", "query": "passport", "max_results": 2}),
        ("kite_personal_files_read", {"operation": "read", "root": "family", "relative_path": "/etc/passwd"}),
        ("kite_personal_files_read", {"operation": "read", "root": "unknown-root", "relative_path": "child-passport.png"}),
        ("kite_gmail_attachment_extract", {"account": "work", "message_id": "message-1", "attachment_id": "attachment-1"}),
    ):
        denied, source = runtime.private_reads.resolve_document_candidate(tool, args)
        assert json.loads(denied)["status"] == "error"
        assert source is None

    assert not hasattr(runtime, "send_document")
    assert "send_message" not in runtime.private_read_tool_names
    assert all("media" not in name for name in runtime.private_read_tool_names)


@pytest.mark.parametrize(
    "name,payload",
    [
        ("oversize.png", b"\x89PNG\r\n\x1a\n" + b"x" * (8 * 1024 * 1024)),
        # NB: unrecognised bytes are deliberately carried now, not refused --
        # a name that disagrees with its content is caught by the resolver
        # instead (test_a_text_file_wearing_an_image_name_is_still_caught).
        ("executable.png", b"MZ" + b"\x00" * 200),
        ("encrypted.pdf", b"%PDF-1.7\n1 0 obj<</Encrypt 2 0 R>>endobj\n%%EOF"),
        ("active.pdf", b"%PDF-1.7\n1 0 obj<</JavaScript 2 0 R>>endobj\n%%EOF"),
        ("escaped-active.pdf", b"%PDF-1.7\n1 0 obj<</Java#53cript 2 0 R>>endobj\n%%EOF"),
        ("html.pdf", b"%PDF-1.7\n/OpenAction<</S/URI/URI(https://example.test)>>\n%%EOF"),
        ("too-many-pages.pdf", b"%PDF-1.7\n" + b"/Type /Page\n" * 26 + b"%%EOF"),
        ("malformed.pdf", b"%PDF-1.7\n/Type /Page\n"),
    ],
    ids=[
        "oversize",
        "executable-bytes",
        "encrypted-pdf",
        "active-pdf",
        "escaped-active-pdf",
        "uri-pdf",
        "page-limit",
        "malformed-pdf",
    ],
)
def test_format_gate_rejects_unsafe_artifacts_without_staging(tmp_path, name, payload):
    root = tmp_path / "family"
    root.mkdir()
    (root / name).write_bytes(payload)
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())
    assert runtime.document_releases.inspect_source_for_test(root / name) is None
    staging = tmp_path / "authority" / "document-staging"
    assert not staging.exists() or not list(staging.glob("*.stage"))


def test_format_gate_accepts_only_valid_png_jpeg_and_pdf(tmp_path):
    root = tmp_path / "family"
    root.mkdir()
    (root / "valid.png").write_bytes(_png_bytes())
    (root / "valid.jpg").write_bytes(_jpeg_bytes())
    # Small, inert one-page PDF fixture produced directly to avoid sanitizer behavior.
    (root / "valid.pdf").write_bytes(
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 10 10]>>endobj\n%%EOF"
    )
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())
    assert runtime.document_releases.inspect_source_for_test(root / "valid.png").mime_type == "image/png"
    assert runtime.document_releases.inspect_source_for_test(root / "valid.jpg").mime_type == "image/jpeg"
    assert runtime.document_releases.inspect_source_for_test(root / "valid.pdf").page_count == 1


@pytest.mark.parametrize(
    "payload",
    [
        b"BT (COMPANY CONFIDENTIAL: internal board pack) Tj ET",
        b"BT (api_key=AKIAIOSFODNN7EXAMPLE) Tj ET",
    ],
    ids=["work-marker", "credential"],
)
def test_format_gate_rejects_prohibited_text_in_flate_stream(tmp_path, payload):
    root = tmp_path / "family"
    root.mkdir()
    source = root / "blocked.pdf"
    source.write_bytes(_pdf_with_stream(payload))
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    assert runtime.document_releases.inspect_source_for_test(source) is None


@pytest.mark.parametrize(
    "token",
    [b"/JavaScript", b"/Java#53cript", b"/Launch", b"/EmbeddedFile", b"/SubmitForm"],
)
def test_format_gate_rejects_active_tokens_in_flate_stream(tmp_path, token):
    root = tmp_path / "family"
    root.mkdir()
    source = root / "active.pdf"
    source.write_bytes(_pdf_with_stream(b"BT " + token + b" ET"))
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    assert runtime.document_releases.inspect_source_for_test(source) is None


@pytest.mark.parametrize(
    "filter_name",
    [b"FlateDecode", b"Fl", None],
    ids=["flate", "flate-abbreviation", "unfiltered"],
)
def test_format_gate_accepts_benign_inspectable_streams(tmp_path, filter_name):
    root = tmp_path / "family"
    root.mkdir()
    source = root / "ordinary.pdf"
    source.write_bytes(
        _pdf_with_stream(
            b"BT (ordinary family travel itinerary) Tj ET",
            filter_name=filter_name,
        )
    )
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    assert runtime.document_releases.inspect_source_for_test(source).page_count == 1


@pytest.mark.parametrize(
    "payload",
    [
        _pdf_with_stream(
            b"unused",
            filter_name=b"FlateDecode",
            encoded_payload=b"not-a-zlib-stream",
        ),
    ],
    ids=["invalid-flate"],
)
def test_format_gate_rejects_uninspectable_streams(tmp_path, payload):
    root = tmp_path / "family"
    root.mkdir()
    source = root / "uninspectable.pdf"
    source.write_bytes(payload)
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    assert runtime.document_releases.inspect_source_for_test(source) is None


def test_format_gate_rejects_flate_stream_over_decompressed_byte_cap(tmp_path):
    root = tmp_path / "family"
    root.mkdir()
    source = root / "compression-bomb.pdf"
    source.write_bytes(
        _pdf_with_stream(b"A" * (MAX_PDF_DECOMPRESSED_BYTES_PER_STREAM + 1))
    )
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    with pytest.raises(DocumentReleaseDenied, match="stream inspection bounds"):
        runtime.document_releases.inspect_bytes(source.read_bytes())


def test_format_gate_rejects_bytes_after_final_pdf_eof(tmp_path):
    root = tmp_path / "family"
    root.mkdir()
    source = root / "polyglot.pdf"
    source.write_bytes(
        _pdf_with_stream(b"BT (ordinary family document) Tj ET")
        + b"<html><script>alert(1)</script></html>"
    )
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    assert runtime.document_releases.inspect_source_for_test(source) is None


def test_format_gate_rejects_symlink_nonregular_credentials_and_work(tmp_path):
    root = tmp_path / "family"
    root.mkdir()
    ordinary = root / "ordinary.png"
    ordinary.write_bytes(_png_bytes())
    (root / "link.png").symlink_to(ordinary)
    (root / "hardlink.png").hardlink_to(ordinary)
    (root / "folder.png").mkdir()
    (root / "credential.png").write_bytes(_png_bytes(text="OTP code: 123456"))
    (root / "work.png").write_bytes(_png_bytes(text="COMPANY CONFIDENTIAL internal only"))
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    for name in (
        "link.png",
        "hardlink.png",
        "folder.png",
        "credential.png",
        "work.png",
    ):
        assert runtime.document_releases.inspect_source_for_test(root / name) is None


@pytest.mark.parametrize(
    "text",
    [
        "api_key=synthetic-key",
        "session_cookie=synthetic-cookie",
        "pairing code: 987654",
        "QR payload: synthetic-qr-material",
        "https://login.invalid/magic?token=synthetic-token",
        "AKIAABCDEFGHIJKLMNOP",
    ],
)
def test_format_gate_rejects_authentication_material(tmp_path, text):
    root = tmp_path / "family"
    root.mkdir()
    source = root / "blocked.png"
    source.write_bytes(_png_bytes(text=text))
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())
    assert runtime.document_releases.inspect_source_for_test(source) is None


def test_source_identity_change_between_resolution_and_staging_denies(tmp_path):
    root = tmp_path / "family"
    root.mkdir()
    source = root / "child-passport.png"
    source.write_bytes(_png_bytes())
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())
    _encoded, internal = runtime.private_reads.resolve_document_candidate(
        "kite_personal_files_read",
        {
            "operation": "read",
            "root": "family",
            "relative_path": source.name,
        },
    )
    assert internal is not None
    source.unlink()
    source.write_bytes(_png_bytes(text="changed after resolution"))

    with pytest.raises(DocumentReleaseDenied):
        runtime.document_releases.stage_path(
            internal["path"],
            source_class=internal["source_class"],
            display_name=internal["display_name"],
            expected_identity=internal["expected_identity"],
        )


def test_document_release_is_phase_one_exact_james_only(tmp_path):
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    config = _config(tmp_path, root, mode="juno")
    config["juno_kite_trusted_principal"]["policy"]["principals"]["lucy"]["conversation_eligibility"]["group"] = True
    runtime = TrustedPrincipalRuntime(config, active_profile="juno", clock=Clock())
    assert runtime.document_releases.phase_one_principal == "james"
    capabilities = {"juno.shared.children"}
    assert disclosure_decision(
        principal="james",
        effective_capability_ids=capabilities,
        capability_id="juno.shared.children",
        output_tier=DOCUMENT_DESCRIPTOR,
    ).allowed
    assert not disclosure_decision(
        principal="lucy",
        effective_capability_ids=capabilities,
        capability_id="juno.shared.children",
        output_tier=DOCUMENT_DESCRIPTOR,
    ).allowed


# The two document-tier phrasings below are the ones observed in live traffic on
# 2026-08-09: James's own words in the group, and the exact question_or_goal Juno
# composed from them for Kite. They are deliberately taken from that recorded
# turn rather than authored against the classifier's pattern vocabulary.
JAMES_LIVE_REQUEST = "Show me the nacho engagement letter"
JUNO_LIVE_QUESTION_OR_GOAL = (
    "Retrieve the authenticated principal's latest engagement letter involving "
    "Nacho Rodriguez, previously identified as 'amended Terms of Business' "
    "received 7 August 2026 at 15:53 CEST, and securely release the actual "
    "document to this bound current conversation if authorized. Return a "
    "releasable file reference. Do not contact anyone, modify records, or "
    "retrieve unrelated files."
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "question", [JAMES_LIVE_REQUEST, JUNO_LIVE_QUESTION_OR_GOAL]
)
async def test_document_tier_without_a_typed_read_denies_and_names_staging(
    tmp_path, question
):
    """A document-tier turn that runs no typed read must name the real stage.

    This is the production failure. Kite answered the document tier in a single
    API call with no tool call at all, so nothing was staged, and the host
    returned one generic denial that read as an entitlement problem. The
    end-to-end test could not catch it because it performs the typed reads
    itself before calling ``transform_llm_output``.
    """
    root = tmp_path / "family"
    root.mkdir()
    (root / "engagement-letter.png").write_bytes(_png_bytes())
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)

    juno = _runtime(tmp_path, root, mode="juno", clock=clock)
    ingress = await juno.pre_gateway_dispatch(
        event=_event(question),
        gateway=SimpleNamespace(adapters={Platform.WHATSAPP: adapter}),
        critical_ingress_token=object(),
    )
    assert ingress["action"] == "critical_allow"
    prepared = _session(
        lambda: juno._prepare_request({"question_or_goal": question}), mode="juno"
    )
    kite = _runtime(tmp_path, root, mode="kite", clock=clock)

    def kite_turn():
        policy = kite.pre_llm_call(
            user_message=prepared.message,
            session_id="kite-session",
            turn_id="kite-turn",
        )
        assert DOCUMENT_DESCRIPTOR in policy["context"]
        # No typed reader is invoked here: exactly what the live model did.
        return kite.transform_llm_output(
            response_text=json.dumps({"capability_id": "juno.private.james"}),
            session_id="kite-session",
            turn_id="kite-turn",
        )

    envelope = _session(
        kite_turn, mode="kite", context_id=prepared.mapping.context_id
    )
    answer = json.loads(
        _session(
            lambda: juno._verify_response(
                envelope, prepared.mapping, prepared.request_id
            ),
            mode="juno",
        )
    )
    assert answer["outcome"] == "denied"
    # Nothing was read at all, so every document source is unsearched and the
    # denial says which ones rather than only that staging produced nothing.
    assert answer["stage"] == "search-incomplete"
    assert "kite_personal_files_read" in answer["reason"]
    assert "kite_gmail_attachment_extract" in answer["reason"]
    # The oracle allows this exact request, so the denial is a staging failure
    # and must never be phrased as an authorization or entitlement one.
    assert disclosure_decision(
        principal="james",
        effective_capability_ids=["juno.private.james"],
        capability_id="juno.private.james",
        output_tier=DOCUMENT_DESCRIPTOR,
    ).allowed is True
    assert "authoriz" not in answer["reason"].lower()


def test_juno_side_document_release_needs_no_private_read_backends(tmp_path):
    """Juno holds document_release for the APPROVE half without typed readers.

    The delivery side only claims a code, revalidates the staged inode, and
    sends. Requiring Slice B here would force private-read backends into the
    low-trust profile, and leaving the requirement in place made the config
    fix crash the plugin into the fail-closed runtime, silencing Juno.
    """
    root = tmp_path / "family"
    root.mkdir()
    config = _config(tmp_path, root, mode="juno")
    config["juno_kite_trusted_principal"].pop("private_reads")
    runtime = TrustedPrincipalRuntime(config, active_profile="juno", clock=Clock())
    assert runtime.document_releases.enabled is True
    assert runtime.private_reads.enabled is False
    assert runtime.private_read_tool_names == frozenset()


def test_kite_side_document_release_still_requires_private_reads(tmp_path):
    root = tmp_path / "family"
    root.mkdir()
    config = _config(tmp_path, root, mode="kite")
    config["juno_kite_trusted_principal"].pop("private_reads")
    with pytest.raises(ValueError, match="Slice B private reads"):
        TrustedPrincipalRuntime(config, active_profile="kite", clock=Clock())


def test_document_tier_guidance_orders_the_typed_read_before_the_selection():
    """The tier rule must read as an action, not only an output format."""
    from plugins.juno_kite_trusted_principal.disclosure import (
        generated_semantic_guidance,
    )

    guidance = generated_semantic_guidance(
        principal="james",
        effective_capability_ids=["juno.private.james"],
        configured_policy={"juno.private.james": {"domain": "juno.private.james"}},
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    rule = guidance["output_tier_rule"]
    assert "kite_personal_files_read" in rule
    assert "capability_id" in rule
    assert rule.index("kite_personal_files_read") < rule.index("capability_id")
    steps = guidance["document_release_mode"]["required_steps"]
    assert "typed reader" in steps and "capability_id" in steps


@pytest.mark.asyncio
async def test_document_tier_policy_view_rule_does_not_ask_for_a_minimized_answer(
    tmp_path,
):
    """The top-level rule must agree with the tier.

    The nested tier rule said "call the typed reader"; the top-level rule said
    "return only a minimized answer". The model followed the top-level one --
    one API call, no typed read, nothing staged -- on every live document turn.
    """
    root = tmp_path / "family"
    root.mkdir()
    (root / "engagement-letter.png").write_bytes(_png_bytes())
    clock = Clock()
    adapter = RecordingWhatsAppAdapter(MutableRoster())

    juno = _runtime(tmp_path, root, mode="juno", clock=clock)
    await juno.pre_gateway_dispatch(
        event=_event(JAMES_LIVE_REQUEST),
        gateway=SimpleNamespace(adapters={Platform.WHATSAPP: adapter}),
        critical_ingress_token=object(),
    )
    prepared = _session(
        lambda: juno._prepare_request({"question_or_goal": JAMES_LIVE_REQUEST}),
        mode="juno",
    )
    kite = _runtime(tmp_path, root, mode="kite", clock=clock)
    context = _session(
        lambda: kite.pre_llm_call(
            user_message=prepared.message,
            session_id="kite-session",
            turn_id="kite-turn",
        )["context"],
        mode="kite",
        context_id=prepared.mapping.context_id,
    )
    view = json.loads(context.split("\n", 1)[1])
    assert "minimized answer" not in view["rule"]
    assert "minimized" not in view["requested_disclosure"]
    assert "typed reader" in view["rule"]
    assert "capability_id" in view["rule"]

    # An ordinary turn keeps the minimized rule unchanged.
    ordinary = _runtime(tmp_path, root, mode="juno", clock=clock)
    await ordinary.pre_gateway_dispatch(
        event=_event("What did nacho say about the amended terms"),
        gateway=SimpleNamespace(adapters={Platform.WHATSAPP: adapter}),
        critical_ingress_token=object(),
    )
    plain = _session(
        lambda: ordinary._prepare_request(
            {"question_or_goal": "What did nacho say about the amended terms"}
        ),
        mode="juno",
    )
    plain_context = _session(
        lambda: kite.pre_llm_call(
            user_message=plain.message,
            session_id="kite-session",
            turn_id="kite-turn-2",
        )["context"],
        mode="kite",
        context_id=plain.mapping.context_id,
    )
    plain_view = json.loads(plain_context.split("\n", 1)[1])
    assert "Return only a minimized answer" in plain_view["rule"]


# The exact question_or_goal Juno composed on the second live attempt (18:55).
# Same James message as JAMES_LIVE_REQUEST, reworded by the model, and the
# rewording alone drops it out of the document tier.
JUNO_LIVE_PARAPHRASE_MINIMIZED = (
    "Retrieve and securely release to this exact bound conversation the "
    "authenticated principal's latest engagement letter involving Nacho "
    "Rodriguez, previously identified as 'amended Terms of Business' received "
    "7 August 2026 at 15:53 CEST. Use the approved typed document/email reader "
    "and stage the matching attachment for release if authorized. Return only a "
    "releasable file reference and minimal identification. Do not contact "
    "anyone, modify records, or access unrelated material."
)


def test_a_reworded_paraphrase_cannot_drop_the_document_tier():
    """The live 18:55 failure: the model's rewording de-classified the request.

    Both paraphrases came from the same James message. Classifying only the
    peer-authored string made the tier -- a security control -- depend on
    wording the model chooses fresh each turn.
    """
    from plugins.juno_kite_trusted_principal.disclosure import (
        MINIMIZED,
        classify_output_tier,
        strongest_output_tier,
    )

    assert classify_output_tier(JAMES_LIVE_REQUEST) == DOCUMENT_DESCRIPTOR
    assert classify_output_tier(JUNO_LIVE_PARAPHRASE_MINIMIZED) == MINIMIZED
    # The host-classified inbound message keeps the tier where it belongs.
    assert strongest_output_tier([
        classify_output_tier(JAMES_LIVE_REQUEST),
        classify_output_tier(JUNO_LIVE_PARAPHRASE_MINIMIZED),
    ]) == DOCUMENT_DESCRIPTOR


def test_strongest_output_tier_is_fail_closed():
    from plugins.juno_kite_trusted_principal.disclosure import (
        BOUNDED_EXCERPT,
        BULK_RAW,
        MINIMIZED,
        strongest_output_tier,
    )

    assert strongest_output_tier([]) == MINIMIZED
    assert strongest_output_tier(["", None]) == MINIMIZED
    assert strongest_output_tier([MINIMIZED, BOUNDED_EXCERPT]) == BOUNDED_EXCERPT
    assert strongest_output_tier([DOCUMENT_DESCRIPTOR, MINIMIZED]) == DOCUMENT_DESCRIPTOR
    assert strongest_output_tier([BULK_RAW, DOCUMENT_DESCRIPTOR]) == BULK_RAW
    # An unrecognized tier must never relax the outcome.
    assert strongest_output_tier([MINIMIZED, "anything-else"]) == BULK_RAW


@pytest.mark.asyncio
async def test_host_classified_tier_survives_a_de_escalating_paraphrase(tmp_path):
    """End to end: James asks naturally, Juno reworders it, tier still holds."""
    root = tmp_path / "family"
    root.mkdir()
    (root / "engagement-letter.png").write_bytes(_png_bytes())
    clock = Clock()
    adapter = RecordingWhatsAppAdapter(MutableRoster())

    juno = _runtime(tmp_path, root, mode="juno", clock=clock)
    await juno.pre_gateway_dispatch(
        event=_event(JAMES_LIVE_REQUEST),
        gateway=SimpleNamespace(adapters={Platform.WHATSAPP: adapter}),
        critical_ingress_token=object(),
    )
    # The model hands back the de-escalating rewording seen in production.
    prepared = _session(
        lambda: juno._prepare_request(
            {"question_or_goal": JUNO_LIVE_PARAPHRASE_MINIMIZED}
        ),
        mode="juno",
    )
    kite = _runtime(tmp_path, root, mode="kite", clock=clock)
    context = _session(
        lambda: kite.pre_llm_call(
            user_message=prepared.message,
            session_id="kite-session",
            turn_id="kite-turn",
        )["context"],
        mode="kite",
        context_id=prepared.mapping.context_id,
    )
    view = json.loads(context.split("\n", 1)[1])
    assert view["semantic_disclosure"]["output_tier"] == DOCUMENT_DESCRIPTOR
    assert "typed reader" in view["rule"]


def test_document_tool_descriptions_do_not_disown_the_staging_step():
    """The tools must not describe staging as a separate flow to go and find.

    Live transcript, 2026-08-08: the model searched Gmail, read the exact
    message, fetched the extractor schema, then declined to call it --
    "releasing the binary requires the separate host-bound Slice C
    staging-and-approval flow, which is not present in this request". It was
    reading the tool's own description, which said only that separate flow may
    stage the binary. In fact calling this tool on a document turn IS the
    staging step: runtime routes it through resolve_document_candidate.
    """
    from plugins.juno_kite_trusted_principal.private_reads import TOOL_SCHEMAS

    for name in ("kite_gmail_attachment_extract", "kite_personal_files_read"):
        description = TOOL_SCHEMAS[name]["description"]
        assert "host side effect" in description, name
        assert "not a separate flow" in description, name
        # The wording that made the model disown the step must not come back.
        assert "Only the separately gated" not in description, name


def test_file_root_names_are_bound_into_the_model_facing_schema(tmp_path):
    """The model must not have to guess which personal root exists.

    Live turn, 20:26: every kite_personal_files_read call failed with
    "personal file root is unavailable" because ``root`` was an unconstrained
    string and the model guessed a name. Root names are host-configured and
    non-sensitive -- their paths are not, and stay in Kite -- exactly like the
    Gmail account aliases that were already enumerated.
    """
    root = tmp_path / "family"
    root.mkdir()
    config = _config(tmp_path, root, mode="kite")
    section = config["juno_kite_trusted_principal"]
    runtime = TrustedPrincipalRuntime(config, active_profile="kite", clock=Clock())

    schema = runtime.private_reads.schema_for("kite_personal_files_read")
    configured = [
        entry["name"] for entry in section["private_reads"]["files"]["roots"]
    ]
    assert schema["parameters"]["properties"]["root"]["enum"] == sorted(configured)
    for name in configured:
        assert name in schema["description"]
    # The configured path itself must never reach the model.
    for entry in section["private_reads"]["files"]["roots"]:
        assert entry["path"] not in json.dumps(schema)
    # The shared static schema must not be mutated by building a bound one.
    from plugins.juno_kite_trusted_principal.private_reads import TOOL_SCHEMAS

    assert "enum" not in TOOL_SCHEMAS["kite_personal_files_read"]["parameters"][
        "properties"
    ]["root"]


def test_document_guidance_requires_searching_every_source_before_concluding():
    """A miss in one source is not evidence the document does not exist.

    Live turn, 20:38, on a freshly reset session: the model searched Gmail,
    found nothing, and reported the document missing without ever calling the
    file reader that actually held it. A local file can never appear in an
    email search.
    """
    from plugins.juno_kite_trusted_principal.disclosure import (
        generated_semantic_guidance,
    )

    rule = generated_semantic_guidance(
        principal="james",
        effective_capability_ids=["juno.private.james"],
        configured_policy={"juno.private.james": {"domain": "juno.private.james"}},
        output_tier=DOCUMENT_DESCRIPTOR,
    )["output_tier_rule"]
    assert "BOTH" in rule
    assert "kite_personal_files_read" in rule
    assert "kite_gmail_attachment_extract" in rule
    assert "before saying a document is missing" in rule
    assert "never appears in an email search" in rule


@pytest.mark.asyncio
async def test_auto_release_delivers_without_an_approval_message(tmp_path):
    """James's own document reaches him without re-typing a code back.

    The one-use authority is still minted and consumed -- it is just never
    shown to anyone, so every binding it carries is still enforced.
    """
    from plugins.juno_kite_trusted_principal.runtime import _ACTIVE_AUDIENCE

    artifact = _png_bytes()
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(artifact)
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)

    juno, _gateway, preview = await _propose(tmp_path, root, clock, roster, adapter)
    audience = _ACTIVE_AUDIENCE.get()
    assert audience is not None

    result = json.loads(await juno._auto_release(json.dumps(preview), audience))

    assert result["outcome"] == "delivered"
    assert len(adapter.document_calls) == 1
    assert adapter.document_calls[0]["bytes"] == artifact
    assert adapter.document_calls[0]["chat_id"] == GROUP
    # The staged artifact is unlinked once delivery is terminal.
    assert not Path(adapter.document_calls[0]["file_path"]).exists()
    # The host-internal code is never surfaced to the model or the chat.
    code = preview["approval"]["code"]
    assert code not in json.dumps(result)
    assert not any(code in receipt for receipt in adapter.receipts)


@pytest.mark.asyncio
async def test_the_same_document_is_not_sent_twice_in_one_turn(tmp_path):
    """Asked for the family's passports, Albert's arrived twice.

    Juno consulted Kite once per person and asked for Albert twice. Each
    consultation is separately authorized and neither is wrong on its own,
    so no single gate could refuse it -- the repeat only exists in the
    relationship between them, which is where it is caught.
    """
    from plugins.juno_kite_trusted_principal.runtime import _ACTIVE_AUDIENCE

    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)

    juno, _gateway, preview = await _propose(tmp_path, root, clock, roster, adapter)
    audience = _ACTIVE_AUDIENCE.get()

    first = json.loads(await juno._auto_release(json.dumps(preview), audience))
    assert first["outcome"] == "delivered"
    assert len(adapter.document_calls) == 1

    repeat = json.loads(await juno._auto_release(json.dumps(preview), audience))
    assert repeat["outcome"] == "already_delivered"
    assert repeat["document"] == preview["document"]
    assert len(adapter.document_calls) == 1, "the document was sent twice"

    # A new inbound message is a new turn, and may ask for it again.
    juno._delivered_documents.clear()
    _juno, _gateway2, again = await _propose(tmp_path, root, clock, roster, adapter)
    assert json.loads(
        await juno._auto_release(json.dumps(again), _ACTIVE_AUDIENCE.get())
    )["outcome"] == "delivered"
    assert len(adapter.document_calls) == 2


@pytest.mark.asyncio
async def test_auto_release_still_fails_closed_on_a_changed_roster(tmp_path):
    """Removing the owner prompt must not remove any gate behind it."""
    from plugins.juno_kite_trusted_principal.runtime import _ACTIVE_AUDIENCE

    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)

    juno, _gateway, preview = await _propose(tmp_path, root, clock, roster, adapter)
    audience = _ACTIVE_AUDIENCE.get()
    # A stranger joins between the release decision and dispatch.
    roster.change_on_call = roster.calls + 1

    result = json.loads(await juno._auto_release(json.dumps(preview), audience))

    assert result["outcome"].startswith("delivery_")
    assert adapter.document_calls == []


@pytest.mark.asyncio
async def test_auto_release_leaves_a_non_release_answer_untouched(tmp_path):
    from plugins.juno_kite_trusted_principal.runtime import _ACTIVE_AUDIENCE

    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)

    juno, _gateway, _preview = await _propose(tmp_path, root, clock, roster, adapter)
    audience = _ACTIVE_AUDIENCE.get()
    for answer in ("an ordinary minimized answer", '{"outcome":"denied"}'):
        assert await juno._auto_release(answer, audience) == answer
    assert adapter.document_calls == []


@pytest.mark.asyncio
async def test_delivery_is_scheduled_onto_the_gateway_loop(tmp_path):
    """Dispatch must run where the adapter's HTTP session lives.

    An async tool handler is executed by _run_async on a fresh loop in a
    disposable thread. The platform adapter's session is bound to the
    gateway's loop and raises when touched from another one, which the
    transport surfaces only as SendResult(success=False) -- the live 21:09
    failure, recorded in the ledger as "failed" with no exception anywhere.
    """
    import asyncio as _asyncio
    from plugins.juno_kite_trusted_principal.runtime import _ACTIVE_LOOP

    seen: dict = {}

    async def _work() -> str:
        seen["loop"] = _asyncio.get_running_loop()
        return "delivered"

    gateway_loop = _asyncio.new_event_loop()
    thread = __import__("threading").Thread(
        target=gateway_loop.run_forever, daemon=True
    )
    thread.start()
    token = _ACTIVE_LOOP.set(gateway_loop)
    try:
        result = await TrustedPrincipalRuntime._on_gateway_loop(_work())
        assert result == "delivered"
        assert seen["loop"] is gateway_loop
        assert seen["loop"] is not _asyncio.get_running_loop()
    finally:
        _ACTIVE_LOOP.reset(token)
        gateway_loop.call_soon_threadsafe(gateway_loop.stop)
        thread.join(timeout=5)
        gateway_loop.close()


@pytest.mark.asyncio
async def test_delivery_runs_inline_when_no_gateway_loop_is_recorded(tmp_path):
    import asyncio as _asyncio
    from plugins.juno_kite_trusted_principal.runtime import _ACTIVE_LOOP

    async def _work() -> str:
        return "delivered"

    token = _ACTIVE_LOOP.set(None)
    try:
        assert await TrustedPrincipalRuntime._on_gateway_loop(_work()) == "delivered"
    finally:
        _ACTIVE_LOOP.reset(token)


def test_delivered_file_is_named_after_the_document():
    name = TrustedPrincipalRuntime._delivery_file_name(
        "Juno Test Engagement Letter", ".pdf"
    )
    assert name == "Juno Test Engagement Letter.pdf"
    # Anything unusable falls back rather than producing an odd or empty name.
    assert TrustedPrincipalRuntime._delivery_file_name("", ".pdf") == (
        "requested-document.pdf"
    )
    assert TrustedPrincipalRuntime._delivery_file_name(None, ".png") == (
        "requested-document.png"
    )
    # A title crossing the boundary is re-reduced on this side: no separators,
    # no traversal, no control characters, bounded length.
    for hostile in ("../../etc/passwd", "a/b\\c", "x\x00y", "  ...  "):
        produced = TrustedPrincipalRuntime._delivery_file_name(hostile, ".pdf")
        assert "/" not in produced and "\\" not in produced
        assert ".." not in produced
        assert "\x00" not in produced
        assert produced.endswith(".pdf") and len(produced) <= 84
    assert TrustedPrincipalRuntime._delivery_file_name("A" * 300, ".pdf") == (
        "A" * 80 + ".pdf"
    )


@pytest.mark.asyncio
async def test_the_document_is_the_answer_so_the_follow_up_line_is_dropped(tmp_path):
    """One message, not two: the file arrives and nothing narrates it."""
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    runtime = _runtime(tmp_path, root, mode="juno", clock=Clock())

    runtime._auto_delivered.add("juno-session")
    suppressed = runtime.transform_llm_output(
        response_text="The document has been delivered to this conversation.",
        session_id="juno-session",
        turn_id="turn-1",
    )
    # The gateway strips this to empty and then sends nothing; returning ""
    # would instead mean "leave the model's sentence unchanged".
    assert suppressed is not None and suppressed.strip() == ""
    # Consumed once: the next reply in the same session is untouched.
    assert runtime.transform_llm_output(
        response_text="an ordinary answer",
        session_id="juno-session",
        turn_id="turn-2",
    ) is None


def test_delivery_flag_survives_a_handler_that_gets_no_session_id():
    """The live 21:27 miss: tool handlers are not given session identifiers.

    handler_kwargs is whatever the caller passed, so keying the flag off
    kwargs produced an empty key and the hook never matched it.
    """
    keys = TrustedPrincipalRuntime._delivery_turn_keys({})
    assert "" not in keys
    keys_with_id = TrustedPrincipalRuntime._delivery_turn_keys(
        {"session_id": "juno-session"}
    )
    assert "juno-session" in keys_with_id


def test_delivery_caption_describes_the_artifact_safely():
    caption = TrustedPrincipalRuntime._delivery_caption({
        "title": "Juno Test Engagement Letter",
        "mime_type": "application/pdf",
        "page_count": 1,
    })
    assert caption == "Juno Test Engagement Letter · PDF"
    multi = TrustedPrincipalRuntime._delivery_caption({
        "title": "Deed of Sale",
        "mime_type": "application/pdf",
        "page_count": 12,
    })
    assert multi == "Deed of Sale · PDF · 12 pages"
    # Nothing crosses into the chat unreduced, and an empty descriptor is fine.
    hostile = TrustedPrincipalRuntime._delivery_caption({
        "title": "../../etc/passwd\x00",
        "mime_type": "application/pdf",
    })
    assert ".." not in hostile and "/" not in hostile and "\x00" not in hostile
    assert TrustedPrincipalRuntime._delivery_caption({}) == ""


@pytest.mark.asyncio
async def test_typing_settles_once_the_document_is_the_whole_reply(tmp_path):
    """No lingering "typing…" after a delivery that ends the turn silently.

    The model's follow-up is dropped, so nothing else is sent and the refresh
    loop would otherwise keep asserting the indicator until the turn ended.
    """
    from plugins.juno_kite_trusted_principal.runtime import _ACTIVE_AUDIENCE

    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)
    paused: list = []
    stopped: list = []
    adapter.pause_typing_for_chat = paused.append

    async def _stop_typing(chat_id):
        stopped.append(chat_id)

    adapter.stop_typing = _stop_typing

    juno, _gateway, preview = await _propose(tmp_path, root, clock, roster, adapter)
    audience = _ACTIVE_AUDIENCE.get()
    result = json.loads(await juno._auto_release(json.dumps(preview), audience))

    assert result["outcome"] == "delivered"
    assert paused == [GROUP]
    assert stopped == [GROUP]


@pytest.mark.asyncio
async def test_typing_helper_never_breaks_a_delivery(tmp_path):
    """An adapter without the typing API, or one that raises, is harmless."""
    class Hostile:
        def pause_typing_for_chat(self, _chat_id):
            raise RuntimeError("no typing API here")

    await TrustedPrincipalRuntime._quiet_typing(Hostile(), GROUP)
    await TrustedPrincipalRuntime._quiet_typing(object(), GROUP)


def test_a_bare_follow_up_is_only_a_document_request_in_context():
    """"retrieve and send it again" is James's real 21:36 and 21:43 phrasing.

    It names no document, so on its own it is an ordinary turn. It worked once
    and failed once purely because Juno happened to quote the earlier request
    in relevant_context the first time.
    """
    from plugins.juno_kite_trusted_principal.disclosure import (
        MINIMIZED,
        classify_output_tier,
        is_document_followup,
    )

    followup = "retrieve and send it again"
    assert classify_output_tier(followup) == MINIMIZED
    assert is_document_followup(followup) is True
    # A turn that carries its own subject is never treated as a follow-up.
    for standalone in (
        "what did nacho say about the amended terms",
        "send me an update about the villa instead",
        "remind me when the survey is due",
    ):
        assert is_document_followup(standalone) is False, standalone
    # Nor is anything that already classifies on its own.
    assert is_document_followup("Show me the juno test engagement letter") is False


def test_resend_and_retrieve_classify_without_any_history():
    from plugins.juno_kite_trusted_principal.disclosure import classify_output_tier

    for phrase in (
        "resend the engagement letter",
        "re-send the engagement letter",
        "retrieve the child passport scan",
    ):
        assert classify_output_tier(phrase) == DOCUMENT_DESCRIPTOR, phrase


@pytest.mark.asyncio
async def test_follow_up_inherits_only_a_recent_same_conversation_document_turn(
    tmp_path,
):
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    clock = Clock()
    juno = _runtime(tmp_path, root, mode="juno", clock=clock)
    binding = "conversation-binding-digest"
    other = "a-different-conversation"
    followup = "retrieve and send it again"

    # With no prior document turn the follow-up stays an ordinary turn.
    assert juno._host_output_tier(followup, binding) == "minimized_answer"
    # After a real document request in that conversation it resolves.
    assert juno._host_output_tier(
        "Show me the juno test engagement letter", binding
    ) == DOCUMENT_DESCRIPTOR
    assert juno._host_output_tier(followup, binding) == DOCUMENT_DESCRIPTOR
    # Never across conversations.
    assert juno._host_output_tier(followup, other) == "minimized_answer"
    # And never after it goes stale.
    clock.value += 301
    assert juno._host_output_tier(followup, binding) == "minimized_answer"


def test_minimized_guidance_forbids_inventing_a_release_gate():
    """Kite told James release was "blocked at the next host approval gate".

    No gate runs on a minimized turn; there was nothing to block.
    """
    from plugins.juno_kite_trusted_principal.disclosure import (
        MINIMIZED,
        generated_semantic_guidance,
    )

    rule = generated_semantic_guidance(
        principal="james",
        effective_capability_ids=["juno.private.james"],
        configured_policy={"juno.private.james": {"domain": "juno.private.james"}},
        output_tier=MINIMIZED,
    )["output_tier_rule"]
    assert "never explain a document you did not return by inventing one" in rule


@pytest.mark.parametrize(
    "token", [b"/URI", b"/AA", b"/OpenAction", b"/AcroForm", b"/ObjStm"]
)
def test_ordinary_document_structure_is_not_treated_as_active_content(
    tmp_path, token
):
    """A hyperlink is not an executable.

    The real engagement letter carried /URI six times and /AA eighteen times --
    a website, a LinkedIn profile, an email address in a signature block -- and
    was refused as "active-content". That rejected essentially every document a
    professional actually sends.
    """
    root = tmp_path / "family"
    root.mkdir()
    source = root / "ordinary.pdf"
    source.write_bytes(_pdf_with_stream(b"BT " + token + b" ET"))
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    inspected = runtime.document_releases.inspect_source_for_test(source)
    assert inspected is not None, token
    assert inspected.mime_type == "application/pdf"


def test_executable_and_payload_carrying_constructs_stay_refused():
    """The loosening is bounded: code, external fetch, and embedding still fail."""
    from plugins.juno_kite_trusted_principal.document_release import (
        _PDF_ACTIVE_TOKENS,
        _PDF_INERT_TOKENS,
    )

    for token in (
        b"/JavaScript", b"/JS", b"/XFA", b"/Launch", b"/GoToR", b"/SubmitForm",
        b"/ImportData", b"/EmbeddedFile", b"/FileAttachment", b"/RichMedia",
        b"/Movie", b"/Sound",
    ):
        assert token in _PDF_ACTIVE_TOKENS, token
    # Nothing may be in both lists.
    assert not set(_PDF_ACTIVE_TOKENS) & set(_PDF_INERT_TOKENS)


def test_script_hidden_inside_an_object_stream_is_still_caught(tmp_path):
    """Allowing /ObjStm must not create a place to hide /JS.

    Decoded streams are scanned for the refused tokens, so a compressed object
    stream is inspected rather than trusted.
    """
    root = tmp_path / "family"
    root.mkdir()
    source = root / "hidden.pdf"
    source.write_bytes(_pdf_with_stream(b"<</Type/ObjStm>> /JavaScript (evil)"))
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    assert runtime.document_releases.inspect_source_for_test(source) is None


@pytest.mark.parametrize(
    "filter_name", [b"DCTDecode", b"CCITTFaxDecode", b"LZWDecode", b"JBIG2Decode"]
)
def test_an_image_codec_does_not_make_a_document_unreleasable(tmp_path, filter_name):
    """A scanned page is not a reason to refuse a letter.

    The real engagement letter failed here after clearing the active-content
    gate: the scanner refused any stream it could not inflate, and a printed or
    scanned document is full of them.
    """
    root = tmp_path / "family"
    root.mkdir()
    source = root / "scanned.pdf"
    source.write_bytes(_pdf_with_stream(b"\xff\xd8\xff image samples", filter_name=filter_name))
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    assert runtime.document_releases.inspect_source_for_test(source) is not None


@pytest.mark.parametrize("filter_name", [b"DCTDecode", b"LZWDecode"])
def test_an_opaque_stream_is_scanned_as_stored(tmp_path, filter_name):
    """Not inflating a stream must not mean not looking at it.

    The bytes are scanned exactly as they sit in the file. This cannot see
    through an encoding it cannot decode -- a token buried inside real JPEG
    entropy data would not be visible -- but a viewer does not execute image
    samples either; actions have to reach the object graph, which is scanned.
    """
    root = tmp_path / "family"
    root.mkdir()
    source = root / "smuggled.pdf"
    source.write_bytes(
        _pdf_with_stream(
            b"unused",
            filter_name=filter_name,
            encoded_payload=b"cover /JavaScript (evil) cover",
        )
    )
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    assert runtime.document_releases.inspect_source_for_test(source) is None


def test_a_stream_claiming_flate_that_will_not_inflate_is_still_refused(tmp_path):
    """Opaque is for codecs this cannot read, not for a broken Flate claim."""
    root = tmp_path / "family"
    root.mkdir()
    source = root / "lying.pdf"
    source.write_bytes(
        _pdf_with_stream(
            b"unused", filter_name=b"FlateDecode", encoded_payload=b"not-zlib"
        )
    )
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    assert runtime.document_releases.inspect_source_for_test(source) is None


def test_a_real_gmail_attachment_id_fits_the_extractor_schema():
    """The live 22:25 block: the id was longer than its own schema allowed.

    Gmail attachment handles are hundreds of characters -- the engagement
    letter's is 319 -- and are regenerated per response, so they cannot be
    shortened or substituted. A 256 cap rejected the argument before the
    reader ever ran, making every real attachment unreachable.
    """
    from plugins.juno_kite_trusted_principal.private_reads import (
        TOOL_SCHEMAS,
        validate_tool_arguments,
    )

    schema = TOOL_SCHEMAS["kite_gmail_attachment_extract"]["parameters"]
    assert schema["properties"]["attachment_id"]["maxLength"] >= 512
    # Message ids stay tightly bounded; only the attachment handle is long.
    assert schema["properties"]["message_id"]["maxLength"] == 256

    realistic = "ANGjdJ" + "aB9_-x" * 52  # 318 chars, Gmail's alphabet
    assert len(realistic) > 256
    assert validate_tool_arguments(
        "kite_gmail_attachment_extract",
        {"account": "personal", "message_id": "19fdc822d5bea6a9",
         "attachment_id": realistic},
    ) is True
    # Still bounded, and still only the URL-safe alphabet.
    assert validate_tool_arguments(
        "kite_gmail_attachment_extract",
        {"account": "personal", "message_id": "19fdc822d5bea6a9",
         "attachment_id": "a" * 4096},
    ) is False
    # The alphabet is enforced a layer down, at execution, not by the schema.
    from plugins.juno_kite_trusted_principal.private_reads import _ATTACHMENT_ID_RE

    assert _ATTACHMENT_ID_RE.fullmatch(realistic) is not None
    for rejected in ("../../etc/passwd", "a b", "a/b", "x" * 2048, ""):
        assert _ATTACHMENT_ID_RE.fullmatch(rejected) is None, rejected


class _RecordingSessionStore:
    def __init__(self, keys):
        self._keys = list(keys)
        self.reset_keys: list[str] = []

    def list_sessions(self, active_minutes=None):
        return [SimpleNamespace(session_key=key) for key in self._keys]

    def reset_session(self, session_key, display_name=None):
        self.reset_keys.append(session_key)
        return SimpleNamespace(session_key=session_key)


def _a2a_event(text, *, chat_id="jk-context", user_id="juno"):
    """The A2A lane carries a plain "a2a" platform string, not a Platform member."""
    return SimpleNamespace(
        text=text,
        source=SimpleNamespace(
            platform="a2a", user_id=user_id, chat_id=chat_id, chat_type="dm"
        ),
    )


@pytest.mark.asyncio
async def test_each_juno_request_starts_from_a_clean_kite_session(tmp_path):
    """Kite must not reason from a previous turn's stale failure.

    Live 22:40: on a build where the attachment id limit had already been
    raised, the model reported it as "still" overlength and never called the
    reader -- quoting its own earlier failure from the same session. That
    confounded five separate tests today.
    """
    from plugins.juno_kite_trusted_principal.runtime import REQUEST_PREFIX

    root = tmp_path / "family"
    root.mkdir()
    kite = _runtime(tmp_path, root, mode="kite", clock=Clock())
    store = _RecordingSessionStore([
        "agent:main:a2a:dm:jk-context",
        "agent:main:whatsapp:group:unrelated",
        "agent:main:a2a:dm:some-other-context",
    ])

    await kite.pre_gateway_dispatch(
        event=_a2a_event("guard\n" + REQUEST_PREFIX + "{}"),
        gateway=None,
        session_store=store,
    )
    assert store.reset_keys == ["agent:main:a2a:dm:jk-context"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,user_id",
    [
        ("an ordinary peer message", "juno"),
        ("guard\nJUNO_KITE_REQUEST_V2 {}", "someone-else"),
    ],
    ids=["not-a-signed-request", "not-the-juno-peer"],
)
async def test_unrelated_a2a_traffic_never_resets_a_session(tmp_path, text, user_id):
    root = tmp_path / "family"
    root.mkdir()
    kite = _runtime(tmp_path, root, mode="kite", clock=Clock())
    store = _RecordingSessionStore(["agent:main:a2a:dm:jk-context"])

    await kite.pre_gateway_dispatch(
        event=_a2a_event(text, user_id=user_id), gateway=None, session_store=store
    )
    assert store.reset_keys == []


@pytest.mark.asyncio
async def test_lane_reset_never_breaks_dispatch(tmp_path):
    """A store without the API, or one that raises, must not block a turn."""
    from plugins.juno_kite_trusted_principal.runtime import REQUEST_PREFIX

    class Hostile:
        def list_sessions(self, active_minutes=None):
            raise RuntimeError("no listing here")

        def reset_session(self, session_key, display_name=None):
            raise RuntimeError("no reset here")

    root = tmp_path / "family"
    root.mkdir()
    kite = _runtime(tmp_path, root, mode="kite", clock=Clock())
    event = _a2a_event("guard\n" + REQUEST_PREFIX + "{}")
    assert await kite.pre_gateway_dispatch(
        event=event, gateway=None, session_store=Hostile()
    ) is None
    assert await kite.pre_gateway_dispatch(
        event=event, gateway=None, session_store=object()
    ) is None


def test_attachment_transport_cap_does_not_reject_a_real_document(tmp_path):
    """The live 22:53 and 22:55 failures: cap_exceeded on the pipe, not the file.

    The engagement letter is 254398 bytes, ~339KB once base64-encoded, against
    a 256KB text-answer cap. Every real attachment failed to extract while the
    artifact policy itself would have allowed it.
    """
    import base64 as _base64
    from types import SimpleNamespace as _NS
    from plugins.juno_kite_trusted_principal.private_reads import (
        _ATTACHMENT_COMMAND_OUTPUT_BYTES,
    )

    artifact = b"%PDF-1.4 " + b"x" * 300_000
    payload = json.dumps({
        "filename": "engagement letter.pdf",
        "mime_type": "application/pdf",
        "size_bytes": len(artifact),
        "text": "",
        "artifact_base64": _base64.b64encode(artifact).decode("ascii"),
    })
    assert len(payload.encode()) > 262144  # over the ordinary answer cap

    calls: list = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return _NS(returncode=0, stdout=payload, stderr="")

    root = tmp_path / "family"
    root.mkdir()
    executable = tmp_path / "reader"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o700)
    config = _config(tmp_path, root, mode="kite")["juno_kite_trusted_principal"]
    reads = dict(config["private_reads"])
    reads["gmail"] = {
        "executable": str(executable),
        "account_aliases": {"personal": "personal", "kite": "kite"},
    }
    from plugins.juno_kite_trusted_principal.private_reads import PrivateReadService

    service = PrivateReadService(
        reads, backends=None, command_runner=runner,
        url_opener=None, secret_values=set(),
    )
    assert service.output_bytes < _ATTACHMENT_COMMAND_OUTPUT_BYTES

    result = service._source_or_google_command(
        "gmail", "attachment_extract",
        {"account": "personal", "message_id": "abc", "attachment_id": "xyz"},
    )
    assert result["size_bytes"] == len(artifact)
    assert calls and calls[0][-3:] == ["attachment", "abc", "xyz"]

    # An ordinary Gmail answer keeps the tight cap.
    capped = False
    try:
        service._source_or_google_command(
            "gmail", "get", {"account": "personal", "message_id": "abc"}
        )
    except Exception as exc:  # SourceFailure is frozen; inspect it directly
        capped = getattr(exc, "code", "") == "cap_exceeded"
    assert capped


@pytest.mark.asyncio
async def test_a_preview_titled_after_its_source_file_is_not_a_leak(tmp_path):
    """The 07:09 failure: the host's own descriptor tripped the leak policy.

    A document's title comes from the artifact's filename, and the reader that
    found it records filenames as provenance. At the document tier any overlap
    denies, so the approval preview collided with itself and the envelope came
    back empty with "output minimized by deterministic leak policy" -- for a
    payload the model never wrote.
    """
    artifact = _png_bytes()
    root = tmp_path / "family"
    root.mkdir()
    # The searchable name and the delivered title are necessarily the same.
    (root / "engagement-letter.png").write_bytes(artifact)
    clock = Clock()
    roster = MutableRoster()
    adapter = RecordingWhatsAppAdapter(roster)

    _juno, _gateway, preview = await _propose(
        tmp_path,
        root,
        clock,
        roster,
        adapter,
        question="Show me the engagement letter",
        relative_path="engagement-letter.png",
        capability_id="juno.private.james",
        purpose="personal administration",
        search_query="engagement",
    )

    assert preview["outcome"] == "approval_required"
    assert "engagement" in preview["document"]["title"].casefold()


def test_only_a_document_turn_skips_the_overlap_check():
    """The exemption is for host-authored payloads, not a general relaxation."""
    source = (
        Path("plugins/juno_kite_trusted_principal/runtime.py").read_text()
    )
    assert "and not host_authored" in source
    # It is set in exactly one place: right after the host replaces the answer.
    assert source.count("host_authored = True") == 1
    assert source.count("host_authored = False") == 1


def test_a_dated_document_title_is_not_mistaken_for_a_phone_number(tmp_path):
    """The 07:35 failure: "EL MS 07 08 2026" is a date, read as a phone number.

    The generic output scan is written for model prose. Applied to the host's
    own descriptor it blanked the entire release -- the envelope came back
    empty with "output minimized by deterministic leak policy" for a payload
    the model never wrote.
    """
    root = tmp_path / "family"
    root.mkdir()
    runtime = _runtime(tmp_path, root, mode="juno", clock=Clock())

    assert runtime._safe_release_title("EL MS 07 08 2026") == "EL MS 07 08 2026"
    assert runtime._safe_release_title("Engagement Letter 2026") == (
        "Engagement Letter 2026"
    )
    # This once tripped the phone-shaped scan, which is why the title is
    # sanitised rather than scanned. The scan no longer confuses a date with
    # a dialled number, so the title now survives both checks -- the
    # sanitiser above is still what guarantees it.
    assert runtime._leak_reason("EL MS 07 08 2026", output=True) == ""


def test_a_title_carrying_something_unshippable_is_replaced_not_denied(tmp_path):
    """Protection is kept, but it can never block the document itself."""
    root = tmp_path / "family"
    root.mkdir()
    runtime = _runtime(tmp_path, root, mode="juno", clock=Clock())
    runtime.secret_values = {"super-secret-token-value"}

    for hostile in (
        "invoice for adviser@example.com",
        "creds api_key=abcdef123456",
        "notes super-secret-token-value",
        "",
    ):
        assert runtime._safe_release_title(hostile) == "Requested document", hostile


def test_attachment_download_gets_its_own_timeout(tmp_path):
    """The live pipeline died mid-download on the shared 15s source timeout.

    One attachment command makes two API round-trips and pulls the document,
    where a text answer makes one and returns a few KB.
    """
    from types import SimpleNamespace as _NS
    from plugins.juno_kite_trusted_principal.private_reads import (
        PrivateReadService,
        _ATTACHMENT_COMMAND_TIMEOUT_SECONDS,
    )

    seen: list = []

    def runner(argv, **kwargs):
        seen.append(kwargs.get("timeout"))
        return _NS(returncode=0, stdout=json.dumps({
            "filename": "d.pdf", "mime_type": "application/pdf",
            "size_bytes": 3, "text": "", "artifact_base64": "AAAA",
        }), stderr="")

    root = tmp_path / "family"
    root.mkdir()
    executable = tmp_path / "reader"
    executable.write_text("#!/bin/sh\n")
    executable.chmod(0o700)
    reads = dict(_config(tmp_path, root, mode="kite")["juno_kite_trusted_principal"]["private_reads"])
    reads["gmail"] = {
        "executable": str(executable),
        "account_aliases": {"personal": "personal", "kite": "kite"},
    }
    service = PrivateReadService(
        reads, backends=None, command_runner=runner, url_opener=None,
        secret_values=set(),
    )

    service._source_or_google_command(
        "gmail", "attachment_extract",
        {"account": "personal", "message_id": "abc", "attachment_id": "xyz"},
    )
    assert seen == [_ATTACHMENT_COMMAND_TIMEOUT_SECONDS]
    assert _ATTACHMENT_COMMAND_TIMEOUT_SECONDS > service.timeout

    # An ordinary answer keeps the short timeout.
    seen.clear()
    service._source_or_google_command(
        "gmail", "get", {"account": "personal", "message_id": "abc"}
    )
    assert seen == [service.timeout]


def test_juno_accepts_the_host_descriptor_it_cannot_distinguish_by_signature(tmp_path):
    """The 07:51 failure: Kite fully succeeded and Juno rejected the envelope.

    Kite extracted the attachment, issued C7-T6REKJNX3DVQC2RN and returned
    approval_required with denied=False. Juno then ran its own prose scan over
    the answer, matched "07 08 2026" in the title as a phone number, and
    blocked the consultation -- leaving the record staged and never claimed.
    Fixing only the Kite side left the identical bug on the other side of the
    wire.
    """
    root = tmp_path / "family"
    root.mkdir()
    juno = _runtime(tmp_path, root, mode="juno", clock=Clock())
    preview = canonical = json.dumps({
        "outcome": "approval_required",
        "document": {"title": "EL MS 07 08 2026",
                     "source_class": "personal Gmail attachment",
                     "mime_type": "application/pdf",
                     "size_bytes": 254398, "page_count": 5},
        "audience": "James only in this WhatsApp conversation",
        "purpose": "property administration",
        "approval": {"code": "C7-T6REKJNX3DVQC2RN",
                     "instruction": "APPROVE C7-T6REKJNX3DVQC2RN",
                     "expires_at": "2026-08-10T07:01:57+00:00"},
    })
    assert juno._release_descriptor(preview) is not None
    # The prose scan once refused this descriptor over "07 08 2026" in the
    # title, which is why recognising the shape is what admits it. The scan
    # itself no longer objects; the descriptor check above is still the
    # guarantee, and it is what holds if the scan tightens again.
    assert juno._leak_reason(preview, output=True) == ""


@pytest.mark.parametrize(
    "mutate",
    [
        {"extra": "smuggled prose"},
        {"audience": "everyone"},
        {"purpose": "whatever administration"},
    ],
    ids=["extra-key", "wrong-audience", "unknown-purpose"],
)
def test_only_the_exact_host_shape_bypasses_the_prose_scan(tmp_path, mutate):
    """Nothing may wear the descriptor's shape to skip the scan."""
    root = tmp_path / "family"
    root.mkdir()
    juno = _runtime(tmp_path, root, mode="juno", clock=Clock())
    payload = {
        "outcome": "approval_required",
        "document": {"title": "Letter", "source_class": "personal files",
                     "mime_type": "application/pdf",
                     "size_bytes": 10, "page_count": 1},
        "audience": "James only in this WhatsApp conversation",
        "purpose": "property administration",
        "approval": {"code": "C7-AAAAAAAAAAAAAAAA",
                     "instruction": "APPROVE C7-AAAAAAAAAAAAAAAA",
                     "expires_at": "2026-01-01T00:00:00+00:00"},
    }
    assert juno._release_descriptor(json.dumps(payload)) is not None
    payload.update(mutate)
    assert juno._release_descriptor(json.dumps(payload)) is None
    # Ordinary answers are still prose, and still scanned.
    assert juno._release_descriptor("here is a summary of the letter") is None
    assert juno._release_descriptor(
        '{"outcome":"denied","reason":"nope"}'
    ) is None


def test_the_release_candidate_tells_the_model_which_document_it_picked(tmp_path):
    """08:09 and 08:11: the model chose blind and sent the wrong passport.

    The descriptor carried only a MIME type and a byte count, so the model
    could not check its own choice or report it. It picked "Epson_07082026151807"
    and then "photo" -- scanner defaults that identify nothing -- inferring from
    the surrounding email that an image was a British passport when it was the
    front cover of the Irish one.
    """
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    encoded, internal = runtime.private_reads.resolve_document_candidate(
        "kite_personal_files_read",
        {"operation": "read", "root": "family",
         "relative_path": "child-passport.png"},
    )
    assert internal is not None
    descriptor = json.loads(encoded)["data"]
    assert descriptor["document_name"] == "child-passport"
    # Still closed: no path, no root, no bytes.
    assert set(descriptor) == {
        "outcome", "source_class", "document_name", "document_preview",
        "mime_type", "size_bytes",
    }
    assert str(tmp_path) not in encoded and "family" not in descriptor["document_name"]


def test_a_candidate_name_is_reduced_before_the_model_sees_it():
    from plugins.juno_kite_trusted_principal.private_reads import (
        _release_display_name,
    )

    assert _release_display_name("EL MS 07 08 2026.pdf") == "EL MS 07 08 2026"
    assert _release_display_name("Epson_07082026151807.jpg") == "Epson_07082026151807"
    # Percent-encoding is already decoded upstream; separators never survive.
    for hostile in ("../../etc/passwd", "a/b\\c.pdf", "x\x00y.png"):
        produced = _release_display_name(hostile)
        assert "/" not in produced and "\\" not in produced and ".." not in produced
        assert "\x00" not in produced
    assert _release_display_name("") == "untitled"
    assert len(_release_display_name("A" * 300 + ".pdf")) <= 96


def test_document_guidance_requires_checking_the_name_before_releasing():
    from plugins.juno_kite_trusted_principal.disclosure import (
        generated_semantic_guidance,
    )

    rule = generated_semantic_guidance(
        principal="james",
        effective_capability_ids=["juno.private.james"],
        configured_policy={"juno.private.james": {"domain": "juno.private.james"}},
        output_tier=DOCUMENT_DESCRIPTOR,
    )["output_tier_rule"]
    assert "document_preview" in rule
    assert "document_name" in rule
    assert "identifies nothing" in rule          # a scanner default is not evidence
    assert "not the topic" in rule               # British vs Irish are both passports
    assert "cannot be recalled" in rule


def test_the_candidate_carries_a_preview_of_what_the_document_says(tmp_path):
    """A name cannot answer "is this the British one?"; the contents can."""
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    encoded, internal = runtime.private_reads.resolve_document_candidate(
        "kite_personal_files_read",
        {"operation": "read", "root": "family", "relative_path": "child-passport.png"},
    )
    assert internal is not None
    descriptor = json.loads(encoded)["data"]
    assert set(descriptor) == {
        "outcome", "source_class", "document_name", "document_preview",
        "mime_type", "size_bytes",
    }
    # An 8x8 fixture has no legible text: empty, which says "unidentified".
    assert isinstance(descriptor["document_preview"], str)


def test_preview_is_bounded_collapsed_and_never_guesses(monkeypatch):
    from types import SimpleNamespace as _NS
    from plugins.juno_kite_trusted_principal import private_reads as pr

    monkeypatch.setattr(
        pr.subprocess, "run",
        lambda *a, **k: _NS(returncode=0, stdout="a\n\n  b\t" + "x" * 5000),
    )
    out = pr._document_preview(b"%PDF-1.4", "application/pdf")
    assert len(out) <= 600
    assert out.startswith("a b x")
    assert "\n" not in out and "\t" not in out

    # A reader that fails, or a format with no reader, yields nothing at all
    # rather than a guess. A different document, because the first one has now
    # been read successfully and a second look at it is answered from memory.
    monkeypatch.setattr(
        pr.subprocess, "run", lambda *a, **k: _NS(returncode=1, stdout="secret")
    )
    assert pr._document_preview(b"%PDF-1.4 unreadable", "application/pdf") == ""
    assert pr._document_preview(b"x", "application/zip") == ""
    assert pr._document_preview(b"x", "") == ""


def test_preview_reader_runs_locally_and_cleans_up(monkeypatch, tmp_path):
    """The artifact must not leave the machine to be identified."""
    from types import SimpleNamespace as _NS
    from plugins.juno_kite_trusted_principal import private_reads as pr

    seen: dict = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["env"] = kwargs.get("env")
        seen["path"] = next(a for a in argv if "/T/" in a or "tmp" in a)
        seen["existed"] = Path(seen["path"]).exists()
        return _NS(returncode=0, stdout="text")

    monkeypatch.setattr(pr.subprocess, "run", fake_run)
    assert pr._document_preview(b"%PDF-1.4 hello", "application/pdf") == "text"
    # A local executable, a bounded environment, and the temp file removed after.
    assert seen["argv"][0].endswith("pdftotext")
    assert seen["env"] == {"PATH": "/usr/bin:/bin"}
    assert seen["existed"] is True
    assert not Path(seen["path"]).exists()


def test_document_guidance_requires_matching_the_contents_not_the_topic():
    from plugins.juno_kite_trusted_principal.disclosure import (
        generated_semantic_guidance,
    )

    rule = generated_semantic_guidance(
        principal="james",
        effective_capability_ids=["juno.private.james"],
        configured_policy={"juno.private.james": {"domain": "juno.private.james"}},
        output_tier=DOCUMENT_DESCRIPTOR,
    )["output_tier_rule"]
    assert "document_preview" in rule
    assert "read the next candidate" in rule
    assert "empty preview" in rule.lower()


def test_a_rejected_question_says_what_matched(tmp_path):
    """A question refused here is never persisted, so it must name itself."""
    root = tmp_path / "family"
    root.mkdir()
    runtime = _runtime(tmp_path, root, mode="juno", clock=Clock())
    source = Path("plugins/juno_kite_trusted_principal/runtime.py").read_text()
    assert 'f"({handoff_reason})"' in source


def test_a_scanned_pdf_with_no_text_layer_is_still_read(monkeypatch):
    """TB.pdf: 290KB of scanned terms, and pdftotext returns nothing for it.

    Without the rendered-page fallback the candidate stays unidentifiable,
    which is precisely the case the preview exists to solve.
    """
    from plugins.juno_kite_trusted_principal import private_reads as pr

    calls: list = []

    def fake_reader(argv, limit=600):
        calls.append(argv)
        if argv[0].endswith("pdftotext"):
            return ""          # no text layer
        return "Terms of Business - the attached professional engagement"

    monkeypatch.setattr(pr, "_run_preview_reader", fake_reader)
    out = pr._document_preview(b"%PDF-1.4 scanned", "application/pdf")
    assert out.startswith("Terms of Business")
    # It tried the text layer first, then the local renderer.
    assert calls[0][0].endswith("pdftotext")
    assert calls[1][0] == pr._SYSTEM_PYTHON
    assert calls[1][1].endswith("macos_ocr.py")


def test_a_pdf_with_a_text_layer_does_not_pay_for_ocr(monkeypatch):
    from plugins.juno_kite_trusted_principal import private_reads as pr

    calls: list = []

    def fake_reader(argv, limit=600):
        calls.append(argv)
        return "PRIVATE AND CONFIDENTIAL Palma de Mallorca"

    monkeypatch.setattr(pr, "_run_preview_reader", fake_reader)
    assert pr._document_preview(b"%PDF-1.4", "application/pdf").startswith("PRIVATE")
    assert len(calls) == 1


def test_a_second_look_at_one_document_does_not_pay_the_recogniser_again(monkeypatch):
    """Weighing four candidates used to cost the recogniser four times a turn.

    Nearly all of that is fixed cost -- a cold interpreter importing the Vision
    bindings, then warming the OS text models -- and it was paid again next
    turn over the same unchanged files. The extraction is a pure function of
    the document's bytes, so the second look should be free.
    """
    from plugins.juno_kite_trusted_principal import private_reads as pr

    calls: list = []

    monkeypatch.setattr(pr, "_normalise_artifact", lambda data, mime: (data, mime))
    monkeypatch.setattr(
        pr,
        "_run_preview_reader",
        lambda argv, limit=600: calls.append(argv) or "SPECIMEN PASSPORT ZZ0000001",
    )

    first = pr._document_preview(b"scan-one", "image/jpeg")
    second = pr._document_preview(b"scan-one", "image/jpeg")
    assert first == second == "SPECIMEN PASSPORT ZZ0000001"
    assert len(calls) == 1, "the recogniser ran a second time on unchanged bytes"

    # A shorter bound is served from the same remembered extraction, truncated
    # per call, so the bound is not baked into what is remembered.
    assert pr._document_preview(b"scan-one", "image/jpeg", limit=8) == "SPECIMEN"
    assert len(calls) == 1

    # A different page bound is a different extraction, and so a different key.
    pr._document_preview(b"scan-one", "image/jpeg", pages=pr._READ_MAX_PAGES)
    assert len(calls) == 2


def test_a_changed_document_is_read_again_rather_than_remembered(monkeypatch):
    """The cache must never answer for a file whose contents have moved on.

    Keyed on a digest of the bytes rather than on a stat tuple precisely so a
    rewritten document cannot be served from the previous one's preview.
    """
    from plugins.juno_kite_trusted_principal import private_reads as pr

    calls: list = []

    def fake_reader(argv, limit=600):
        calls.append(argv)
        # The reader sees the staged temp file, so it answers from the bytes.
        return Path(argv[-2]).read_text()

    monkeypatch.setattr(pr, "_normalise_artifact", lambda data, mime: (data, mime))
    monkeypatch.setattr(pr, "_run_preview_reader", fake_reader)

    assert pr._document_preview(b"COUNCIL TAX BILL", "image/jpeg") == "COUNCIL TAX BILL"
    assert len(calls) == 1

    # Same document, rewritten. Different bytes, so a fresh extraction.
    assert pr._document_preview(b"TENANCY AGREEMENT", "image/jpeg") == (
        "TENANCY AGREEMENT"
    )
    assert len(calls) == 2

    # And the first document is still remembered, not evicted by the second.
    assert pr._document_preview(b"COUNCIL TAX BILL", "image/jpeg") == "COUNCIL TAX BILL"
    assert len(calls) == 2


def test_the_preview_cache_is_bounded_and_never_written_to_disk(monkeypatch):
    """Someone's documents live in memory here, so both bounds must hold."""
    from plugins.juno_kite_trusted_principal import private_reads as pr

    calls: list = []
    monkeypatch.setattr(pr, "_normalise_artifact", lambda data, mime: (data, mime))
    monkeypatch.setattr(
        pr, "_run_preview_reader", lambda argv, limit=600: calls.append(argv) or "text"
    )

    for index in range(pr._PREVIEW_CACHE_MAX_ENTRIES + 10):
        pr._document_preview(f"document-{index}".encode(), "image/jpeg")
    assert len(pr._PREVIEW_CACHE) == pr._PREVIEW_CACHE_MAX_ENTRIES

    # The character bound holds too, however few entries that leaves.
    pr._reset_document_preview_cache()
    monkeypatch.setattr(
        pr,
        "_run_preview_reader",
        lambda argv, limit=600: "y" * pr._READ_EXTRACT_CHARS,
    )
    for index in range(40):
        pr._document_preview(f"long-{index}".encode(), "image/jpeg")
    assert sum(len(v) for v in pr._PREVIEW_CACHE.values()) <= pr._PREVIEW_CACHE_MAX_CHARS

    # A caller asking beyond what the cache agrees to hold bypasses it entirely.
    pr._reset_document_preview_cache()
    pr._document_preview(
        b"oversized", "image/jpeg", limit=pr._READ_EXTRACT_CHARS + 1
    )
    assert not pr._PREVIEW_CACHE


def test_a_sentence_about_verification_is_not_a_verification_code(tmp_path):
    """The 08:45 block: "Send me my British passport" never reached Kite.

    The composed question said "require exact source verification that the
    document is both a British passport and belongs to the authenticated
    principal". The credential rule for one-time codes matched "verification
    that" -- the qualifier was optional, so any of these words followed by the
    next English word read as a secret.
    """
    root = tmp_path / "family"
    root.mkdir()
    runtime = _runtime(tmp_path, root, mode="juno", clock=Clock())

    # The exact live question, recovered from the session store.
    live = (
        "Locate and securely deliver the authenticated principal's own British "
        "passport biodata page to this exact bound WhatsApp conversation. Because "
        "two prior candidates were wrong, require exact source verification that "
        "the document is both a British passport and belongs to the authenticated "
        "principal before release."
    )
    assert runtime._leak_reason(live, output=False) == ""
    for ordinary in (
        "verification that the document is his",
        "authentication of ownership is required",
        "recovery of the original letter",
        "if exact verification succeeds, deliver it",
    ):
        assert runtime._leak_reason(ordinary, output=False) == "", ordinary

    # Real one-time secrets are still caught, with or without the qualifier.
    for secret in (
        "verification code 8f3k2a",
        "your otp is 402913",
        "one-time password 55télé" .replace("télé", "1234"),
        "verification code: abc123",
        "pairing code = 99887766",
    ):
        assert runtime._leak_reason(secret, output=False) == (
            "credential-shaped content"
        ), secret


def test_the_same_rule_no_longer_blocks_staging_a_document(tmp_path):
    """document_release carries its own copy of the rule, used when staging."""
    from plugins.juno_kite_trusted_principal.document_release import (
        DocumentReleaseService,
    )

    assert DocumentReleaseService._text_is_denied(
        "require exact source verification that the document is his"
    ) is False
    assert DocumentReleaseService._text_is_denied("verification code 8f3k2a") is True


def _docx_bytes(*, macro: bool = False, sheet: bool = False) -> bytes:
    import io as _io, zipfile as _zip
    buf = _io.BytesIO()
    with _zip.ZipFile(buf, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        if sheet:
            archive.writestr("xl/workbook.xml", "<workbook/>")
            archive.writestr("xl/sharedStrings.xml", "<sst><si><t>Fees 2026</t></si></sst>")
        else:
            archive.writestr(
                "word/document.xml",
                "<w:document><w:t>Terms of engagement for James Smith</w:t></w:document>",
            )
        if macro:
            archive.writestr("word/vbaProject.bin", b"\x00macro")
    return buf.getvalue()


@pytest.mark.parametrize(
    "payload,expected",
    [
        (b"Engagement letter for James Smith\n", "text/plain"),
        (b'{"holder": "James", "passport": "British"}', "application/json"),
        (b"a,b,c\n1,2,3\n", "text/plain"),
    ],
    ids=["txt", "json", "csv"],
)
def test_text_documents_are_releasable(tmp_path, payload, expected):
    from plugins.juno_kite_trusted_principal.document_release import (
        ALLOWED_MIME_EXTENSIONS,
    )

    root = tmp_path / "family"
    root.mkdir()
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())
    info = runtime.document_releases.inspect_bytes(payload)
    assert info.mime_type == expected
    assert info.mime_type in ALLOWED_MIME_EXTENSIONS


def test_office_documents_are_releasable_but_macros_are_not(tmp_path):
    """James accepted weaker checks for office formats; macros are still out."""
    root = tmp_path / "family"
    root.mkdir()
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    word = runtime.document_releases.inspect_bytes(_docx_bytes())
    assert word.mime_type.endswith("wordprocessingml.document")
    sheet = runtime.document_releases.inspect_bytes(_docx_bytes(sheet=True))
    assert sheet.mime_type.endswith("spreadsheetml.sheet")

    with pytest.raises(DocumentReleaseDenied, match="macro"):
        runtime.document_releases.inspect_bytes(_docx_bytes(macro=True))


def test_a_text_document_with_a_credential_is_still_refused(tmp_path):
    root = tmp_path / "family"
    root.mkdir()
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())
    with pytest.raises(DocumentReleaseDenied, match="prohibited"):
        runtime.document_releases.inspect_bytes(b"api_key=abcdef1234567890\n")
    # Binary is no longer refused for being unrecognised -- it is carried as
    # opaque data -- but the credential scan still applies to what can be read
    # out of it, which is the property that actually protects anything.
    assert runtime.document_releases.inspect_bytes(
        b"\x00\x01binary\xff" + b"\x99" * 64
    ).mime_type == "application/octet-stream"
    with pytest.raises(DocumentReleaseDenied, match="prohibited"):
        runtime.document_releases.inspect_bytes(
            b"\x00\x01" + b"api_key=abcdef1234567890" + b"\xff" * 32
        )


def test_a_phone_photo_is_converted_rather_than_refused(monkeypatch):
    """HEIC is what an iPhone produces; it was refused outright."""
    from types import SimpleNamespace as _NS
    from plugins.juno_kite_trusted_principal import private_reads as pr

    jpeg = b"\xff\xd8\xff" + b"body"

    def fake_run(argv, **kwargs):
        assert argv[0] == pr._SIPS and "jpeg" in argv
        Path(argv[-1]).write_bytes(jpeg)
        return _NS(returncode=0)

    monkeypatch.setattr(pr.subprocess, "run", fake_run)
    for mime in ("image/heic", "image/heif", "image/tiff"):
        data, new_mime = pr._normalise_artifact(b"original-bytes", mime)
        assert (data, new_mime) == (jpeg, "image/jpeg"), mime
    # Already-releasable formats are passed through untouched.
    assert pr._normalise_artifact(b"%PDF-1.4", "application/pdf") == (
        b"%PDF-1.4", "application/pdf"
    )


def test_office_preview_reads_the_document_text():
    from plugins.juno_kite_trusted_principal.private_reads import _document_preview

    word = _document_preview(
        _docx_bytes(),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    assert "Terms of engagement for James Smith" in word
    assert "<w:" not in word


def test_a_text_file_wearing_an_image_name_is_still_caught(tmp_path):
    """Allowing text must not let a mislabelled file through the real path.

    inspect_bytes now reads "not an image" in a .png as text, correctly. The
    protection that matters lives one level up: the resolver states the mime it
    expects from the name, and staging discards anything that disagrees.
    """
    root = tmp_path / "family"
    root.mkdir()
    (root / "wrong.png").write_bytes(b"not an image, just text\n")
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    encoded, internal = runtime.private_reads.resolve_document_candidate(
        "kite_personal_files_read",
        {"operation": "read", "root": "family", "relative_path": "wrong.png"},
    )
    assert internal is not None
    # The name claims PNG; the bytes are text. Staging compares the two.
    assert internal["expected_mime"] == "image/png"
    assert runtime.document_releases.inspect_bytes(
        internal["path"].read_bytes()
    ).mime_type == "text/plain"


@pytest.mark.parametrize(
    "path,allowed",
    [
        ("/Users/james", False),
        ("/Users/james/Documents", False),
        ("/Users/james/Library", False),
        ("/Users/james/Library/Keychains", False),
        ("/Users/james/.ssh", False),
        ("/Users/james/.hermes/cache", False),
        ("/Users/james/Documents/work/payroll", False),
        ("/Users/james/Documents/Family/Passports", True),
        ("/Users/james/Desktop/Scans", True),
    ],
)
def test_root_areas_are_an_allow_list_not_a_deny_list(path, allowed):
    """The old rule blocked what it had thought of and permitted the rest.

    It refused home and Documents, but ~/Library was a legal root -- and that
    holds Keychains and the Messages database. A root now has to sit beneath a
    nominated documents area, so an oversight fails closed.
    """
    from plugins.juno_kite_trusted_principal.private_reads import PrivateReadService

    try:
        PrivateReadService._roots({"roots": [{"name": "t", "path": path}]})
        got = True
    except ValueError:
        got = False
    assert got is allowed, path


def test_naming_a_whole_area_is_not_a_root():
    from plugins.juno_kite_trusted_principal.private_reads import (
        PrivateReadService, _PERSONAL_ROOT_BASES,
    )

    for base in _PERSONAL_ROOT_BASES:
        with pytest.raises(ValueError, match="folder, not a whole area"):
            PrivateReadService._roots({"roots": [{"name": "t", "path": base}]})


def test_allowed_bases_must_be_deliberate():
    from plugins.juno_kite_trusted_principal.private_reads import PrivateReadService

    for bases in ([], "/", ["/"], [""]):
        with pytest.raises(ValueError):
            PrivateReadService._roots(
                {"roots": [{"name": "t", "path": "/Users/james/Documents/X"}],
                 "allowed_bases": bases}
            )


def _session_store(tmp_path, rows):
    """A stand-in for Kite's own session store, same shape as the real one."""
    import sqlite3 as _sql
    path = tmp_path / "sessions.sqlite3"
    db = _sql.connect(path)
    db.executescript(
        "create table sessions(id text primary key, session_key text);"
        "create table messages(id integer primary key, session_id text, role text,"
        " content text, timestamp real);"
        "create virtual table messages_fts using fts5(content);"
    )
    for index, (key, role, content, stamp) in enumerate(rows, start=1):
        db.execute("insert or ignore into sessions values (?,?)", (key, key))
        db.execute("insert into messages values (?,?,?,?,?)",
                   (index, key, role, content, stamp))
        db.execute("insert into messages_fts(rowid, content) values (?,?)",
                   (index, content))
    db.commit()
    db.close()
    return path


def _session_service(tmp_path, rows):
    from plugins.juno_kite_trusted_principal.private_reads import PrivateReadService
    return PrivateReadService(
        {"enabled": True, "output_bytes": 262144,
         "sessions": {"database": str(_session_store(tmp_path, rows))}},
        backends=None, command_runner=None, url_opener=None, secret_values=set(),
    )


def test_session_recall_answers_where_a_document_was_filed(tmp_path):
    """The case that started this: Kite knew, and could not say so.

    It had told James "saved the passport scans in a durable family folder"
    and the lane had no way to reach that.
    """
    service = _session_service(tmp_path, [
        ("agent:main:mattermost:channel:x", "assistant",
         "Saved the three current passport scans in a durable family folder: "
         "/Users/james/Documents/Family/Passports", 1786307203.0),
        ("agent:main:mattermost:channel:x", "assistant",
         "The weather tomorrow looks fine for the drive", 1786307100.0),
    ])
    found = service._sessions({"query": "passport scans", "max_results": 5})
    assert len(found) == 1
    assert "Family/Passports" in found[0]["excerpt"]
    assert found[0]["when"].startswith("2026-")
    assert found[0]["surface"] == "mattermost"


def test_session_recall_drops_anything_secret_shaped(tmp_path):
    """A transcript has no capability, so secrets never enter the turn."""
    service = _session_service(tmp_path, [
        ("agent:main:mattermost:channel:x", "assistant",
         "the passport portal api_key=abcdef1234567890 is stored in the vault",
         1786307203.0),
        ("agent:main:mattermost:channel:x", "assistant",
         "passport scans are filed under the family folder", 1786307100.0),
    ])
    found = service._sessions({"query": "passport", "max_results": 5})
    assert len(found) == 1
    assert "api_key" not in found[0]["excerpt"]


def test_session_recall_excludes_this_lane_and_bounds_its_output(tmp_path):
    service = _session_service(tmp_path, [
        ("agent:main:a2a:dm:jk-context", "assistant",
         "passport request handled on the juno lane " + "x" * 400, 1786307203.0),
        ("agent:main:mattermost:channel:x", "assistant",
         "passport " + "y" * 900, 1786307100.0),
    ])
    found = service._sessions({"query": "passport", "max_results": 5})
    assert len(found) == 1                      # the a2a lane's own traffic is not recall
    assert found[0]["surface"] == "mattermost"
    assert len(found[0]["excerpt"]) <= 300      # an excerpt, never a transcript


def test_session_recall_rejects_an_unbounded_or_odd_query(tmp_path):
    service = _session_service(tmp_path, [
        ("agent:main:mattermost:channel:x", "assistant", "passport filed", 1.0),
    ])
    # Still refused: nothing to search, or past the bound.
    for bad in ("a", "x" * 200, "£ $ %", "  "):
        raised = False
        try:
            service._sessions({"query": bad, "max_results": 3})
        except Exception as exc:
            raised = getattr(exc, "code", "") in {"invalid_arguments", "cap_exceeded"}
        assert raised, bad


def test_session_recall_cannot_change_the_store(tmp_path):
    """SQL-shaped words are just words: parameterised, read-only, no effect."""
    import sqlite3 as _sql
    service = _session_service(tmp_path, [
        ("agent:main:mattermost:channel:x", "assistant", "passport filed here", 1.0),
    ])
    database = service.config["sessions"]["database"]
    before = list(_sql.connect(database).execute("select count(*) from messages"))
    service._sessions({"query": "drop table messages", "max_results": 3})
    after = list(_sql.connect(database).execute("select count(*) from messages"))
    assert before == after and before[0][0] == 1


def test_session_recall_is_bound_to_one_principal():
    """Lucy inherits nothing here; adding her has to be a deliberate change."""
    from plugins.juno_kite_trusted_principal.runtime import _PRINCIPAL_BOUND_READS

    assert _PRINCIPAL_BOUND_READS["kite_session_search"] == frozenset({"james"})


def test_recall_is_offered_where_the_model_will_need_it():
    """The model has to choose the tool; today showed it needs telling."""
    from plugins.juno_kite_trusted_principal.disclosure import (
        MINIMIZED, generated_semantic_guidance,
    )

    def rule(tier):
        return generated_semantic_guidance(
            principal="james",
            effective_capability_ids=["juno.private.james"],
            configured_policy={"juno.private.james": {"domain": "juno.private.james"}},
            output_tier=tier,
        )["output_tier_rule"]

    assert "kite_session_search" in rule(MINIMIZED)
    assert "kite_session_search" in rule(DOCUMENT_DESCRIPTOR)


def test_recall_ranks_by_match_quality_not_recency(tmp_path):
    """Recency alone surfaced messages that merely contained the words."""
    service = _session_service(tmp_path, [
        ("agent:main:mattermost:channel:x", "assistant",
         "an unrelated note that happens to mention passports once", 1786300000.0),
        ("agent:main:mattermost:channel:x", "assistant",
         "passports passports filed: /Users/james/Documents/Family/Passports",
         1786200000.0),
    ])
    found = service._sessions({"query": "passports filed", "max_results": 2})
    # The older, better match leads.
    assert "Family/Passports" in found[0]["excerpt"]


def test_recall_matches_on_any_word_not_every_word(tmp_path):
    """The live Mauritius failure: 11 words, strict AND, zero results.

    The model asked "Mauritius trip confirmed dates travelers accommodation
    flights transport unresolved decisions" and got nothing back, so it told
    James the planning context was unavailable. bm25 puts the best match
    first; requiring every word just meant no match at all.
    """
    service = _session_service(tmp_path, [
        ("agent:main:mattermost:channel:x", "assistant",
         "Mauritius trip: flights confirmed for the family in August", 1786300000.0),
        ("agent:main:mattermost:channel:x", "assistant",
         "unrelated note about the garden fence", 1786200000.0),
    ])
    found = service._sessions({
        "query": "Mauritius trip confirmed dates travelers accommodation flights",
        "max_results": 5,
    })
    assert found and "Mauritius" in found[0]["excerpt"]


def test_recall_reduces_an_awkward_query_rather_than_refusing_it(tmp_path):
    """"One&Only Mauritius dates" was refused as "not plain words"."""
    service = _session_service(tmp_path, [
        ("agent:main:mattermost:channel:x", "assistant",
         "One&Only accepted the Mercedes V-Class for the airport transfer",
         1786300000.0),
    ])
    found = service._sessions({"query": "One&Only Mauritius dates", "max_results": 3})
    assert found and "One&Only" in found[0]["excerpt"]
    # Punctuation is reduced away, so FTS operators can never reach the match.
    for hostile in ('NEAR("a" "b")', "a AND b OR c", 'x" OR "y'):
        service._sessions({"query": hostile, "max_results": 3})
    # A query with no usable word is still refused rather than run empty.
    raised = False
    try:
        service._sessions({"query": "£ $ %", "max_results": 3})
    except Exception as exc:
        raised = getattr(exc, "code", "") == "invalid_arguments"
    assert raised


@pytest.mark.parametrize(
    "tier",
    ["minimized_answer", "bounded_excerpt", "specific_full_document_descriptor",
     "bulk_raw_export"],
)
def test_the_policy_view_fits_its_limit_on_every_tier(tmp_path, tier):
    """The guidance grew until the binding itself failed.

    _policy_view raises when the rendered view passes policy_view_chars, and
    _bind_request turns that into "Kite policy binding denied". The model then
    runs with no lane instructions at all and refuses -- which reads exactly
    like a policy refusal and is nothing of the kind. Every sentence added to
    the guidance spends this budget, so it is asserted per tier, with the full
    production capability set.
    """
    from plugins.juno_kite_trusted_principal.runtime import TurnBinding

    root = tmp_path / "family"
    root.mkdir()
    config = _config(tmp_path, root, mode="kite")
    section = config["juno_kite_trusted_principal"]
    # The production capability set, which is what the live view is rendered
    # against -- a smaller fixture would pass while production failed.
    live_caps = [
        "juno.private.james", "juno.shared.family", "juno.shared.children",
        "juno.shared.mauritius", "juno.shared.property_intel",
        "juno.shared.villa_lena", "juno.public",
    ]
    principal = section["policy"]["principals"]["james"]
    principal["read_capability_ids"] = list(live_caps)
    principal["semantic_policy"] = {c: {"domain": c} for c in live_caps}
    # The fixture is generous (20000); production allows 8000, and it is
    # production that decides whether a turn binds at all.
    section["limits"]["policy_view_chars"] = 8000
    caps = tuple(live_caps)
    runtime = TrustedPrincipalRuntime(config, active_profile="kite", clock=Clock())

    binding = TurnBinding(
        True, "",
        SimpleNamespace(principal="james", correlation_id="corr-x",
                        context_id="ctx-x"),
        SimpleNamespace(request_id="req-x"),
        "kite-session", "kite-turn", caps, (), tier,
    )
    rendered = runtime._policy_view(binding)
    limit = runtime.limits.policy_view_chars
    assert len(rendered) <= limit, (
        f"{tier}: policy view is {len(rendered)} chars against a {limit} limit"
    )


def test_a_childs_passport_is_within_the_configured_policy():
    """Juno refused "send me Albie's passport" without ever asking Kite.

    api_calls=1, no tool call, nothing in the A2A log -- a refusal invented on
    the low-trust side, which leaves no denial anywhere because nothing denied.
    It is also wrong: juno.shared.children covers children's passport and
    identity documents, and that capability is releasable.
    """
    from plugins.juno_kite_trusted_principal.disclosure import (
        CAPABILITY_DOMAINS, _DOCUMENT_RELEASABLE_CAPABILITIES, disclosure_decision,
    )

    domains = " ".join(CAPABILITY_DOMAINS["juno.shared.children"]).lower()
    assert "passport" in domains and "identity" in domains
    assert "juno.shared.children" in _DOCUMENT_RELEASABLE_CAPABILITIES

    decision = disclosure_decision(
        principal="james",
        effective_capability_ids=["juno.shared.children", "juno.private.james"],
        capability_id="juno.shared.children",
        output_tier=DOCUMENT_DESCRIPTOR,
    )
    assert decision.allowed, "a child's passport is releasable to James"


def test_juno_is_told_not_to_pre_judge_whose_document_it_is():
    """The only lever on Juno's side is the tool description."""
    from plugins.juno_kite_trusted_principal import TOOL_DESCRIPTION

    lowered = TOOL_DESCRIPTION.lower()
    assert "children" in lowered
    assert "never refuse because a document belongs to someone other" in lowered
    assert "host's decision" in lowered


def _juno_for_context(tmp_path):
    root = tmp_path / "family"
    root.mkdir()
    return _runtime(tmp_path, root, mode="juno", clock=Clock())


@pytest.mark.parametrize(
    "typed,expect_context",
    [
        ("Send me Frankie's passport", True),
        ("Send me Albie's passport", True),
        ("Show me the nacho engagement letter", True),
        ("What did we decide about the Mauritius trip?", False),
        ("Where did you file my passport scans?", False),
        ("", False),
    ],
)
def test_a_document_turn_carries_its_instruction_into_the_turn(
    tmp_path, typed, expect_context
):
    """Twice Juno refused a document request with one API call and no consult.

    The tool description already forbade that and was not enough. A static
    description is skimmed; a line in the turn is read. This fires only on a
    document turn, so ordinary questions are untouched.
    """
    from plugins.juno_kite_trusted_principal.runtime import _ACTIVE_INBOUND_TEXT

    juno = _juno_for_context(tmp_path)
    token = _ACTIVE_INBOUND_TEXT.set(typed)
    try:
        result = _session(lambda: juno.pre_llm_call(user_message=typed), mode="juno")
    finally:
        _ACTIVE_INBOUND_TEXT.reset(token)

    if not expect_context:
        assert result is None, typed
        return
    assert result is not None and "consult_kite" in result["context"], typed
    lowered = result["context"].lower()
    # It directs, without deciding entitlement itself.
    assert "host's decisions" in lowered
    assert "children's documents" in lowered
    assert "without having asked" in lowered


def test_the_turn_instruction_never_reaches_the_kite_lane(tmp_path):
    """Kite has its own policy view; this is only for the low-trust side."""
    root = tmp_path / "family"
    root.mkdir()
    kite = _runtime(tmp_path, root, mode="kite", clock=Clock())
    assert kite._juno_turn_context() is None


def test_a_refused_artifact_says_which_gate_refused_it(tmp_path):
    """"failed the release gate" cannot distinguish oversized from wrong-type.

    Frankie's passport is a 4.9MB scan that exists and was found, and the reply
    said only that a private source was incomplete -- which is neither the
    reason nor even the right category.
    """
    root = tmp_path / "family"
    root.mkdir()
    # A JPEG far past the artifact size ceiling: a real, nameable gate.
    huge = b"\xff\xd8\xff" + b"\x00" * (9 * 1024 * 1024)
    (root / "huge.jpg").write_bytes(huge)
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    from plugins.juno_kite_trusted_principal.document_release import (
        DocumentReleaseDenied,
    )
    raised = ""
    try:
        runtime.document_releases.inspect_bytes(huge)
    except DocumentReleaseDenied as exc:
        raised = str(exc)
    assert "size is out of bounds" in raised

    # The runtime surfaces that wording rather than swallowing it.
    source = Path("plugins/juno_kite_trusted_principal/runtime.py").read_text()
    assert 'f": {detail}" if detail else ""' in source
    assert "_typed_read_failures" in source


def test_the_release_gate_reasons_are_safe_to_surface():
    """They name the gate, not the document -- that is what they are for."""
    from plugins.juno_kite_trusted_principal.document_release import (
        DocumentReleaseService, DocumentReleaseDenied,
    )
    svc = DocumentReleaseService(None, store=None, mapping_key=b"0" * 32,
                                 clock=lambda: 0.0)
    for payload in (b"", b"\x00\x01binary\xff", b"%PDF-1.7\n/JavaScript\n%%EOF"):
        try:
            svc.inspect_bytes(payload)
        except DocumentReleaseDenied as exc:
            message = str(exc)
            # No paths, no names, no content -- just the rule that fired.
            assert "/" not in message and len(message) < 80, message


def test_a_phone_photo_is_a_still_not_an_animation(tmp_path):
    """Every family passport scan was refused; a PNG of the same page was not.

    The gate read "document MIME is mismatched" for ~4.9MB JPEG-framed files.
    An iPhone HDR or portrait photo is MPO: the same JPEG container carrying a
    second rendition, usually a gain map. It is a still image, and the frame
    rule exists to refuse things a viewer would animate.
    """
    from plugins.juno_kite_trusted_principal.document_release import (
        _JPEG_FORMATS, _MPO_MAX_FRAMES, DocumentReleaseService,
    )

    assert "MPO" in _JPEG_FORMATS and "JPEG" in _JPEG_FORMATS
    assert _MPO_MAX_FRAMES > 1

    source = Path("plugins/juno_kite_trusted_principal/document_release.py").read_text()
    # The frame allowance is scoped to MPO; a real animation is still refused.
    assert 'limit = _MPO_MAX_FRAMES if observed == "MPO" else 1' in source
    # A PNG is never widened by this.
    assert 'frozenset({"PNG"})' in source

    svc = DocumentReleaseService(None, store=None, mapping_key=b"0" * 32,
                                 clock=lambda: 0.0)
    from plugins.juno_kite_trusted_principal.document_release import (
        DocumentReleaseDenied,
    )
    # A JPEG-framed file that is not a still names the format it was read as.
    raised = ""
    try:
        svc.inspect_bytes(b"\xff\xd8\xff" + b"not really an image")
    except DocumentReleaseDenied as exc:
        raised = str(exc)
    assert raised, "a broken JPEG must still be refused"


def test_an_unfamiliar_document_type_is_carried_not_refused():
    """An allow-list refuses a new format every time one appears.

    HEIC, MPO and office files each cost a real failure before anyone
    noticed. A document does not become dangerous by being a format nobody
    anticipated, so the rule is now the one that matters: refuse what runs.
    """
    from plugins.juno_kite_trusted_principal.document_release import (
        DocumentReleaseService, DocumentReleaseDenied, ALLOWED_MIME_EXTENSIONS,
    )
    svc = DocumentReleaseService(None, store=None, mapping_key=b"0" * 32,
                                 clock=lambda: 0.0)

    # Formats nobody enumerated: a Numbers/Keynote blob, a RAW photo header.
    for blob in (b"\x0e\x0eNUMBERS" + b"\x11" * 400, b"II*\x00" + b"\x99" * 400):
        assert svc.inspect_bytes(blob).mime_type == "application/octet-stream"
    # And it can actually be delivered: the extension comes from the file.
    assert ALLOWED_MIME_EXTENSIONS["application/octet-stream"] == ""
    assert DocumentReleaseService._safe_title(
        "Family budget.numbers", keep_suffix=True) == "Family budget.numbers"


@pytest.mark.parametrize(
    "payload,label",
    [
        (b"#!/bin/sh\necho hi", "shell script"),
        (b"#!/usr/bin/env python3\nprint(1)", "python script"),
        (b"MZ" + b"\x00" * 200, "windows executable"),
        (b"\x7fELF" + b"\x00" * 200, "elf binary"),
        (b"\xcf\xfa\xed\xfe" + b"\x00" * 200, "mach-o binary"),
    ],
)
def test_things_that_run_are_still_refused(payload, label):
    """A script is executable and also decodes cleanly as text.

    Checking this only in the unrecognised branch would have let every
    shebang through as text/plain.
    """
    from plugins.juno_kite_trusted_principal.document_release import (
        DocumentReleaseService, DocumentReleaseDenied,
    )
    svc = DocumentReleaseService(None, store=None, mapping_key=b"0" * 32,
                                 clock=lambda: 0.0)
    raised = ""
    try:
        svc.inspect_bytes(payload)
    except DocumentReleaseDenied as exc:
        raised = str(exc)
    assert "executable" in raised, label


def test_an_executable_name_is_refused_even_with_harmless_bytes(tmp_path):
    """Bytes are not the only signal; the name matters at staging."""
    from plugins.juno_kite_trusted_principal.document_release import (
        DocumentReleaseService, DocumentReleaseDenied, _EXECUTABLE_SUFFIXES,
    )
    staging = tmp_path / "stage"
    from plugins.juno_kite_trusted_principal.mapping_store import MappingStore
    svc = DocumentReleaseService(
        {"enabled": True, "staging_path": str(staging)},
        store=MappingStore(tmp_path / "m.sqlite3", b"0" * 32),
        mapping_key=b"0" * 32, clock=lambda: 0.0,
    )
    assert ".command" in _EXECUTABLE_SUFFIXES and ".app" in _EXECUTABLE_SUFFIXES
    raised = ""
    try:
        svc.stage_bytes(b"just some text\n", source_class="personal files",
                        display_name="totally-safe.command")
    except DocumentReleaseDenied as exc:
        raised = str(exc)
    assert "executable" in raised
    assert not list(staging.glob("*.stage")), "nothing may be staged"


@pytest.mark.asyncio
async def test_a_question_about_a_document_is_not_a_request_for_one(tmp_path):
    """James asked for Lucy's passport number and was sent Lucy's passport.

    Both tiers were right -- minimized. The escalation came from
    relevant_context: Juno quoted the previous turn, "Send me Frankie's
    passport", and the strongest-tier rule counted quoted history as part of
    the current request.
    """
    from plugins.juno_kite_trusted_principal.disclosure import (
        MINIMIZED, classify_output_tier,
    )

    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    clock = Clock()
    adapter = RecordingWhatsAppAdapter(MutableRoster())
    juno = _runtime(tmp_path, root, mode="juno", clock=clock)

    asked = "What is Lucy's passport number and expiry?"
    assert classify_output_tier(asked) == MINIMIZED

    await juno.pre_gateway_dispatch(
        event=_event(asked),
        gateway=SimpleNamespace(adapters={Platform.WHATSAPP: adapter}),
        critical_ingress_token=object(),
    )
    prepared = _session(
        lambda: juno._prepare_request({
            "question_or_goal": "Extract the passport number and expiry",
            # The previous turn, quoted as context exactly as Juno quoted it.
            "relevant_context": [
                {"role": "user", "text": "Send me Frankie's passport"},
                {"role": "user", "text": asked},
            ],
        }),
        mode="juno",
    )
    payload = json.loads(prepared.message.split("JUNO_KITE_REQUEST_V2", 1)[1])
    assert payload["host_output_tier"] == MINIMIZED
    assert payload["host_informational"] is True

    # And the binding no longer scores quoted history at all.
    source = Path("plugins/juno_kite_trusted_principal/runtime.py").read_text()
    assert 'for turn in payload["relevant_context"]' not in source
    assert 'payload.get("host_informational") is True' in source


@pytest.mark.asyncio
async def test_asking_for_a_document_still_reaches_the_document_tier(tmp_path):
    """The cap must not disarm an actual request."""
    root = tmp_path / "family"
    root.mkdir()
    (root / "child-passport.png").write_bytes(_png_bytes())
    adapter = RecordingWhatsAppAdapter(MutableRoster())
    juno = _runtime(tmp_path, root, mode="juno", clock=Clock())

    await juno.pre_gateway_dispatch(
        event=_event("Send me Frankie's passport"),
        gateway=SimpleNamespace(adapters={Platform.WHATSAPP: adapter}),
        critical_ingress_token=object(),
    )
    prepared = _session(
        lambda: juno._prepare_request({"question_or_goal": "Release the passport"}),
        mode="juno",
    )
    payload = json.loads(prepared.message.split("JUNO_KITE_REQUEST_V2", 1)[1])
    assert payload["host_output_tier"] == DOCUMENT_DESCRIPTOR
    assert payload["host_informational"] is False


def test_a_document_can_be_read_without_being_sent(tmp_path, monkeypatch):
    """"What is Lucy's passport number" could only be answered by sending it.

    A PDF or a scan is readable even though it is not text; refusing to read
    it left the model no way to answer except release.
    """
    from types import SimpleNamespace as _NS
    from plugins.juno_kite_trusted_principal import private_reads as pr

    monkeypatch.setattr(
        pr, "_run_preview_reader",
        lambda argv, limit=600: "PASSPORT UNITED KINGDOM No 123456789 Expiry 04 MAR 2031",
    )
    root = tmp_path / "family"
    root.mkdir()
    (root / "passport.pdf").write_bytes(b"%PDF-1.4 scanned")
    runtime = _runtime(tmp_path, root, mode="kite", clock=Clock())

    result = json.loads(runtime.private_reads.execute(
        "kite_personal_files_read",
        {"operation": "read", "root": "family", "relative_path": "passport.pdf"},
    ))
    assert result["status"] == "ok"
    data = result["data"]
    assert data["outcome"] == "extracted"
    assert "123456789" in data["text"]
    # Still a bounded read of a named file, not the bytes.
    assert data["descriptor"]["mime_type"] == "application/pdf"
    assert "artifact" not in json.dumps(data)
