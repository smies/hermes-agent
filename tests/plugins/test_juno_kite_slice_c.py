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
        "roots": [{"name": "family", "path": str(personal_root)}]
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
        "mime_type",
        "size_bytes",
    }
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
        ("wrong.png", b"not an image"),
        ("encrypted.pdf", b"%PDF-1.7\n1 0 obj<</Encrypt 2 0 R>>endobj\n%%EOF"),
        ("active.pdf", b"%PDF-1.7\n1 0 obj<</JavaScript 2 0 R>>endobj\n%%EOF"),
        ("escaped-active.pdf", b"%PDF-1.7\n1 0 obj<</Java#53cript 2 0 R>>endobj\n%%EOF"),
        ("html.pdf", b"%PDF-1.7\n/OpenAction<</S/URI/URI(https://example.test)>>\n%%EOF"),
        ("too-many-pages.pdf", b"%PDF-1.7\n" + b"/Type /Page\n" * 26 + b"%%EOF"),
        ("malformed.pdf", b"%PDF-1.7\n/Type /Page\n"),
    ],
    ids=[
        "oversize",
        "wrong-mime",
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
    "token", [b"/JavaScript", b"/Java#53cript", b"/OpenAction", b"/ObjStm"]
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
        _pdf_with_stream(b"ordinary text", filter_name=b"LZWDecode"),
        _pdf_with_stream(
            b"unused",
            filter_name=b"FlateDecode",
            encoded_payload=b"not-a-zlib-stream",
        ),
    ],
    ids=["unsupported-filter", "invalid-flate"],
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
    assert "never grounds to report the document missing" in rule


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
