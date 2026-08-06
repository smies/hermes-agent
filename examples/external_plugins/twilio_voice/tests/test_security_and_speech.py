from __future__ import annotations

from twilio_voice.security import (
    PendingCallStore,
    compute_twilio_signature,
    validate_twilio_signature,
)
from twilio_voice.speech import StreamingSpeech, phone_friendly_text


def test_signature_valid_invalid_and_parameter_order():
    params = {"To": "+442000000002", "CallSid": "CA" + "1" * 32, "From": "+442000000001"}
    url = "https://voice.example.test/twilio/voice"
    signature = compute_twilio_signature("test-auth-token", url, params)
    assert validate_twilio_signature("test-auth-token", url, params, signature)
    assert not validate_twilio_signature("wrong", url, params, signature)
    assert not validate_twilio_signature("test-auth-token", url + "/", params, signature)
    assert not validate_twilio_signature("test-auth-token", url, params, "not-base64")


def test_signature_matches_twilio_documented_vector():
    url = "https://example.com/myapp.php?foo=1&bar=2"
    params = {
        "Digits": "1234",
        "To": "+18005551212",
        "From": "+14158675310",
        "Caller": "+14158675310",
        "CallSid": "CA1234567890ABCDE",
    }
    assert compute_twilio_signature("12345", url, params) == "L/OH5YylLD5NRKLltdqwSvS0BnU="


def test_pending_call_state_is_one_use_bounded_and_expiring():
    store = PendingCallStore(ttl_seconds=5, max_entries=2)
    common = dict(account_sid="AC" + "1" * 32, caller="+442000000001", called="+442000000002", pin_verified=True)
    first = store.create(call_sid="CA" + "1" * 32, now=10, **common)
    second = store.create(call_sid="CA" + "2" * 32, now=11, **common)
    third = store.create(call_sid="CA" + "3" * 32, now=12, **common)
    assert store.consume(first.nonce, now=12) is None
    assert store.consume(second.nonce, now=12) == second
    assert store.consume(second.nonce, now=12) is None
    assert store.consume(third.nonce, now=18) is None


def test_phone_text_and_incremental_stream_avoid_markdown_code_and_urls():
    raw = "## Result\nSee [the docs](https://secret.example/path). `value`\n```python\nprint('secret')\n```"
    spoken = phone_friendly_text(raw)
    assert "https://" not in spoken
    assert "```" not in spoken
    assert "print(" not in spoken
    assert "a link" in spoken
    assert "Code omitted" in spoken

    stream = StreamingSpeech(max_buffer=48)
    assert stream.update("Visit https://secret", final=False) == []
    chunks = stream.update("Visit https://secret.example/path now. Then continue ", final=False)
    assert chunks
    assert "secret.example" not in "".join(chunks)
    tail = stream.update("Visit https://secret.example/path now. Then continue safely", final=True)
    assert "safely" in "".join(tail)


def test_streaming_split_fence_and_long_bare_domain_never_leak():
    stream = StreamingSpeech(max_buffer=48)
    assert stream.update("Before. ``", final=False) == ["Before. "]
    assert stream.update("Before. ```python\nprivate_call()", final=False) == []
    tail = stream.update(
        "Before. ```python\nprivate_call()\n``` After secret.example/" + "x" * 80,
        final=True,
    )
    spoken = "".join(tail)
    assert "private_call" not in spoken
    assert "secret.example" not in spoken
    assert "Code omitted" in spoken
