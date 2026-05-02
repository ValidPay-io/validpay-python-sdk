from __future__ import annotations

import base64
import json
from typing import Any, List, Optional
from unittest.mock import patch

import pytest

from validpay import (
    CreateIntentResult,
    ValidPayClient,
    ValidPayError,
    decrypt,
    encrypt,
    generate_key,
)


class _FakeResponse:
    def __init__(self, status_code: int, body: Any):
        self.status_code = status_code
        self.text = json.dumps(body) if body is not None else ""
        self.ok = 200 <= status_code < 300


class _FakeSession:
    """Records every request and returns scripted responses."""

    def __init__(self, responses: List[_FakeResponse]):
        self._responses = list(responses)
        self.calls: List[dict] = []

    def request(self, method, url, headers=None, data=None, timeout=None):
        self.calls.append({
            "method": method,
            "url": url,
            "headers": dict(headers or {}),
            "data": data,
            "timeout": timeout,
        })
        if not self._responses:
            raise AssertionError("No more scripted responses")
        return self._responses.pop(0)


def test_requires_api_key():
    with pytest.raises(ValidPayError):
        ValidPayClient(api_key="")


def test_create_intent_encrypts_locally_and_never_sends_key():
    session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_abc123def456", "status": "active"}),
    ])
    client = ValidPayClient(
        api_key="test_key",
        base_url="https://api.example.test",
        session=session,
    )

    payload = {"ssn": "123-45-6789", "name": "Jane Doe"}
    result = client.create_intent(document_type="ssn_card", payload=payload)

    assert isinstance(result, CreateIntentResult)
    assert result.retrieval_id == "vp_abc123def456"
    assert len(base64.b64decode(result.key)) == 32

    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://api.example.test/v1/intent"
    assert call["headers"]["Authorization"] == "Bearer test_key"
    assert call["headers"]["Content-Type"] == "application/json"

    sent_body = json.loads(call["data"])
    assert sent_body["document_type"] == "ssn_card"
    assert isinstance(sent_body["encrypted_payload"], str)

    full_call = json.dumps(call)
    assert result.key not in full_call
    assert "123-45-6789" not in full_call
    assert "Jane Doe" not in full_call

    decrypted = json.loads(decrypt(sent_body["encrypted_payload"], result.key))
    assert decrypted == payload


def test_base_url_trailing_slash_is_stripped():
    session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_x", "status": "active"}),
    ])
    client = ValidPayClient(
        api_key="k",
        base_url="https://api.example.test/",
        session=session,
    )
    client.create_intent(document_type="t", payload={})
    assert session.calls[0]["url"] == "https://api.example.test/v1/intent"


def test_create_intent_raises_on_non_2xx():
    session = _FakeSession([_FakeResponse(401, {"error": "unauthorized"})])
    client = ValidPayClient(
        api_key="bad",
        base_url="https://api.example.test",
        session=session,
    )
    with pytest.raises(ValidPayError) as exc:
        client.create_intent(document_type="t", payload={})
    assert exc.value.code == "unauthorized"
    assert exc.value.status == 401


def test_verify_intent_fetches_without_auth_and_decrypts():
    real_key = generate_key()
    blob = encrypt(json.dumps({"ssn": "111-22-3333"}), real_key)

    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_id_1",
            "encrypted_payload": blob,
            "issuer": "Acme Bank",
            "issuer_verified": True,
            "registered_at": "2026-04-29T12:00:00.000Z",
            "status": "active",
        }),
    ])
    client = ValidPayClient(
        api_key="unused",
        base_url="https://api.example.test",
        session=session,
    )

    result = client.verify_intent(retrieval_id="vp_id_1", key=real_key)

    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://api.example.test/v1/intent/vp_id_1"
    assert "Authorization" not in call["headers"]
    assert real_key not in json.dumps(call)

    assert result.intent_id == "vp_id_1"
    assert result.payload == {"ssn": "111-22-3333"}
    assert result.issuer == "Acme Bank"
    assert result.issuer_verified is True
    assert result.registered_at == "2026-04-29T12:00:00.000Z"
    assert result.status == "active"


def test_verify_intent_with_wrong_key_raises_decryption_failed():
    real_key = generate_key()
    wrong_key = generate_key()
    blob = encrypt(json.dumps({"a": 1}), real_key)

    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_x",
            "encrypted_payload": blob,
            "issuer": "X",
            "issuer_verified": True,
            "registered_at": "2026-04-29T12:00:00.000Z",
            "status": "active",
        }),
    ])
    client = ValidPayClient(
        api_key="k",
        base_url="https://api.example.test",
        session=session,
    )
    with pytest.raises(ValidPayError) as exc:
        client.verify_intent(retrieval_id="vp_x", key=wrong_key)
    assert exc.value.code == "decryption_failed"


def test_verify_intent_surfaces_404():
    session = _FakeSession([_FakeResponse(404, {"error": "not_found"})])
    client = ValidPayClient(
        api_key="k",
        base_url="https://api.example.test",
        session=session,
    )
    with pytest.raises(ValidPayError) as exc:
        client.verify_intent(retrieval_id="vp_missing", key="a" * 44)
    assert exc.value.code == "not_found"
    assert exc.value.status == 404


def test_argument_validation():
    client = ValidPayClient(api_key="k", session=_FakeSession([]))
    with pytest.raises(ValidPayError):
        client.verify_intent(retrieval_id="", key="k")
    with pytest.raises(ValidPayError):
        client.verify_intent(retrieval_id="id", key="")
    with pytest.raises(ValidPayError):
        client.create_intent(document_type="", payload={})


def test_create_intent_batch_encrypts_each_payload_with_unique_key():
    session = _FakeSession([
        _FakeResponse(201, {
            "results": [
                {"retrieval_id": "vp_one", "status": "active"},
                {"retrieval_id": "vp_two", "status": "active"},
            ],
            "count": 2,
        }),
    ])
    client = ValidPayClient(
        api_key="k",
        base_url="https://api.example.test",
        session=session,
    )

    inputs = [
        {"document_type": "check", "payload": {"payee": "Alice", "amount": 500}},
        {"document_type": "check", "payload": {"payee": "Bob", "amount": 750}},
    ]
    results = client.create_intent_batch(inputs)

    assert len(results) == 2
    assert results[0].retrieval_id == "vp_one"
    assert results[1].retrieval_id == "vp_two"
    assert results[0].key != results[1].key

    call = session.calls[0]
    assert call["url"] == "https://api.example.test/v1/intent/batch"
    sent = json.loads(call["data"])
    assert len(sent["intents"]) == 2

    full_call = json.dumps(call)
    assert "Alice" not in full_call
    assert "Bob" not in full_call
    assert results[0].key not in full_call
    assert results[1].key not in full_call

    assert json.loads(decrypt(sent["intents"][0]["encrypted_payload"], results[0].key)) == inputs[0]["payload"]
    assert json.loads(decrypt(sent["intents"][1]["encrypted_payload"], results[1].key)) == inputs[1]["payload"]


def test_create_intent_batch_rejects_empty_and_oversized():
    client = ValidPayClient(api_key="k", session=_FakeSession([]))
    with pytest.raises(ValidPayError):
        client.create_intent_batch([])
    too_many = [{"document_type": "t", "payload": {}}] * 101
    with pytest.raises(ValidPayError):
        client.create_intent_batch(too_many)


def test_create_intent_batch_rejects_malformed_items():
    client = ValidPayClient(api_key="k", session=_FakeSession([]))
    with pytest.raises(ValidPayError):
        client.create_intent_batch([{"payload": {}}])  # missing document_type
    with pytest.raises(ValidPayError):
        client.create_intent_batch([{"document_type": "t"}])  # missing payload


def test_network_error_wrapped_as_validpay_error():
    import requests

    class _BoomSession:
        def request(self, *a, **kw):
            raise requests.ConnectionError("dns failure")

    client = ValidPayClient(api_key="k", session=_BoomSession())  # type: ignore[arg-type]
    with pytest.raises(ValidPayError) as exc:
        client.create_intent(document_type="t", payload={})
    assert exc.value.code == "network_error"
