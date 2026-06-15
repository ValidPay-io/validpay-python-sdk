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
    build_aad,
    build_key_map,
    combine_key_shares,
    compute_commitment_hash,
    decrypt,
    decrypt_fields,
    encrypt,
    encrypt_fields,
    generate_key,
    split_key,
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
    """Since 1.1.0 create_intent defaults to split-key: the result key is
    Share A, Share B travels to the server, and neither the full key nor
    the plaintext ever appears on the wire."""
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
    assert sent_body["split_key"] is True
    assert isinstance(sent_body["key_fragment_b"], str)

    full_call = json.dumps(call)
    assert result.key not in full_call  # Share A never sent
    assert "123-45-6789" not in full_call
    assert "Jane Doe" not in full_call

    # Share A (returned) XOR Share B (sent) reconstructs the full key.
    full_key = combine_key_shares(result.key, sent_body["key_fragment_b"])
    assert full_key not in full_call  # full key never on the wire either
    # M-5: the blob is AAD-bound, so pass the same AAD the create call used.
    decrypted = json.loads(
        decrypt(sent_body["encrypted_payload"], full_key, build_aad("ssn_card"))
    )
    assert decrypted == payload


def test_create_intent_split_key_false_is_legacy_full_key():
    """split_key=False preserves the 1.0.x behavior: no fragment fields,
    and the returned key decrypts the payload directly."""
    session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_legacy1", "status": "active"}),
    ])
    client = ValidPayClient(
        api_key="test_key",
        base_url="https://api.example.test",
        session=session,
    )

    payload = {"amount": "100.00"}
    result = client.create_intent(
        document_type="check", payload=payload, split_key=False,
    )

    sent_body = json.loads(session.calls[0]["data"])
    assert "split_key" not in sent_body
    assert "key_fragment_b" not in sent_body
    # M-5: create_intent binds AAD even for the legacy single-key flow.
    decrypted = json.loads(
        decrypt(sent_body["encrypted_payload"], result.key, build_aad("check"))
    )
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

    assert json.loads(decrypt(sent["intents"][0]["encrypted_payload"], results[0].key, build_aad(inputs[0]["document_type"]))) == inputs[0]["payload"]
    assert json.loads(decrypt(sent["intents"][1]["encrypted_payload"], results[1].key, build_aad(inputs[1]["document_type"]))) == inputs[1]["payload"]


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


def test_create_intent_sends_commitment_hash_over_ciphertext():
    session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_h", "status": "active"}),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)

    payload = {"payee": "Alice", "amount": 100}
    client.create_intent(document_type="check", payload=payload)

    sent = json.loads(session.calls[0]["data"])
    # C-1: the commitment is SHA-256 of the ciphertext blob, NOT the plaintext.
    assert sent["commitment_hash"] == compute_commitment_hash(sent["encrypted_payload"])
    assert sent["commitment_hash"] != compute_commitment_hash(json.dumps(payload))
    assert len(sent["commitment_hash"]) == 64


def test_create_intent_batch_includes_per_item_commitment_hash():
    session = _FakeSession([
        _FakeResponse(201, {
            "results": [
                {"retrieval_id": "vp_a", "status": "active"},
                {"retrieval_id": "vp_b", "status": "active"},
            ],
            "count": 2,
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)

    payloads = [{"x": 1}, {"y": 2}]
    client.create_intent_batch([
        {"document_type": "check", "payload": payloads[0]},
        {"document_type": "check", "payload": payloads[1]},
    ])
    sent = json.loads(session.calls[0]["data"])["intents"]
    # C-1: per-item commitment is over each item's ciphertext blob.
    assert sent[0]["commitment_hash"] == compute_commitment_hash(sent[0]["encrypted_payload"])
    assert sent[1]["commitment_hash"] == compute_commitment_hash(sent[1]["encrypted_payload"])


def test_verify_intent_with_matching_commitment_hash_sets_integrity_verified():
    real_key = generate_key()
    plaintext = json.dumps({"amount": 1500})
    blob = encrypt(plaintext, real_key)
    # C-1: commitment v2 is over the ciphertext, and the response must carry
    # commitment_version >= 2 for the verifier to enforce it.
    commitment_hash = compute_commitment_hash(blob)

    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_int_1",
            "encrypted_payload": blob,
            "commitment_hash": commitment_hash,
            "commitment_version": 2,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)

    result = client.verify_intent(retrieval_id="vp_int_1", key=real_key)
    assert result.integrity_verified is True
    assert result.payload == {"amount": 1500}


def test_verify_intent_with_mismatched_commitment_hash_raises_integrity_failure():
    real_key = generate_key()
    plaintext = json.dumps({"amount": 1500})
    blob = encrypt(plaintext, real_key)
    bad_hash = "0" * 64

    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_int_2",
            "encrypted_payload": blob,
            "commitment_hash": bad_hash,
            "commitment_version": 2,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    with pytest.raises(ValidPayError) as exc:
        client.verify_intent(retrieval_id="vp_int_2", key=real_key)
    assert exc.value.code == "integrity_failure"


def test_verify_intent_legacy_v1_commitment_is_skipped():
    # A v1 (or version-less) commitment over plaintext must NOT be enforced —
    # it's the confirmation-oracle risk C-1 fixes. Integrity stays False and
    # verification still succeeds so legacy QR codes keep working.
    real_key = generate_key()
    plaintext = json.dumps({"amount": 1500})
    blob = encrypt(plaintext, real_key)

    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_v1",
            "encrypted_payload": blob,
            "commitment_hash": compute_commitment_hash(plaintext),  # legacy plaintext hash
            "commitment_version": 1,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    result = client.verify_intent(retrieval_id="vp_v1", key=real_key)
    assert result.integrity_verified is False
    assert result.payload == {"amount": 1500}


def test_verify_intent_legacy_intent_without_commitment_hash_passes_with_integrity_false():
    real_key = generate_key()
    plaintext = json.dumps({"amount": 1500})
    blob = encrypt(plaintext, real_key)

    # No commitment_hash key in the response — simulates a legacy intent.
    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_legacy",
            "encrypted_payload": blob,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)

    result = client.verify_intent(retrieval_id="vp_legacy", key=real_key)
    assert result.integrity_verified is False
    assert result.payload == {"amount": 1500}


def test_verify_intent_with_null_commitment_hash_passes_with_integrity_false():
    real_key = generate_key()
    plaintext = json.dumps({"a": 1})
    blob = encrypt(plaintext, real_key)

    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_null_hash",
            "encrypted_payload": blob,
            "commitment_hash": None,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    result = client.verify_intent(retrieval_id="vp_null_hash", key=real_key)
    assert result.integrity_verified is False


def test_verify_intent_revoked_raises_intent_revoked():
    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_rev_1",
            "encrypted_payload": None,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "revoked",
            "revoked_at": "2026-05-02T12:00:00.000Z",
            "revocation_reason": "Stop payment requested by account holder",
            "commitment_hash": None,
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    with pytest.raises(ValidPayError) as exc:
        client.verify_intent(retrieval_id="vp_rev_1", key=generate_key())
    assert exc.value.code == "intent_revoked"
    assert "Stop payment" in exc.value.message
    assert exc.value.details["status"] == "revoked"
    assert exc.value.details["revoked_at"] == "2026-05-02T12:00:00.000Z"


def test_revoke_intent_sends_patch_with_reason():
    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_x",
            "status": "revoked",
            "revoked_at": "2026-05-02T13:00:00.000Z",
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    result = client.revoke_intent("vp_x", reason="Account holder requested stop")
    assert result["status"] == "revoked"
    assert result["revoked_at"] == "2026-05-02T13:00:00.000Z"

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["url"] == "https://api.example.test/v1/intent/vp_x/revoke"
    assert call["headers"]["Authorization"] == "Bearer k"
    sent = json.loads(call["data"])
    assert sent == {"reason": "Account holder requested stop"}


def test_revoke_intent_without_reason_sends_empty_body():
    session = _FakeSession([
        _FakeResponse(200, {"intent_id": "vp_x", "status": "revoked", "revoked_at": "2026-05-02T13:00:00.000Z"}),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    client.revoke_intent("vp_x")
    call = session.calls[0]
    # Spec: when no reason is provided, send an empty JSON body `{}`.
    assert json.loads(call["data"]) == {}
    assert call["headers"]["Content-Type"] == "application/json"


def test_revoke_intent_validates_retrieval_id():
    client = ValidPayClient(api_key="k", session=_FakeSession([]))
    with pytest.raises(ValidPayError):
        client.revoke_intent("")


def test_reinstate_intent_sends_patch():
    session = _FakeSession([
        _FakeResponse(200, {"intent_id": "vp_x", "status": "active"}),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    result = client.reinstate_intent("vp_x", reason="False alarm")
    assert result["status"] == "active"

    call = session.calls[0]
    assert call["method"] == "PATCH"
    assert call["url"] == "https://api.example.test/v1/intent/vp_x/reinstate"
    sent = json.loads(call["data"])
    assert sent == {"reason": "False alarm"}


def test_reinstate_intent_validates_retrieval_id():
    client = ValidPayClient(api_key="k", session=_FakeSession([]))
    with pytest.raises(ValidPayError):
        client.reinstate_intent("")


def test_revoke_intent_409_raises_already_revoked():
    session = _FakeSession([_FakeResponse(409, {"error": "already_revoked"})])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    with pytest.raises(ValidPayError) as exc:
        client.revoke_intent("vp_x")
    assert exc.value.code == "already_revoked"
    assert exc.value.status == 409


def test_get_revocation_history_returns_events_list():
    session = _FakeSession([
        _FakeResponse(200, {
            "events": [
                {"id": "u1", "action": "reinstated", "reason": "False alarm", "performed_at": "2026-05-02T14:00:00.000Z"},
                {"id": "u2", "action": "revoked", "reason": None, "performed_at": "2026-05-02T13:00:00.000Z"},
            ]
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    events = client.get_revocation_history("vp_x")
    assert len(events) == 2
    assert events[0]["action"] == "reinstated"
    assert events[1]["action"] == "revoked"

    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://api.example.test/v1/intent/vp_x/revocations"
    assert call["headers"]["Authorization"] == "Bearer k"


def test_get_revocation_history_validates_retrieval_id():
    client = ValidPayClient(api_key="k", session=_FakeSession([]))
    with pytest.raises(ValidPayError):
        client.get_revocation_history("")


def test_split_key_create_sends_fragment_b_and_returns_share_a():
    session = _FakeSession([
        _FakeResponse(201, {
            "retrieval_id": "vp_sk_1",
            "status": "active",
            "split_key": True,
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)

    payload = {"payee": "Alice", "amount": 1000}
    result = client.create_split_key_intent(document_type="check", payload=payload)

    assert isinstance(result, CreateIntentResult)
    assert result.retrieval_id == "vp_sk_1"
    # `result.key` is Share A — base64, 32 bytes when decoded.
    assert len(base64.b64decode(result.key)) == 32

    sent = json.loads(session.calls[0]["data"])
    assert sent["split_key"] is True
    assert sent["document_type"] == "check"
    assert isinstance(sent["encrypted_payload"], str)
    assert isinstance(sent["key_fragment_b"], str)
    assert len(base64.b64decode(sent["key_fragment_b"])) == 32

    # Critical: Share B (sent to the server) is NOT the same as Share A
    # (returned to the caller). Neither alone reveals the full key.
    assert sent["key_fragment_b"] != result.key


def test_split_key_round_trip():
    """End-to-end: create on the wire, then verify on the wire, decrypts back."""
    payload = {"ssn": "555-01-0001", "name": "Bob"}

    # Track calls so we can replay state across mocked requests.
    captured_body: dict = {}

    create_session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_sk_2", "status": "active", "split_key": True}),
    ])
    creator = ValidPayClient(api_key="k", base_url="https://api.example.test", session=create_session)
    create_result = creator.create_split_key_intent(document_type="ssn_card", payload=payload)
    captured_body = json.loads(create_session.calls[0]["data"])

    # Now simulate the verifier side. The server stored fragment_b and the
    # encrypted payload — replay both back through the verify call.
    encrypted_payload = captured_body["encrypted_payload"]
    fragment_b = captured_body["key_fragment_b"]

    verify_session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_sk_2",
            "encrypted_payload": encrypted_payload,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
            "split_key": True,
            "commitment_hash": captured_body["commitment_hash"],
            "commitment_version": 2,
            # M-5: echo the fields the verifier rebuilds the AAD from. The
            # create call bound build_aad("ssn_card", None, None).
            "encryption_version": 2,
            "document_type": "ssn_card",
        }),
        _FakeResponse(200, {"intent_id": "vp_sk_2", "fragment_b": fragment_b}),
    ])
    verifier = ValidPayClient(api_key="k", base_url="https://api.example.test", session=verify_session)
    result = verifier.verify_split_key_intent(retrieval_id="vp_sk_2", share_a=create_result.key)

    assert result.payload == payload
    assert result.integrity_verified is True

    # The fragment GET hit the right URL, no auth header.
    fragment_call = verify_session.calls[1]
    assert fragment_call["method"] == "GET"
    assert fragment_call["url"] == "https://api.example.test/v1/intent/vp_sk_2/fragment"
    assert "Authorization" not in fragment_call["headers"]


def test_verify_intent_delegates_to_split_key_flow():
    """Since 1.1.0 verify_intent treats the key as Share A on a split-key
    intent and transparently runs the split-key flow, so the natural
    create_intent -> verify_intent round trip works."""
    payload = {"x": 1}

    create_session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_sk_3", "status": "active", "split_key": True}),
    ])
    creator = ValidPayClient(api_key="k", base_url="https://api.example.test", session=create_session)
    create_result = creator.create_intent(document_type="check", payload=payload)
    sent_body = json.loads(create_session.calls[0]["data"])

    verify_session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_sk_3",
            "encrypted_payload": sent_body["encrypted_payload"],
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
            "split_key": True,
            "commitment_hash": sent_body["commitment_hash"],
            "commitment_version": 2,
            # M-5: verify reconstructs the AAD from these.
            "encryption_version": 2,
            "document_type": "check",
        }),
        _FakeResponse(200, {"intent_id": "vp_sk_3", "fragment_b": sent_body["key_fragment_b"]}),
    ])
    verifier = ValidPayClient(api_key="k", base_url="https://api.example.test", session=verify_session)
    result = verifier.verify_intent(retrieval_id="vp_sk_3", key=create_result.key)
    assert result.payload == payload
    assert result.integrity_verified is True
    # The delegation fetched the fragment endpoint.
    assert verify_session.calls[1]["url"].endswith("/v1/intent/vp_sk_3/fragment")


def test_verify_split_key_intent_revoked_raises():
    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_sk_4",
            "encrypted_payload": None,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "revoked",
            "revoked_at": "2026-05-02T12:00:00.000Z",
            "revocation_reason": "Stop payment",
            "split_key": True,
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    a, _b = split_key(generate_key())
    with pytest.raises(ValidPayError) as exc:
        client.verify_split_key_intent(retrieval_id="vp_sk_4", share_a=a)
    assert exc.value.code == "intent_revoked"


def test_verify_split_key_intent_validates_arguments():
    client = ValidPayClient(api_key="k", session=_FakeSession([]))
    with pytest.raises(ValidPayError):
        client.verify_split_key_intent(retrieval_id="", share_a="anything")
    with pytest.raises(ValidPayError):
        client.verify_split_key_intent(retrieval_id="vp_x", share_a="")


def test_verify_split_key_intent_missing_fragment_raises():
    real_key = generate_key()
    blob = encrypt(json.dumps({"x": 1}), real_key)
    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_sk_5",
            "encrypted_payload": blob,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
            "split_key": True,
        }),
        _FakeResponse(200, {"error": "intent_revoked"}),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    a, _b = split_key(generate_key())
    with pytest.raises(ValidPayError) as exc:
        client.verify_split_key_intent(retrieval_id="vp_sk_5", share_a=a)
    assert exc.value.code == "intent_revoked"


def test_split_key_xor_relationship_holds_via_combine_helper():
    """Sanity check that the pieces the SDK sends actually XOR back to a key."""
    session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_sk_6", "status": "active", "split_key": True}),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    result = client.create_split_key_intent(document_type="check", payload={"amount": 1})

    sent = json.loads(session.calls[0]["data"])
    full_key = combine_key_shares(result.key, sent["key_fragment_b"])
    # Decrypting with the recombined key should work — that's what the verifier does.
    # M-5: the blob is AAD-bound, so pass the same AAD the create call used.
    assert decrypt(sent["encrypted_payload"], full_key, build_aad("check")) == json.dumps({"amount": 1})


def test_network_error_wrapped_as_validpay_error():
    import requests

    class _BoomSession:
        def request(self, *a, **kw):
            raise requests.ConnectionError("dns failure")

    client = ValidPayClient(api_key="k", session=_BoomSession())  # type: ignore[arg-type]
    with pytest.raises(ValidPayError) as exc:
        client.create_intent(document_type="t", payload={})
    assert exc.value.code == "network_error"


def test_create_selective_intent_sends_envelope_and_policy():
    session = _FakeSession([
        _FakeResponse(201, {
            "retrieval_id": "vp_sel_1",
            "status": "active",
            "selective_disclosure": True,
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)

    payload = {"name": "Alice", "amount": 100, "ssn": "111-22-3333"}
    policy = {"bank": ["amount"], "auditor": ["amount", "name"]}
    result = client.create_selective_intent(
        document_type="check",
        payload=payload,
        disclosure_policy=policy,
    )
    assert result.retrieval_id == "vp_sel_1"

    sent = json.loads(session.calls[0]["data"])
    assert sent["selective_disclosure"] is True
    assert sent["disclosure_policy"] == json.dumps(policy)
    assert isinstance(sent["encrypted_key_map"], str)
    # encrypted_payload must be a JSON envelope (dict of field → ciphertext),
    # not a single opaque blob.
    envelope = json.loads(sent["encrypted_payload"])
    assert isinstance(envelope, dict)
    assert set(envelope.keys()) == {"name", "amount", "ssn"}
    # Plaintext values must not leak into the request body.
    full_call = json.dumps(session.calls[0])
    assert "Alice" not in full_call
    assert "111-22-3333" not in full_call


def test_create_selective_intent_validates_policy_fields():
    client = ValidPayClient(api_key="k", session=_FakeSession([]))
    with pytest.raises(ValidPayError) as exc:
        client.create_selective_intent(
            document_type="check",
            payload={"name": "Alice"},
            disclosure_policy={"bank": ["nonexistent"]},
        )
    assert exc.value.code == "invalid_argument"


def test_verify_intent_rejects_selective_disclosure():
    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_sel_2",
            "encrypted_payload": json.dumps({"a": "blob"}),
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
            "selective_disclosure": True,
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    with pytest.raises(ValidPayError) as exc:
        client.verify_intent(retrieval_id="vp_sel_2", key=generate_key())
    assert exc.value.code == "selective_disclosure_required"


def _build_selective_intent_response(payload: dict, policy: dict, *, intent_id: str = "vp_sel_x", split_key_flag: bool = False):
    """Helper: produce the (master_key, server_response) for a selective intent."""
    master_key = generate_key()
    encrypted_fields, field_keys = encrypt_fields(payload)
    key_map = build_key_map(field_keys, policy)
    encrypted_key_map = encrypt(json.dumps(key_map), master_key)
    envelope = json.dumps(encrypted_fields)
    # C-1: commitment v2 is over the ciphertext envelope, role-independent.
    commitment_hash = compute_commitment_hash(envelope)
    response = {
        "intent_id": intent_id,
        "encrypted_payload": envelope,
        "issuer": "Acme",
        "issuer_verified": True,
        "registered_at": "2026-05-02T00:00:00.000Z",
        "status": "active",
        "split_key": split_key_flag,
        "selective_disclosure": True,
        "disclosure_policy": json.dumps(policy),
        "encrypted_key_map": encrypted_key_map,
        "commitment_hash": commitment_hash,
        "commitment_version": 2,
    }
    return master_key, response


def test_verify_selective_intent_full_role_decrypts_all():
    payload = {"name": "Alice", "amount": 100, "ssn": "111-22-3333"}
    policy = {"bank": ["amount"]}
    master_key, response = _build_selective_intent_response(payload, policy)

    session = _FakeSession([_FakeResponse(200, response)])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    result = client.verify_selective_intent(
        retrieval_id="vp_sel_x",
        key=master_key,
        role="full",
    )
    assert result.payload == payload
    assert result.integrity_verified is True


def test_verify_selective_intent_partial_role_redacts():
    payload = {"name": "Alice", "amount": 100, "ssn": "111-22-3333"}
    policy = {"bank": ["amount"]}
    master_key, response = _build_selective_intent_response(payload, policy)

    session = _FakeSession([_FakeResponse(200, response)])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    result = client.verify_selective_intent(
        retrieval_id="vp_sel_x",
        key=master_key,
        role="bank",
    )
    assert result.payload["amount"] == 100
    assert result.payload["name"] == "[REDACTED]"
    assert result.payload["ssn"] == "[REDACTED]"
    # C-1: the commitment is over the ciphertext envelope, so integrity is
    # now verified for ANY role — not just "full" (it no longer needs the
    # decrypted plaintext).
    assert result.integrity_verified is True


def test_verify_selective_intent_invalid_role_raises():
    payload = {"name": "Alice", "amount": 100}
    policy = {"bank": ["amount"]}
    master_key, response = _build_selective_intent_response(payload, policy)

    session = _FakeSession([_FakeResponse(200, response)])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    with pytest.raises(ValidPayError) as exc:
        client.verify_selective_intent(
            retrieval_id="vp_sel_x",
            key=master_key,
            role="nonexistent",
        )
    assert exc.value.code == "invalid_role"


def test_create_selective_intent_with_split_key():
    """End-to-end: split-key + selective disclosure round-trip."""
    payload = {"name": "Alice", "amount": 100, "ssn": "111-22-3333"}
    policy = {"bank": ["amount"]}

    create_session = _FakeSession([
        _FakeResponse(201, {
            "retrieval_id": "vp_sel_sk",
            "status": "active",
            "selective_disclosure": True,
            "split_key": True,
        }),
    ])
    creator = ValidPayClient(api_key="k", base_url="https://api.example.test", session=create_session)
    create_result = creator.create_selective_intent(
        document_type="check",
        payload=payload,
        disclosure_policy=policy,
        split_key=True,
    )

    sent = json.loads(create_session.calls[0]["data"])
    assert sent["split_key"] is True
    assert sent["selective_disclosure"] is True
    assert "key_fragment_b" in sent
    # Share A is what came back to the caller — must differ from Share B.
    assert create_result.key != sent["key_fragment_b"]

    verify_session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_sel_sk",
            "encrypted_payload": sent["encrypted_payload"],
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
            "split_key": True,
            "selective_disclosure": True,
            "disclosure_policy": sent["disclosure_policy"],
            "encrypted_key_map": sent["encrypted_key_map"],
            "commitment_hash": sent["commitment_hash"],
            "commitment_version": 2,
        }),
        _FakeResponse(200, {"intent_id": "vp_sel_sk", "fragment_b": sent["key_fragment_b"]}),
    ])
    verifier = ValidPayClient(api_key="k", base_url="https://api.example.test", session=verify_session)
    result = verifier.verify_selective_intent(
        retrieval_id="vp_sel_sk",
        key=create_result.key,  # Share A
        role="full",
    )
    assert result.payload == payload
    assert result.integrity_verified is True


# ---------------------------------------------------------------------------
# Time-Locked Verification (Patent D)
# ---------------------------------------------------------------------------

from datetime import datetime, timedelta, timezone


def _iso_in(seconds: int) -> str:
    """Build an ISO-8601 UTC timestamp ``seconds`` from now (negative = past)."""
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def test_create_intent_with_time_lock():
    session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_tl_1", "status": "active"}),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    vf = _iso_in(60)
    vu = _iso_in(3600)
    result = client.create_intent(
        document_type="check",
        payload={"a": 1},
        valid_from=vf,
        valid_until=vu,
    )
    assert result.retrieval_id == "vp_tl_1"
    sent = json.loads(session.calls[0]["data"])
    assert sent["valid_from"] == vf
    assert sent["valid_until"] == vu


def test_create_intent_time_lock_validation():
    client = ValidPayClient(api_key="k", session=_FakeSession([]))
    vf = _iso_in(3600)
    vu = _iso_in(60)  # before valid_from
    with pytest.raises(ValidPayError) as exc:
        client.create_intent(
            document_type="check",
            payload={"a": 1},
            valid_from=vf,
            valid_until=vu,
        )
    assert exc.value.code == "invalid_argument"


def test_create_intent_with_only_valid_from():
    session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_tl_2", "status": "active"}),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    vf = _iso_in(60)
    client.create_intent(document_type="check", payload={"a": 1}, valid_from=vf)
    sent = json.loads(session.calls[0]["data"])
    assert sent["valid_from"] == vf
    assert "valid_until" not in sent


def test_create_intent_with_only_valid_until():
    session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_tl_3", "status": "active"}),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    vu = _iso_in(3600)
    client.create_intent(document_type="check", payload={"a": 1}, valid_until=vu)
    sent = json.loads(session.calls[0]["data"])
    assert sent["valid_until"] == vu
    assert "valid_from" not in sent


def test_create_intent_without_time_lock():
    session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_tl_4", "status": "active"}),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    client.create_intent(document_type="check", payload={"a": 1})
    sent = json.loads(session.calls[0]["data"])
    assert "valid_from" not in sent
    assert "valid_until" not in sent


def test_verify_intent_time_lock_valid():
    real_key = generate_key()
    plaintext = json.dumps({"x": 1})
    blob = encrypt(plaintext, real_key)
    vf = _iso_in(-3600)
    vu = _iso_in(3600)
    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_tl_v",
            "encrypted_payload": blob,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
            "valid_from": vf,
            "valid_until": vu,
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    result = client.verify_intent(retrieval_id="vp_tl_v", key=real_key)
    assert result.time_lock_status == "valid"
    assert result.valid_from == vf
    assert result.valid_until == vu


def test_verify_intent_time_lock_not_yet_valid():
    real_key = generate_key()
    plaintext = json.dumps({"x": 1})
    blob = encrypt(plaintext, real_key)
    vf = _iso_in(3600)
    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_tl_n",
            "encrypted_payload": blob,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
            "valid_from": vf,
            "valid_until": None,
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    # Critical: must NOT raise; surface status on the result instead.
    result = client.verify_intent(retrieval_id="vp_tl_n", key=real_key)
    assert result.time_lock_status == "not_yet_valid"
    assert result.valid_from == vf


def test_verify_intent_time_lock_expired():
    real_key = generate_key()
    plaintext = json.dumps({"x": 1})
    blob = encrypt(plaintext, real_key)
    vu = _iso_in(-3600)
    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_tl_e",
            "encrypted_payload": blob,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
            "valid_from": None,
            "valid_until": vu,
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    result = client.verify_intent(retrieval_id="vp_tl_e", key=real_key)
    assert result.time_lock_status == "expired"
    assert result.valid_until == vu


def test_verify_intent_no_time_lock():
    real_key = generate_key()
    plaintext = json.dumps({"x": 1})
    blob = encrypt(plaintext, real_key)
    session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_tl_none",
            "encrypted_payload": blob,
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    result = client.verify_intent(retrieval_id="vp_tl_none", key=real_key)
    assert result.time_lock_status is None
    assert result.valid_from is None
    assert result.valid_until is None


def test_verify_split_key_intent_time_lock():
    payload = {"a": 1}
    # The validity window must be bound at creation (M-5 AAD), so compute it
    # first and pass it to create; the verify response echoes the same window.
    vf = _iso_in(-3600)
    vu = _iso_in(3600)
    create_session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_tl_sk", "status": "active", "split_key": True}),
    ])
    creator = ValidPayClient(api_key="k", base_url="https://api.example.test", session=create_session)
    create_result = creator.create_split_key_intent(
        document_type="check", payload=payload, valid_from=vf, valid_until=vu
    )
    sent = json.loads(create_session.calls[0]["data"])

    verify_session = _FakeSession([
        _FakeResponse(200, {
            "intent_id": "vp_tl_sk",
            "encrypted_payload": sent["encrypted_payload"],
            "issuer": "Acme",
            "issuer_verified": True,
            "registered_at": "2026-05-02T00:00:00.000Z",
            "status": "active",
            "split_key": True,
            "commitment_hash": sent["commitment_hash"],
            "commitment_version": 2,
            "encryption_version": 2,
            "document_type": "check",
            "valid_from": vf,
            "valid_until": vu,
        }),
        _FakeResponse(200, {"intent_id": "vp_tl_sk", "fragment_b": sent["key_fragment_b"]}),
    ])
    verifier = ValidPayClient(api_key="k", base_url="https://api.example.test", session=verify_session)
    result = verifier.verify_split_key_intent(retrieval_id="vp_tl_sk", share_a=create_result.key)
    assert result.time_lock_status == "valid"
    assert result.valid_from == vf
    assert result.valid_until == vu


def test_create_intent_batch_with_time_lock():
    session = _FakeSession([
        _FakeResponse(201, {
            "results": [
                {"retrieval_id": "vp_b1", "status": "active"},
                {"retrieval_id": "vp_b2", "status": "active"},
            ],
            "count": 2,
        }),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    vf = _iso_in(60)
    vu = _iso_in(3600)
    client.create_intent_batch([
        {"document_type": "check", "payload": {"a": 1}, "valid_from": vf, "valid_until": vu},
        {"document_type": "check", "payload": {"b": 2}},  # no time-lock
    ])
    sent_items = json.loads(session.calls[0]["data"])["intents"]
    assert sent_items[0]["valid_from"] == vf
    assert sent_items[0]["valid_until"] == vu
    assert "valid_from" not in sent_items[1]
    assert "valid_until" not in sent_items[1]


def test_create_split_key_intent_with_time_lock():
    session = _FakeSession([
        _FakeResponse(201, {"retrieval_id": "vp_sk_tl", "status": "active", "split_key": True}),
    ])
    client = ValidPayClient(api_key="k", base_url="https://api.example.test", session=session)
    vf = _iso_in(60)
    vu = _iso_in(3600)
    client.create_split_key_intent(
        document_type="check",
        payload={"a": 1},
        valid_from=vf,
        valid_until=vu,
    )
    sent = json.loads(session.calls[0]["data"])
    assert sent["split_key"] is True
    assert "key_fragment_b" in sent
    assert sent["valid_from"] == vf
    assert sent["valid_until"] == vu
