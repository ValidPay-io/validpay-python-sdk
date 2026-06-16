from __future__ import annotations

import base64
import hashlib

import pytest

from validpay import (
    ValidPayError,
    build_key_map,
    combine_key_shares,
    compute_commitment_hash,
    decrypt,
    decrypt_bytes,
    decrypt_fields,
    encrypt,
    encrypt_bytes,
    encrypt_fields,
    generate_key,
    split_key,
)


def test_encrypt_bytes_roundtrip_binary():
    # Non-UTF-8 bytes (a tiny "PDF-ish" header + binary noise) must survive
    # encrypt_bytes -> decrypt_bytes exactly, byte-for-byte (file mode).
    key = generate_key()
    original = b"%PDF-1.7\x00\x01\x02\xff\xfe\r\n binary \x80\x90"
    blob = encrypt_bytes(original, key)
    assert decrypt_bytes(blob, key) == original


def test_encrypt_bytes_aad_mismatch_fails():
    key = generate_key()
    blob = encrypt_bytes(b"\x00\x01\x02", key, aad="a")
    with pytest.raises(ValidPayError):
        decrypt_bytes(blob, key, aad="b")


def test_encrypt_delegates_to_encrypt_bytes():
    # The string wrapper must produce a blob decrypt_bytes reads back as UTF-8.
    key = generate_key()
    blob = encrypt("héllo ✓", key)
    assert decrypt_bytes(blob, key).decode("utf-8") == "héllo ✓"


def test_generate_key_returns_32_byte_base64():
    key = generate_key()
    assert isinstance(key, str)
    assert len(base64.b64decode(key)) == 32


def test_generate_key_returns_unique_keys():
    assert generate_key() != generate_key()


def test_round_trip_encrypt_decrypt():
    key = generate_key()
    plaintext = '{"ssn": "123-45-6789", "name": "Jane Doe"}'
    blob = encrypt(plaintext, key)
    assert isinstance(blob, str)
    assert plaintext not in blob
    assert decrypt(blob, key) == plaintext


def test_unicode_and_large_payload():
    key = generate_key()
    plaintext = "héllo 🔐 " + ("x" * 10_000)
    assert decrypt(encrypt(plaintext, key), key) == plaintext


def test_random_iv_produces_different_ciphertext():
    key = generate_key()
    a = encrypt("hello", key)
    b = encrypt("hello", key)
    assert a != b


def test_blob_format_iv_tag_ciphertext():
    key = generate_key()
    plaintext = "hi"
    blob = encrypt(plaintext, key)
    raw = base64.b64decode(blob)
    assert len(raw) == 12 + 16 + len(plaintext.encode("utf-8"))


def test_decrypt_with_wrong_key_raises():
    blob = encrypt("secret", generate_key())
    with pytest.raises(ValidPayError) as exc:
        decrypt(blob, generate_key())
    assert exc.value.code == "decryption_failed"


def test_tampered_ciphertext_raises():
    key = generate_key()
    blob = encrypt("secret", key)
    raw = bytearray(base64.b64decode(blob))
    raw[-1] ^= 0x01
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(ValidPayError) as exc:
        decrypt(tampered, key)
    assert exc.value.code == "decryption_failed"


def test_tampered_auth_tag_raises():
    key = generate_key()
    blob = encrypt("secret", key)
    raw = bytearray(base64.b64decode(blob))
    raw[12] ^= 0xFF
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(ValidPayError) as exc:
        decrypt(tampered, key)
    assert exc.value.code == "decryption_failed"


def test_too_short_blob_raises():
    with pytest.raises(ValidPayError) as exc:
        decrypt(base64.b64encode(b"hi").decode("ascii"), generate_key())
    assert exc.value.code == "invalid_blob"


def test_invalid_key_length_raises():
    short_key = base64.b64encode(b"short").decode("ascii")
    with pytest.raises(ValidPayError) as exc:
        encrypt("hello", short_key)
    assert exc.value.code == "invalid_key"


def test_node_sdk_wire_format_compatibility():
    """Decrypt a blob shaped exactly the way the Node SDK would emit it.

    The Node SDK assembles ``base64(iv || authTag || ciphertext)``. We hand-build
    one with the cryptography library and confirm the Python SDK accepts it.
    """
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key_bytes = os.urandom(32)
    key = base64.b64encode(key_bytes).decode("ascii")
    iv = os.urandom(12)
    plaintext = '{"hello": "world"}'

    ct_with_tag = AESGCM(key_bytes).encrypt(iv, plaintext.encode("utf-8"), None)
    auth_tag = ct_with_tag[-16:]
    ciphertext = ct_with_tag[:-16]

    node_format_blob = base64.b64encode(iv + auth_tag + ciphertext).decode("ascii")
    assert decrypt(node_format_blob, key) == plaintext


def test_commitment_hash_matches_sha256():
    plaintext = '{"hello": "world"}'
    expected = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    assert compute_commitment_hash(plaintext) == expected


def test_commitment_hash_is_64_char_hex():
    h = compute_commitment_hash("anything")
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_commitment_hash_changes_with_input():
    assert compute_commitment_hash("a") != compute_commitment_hash("b")


def test_aad_round_trip():
    from validpay.crypto import build_aad, decrypt, encrypt, generate_key

    key = generate_key()
    aad = build_aad("check", None, "2026-08-01T00:00:00Z")
    blob = encrypt('{"amount": 100}', key, aad)
    assert decrypt(blob, key, aad) == '{"amount": 100}'


def test_aad_mismatch_fails():
    from validpay.crypto import ValidPayError, build_aad, decrypt, encrypt, generate_key
    import pytest

    key = generate_key()
    blob = encrypt('{"amount": 100}', key, build_aad("check"))
    # Altered document_type → GCM tag check fails.
    with pytest.raises(ValidPayError) as exc:
        decrypt(blob, key, build_aad("other"))
    assert exc.value.code == "decryption_failed"


def test_aad_is_canonical_compact_with_epoch_ms():
    from validpay.crypto import build_aad

    # Compact (no spaces), fixed key order, epoch-ms timestamps — must stay
    # byte-identical to the JS SDKs / website verifier.
    assert (
        build_aad("check", None, "2026-08-01T00:00:00Z")
        == '{"document_type":"check","valid_from":null,"valid_until":1785542400000}'
    )


def test_split_key_produces_two_32_byte_shares():
    key = generate_key()
    a, b = split_key(key)
    assert len(base64.b64decode(a)) == 32
    assert len(base64.b64decode(b)) == 32


def test_split_key_shares_are_different_from_original():
    key = generate_key()
    a, b = split_key(key)
    assert a != key
    assert b != key
    assert a != b


def test_combine_key_shares_recovers_original():
    key = generate_key()
    a, b = split_key(key)
    assert combine_key_shares(a, b) == key
    # Order doesn't matter — XOR is commutative.
    assert combine_key_shares(b, a) == key


def test_split_key_is_random():
    key = generate_key()
    a1, b1 = split_key(key)
    a2, b2 = split_key(key)
    assert a1 != a2
    assert b1 != b2


def test_combine_wrong_shares_produces_wrong_key():
    key1 = generate_key()
    key2 = generate_key()
    a1, _b1 = split_key(key1)
    _a2, b2 = split_key(key2)
    assert combine_key_shares(a1, b2) != key1
    assert combine_key_shares(a1, b2) != key2


def test_combine_key_shares_rejects_wrong_length():
    short = base64.b64encode(b"short").decode("ascii")
    with pytest.raises(ValidPayError) as exc:
        combine_key_shares(short, generate_key())
    assert exc.value.code == "invalid_key"


def test_encrypt_fields_produces_unique_keys_per_field():
    payload = {"name": "Alice", "amount": 100, "memo": "hi"}
    encrypted_fields, field_keys = encrypt_fields(payload)
    assert set(encrypted_fields.keys()) == {"name", "amount", "memo"}
    assert set(field_keys.keys()) == {"name", "amount", "memo"}
    keys = list(field_keys.values())
    assert len(set(keys)) == 3, "each field must get a fresh AES key"
    for k in keys:
        assert len(base64.b64decode(k)) == 32


def test_encrypt_fields_round_trip():
    payload = {"name": "Alice", "amount": 100, "active": True, "tags": ["a", "b"]}
    encrypted_fields, field_keys = encrypt_fields(payload)
    for field, value in payload.items():
        plaintext = decrypt(encrypted_fields[field], field_keys[field])
        # Strings round-trip as raw plaintext; non-strings are JSON-encoded.
        if isinstance(value, str):
            assert plaintext == value
        else:
            import json as _json
            assert _json.loads(plaintext) == value


def test_build_key_map_includes_full_role():
    payload = {"a": 1, "b": 2, "c": 3}
    _, field_keys = encrypt_fields(payload)
    key_map = build_key_map(field_keys, {"bank": ["a"]})
    assert "full" in key_map
    assert key_map["full"] == field_keys


def test_build_key_map_restricts_roles():
    payload = {"name": "Alice", "amount": 100, "ssn": "111-22-3333"}
    _, field_keys = encrypt_fields(payload)
    policy = {"bank": ["amount"], "auditor": ["amount", "name"]}
    key_map = build_key_map(field_keys, policy)
    assert set(key_map["bank"].keys()) == {"amount"}
    assert key_map["bank"]["amount"] == field_keys["amount"]
    assert set(key_map["auditor"].keys()) == {"amount", "name"}


def test_decrypt_fields_redacts_unauthorized():
    payload = {"name": "Alice", "amount": 100, "ssn": "111-22-3333"}
    encrypted_fields, field_keys = encrypt_fields(payload)
    # Bank role gets only "amount"
    bank_keys = {"amount": field_keys["amount"]}
    result = decrypt_fields(encrypted_fields, bank_keys)
    assert result["amount"] == 100
    assert result["name"] == "[REDACTED]"
    assert result["ssn"] == "[REDACTED]"


def test_decrypt_fields_full_access():
    payload = {"name": "Alice", "amount": 100, "memo": "lunch"}
    encrypted_fields, field_keys = encrypt_fields(payload)
    result = decrypt_fields(encrypted_fields, field_keys)
    assert result == payload
