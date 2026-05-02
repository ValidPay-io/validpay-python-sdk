from __future__ import annotations

import base64
import hashlib

import pytest

from validpay import (
    ValidPayError,
    compute_commitment_hash,
    decrypt,
    encrypt,
    generate_key,
)


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
