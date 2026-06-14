"""AES-256-GCM encryption matching the ValidPay wire format.

Wire format (base64-encoded): ``iv (12 bytes) || authTag (16 bytes) || ciphertext``.

This format is identical to the Node.js SDK so blobs are interoperable in
both directions.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ValidPayError

_KEY_BYTES = 32
_IV_BYTES = 12
_TAG_BYTES = 16


def generate_key() -> str:
    """Generate a fresh AES-256 key as a base64 string (32 random bytes)."""
    return base64.b64encode(os.urandom(_KEY_BYTES)).decode("ascii")


def split_key(key: str) -> tuple[str, str]:
    """Split an AES-256 key into two shares using XOR (2-of-2 Shamir equivalent).

    Returns ``(share_a, share_b)`` where ``share_a XOR share_b == key`` and
    each share alone reveals zero information about the key (one-time-pad
    secure). For a 2-of-2 threshold this is mathematically equivalent to
    Shamir's polynomial scheme; no external library is needed.

    Args:
        key: Base64-encoded 32-byte AES key.

    Returns:
        Tuple ``(share_a, share_b)``, both as base64 strings.
    """
    key_bytes = _decode_key(key)
    share_a_bytes = os.urandom(_KEY_BYTES)
    share_b_bytes = bytes(a ^ b for a, b in zip(key_bytes, share_a_bytes))
    return (
        base64.b64encode(share_a_bytes).decode("ascii"),
        base64.b64encode(share_b_bytes).decode("ascii"),
    )


def combine_key_shares(share_a: str, share_b: str) -> str:
    """Reconstruct an AES-256 key from two XOR shares.

    Args:
        share_a: Base64-encoded 32-byte share (typically from the QR code).
        share_b: Base64-encoded 32-byte share (typically from the API).

    Returns:
        The reconstructed key, base64-encoded.
    """
    try:
        a_bytes = base64.b64decode(share_a, validate=True)
        b_bytes = base64.b64decode(share_b, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValidPayError("invalid_key", "Key shares are not valid base64") from exc
    if len(a_bytes) != _KEY_BYTES or len(b_bytes) != _KEY_BYTES:
        raise ValidPayError(
            "invalid_key",
            f"Key shares must each be {_KEY_BYTES} bytes",
        )
    key_bytes = bytes(a ^ b for a, b in zip(a_bytes, b_bytes))
    return base64.b64encode(key_bytes).decode("ascii")


def compute_commitment_hash(ciphertext_b64: str) -> str:
    """SHA-256 commitment hash over the *ciphertext* blob (commitment v2).

    Pass the base64 ValidPay wire blob returned by :func:`encrypt` — NOT the
    plaintext. Hashing the ciphertext lets the server publish the commitment
    on the public verify endpoint without creating a confirmation oracle:
    SHA-256(plaintext) over a low-entropy structured document (a check, an
    SSN card) can be brute-forced offline to recover contents without the
    key, which broke the "we cannot read your documents" promise (Prompt 097
    C-1). The commitment still proves the server hasn't swapped the blob
    between issuance and verification — the verifier recomputes
    SHA-256(ciphertext) and compares.
    """
    return hashlib.sha256(ciphertext_b64.encode("utf-8")).hexdigest()


def _decode_key(key: str) -> bytes:
    try:
        buf = base64.b64decode(key, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValidPayError("invalid_key", "Key is not valid base64") from exc
    if len(buf) != _KEY_BYTES:
        raise ValidPayError(
            "invalid_key",
            f"Key must decode to {_KEY_BYTES} bytes (got {len(buf)})",
        )
    return buf


def encrypt(plaintext: str, key: str) -> str:
    """Encrypt ``plaintext`` (UTF-8) with the given base64 AES-256 key.

    Returns a base64 string in the ValidPay wire format::

        base64(iv[12] || authTag[16] || ciphertext)
    """
    key_bytes = _decode_key(key)
    iv = os.urandom(_IV_BYTES)
    aesgcm = AESGCM(key_bytes)
    # cryptography's AESGCM.encrypt returns ``ciphertext || authTag``.
    # Rearrange to match the ValidPay/Node wire format: iv || authTag || ciphertext.
    ct_with_tag = aesgcm.encrypt(iv, plaintext.encode("utf-8"), None)
    auth_tag = ct_with_tag[-_TAG_BYTES:]
    ciphertext = ct_with_tag[:-_TAG_BYTES]
    return base64.b64encode(iv + auth_tag + ciphertext).decode("ascii")


def decrypt(blob: str, key: str) -> str:
    """Decrypt a ValidPay-format base64 blob and return the plaintext (UTF-8)."""
    key_bytes = _decode_key(key)

    try:
        buf = base64.b64decode(blob, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValidPayError("invalid_blob", "Blob is not valid base64") from exc

    if len(buf) < _IV_BYTES + _TAG_BYTES + 1:
        raise ValidPayError(
            "invalid_blob",
            f"Blob too short: expected at least {_IV_BYTES + _TAG_BYTES + 1} bytes",
        )

    iv = buf[:_IV_BYTES]
    auth_tag = buf[_IV_BYTES:_IV_BYTES + _TAG_BYTES]
    ciphertext = buf[_IV_BYTES + _TAG_BYTES:]

    aesgcm = AESGCM(key_bytes)
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
    except InvalidTag as exc:
        raise ValidPayError(
            "decryption_failed",
            "Decryption failed — wrong key or tampered blob",
        ) from exc

    return plaintext.decode("utf-8")


def encrypt_fields(payload: dict, generate_key_fn=None) -> tuple[dict, dict]:
    """Encrypt each field in payload separately (Selective Field Disclosure, Patent E).

    Args:
        payload: Dict of field_name → value (values will be JSON-serialized).
        generate_key_fn: Optional key generator (for testing). Defaults to generate_key.

    Returns:
        (encrypted_fields, field_keys) where:
        - encrypted_fields: { field_name: base64_ciphertext }
        - field_keys: { field_name: base64_key }
    """
    if generate_key_fn is None:
        generate_key_fn = generate_key
    encrypted_fields: dict = {}
    field_keys: dict = {}
    for name, value in payload.items():
        key = generate_key_fn()
        plaintext = json.dumps(value) if not isinstance(value, str) else value
        encrypted_fields[name] = encrypt(plaintext, key)
        field_keys[name] = key
    return encrypted_fields, field_keys


def build_key_map(field_keys: dict, disclosure_policy: dict) -> dict:
    """Build the field key map from field keys and a disclosure policy.

    Args:
        field_keys: { field_name: base64_key } — all field keys.
        disclosure_policy: { role_name: [field_name, ...] } — which role sees which fields.

    Returns:
        { role_name: { field_name: base64_key } } — each role gets only its
        authorized keys. A "full" role is always added with every key.
    """
    key_map: dict = {}
    for role, fields in disclosure_policy.items():
        role_keys: dict = {}
        for field in fields:
            if field in field_keys:
                role_keys[field] = field_keys[field]
        key_map[role] = role_keys
    # "full" role always gets all keys — the issuer view.
    key_map["full"] = dict(field_keys)
    return key_map


def decrypt_fields(encrypted_fields: dict, field_keys: dict) -> dict:
    """Decrypt only fields the caller has keys for; other fields become "[REDACTED]".

    Args:
        encrypted_fields: { field_name: base64_ciphertext }
        field_keys: { field_name: base64_key } — keys for the fields this role can access.

    Returns:
        { field_name: decrypted_value_or_REDACTED }.
    """
    result: dict = {}
    for name, ciphertext in encrypted_fields.items():
        if name in field_keys:
            plaintext = decrypt(ciphertext, field_keys[name])
            try:
                result[name] = json.loads(plaintext)
            except (json.JSONDecodeError, ValueError):
                result[name] = plaintext
        else:
            result[name] = "[REDACTED]"
    return result
