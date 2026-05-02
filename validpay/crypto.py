"""AES-256-GCM encryption matching the ValidPay wire format.

Wire format (base64-encoded): ``iv (12 bytes) || authTag (16 bytes) || ciphertext``.

This format is identical to the Node.js SDK so blobs are interoperable in
both directions.
"""

from __future__ import annotations

import base64
import hashlib
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


def compute_commitment_hash(plaintext: str) -> str:
    """SHA-256 commitment hash of the plaintext payload (Hybrid Commitment Scheme).

    Computed at issuance and stored alongside the ciphertext on the server.
    At verification time, the same hash is recomputed against the freshly
    decrypted plaintext; a mismatch proves the server tampered with or
    swapped the ciphertext, since SHA-256 is one-way and the server cannot
    forge a matching hash without the decryption key.
    """
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


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
