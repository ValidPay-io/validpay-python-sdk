from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CreateIntentResult:
    """Result of creating an intent.

    Attributes:
        retrieval_id: The ``vp_*`` identifier assigned by the API.
        key: The base64-encoded AES-256 key used to encrypt the payload.
            The caller is responsible for delivering this key out-of-band
            to whoever needs to verify the intent — it is never sent to
            the ValidPay API.
    """

    retrieval_id: str
    key: str


@dataclass(frozen=True)
class VerifyIntentResult:
    """Result of verifying (retrieving + decrypting) an intent.

    Attributes:
        intent_id: The ``vp_*`` identifier echoed by the API.
        payload: The decrypted payload, as parsed JSON (typically a dict).
        issuer: Display name of the issuer that registered the intent.
        issuer_verified: Whether the issuer's identity has been verified
            by ValidPay.
        registered_at: ISO-8601 timestamp of when the intent was created.
        status: Lifecycle status (e.g. ``"active"``, ``"revoked"``).
    """

    intent_id: str
    payload: Any
    issuer: str
    issuer_verified: bool
    registered_at: str
    status: str
