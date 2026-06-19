from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


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
        integrity_verified: ``True`` if the server returned a commitment
            hash and it matched the recomputed hash of the decrypted
            plaintext (Hybrid Commitment Scheme). ``False`` for legacy
            intents created before the scheme was deployed — those still
            decrypt successfully, they just haven't been integrity-checked.
            A mismatch raises ``ValidPayError("integrity_failure")``
            instead of returning a result.
    """

    intent_id: str
    payload: Any
    issuer: str
    issuer_verified: bool
    registered_at: str
    status: str
    integrity_verified: bool
    # Time-Locked Verification (Patent D). All None for intents with no
    # validity window. ``time_lock_status`` is "valid", "not_yet_valid", or
    # "expired" when a window exists.
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    time_lock_status: Optional[str] = None
    # Platform delegation (Fork B). ``verification_level`` is the issuer's graded
    # trust rung: "none" < "delegated" < "domain" < "business". ``delegated_by``
    # is set when this was sealed on behalf of, via a platform — a dict
    # ``{"platform": str, "platform_level": "domain"|"business"}`` — else None.
    verification_level: Optional[str] = None
    delegated_by: Optional[dict] = None
