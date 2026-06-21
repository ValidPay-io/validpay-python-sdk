"""KeyHalve rail client (verify side).

Fetches the blind rail share ``B_keyhalve`` from the independent KeyHalve rail and
verifies the rail's Ed25519 signature against a PINNED public key. Fails closed on any
doubt. The caller XOR-combines the verified rail share with the platform share(s) (from
the ValidPay API) and ShareA (the QR key).

The pinned key ships with the SDK, not fetched at runtime — a hijacked rail or DNS path
then produces a signature that fails the pinned check.
"""

from __future__ import annotations

import base64
from urllib.parse import quote

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .errors import ValidPayError

KEYHALVE_RAIL_BASE_URL = "https://rail.keyhalve.com"
KEYHALVE_RAIL_PUBLIC_KEY_SPKI_B64 = (
    "MCowBQYDK2VwAyEAngOcqC4hL467C9RyWUh4bAQD3Fohi9zqhY+l65bul6w="
)
_HOLDER = "keyhalve"


def _canonical_message(intent_id: str, piece: str) -> str:
    return f"keyhalve-rail.v1\n{intent_id}\n{_HOLDER}\n{piece}"


def fetch_rail_piece(
    session: requests.Session,
    rail_base_url: str,
    pinned_spki_b64: str,
    intent_id: str,
    timeout: float,
) -> str:
    """Fetch + verify ``B_keyhalve``. Raises (fails closed) on any failure."""
    base = rail_base_url.rstrip("/")
    try:
        resp = session.get(
            f"{base}/v1/piece/{quote(intent_id, safe='')}",
            headers={"Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise ValidPayError("rail_unreachable", "Could not reach the KeyHalve rail") from exc

    if resp.status_code == 404:
        raise ValidPayError("rail_not_found", "Rail share not found")
    if resp.status_code == 409:
        raise ValidPayError("rail_revoked", "Rail share revoked")
    if not resp.ok:
        raise ValidPayError("rail_error", f"Rail returned {resp.status_code}")

    data = resp.json()
    if not isinstance(data, dict) or data.get("error"):
        raise ValidPayError("rail_error", "Rail returned an error", details=data)
    piece = data.get("piece")
    sig = data.get("sig")
    if not piece or not sig or data.get("holder") != _HOLDER:
        raise ValidPayError("rail_malformed", "Malformed rail response", details=data)

    try:
        pub = load_der_public_key(base64.b64decode(pinned_spki_b64))
        pub.verify(  # type: ignore[union-attr]
            base64.b64decode(sig),
            _canonical_message(intent_id, piece).encode("utf-8"),
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValidPayError(
            "rail_bad_signature", "Rail response failed signature verification"
        ) from exc
    return piece
