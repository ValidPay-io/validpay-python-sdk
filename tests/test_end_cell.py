"""End-Cell tests: crypto round-trip + rail fetch/verify (pinned key)."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from validpay.crypto import generate_key, split_key_pieces, combine_key_pieces
from validpay.errors import ValidPayError
from validpay.rail import fetch_rail_piece

INTENT = "vp_railtest"


def test_split_then_combine_reconstructs_key():
    key = generate_key()
    for holders in (1, 2, 3):
        parts = split_key_pieces(key, holders)
        assert len(parts) == holders + 1  # share_a + one piece per holder
        share_a, pieces = parts[0], parts[1:]
        assert combine_key_pieces(share_a, pieces) == key


def test_split_rejects_zero_pieces():
    with pytest.raises(ValidPayError):
        split_key_pieces(generate_key(), 0)


# --- rail verify --------------------------------------------------------------

def _make_key():
    priv = Ed25519PrivateKey.generate()
    spki = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return priv, base64.b64encode(spki).decode()


def _canonical(intent_id: str, piece: str) -> bytes:
    return f"keyhalve-rail.v1\n{intent_id}\nkeyhalve\n{piece}".encode()


class _Resp:
    def __init__(self, body, status=200):
        self._body = body
        self.status_code = status
        self.ok = 200 <= status < 300

    def json(self):
        return self._body


class _Session:
    def __init__(self, resp=None, exc=None):
        self._resp = resp
        self._exc = exc

    def get(self, *_a, **_k):
        if self._exc:
            raise self._exc
        return self._resp


PIECE = base64.b64encode(b"\x07" * 32).decode()


def _signed(priv, intent=INTENT, piece=PIECE, holder="keyhalve"):
    sig = base64.b64encode(priv.sign(_canonical(intent, piece))).decode()
    return {"holder": holder, "piece": piece, "sig": sig, "alg": "ed25519"}


def test_rail_piece_verifies_against_pinned_key():
    priv, spki = _make_key()
    sess = _Session(_Resp(_signed(priv)))
    assert fetch_rail_piece(sess, "https://rail.test", spki, INTENT, 5) == PIECE


def test_rail_tampered_signature_fails_closed():
    priv, spki = _make_key()
    body = _signed(priv)
    bad = bytearray(base64.b64decode(body["sig"]))
    bad[0] ^= 0xFF
    body["sig"] = base64.b64encode(bytes(bad)).decode()
    with pytest.raises(ValidPayError, match="signature"):
        fetch_rail_piece(_Session(_Resp(body)), "https://rail.test", spki, INTENT, 5)


def test_rail_non_pinned_key_fails_closed():
    attacker, _ = _make_key()
    _, pinned_spki = _make_key()
    with pytest.raises(ValidPayError, match="signature"):
        fetch_rail_piece(_Session(_Resp(_signed(attacker))), "https://rail.test", pinned_spki, INTENT, 5)


def test_rail_wrong_holder_rejected():
    priv, spki = _make_key()
    with pytest.raises(ValidPayError, match="(?i)malformed"):
        fetch_rail_piece(_Session(_Resp(_signed(priv, holder="platform"))), "https://rail.test", spki, INTENT, 5)


def test_rail_404_409_fail_closed():
    _, spki = _make_key()
    with pytest.raises(ValidPayError, match="not found"):
        fetch_rail_piece(_Session(_Resp({}, 404)), "https://rail.test", spki, INTENT, 5)
    with pytest.raises(ValidPayError, match="revoked"):
        fetch_rail_piece(_Session(_Resp({}, 409)), "https://rail.test", spki, INTENT, 5)
