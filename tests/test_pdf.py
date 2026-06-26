"""Tests for validpay.pdf — verify URL, placement math, and embed_qr.

The embed_qr tests need the optional PDF extras; they're skipped if the
deps aren't installed so the core suite still runs everywhere.
"""

import importlib.util

import pytest

from validpay import QrPlacement, build_verify_url, resolve_qr_rect
from validpay.errors import ValidPayError

W, H = 612.0, 792.0  # US Letter, points

_HAS_PDF = all(
    importlib.util.find_spec(m) is not None
    for m in ("qrcode", "reportlab", "pypdf", "PIL")
)
pdf_only = pytest.mark.skipif(not _HAS_PDF, reason="validpay[pdf] extras not installed")


# ── build_verify_url ────────────────────────────────────────────────────────

def test_build_verify_url_basic():
    assert build_verify_url("abc123", "deadbeef") == (
        "https://verify.keyhalve.com/verify/abc123#key=deadbeef"
    )


def test_build_verify_url_base64url_key_and_encoded_id():
    # "K+K/m==" -> base64url "K-K_m"; id is percent-encoded.
    assert build_verify_url("a/b c", "K+K/m==") == (
        "https://verify.keyhalve.com/verify/a%2Fb%20c#key=K-K_m"
    )


def test_build_verify_url_custom_base_strips_slash():
    assert build_verify_url("id", "k", "https://staging.validpay.com/") == (
        "https://staging.validpay.com/verify/id#key=k"
    )


def test_build_verify_url_requires_args():
    with pytest.raises(ValidPayError):
        build_verify_url("", "k")
    with pytest.raises(ValidPayError):
        build_verify_url("id", "")


# ── resolve_qr_rect ─────────────────────────────────────────────────────────

def test_resolve_top_left():
    r = resolve_qr_rect(QrPlacement(anchor="top-left", x=400, y=50, width=90), W, H)
    assert (r.x, r.y, r.size) == (400, 792 - 50 - 90, 90)


def test_resolve_default_anchor_is_top_left():
    r = resolve_qr_rect(QrPlacement(x=10, y=20, width=100), W, H)
    assert (r.x, r.y, r.size) == (10, H - 20 - 100, 100)


def test_resolve_bottom_right():
    r = resolve_qr_rect(QrPlacement(anchor="bottom-right", x=36, y=36, width=90), W, H)
    assert (r.x, r.y, r.size) == (612 - 36 - 90, 36, 90)


def test_resolve_top_right_and_bottom_left():
    tr = resolve_qr_rect(QrPlacement(anchor="top-right", x=40, y=40, width=80), W, H)
    assert (tr.x, tr.y) == (612 - 40 - 80, 792 - 40 - 80)
    bl = resolve_qr_rect(QrPlacement(anchor="bottom-left", x=40, y=40, width=80), W, H)
    assert (bl.x, bl.y) == (40, 40)


def test_resolve_unit_conversion():
    mm = resolve_qr_rect(QrPlacement(anchor="top-left", x=25.4, y=0, width=25.4, units="mm"), W, H)
    assert mm.size == pytest.approx(72)
    assert mm.x == pytest.approx(72)
    inch = resolve_qr_rect(QrPlacement(anchor="bottom-left", x=1, y=1, width=1, units="in"), W, H)
    assert (inch.x, inch.y, inch.size) == (72, 72, 72)


def test_resolve_rejects_bad_anchor_units():
    with pytest.raises(ValidPayError):
        resolve_qr_rect(QrPlacement(x=1, y=1, width=1, anchor="middle"), W, H)
    with pytest.raises(ValidPayError):
        resolve_qr_rect(QrPlacement(x=1, y=1, width=1, units="cm"), W, H)


# ── embed_qr (needs extras) ─────────────────────────────────────────────────

def _blank_pdf(pages: int = 1) -> bytes:
    from reportlab.pdfgen import canvas

    import io

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(W, H))
    for _ in range(pages):
        c.showPage()
    c.save()
    return buf.getvalue()


@pdf_only
def test_embed_qr_returns_valid_pdf():
    from pypdf import PdfReader
    import io

    from validpay import embed_qr

    original = _blank_pdf(1)
    out = embed_qr(original, "abc123", "deadbeef",
                   QrPlacement(anchor="bottom-right", x=36, y=36, width=90))
    assert isinstance(out, bytes) and len(out) > 0
    assert len(PdfReader(io.BytesIO(out)).pages) == 1


@pdf_only
def test_embed_qr_targets_a_page():
    from pypdf import PdfReader
    import io

    from validpay import embed_qr

    out = embed_qr(_blank_pdf(3), "id", "k",
                   QrPlacement(page=2, anchor="top-left", x=50, y=50, width=100))
    assert len(PdfReader(io.BytesIO(out)).pages) == 3


@pdf_only
def test_embed_qr_rejects_out_of_range_page():
    from validpay import embed_qr

    with pytest.raises(ValidPayError, match="out of range"):
        embed_qr(_blank_pdf(1), "id", "k", QrPlacement(page=5, x=10, y=10, width=50))


@pdf_only
def test_embed_qr_rejects_off_page():
    from validpay import embed_qr

    with pytest.raises(ValidPayError, match="off the page"):
        embed_qr(_blank_pdf(1), "id", "k",
                 QrPlacement(anchor="top-left", x=600, y=10, width=100))


@pdf_only
def test_embed_qr_rejects_empty_bytes():
    from validpay import embed_qr

    with pytest.raises(ValidPayError):
        embed_qr(b"", "id", "k", QrPlacement(x=1, y=1, width=50))
