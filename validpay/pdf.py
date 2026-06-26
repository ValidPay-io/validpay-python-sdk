"""QR placement helpers (file mode add-on).

``create_file_intent`` / ``create_intent`` seal a document and return a
``CreateIntentResult`` with ``retrieval_id`` + ``key``. To verify it, a
scannable QR encoding the verify URL must appear ON the document. WHERE it
goes is the integrator's call — but historically they were on their own to
render it and to guess coordinates, which is fiddly and error-prone (PDFs use
a bottom-left origin; every screen uses top-left).

This module fixes that with one canonical placement contract — identical to the
Node SDK and the website "Try it" tool — so a position picked once maps to the
exact same spot here.

``qrcode``, ``reportlab``, and ``pypdf`` are OPTIONAL — the core client needs
none of them. Install them only if you call :func:`embed_qr`::

    pip install "validpay[pdf]"

The pure helpers :func:`build_verify_url` and :func:`resolve_qr_rect` have no
dependencies — use them directly if you render PDFs with a different library.
"""

from __future__ import annotations

import io
import warnings
from dataclasses import dataclass
from typing import Tuple
from urllib.parse import quote

from .errors import ValidPayError

# Which page corner the (x, y) inset is measured from.
QrAnchor = str  # "top-left" | "top-right" | "bottom-left" | "bottom-right"
QrUnit = str  # "pt" | "mm" | "in"

_UNIT_TO_PT = {"pt": 1.0, "mm": 72.0 / 25.4, "in": 72.0}
_ANCHORS = ("top-left", "top-right", "bottom-left", "bottom-right")

#: Smallest QR side considered reliably scannable from a printed page at
#: arm's length (~72pt = 1in = 2.54cm). :func:`embed_qr` warns below this.
MIN_RECOMMENDED_QR_PT = 72.0


@dataclass(frozen=True)
class QrPlacement:
    """Where to place the QR, the way people think about a page.

    ``anchor`` names a page CORNER; ``x`` / ``y`` are the insets from that
    corner's edges; the QR's matching corner is pinned there. So
    ``QrPlacement(anchor="bottom-right", x=36, y=36, width=90)`` sits 36pt in
    from the bottom and right edges and stays bottom-right on any page size.
    The default ``top-left`` anchor reads like screen coordinates.
    """

    x: float
    y: float
    width: float
    page: int = 1
    anchor: QrAnchor = "top-left"
    units: QrUnit = "pt"


@dataclass(frozen=True)
class ResolvedQrRect:
    """A QR rectangle in PDF's bottom-left-origin point space."""

    x: float  # left edge from the page left, in points
    y: float  # bottom edge from the page bottom, in points
    size: float  # QR side length, in points


def _to_base64url(b64: str) -> str:
    """base64 -> base64url. Phone scanners + share-sheets mangle ``+ / =`` in
    URL fragments, so QR keys must be base64url. Idempotent; ``/verify``
    accepts both."""
    return b64.replace("+", "-").replace("/", "_").rstrip("=")


def build_verify_url(
    retrieval_id: str,
    key: str,
    base_url: str = "https://verify.keyhalve.com",
) -> str:
    """Build the canonical verify URL the QR encodes::

        <base_url>/verify/<retrieval_id>#key=<base64url(key)>

    The key rides in the URL FRAGMENT (``#key=``), which browsers never send
    to any server.
    """
    if not retrieval_id:
        raise ValidPayError("invalid_argument", "retrieval_id is required")
    if not key:
        raise ValidPayError("invalid_argument", "key is required")
    base = base_url.rstrip("/")
    return f"{base}/verify/{quote(retrieval_id, safe='')}#key={_to_base64url(key)}"


def resolve_qr_rect(
    placement: QrPlacement,
    page_width_pt: float,
    page_height_pt: float,
) -> ResolvedQrRect:
    """Convert a :class:`QrPlacement` into PDF's bottom-left-origin point
    rectangle for a page of the given size.

    This is the EXACT conversion the website "Try it" tool uses, so copied
    coordinates land in the same place. Pure and dependency-free.
    """
    if placement.anchor not in _ANCHORS:
        raise ValidPayError(
            "invalid_argument",
            f"anchor must be one of {_ANCHORS}, got {placement.anchor!r}",
        )
    if placement.units not in _UNIT_TO_PT:
        raise ValidPayError(
            "invalid_argument",
            f"units must be one of {tuple(_UNIT_TO_PT)}, got {placement.units!r}",
        )
    unit = _UNIT_TO_PT[placement.units]
    size = placement.width * unit
    inset_x = placement.x * unit
    inset_y = placement.y * unit

    left_anchored = placement.anchor in ("top-left", "bottom-left")
    top_anchored = placement.anchor in ("top-left", "top-right")

    x = inset_x if left_anchored else page_width_pt - inset_x - size
    # PDF y is the QR's BOTTOM edge from the page bottom. A top inset measures
    # from the page top down to the QR's top edge.
    y = page_height_pt - inset_y - size if top_anchored else inset_y
    return ResolvedQrRect(x=x, y=y, size=size)


def embed_qr(
    pdf_bytes: bytes,
    retrieval_id: str,
    key: str,
    placement: QrPlacement,
    *,
    base_url: str = "https://verify.keyhalve.com",
    error_correction: str = "M",
    margin: int = 2,
    dark_color: str = "#0A0F1E",
    light_color: str = "#FFFFFF",
) -> bytes:
    """Stamp a scannable verify QR onto an existing PDF and return new bytes.

    The input is not mutated. Requires the optional extras
    (``pip install "validpay[pdf]"``); raises ``missing_dependency`` if absent.

    Example::

        res = client.create_file_intent(document_type="invoice", file=data)
        sealed = embed_qr(
            data, res.retrieval_id, res.key,
            QrPlacement(anchor="bottom-right", x=36, y=36, width=90),
        )
    """
    if not pdf_bytes:
        raise ValidPayError("invalid_argument", "pdf_bytes must be non-empty")
    if placement.width <= 0:
        raise ValidPayError("invalid_argument", "placement.width must be > 0")

    qrcode = _load("qrcode")
    pypdf = _load("pypdf")
    canvas_mod = _load("reportlab.pdfgen.canvas", pip="reportlab")
    imagereader = _load("reportlab.lib.utils", pip="reportlab")

    ec_map = {
        "L": qrcode.constants.ERROR_CORRECT_L,
        "M": qrcode.constants.ERROR_CORRECT_M,
        "Q": qrcode.constants.ERROR_CORRECT_Q,
        "H": qrcode.constants.ERROR_CORRECT_H,
    }
    if error_correction not in ec_map:
        raise ValidPayError(
            "invalid_argument",
            f"error_correction must be one of {tuple(ec_map)}, got {error_correction!r}",
        )

    url = build_verify_url(retrieval_id, key, base_url)
    qr = qrcode.QRCode(error_correction=ec_map[error_correction], border=margin)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color=dark_color, back_color=light_color).convert("RGB")
    png_buf = io.BytesIO()
    img.save(png_buf, format="PNG")
    png_buf.seek(0)

    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    page_count = len(reader.pages)
    idx = placement.page - 1
    if idx < 0 or idx >= page_count:
        raise ValidPayError(
            "invalid_argument",
            f"placement.page {placement.page} is out of range "
            f"(document has {page_count} page(s))",
        )
    target = reader.pages[idx]
    page_w = float(target.mediabox.width)
    page_h = float(target.mediabox.height)
    rect = resolve_qr_rect(placement, page_w, page_h)

    if rect.size < MIN_RECOMMENDED_QR_PT:
        warnings.warn(
            f"QR is {rect.size:.0f}pt wide — below the ~{MIN_RECOMMENDED_QR_PT:.0f}pt "
            "(1in) recommended minimum; it may be hard to scan once printed.",
            stacklevel=2,
        )
    if (
        rect.x < 0
        or rect.y < 0
        or rect.x + rect.size > page_w
        or rect.y + rect.size > page_h
    ):
        raise ValidPayError(
            "invalid_argument",
            "placement puts the QR (partly) off the page — check x/y/width against the page size",
        )

    overlay_buf = io.BytesIO()
    c = canvas_mod.Canvas(overlay_buf, pagesize=(page_w, page_h))
    c.drawImage(
        imagereader.ImageReader(png_buf),
        rect.x,
        rect.y,
        width=rect.size,
        height=rect.size,
        mask="auto",
    )
    c.showPage()
    c.save()
    overlay_buf.seek(0)

    overlay = pypdf.PdfReader(overlay_buf)
    writer = pypdf.PdfWriter()
    for i, page in enumerate(reader.pages):
        if i == idx:
            page.merge_page(overlay.pages[0])
        writer.add_page(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def _load(module: str, *, pip: str | None = None):
    """Import an optional dependency or raise a helpful ValidPayError."""
    import importlib

    try:
        mod = importlib.import_module(module)
        # qrcode needs its constants submodule eagerly for the EC map.
        if module == "qrcode":
            importlib.import_module("qrcode.constants")
        return mod
    except ImportError as exc:  # pragma: no cover - exercised via integration
        pkg = pip or module.split(".")[0]
        raise ValidPayError(
            "missing_dependency",
            f"embed_qr requires the optional dependency '{pkg}'. "
            'Install the PDF extras: pip install "validpay[pdf]"',
        ) from exc


__all__ = [
    "QrAnchor",
    "QrUnit",
    "QrPlacement",
    "ResolvedQrRect",
    "MIN_RECOMMENDED_QR_PT",
    "build_verify_url",
    "resolve_qr_rect",
    "embed_qr",
]
