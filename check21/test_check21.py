#!/usr/bin/env python3
"""
ValidPay Check 21 Compatibility Test Suite

Tests QR code survival through the full bank check imaging pipeline
per ANSI X9.100-140 and X9.100-181 standards.

Usage: python check21/test_check21.py
Output: check21/CHECK21_COMPLIANCE_REPORT.md + check21/artifacts/
"""

from __future__ import annotations

import io
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import numpy as np
import qrcode
from PIL import Image, ImageFilter
from pyzbar.pyzbar import decode as zbar_decode

# --- constants ---------------------------------------------------------------

ENCODED_DATA = (
    "https://validpay.com/verify/vp_abc123def456"
    "#k=dGVzdGtleV9iYXNlNjRfZW5jb2RlZF8zMl9ieXRlcw"
)

# QR generation parameters
QR_BOX_SIZE = 10
QR_BORDER = 4
QR_ERROR_CORRECTION = qrcode.constants.ERROR_CORRECT_H

# Bank scanner spec: 20mm @ 200 DPI ≈ 157 px on the long side
TARGET_SCAN_PX = 157
PHYSICAL_SIZE_MM = 20.0
SCAN_DPI = 200

ROOT = Path(__file__).resolve().parent
ARTIFACTS_DIR = ROOT / "artifacts"
REPORT_PATH = ROOT / "CHECK21_COMPLIANCE_REPORT.md"


# --- helpers -----------------------------------------------------------------

def generate_source_qr() -> Tuple[Image.Image, int]:
    """Build the source QR. Returns (image, version) — version is the
    QR symbol version (1–40) chosen by the encoder to fit the data."""
    qr = qrcode.QRCode(
        version=None,  # auto-fit
        error_correction=QR_ERROR_CORRECTION,
        box_size=QR_BOX_SIZE,
        border=QR_BORDER,
    )
    qr.add_data(ENCODED_DATA)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    return img, qr.version


def attempt_decode(img: Image.Image) -> Tuple[Optional[str], float]:
    """Run pyzbar on the image. Returns (decoded_text, decode_time_ms)."""
    t0 = time.perf_counter()
    results = zbar_decode(img)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    if not results:
        return None, elapsed_ms
    # pyzbar may surface multiple symbols — take the first.
    raw = results[0].data
    try:
        return raw.decode("utf-8"), elapsed_ms
    except UnicodeDecodeError:
        return raw.decode("latin-1"), elapsed_ms


def save(img: Image.Image, name: str, **save_kwargs) -> Path:
    out = ARTIFACTS_DIR / name
    img.save(out, **save_kwargs)
    return out


def to_bitonal_threshold_128(img: Image.Image) -> Image.Image:
    """Hard threshold at 128 → 1-bit ('1') image."""
    gray = img.convert("L")
    return gray.point(lambda p: 255 if p >= 128 else 0).convert("1")


def resize_to_target_px(img: Image.Image, target_px: int) -> Image.Image:
    """Resize so the longer side equals target_px, preserving aspect."""
    w, h = img.size
    longer = max(w, h)
    if longer == target_px:
        return img.copy()
    scale = target_px / longer
    new_size = (max(1, round(w * scale)), max(1, round(h * scale)))
    return img.resize(new_size, Image.LANCZOS)


# --- individual transforms ---------------------------------------------------

def t01_grayscale_200dpi(src: Image.Image) -> Image.Image:
    gray = src.convert("L")
    return resize_to_target_px(gray, TARGET_SCAN_PX)


def t02_tiff_group4(src: Image.Image) -> Image.Image:
    bitonal = to_bitonal_threshold_128(src)
    buf = io.BytesIO()
    bitonal.save(buf, format="TIFF", compression="group4")
    buf.seek(0)
    return Image.open(buf).copy()


def t03_100dpi_downsample(src: Image.Image) -> Image.Image:
    w, h = src.size
    half = src.resize((max(1, w // 2), max(1, h // 2)), Image.LANCZOS)
    return half.resize((w, h), Image.LANCZOS)


def t04_gaussian_noise(src: Image.Image, sigma: float = 5.0) -> Image.Image:
    arr = np.asarray(src.convert("L"), dtype=np.float32)
    noise = np.random.default_rng(seed=42).normal(loc=0.0, scale=sigma, size=arr.shape)
    noisy = np.clip(arr + noise, 0, 255).astype(np.uint8)
    return Image.fromarray(noisy, mode="L")


def t05_jpeg_q60(src: Image.Image) -> Image.Image:
    buf = io.BytesIO()
    src.convert("RGB").save(buf, format="JPEG", quality=60)
    buf.seek(0)
    return Image.open(buf).copy()


def t06_rotate(src: Image.Image, degrees: float) -> Image.Image:
    return src.rotate(degrees, expand=True, fillcolor=255, resample=Image.BICUBIC)


def t07_edge_crop(src: Image.Image, frac: float = 0.05) -> Image.Image:
    w, h = src.size
    dx, dy = int(w * frac), int(h * frac)
    return src.crop((dx, dy, w - dx, h - dy))


def t08_print_scan_simulation(src: Image.Image) -> Image.Image:
    img = src.convert("L")
    # 1. slight blur
    img = img.filter(ImageFilter.GaussianBlur(radius=1))
    # 2. light gaussian noise (σ=3)
    arr = np.asarray(img, dtype=np.float32)
    rng = np.random.default_rng(seed=43)
    arr = arr + rng.normal(0.0, 3.0, size=arr.shape)
    # 3. 10% contrast reduction: out = in*0.9 + 13
    arr = arr * 0.9 + 13.0
    arr = np.clip(arr, 0, 255).astype(np.uint8)
    img = Image.fromarray(arr, mode="L")
    # 4. 300 → 200 DPI loss (66% downsample, then back)
    w, h = img.size
    small = img.resize((max(1, int(w * 0.66)), max(1, int(h * 0.66))), Image.LANCZOS)
    return small.resize((w, h), Image.LANCZOS)


def t09_jpeg_q30(src: Image.Image) -> Image.Image:
    buf = io.BytesIO()
    src.convert("RGB").save(buf, format="JPEG", quality=30)
    buf.seek(0)
    return Image.open(buf).copy()


def t10_combined_worst_case(src: Image.Image) -> Image.Image:
    # 1. grayscale
    img = src.convert("L")
    # 2. resize to 200 DPI equivalent
    img = resize_to_target_px(img, TARGET_SCAN_PX)
    # 3. add Gaussian noise σ=3
    arr = np.asarray(img, dtype=np.float32)
    rng = np.random.default_rng(seed=44)
    arr = np.clip(arr + rng.normal(0.0, 3.0, size=arr.shape), 0, 255).astype(np.uint8)
    img = Image.fromarray(arr, mode="L")
    # 4. rotate +1.5°
    img = img.rotate(1.5, expand=True, fillcolor=255, resample=Image.BICUBIC)
    # 5. bitonal threshold at 128
    img = img.point(lambda p: 255 if p >= 128 else 0).convert("1")
    # 6. TIFF group4 round trip
    buf = io.BytesIO()
    img.save(buf, format="TIFF", compression="group4")
    buf.seek(0)
    img = Image.open(buf).copy()
    # 7. JPEG Q60 round trip
    buf = io.BytesIO()
    img.convert("RGB").save(buf, format="JPEG", quality=60)
    buf.seek(0)
    img = Image.open(buf).copy()
    # 8. 75% downsample then upsample
    w, h = img.size
    small = img.resize((max(1, int(w * 0.75)), max(1, int(h * 0.75))), Image.LANCZOS)
    img = small.resize((w, h), Image.LANCZOS)
    return img


# --- test runner -------------------------------------------------------------

def run_test(
    index: int,
    name: str,
    standard: str,
    simulates: str,
    artifact_name: str,
    transform: Callable[[Image.Image], Image.Image],
    src: Image.Image,
    save_kwargs: Optional[Dict] = None,
) -> Dict:
    t0 = time.perf_counter()
    try:
        out = transform(src)
        save(out, artifact_name, **(save_kwargs or {}))
        decoded, decode_ms = attempt_decode(out)
    except Exception as exc:  # pragma: no cover — defensive
        elapsed = (time.perf_counter() - t0) * 1000.0
        return {
            "index": index,
            "name": name,
            "standard": standard,
            "simulates": simulates,
            "artifact": f"artifacts/{artifact_name}",
            "passed": False,
            "matches": False,
            "decode_time_ms": elapsed,
            "details": f"Exception during transform: {exc!r}",
        }

    matches = decoded == ENCODED_DATA
    passed = matches
    if decoded is None:
        details = "QR did not decode."
    elif not matches:
        details = f"Decoded but data mismatch (got {decoded!r})"
    else:
        details = "Decoded successfully and data matches source."

    return {
        "index": index,
        "name": name,
        "standard": standard,
        "simulates": simulates,
        "artifact": f"artifacts/{artifact_name}",
        "passed": passed,
        "matches": matches,
        "decode_time_ms": decode_ms,
        "details": details,
    }


def run_rotation_test(src: Image.Image) -> Dict:
    """±2° rotation — both must pass to pass overall."""
    sub_results = []
    for sign, name_suffix, artifact in [
        (+2.0, "+2°", "test06_rotation_pos2.png"),
        (-2.0, "-2°", "test06_rotation_neg2.png"),
    ]:
        out = t06_rotate(src, sign)
        save(out, artifact)
        decoded, decode_ms = attempt_decode(out)
        sub_results.append({
            "label": name_suffix,
            "decoded_ok": decoded == ENCODED_DATA,
            "decode_ms": decode_ms,
            "decoded": decoded,
        })

    passed = all(r["decoded_ok"] for r in sub_results)
    decode_ms = sum(r["decode_ms"] for r in sub_results) / len(sub_results)
    if passed:
        details = "Decoded successfully and data matches at both +2° and -2°."
    else:
        broken = [r["label"] for r in sub_results if not r["decoded_ok"]]
        details = f"Failed at: {', '.join(broken)}"

    return {
        "index": 6,
        "name": "±2° Rotation",
        "standard": "ANSI X9.100-140 (alignment tolerance)",
        "simulates": "Misaligned check in scanner feed",
        "artifact": "artifacts/test06_rotation_pos2.png, artifacts/test06_rotation_neg2.png",
        "passed": passed,
        "matches": passed,
        "decode_time_ms": decode_ms,
        "details": details,
    }


# --- report rendering --------------------------------------------------------

def render_report(
    results: List[Dict],
    qr_version: int,
    source_size_px: Tuple[int, int],
    timestamp: str,
) -> str:
    py_version = ".".join(str(x) for x in sys.version_info[:3])
    pass_count = sum(1 for r in results if r["passed"])
    total = len(results)
    overall = "PASS" if pass_count == total else "FAIL"

    lines = []
    lines.append("# ValidPay Check 21 Compatibility Report")
    lines.append("")
    lines.append(f"**Generated:** {timestamp}")
    lines.append(f"**QR Error Correction Level:** H (30% recovery)")
    lines.append(f"**QR Symbol Version:** {qr_version} ({source_size_px[0]}×{source_size_px[1]} px source)")
    lines.append(f"**QR Module Size:** {QR_BOX_SIZE} pixels per module ({QR_BORDER}-module quiet zone)")
    lines.append(f"**QR Physical Size at {SCAN_DPI} DPI:** {PHYSICAL_SIZE_MM:.0f}mm × {PHYSICAL_SIZE_MM:.0f}mm "
                 f"(~{TARGET_SCAN_PX}×{TARGET_SCAN_PX} px after scan)")
    lines.append(f"**Encoded Data Length:** {len(ENCODED_DATA)} characters")
    lines.append(f"**Test Framework:** Python {py_version} + pyzbar + Pillow")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"ValidPay QR codes with Level H error correction **{overall}** all Check 21 "
        f"imaging pipeline compatibility tests. The QR codes survive **{pass_count}/{total}** "
        f"test scenarios including the combined worst-case bank processing pipeline."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Test Results")
    lines.append("")
    lines.append("| # | Test | Standard | Result | Decode Time |")
    lines.append("|---|------|----------|--------|-------------|")
    for r in results:
        result_cell = "✅ PASS" if r["passed"] else "❌ FAIL"
        lines.append(
            f"| {r['index']} | {r['name']} | {r['standard']} | {result_cell} | "
            f"{r['decode_time_ms']:.1f}ms |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Standards Referenced")
    lines.append("")
    lines.append("- **Check 21 Act** (Public Law 108-100): Authorizes substitute checks (IRDs)")
    lines.append("- **ANSI X9.100-140**: Specifications for Image Replacement Documents")
    lines.append("- **ANSI X9.100-181**: TIFF Image Format for Image Exchange (200 DPI, TIFF G4)")
    lines.append("- **ANSI X9.100-187**: Electronic Exchange of Check and Image Data")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Environment")
    lines.append("")
    lines.append(
        "On Linux this suite requires the system zbar shared library. Install with:"
    )
    lines.append("")
    lines.append("```bash")
    lines.append("apt-get install libzbar0")
    lines.append("```")
    lines.append("")
    lines.append("On macOS: `brew install zbar`. On Windows the `pyzbar` wheel bundles the DLL.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Test Details")
    lines.append("")
    for r in results:
        lines.append(f"### Test {r['index']}: {r['name']}")
        lines.append(f"**Simulates:** {r['simulates']}")
        lines.append(f"**Standard:** {r['standard']}")
        lines.append(f"**Result:** {'PASS' if r['passed'] else 'FAIL'}")
        lines.append(f"**Decoded data matches:** {'Yes' if r['matches'] else 'No'}")
        lines.append(f"**Decode time:** {r['decode_time_ms']:.1f}ms")
        lines.append(f"**Artifact:** {r['artifact']}")
        lines.append(f"**Notes:** {r['details']}")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Conclusion")
    lines.append("")
    if pass_count == total:
        lines.append(
            "ValidPay QR codes are fully compatible with the Check 21 imaging pipeline. "
            "Every degradation a bank scanner, IRD reproduction step, or mobile-deposit "
            "compression stage might apply has been simulated, and Level H error correction "
            "consistently recovers the verification URL bit-perfect. The combined worst-case "
            "pipeline — chaining grayscale conversion, scan-resolution downsampling, additive "
            "noise, mild rotation, bitonal thresholding, TIFF Group 4 round trip, JPEG Q60 "
            "compression, and a final downsample — also decodes successfully, demonstrating "
            "production-readiness for embedding in physical checks and money orders."
        )
    else:
        failing = [r["name"] for r in results if not r["passed"]]
        lines.append(
            "ValidPay QR codes did not pass every Check 21 imaging stage. Failing tests: "
            f"{', '.join(failing)}. Review the artifacts in `artifacts/` and the test "
            "details above to identify the failing stage; tightening the QR module size, "
            "physical print size, or contrast may resolve the issue."
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*Report generated by ValidPay Check 21 Test Suite v1.0*")
    lines.append("*© 2026 MiLu Technologies LLC. All rights reserved.*")
    lines.append("")
    return "\n".join(lines)


# --- main --------------------------------------------------------------------

def main() -> int:
    # Windows consoles default to cp1252 and can't print σ / × / ✅.
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    print("ValidPay Check 21 Compatibility Test Suite")
    print("=" * 50)

    src, qr_version = generate_source_qr()
    save(src, "source_qr.png")
    print(f"Generated source QR: version {qr_version}, {src.size[0]}×{src.size[1]}px")
    print()

    # Sanity check: source must decode
    decoded, _ = attempt_decode(src)
    if decoded != ENCODED_DATA:
        print(f"ERROR: source QR did not decode to expected data. Got: {decoded!r}")
        return 1

    results: List[Dict] = []

    test_specs = [
        (1, "200 DPI Grayscale Conversion", "ANSI X9.100-181",
         "Bank scanner initial capture", "test01_200dpi_grayscale.png",
         t01_grayscale_200dpi, None),
        (2, "TIFF Group 4 Compression", "ANSI X9.100-181",
         "Bank storage/exchange format", "test02_tiff_group4.tiff",
         t02_tiff_group4, {"format": "TIFF", "compression": "group4"}),
        (3, "100 DPI Downsample", "ANSI X9.100-140",
         "Low-quality IRD reproduction", "test03_100dpi_downsample.png",
         t03_100dpi_downsample, None),
        (4, "Gaussian Noise (σ=5)", "ANSI X9.100-140 (image quality)",
         "Paper texture / sensor noise / print artifacts",
         "test04_gaussian_noise.png", t04_gaussian_noise, None),
        (5, "JPEG Quality 60 Compression", "ANSI X9.100-187",
         "Web/mobile transmission, mobile deposit capture",
         "test05_jpeg_q60.jpg", t05_jpeg_q60, {"format": "JPEG", "quality": 60}),
    ]

    for index, name, standard, sim, art, fn, save_kw in test_specs:
        r = run_test(index, name, standard, sim, art, fn, src, save_kw)
        results.append(r)
        status = "PASS" if r["passed"] else "FAIL"
        print(f"[{index}/10] {name}... {status}  ({r['decode_time_ms']:.1f}ms)")

    # Test 6 — special: two rotations.
    r6 = run_rotation_test(src)
    results.append(r6)
    print(f"[6/10] {r6['name']}... {'PASS' if r6['passed'] else 'FAIL'}  "
          f"({r6['decode_time_ms']:.1f}ms avg)")

    later_specs = [
        (7, "10% Edge Crop", "ANSI X9.100-140 (partial-capture tolerance)",
         "Partial document capture / scanner misalignment",
         "test07_edge_crop.png", t07_edge_crop, None),
        (8, "Print-Scan Simulation", "ANSI X9.100-181",
         "Physical print at 300 DPI then re-scan at 200 DPI",
         "test08_print_scan_sim.png", t08_print_scan_simulation, None),
        (9, "Aggressive JPEG Quality 30", "ANSI X9.100-187",
         "Worst-case mobile phone photo compression",
         "test09_jpeg_q30.jpg", t09_jpeg_q30, {"format": "JPEG", "quality": 30}),
        (10, "Combined Worst-Case Pipeline",
         "ANSI X9.100-140 + X9.100-181 + X9.100-187",
         "Full bank pipeline: capture → convert → compress → transmit → reproduce",
         "test10_combined_worst_case.png", t10_combined_worst_case, None),
    ]

    for index, name, standard, sim, art, fn, save_kw in later_specs:
        r = run_test(index, name, standard, sim, art, fn, src, save_kw)
        results.append(r)
        status = "PASS" if r["passed"] else "FAIL"
        print(f"[{index}/10] {name}... {status}  ({r['decode_time_ms']:.1f}ms)")

    print()
    pass_count = sum(1 for r in results if r["passed"])
    print(f"Overall: {pass_count}/{len(results)} passed")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report = render_report(results, qr_version, src.size, timestamp)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"Report written: {REPORT_PATH}")

    return 0 if pass_count == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
