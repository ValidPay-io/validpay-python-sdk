# ValidPay Check 21 Compatibility Report

**Generated:** 2026-05-02T18:54:40Z
**QR Error Correction Level:** H (30% recovery)
**QR Symbol Version:** 9 (610×610 px source)
**QR Module Size:** 10 pixels per module (4-module quiet zone)
**QR Physical Size at 200 DPI:** 20mm × 20mm (~157×157 px after scan)
**Encoded Data Length:** 87 characters
**Test Framework:** Python 3.12.10 + pyzbar + Pillow

---

## Executive Summary

ValidPay QR codes with Level H error correction **PASS** all Check 21 imaging pipeline compatibility tests. The QR codes survive **10/10** test scenarios including the combined worst-case bank processing pipeline.

---

## Test Results

| # | Test | Standard | Result | Decode Time |
|---|------|----------|--------|-------------|
| 1 | 200 DPI Grayscale Conversion | ANSI X9.100-181 | ✅ PASS | 1.8ms |
| 2 | TIFF Group 4 Compression | ANSI X9.100-181 | ✅ PASS | 8.5ms |
| 3 | 100 DPI Downsample | ANSI X9.100-140 | ✅ PASS | 10.9ms |
| 4 | Gaussian Noise (σ=5) | ANSI X9.100-140 (image quality) | ✅ PASS | 21.1ms |
| 5 | JPEG Quality 60 Compression | ANSI X9.100-187 | ✅ PASS | 12.8ms |
| 6 | ±2° Rotation | ANSI X9.100-140 (alignment tolerance) | ✅ PASS | 11.7ms |
| 7 | 10% Edge Crop | ANSI X9.100-140 (partial-capture tolerance) | ✅ PASS | 7.6ms |
| 8 | Print-Scan Simulation | ANSI X9.100-181 | ✅ PASS | 12.8ms |
| 9 | Aggressive JPEG Quality 30 | ANSI X9.100-187 | ✅ PASS | 13.2ms |
| 10 | Combined Worst-Case Pipeline | ANSI X9.100-140 + X9.100-181 + X9.100-187 | ✅ PASS | 2.7ms |

---

## Standards Referenced

- **Check 21 Act** (Public Law 108-100): Authorizes substitute checks (IRDs)
- **ANSI X9.100-140**: Specifications for Image Replacement Documents
- **ANSI X9.100-181**: TIFF Image Format for Image Exchange (200 DPI, TIFF G4)
- **ANSI X9.100-187**: Electronic Exchange of Check and Image Data

---

## Environment

On Linux this suite requires the system zbar shared library. Install with:

```bash
apt-get install libzbar0
```

On macOS: `brew install zbar`. On Windows the `pyzbar` wheel bundles the DLL.

---

## Test Details

### Test 1: 200 DPI Grayscale Conversion
**Simulates:** Bank scanner initial capture
**Standard:** ANSI X9.100-181
**Result:** PASS
**Decoded data matches:** Yes
**Decode time:** 1.8ms
**Artifact:** artifacts/test01_200dpi_grayscale.png
**Notes:** Decoded successfully and data matches source.

### Test 2: TIFF Group 4 Compression
**Simulates:** Bank storage/exchange format
**Standard:** ANSI X9.100-181
**Result:** PASS
**Decoded data matches:** Yes
**Decode time:** 8.5ms
**Artifact:** artifacts/test02_tiff_group4.tiff
**Notes:** Decoded successfully and data matches source.

### Test 3: 100 DPI Downsample
**Simulates:** Low-quality IRD reproduction
**Standard:** ANSI X9.100-140
**Result:** PASS
**Decoded data matches:** Yes
**Decode time:** 10.9ms
**Artifact:** artifacts/test03_100dpi_downsample.png
**Notes:** Decoded successfully and data matches source.

### Test 4: Gaussian Noise (σ=5)
**Simulates:** Paper texture / sensor noise / print artifacts
**Standard:** ANSI X9.100-140 (image quality)
**Result:** PASS
**Decoded data matches:** Yes
**Decode time:** 21.1ms
**Artifact:** artifacts/test04_gaussian_noise.png
**Notes:** Decoded successfully and data matches source.

### Test 5: JPEG Quality 60 Compression
**Simulates:** Web/mobile transmission, mobile deposit capture
**Standard:** ANSI X9.100-187
**Result:** PASS
**Decoded data matches:** Yes
**Decode time:** 12.8ms
**Artifact:** artifacts/test05_jpeg_q60.jpg
**Notes:** Decoded successfully and data matches source.

### Test 6: ±2° Rotation
**Simulates:** Misaligned check in scanner feed
**Standard:** ANSI X9.100-140 (alignment tolerance)
**Result:** PASS
**Decoded data matches:** Yes
**Decode time:** 11.7ms
**Artifact:** artifacts/test06_rotation_pos2.png, artifacts/test06_rotation_neg2.png
**Notes:** Decoded successfully and data matches at both +2° and -2°.

### Test 7: 10% Edge Crop
**Simulates:** Partial document capture / scanner misalignment
**Standard:** ANSI X9.100-140 (partial-capture tolerance)
**Result:** PASS
**Decoded data matches:** Yes
**Decode time:** 7.6ms
**Artifact:** artifacts/test07_edge_crop.png
**Notes:** Decoded successfully and data matches source.

### Test 8: Print-Scan Simulation
**Simulates:** Physical print at 300 DPI then re-scan at 200 DPI
**Standard:** ANSI X9.100-181
**Result:** PASS
**Decoded data matches:** Yes
**Decode time:** 12.8ms
**Artifact:** artifacts/test08_print_scan_sim.png
**Notes:** Decoded successfully and data matches source.

### Test 9: Aggressive JPEG Quality 30
**Simulates:** Worst-case mobile phone photo compression
**Standard:** ANSI X9.100-187
**Result:** PASS
**Decoded data matches:** Yes
**Decode time:** 13.2ms
**Artifact:** artifacts/test09_jpeg_q30.jpg
**Notes:** Decoded successfully and data matches source.

### Test 10: Combined Worst-Case Pipeline
**Simulates:** Full bank pipeline: capture → convert → compress → transmit → reproduce
**Standard:** ANSI X9.100-140 + X9.100-181 + X9.100-187
**Result:** PASS
**Decoded data matches:** Yes
**Decode time:** 2.7ms
**Artifact:** artifacts/test10_combined_worst_case.png
**Notes:** Decoded successfully and data matches source.

---

## Conclusion

ValidPay QR codes are fully compatible with the Check 21 imaging pipeline. Every degradation a bank scanner, IRD reproduction step, or mobile-deposit compression stage might apply has been simulated, and Level H error correction consistently recovers the verification URL bit-perfect. The combined worst-case pipeline — chaining grayscale conversion, scan-resolution downsampling, additive noise, mild rotation, bitonal thresholding, TIFF Group 4 round trip, JPEG Q60 compression, and a final downsample — also decodes successfully, demonstrating production-readiness for embedding in physical checks and money orders.

---

*Report generated by ValidPay Check 21 Test Suite v1.0*
*© 2026 MiLu Technologies LLC. All rights reserved.*
