# Check 21 Compatibility Test Suite

This is a **standalone test suite** — not part of the `validpay` SDK
package — that proves a ValidPay QR code embedded in a physical check
or money order survives every stage of a US bank check imaging
pipeline.

ValidPay encodes a verification URL (intent id + decryption key) into a
QR code that gets printed on physical instruments. Banks process those
instruments through Check 21 / ANSI X9.100 imaging: grayscale
conversion, bitonal thresholding, TIFF Group 4 storage, JPEG
transmission, and IRD reproduction. If the QR doesn't decode after that
journey, the whole product fails. This suite simulates that journey end
to end and produces a formal compliance report.

## What it does

`test_check21.py` generates a realistic ValidPay QR (Level H error
correction, ~20 mm physical size at 200 DPI) and runs it through nine
individual degradation tests plus one combined worst-case pipeline.

| # | Test | What it simulates |
|---|------|-------------------|
| 1 | 200 DPI grayscale conversion | Bank scanner initial capture |
| 2 | TIFF Group 4 compression | Bank storage / exchange format (X9.100-181) |
| 3 | 100 DPI downsample | Low-quality IRD reproduction |
| 4 | Gaussian noise (σ=5) | Paper texture / scanner sensor noise |
| 5 | JPEG Q60 compression | Web / mobile-deposit transmission |
| 6 | ±2° rotation | Misaligned check in scanner feed |
| 7 | 10% edge crop | Partial document capture |
| 8 | Print-scan simulation | Print at 300 DPI, re-scan at 200 DPI |
| 9 | JPEG Q30 compression | Aggressive mobile photo compression |
| 10 | Combined worst-case | All of the above, chained |

Each test attempts to decode the transformed image with `pyzbar` and
verifies that the decoded data matches the original verification URL
exactly. Pass = byte-for-byte match.

## Run it

```bash
pip install -r check21/requirements.txt
python check21/test_check21.py
```

Exit code is `0` if all 10 tests pass, `1` otherwise.

### System dependency: zbar

The `pyzbar` Python package wraps the native zbar library, which is
**not** vendored on Linux. Install it with:

```bash
# Debian / Ubuntu
apt-get install libzbar0

# macOS
brew install zbar
```

On Windows the `pyzbar` wheel includes the DLL — no extra step.

## Output

Running the suite produces:

- `check21/CHECK21_COMPLIANCE_REPORT.md` — formal Markdown report with
  the executive summary, results table, standards referenced, and
  per-test details.
- `check21/artifacts/` — every transformed image, one per test, so a
  reviewer can inspect what each pipeline stage actually does to the QR.

The report and artifacts are committed to the repo so anyone can read
the latest compliance state without running anything.

## Standards covered

- **Check 21 Act** (Public Law 108-100) — substitute checks (IRDs)
- **ANSI X9.100-140** — IRD specifications
- **ANSI X9.100-181** — TIFF image format for image exchange
- **ANSI X9.100-187** — electronic check / image data exchange

## Why a separate top-level directory

This suite has heavyweight dependencies (`Pillow`, `numpy`, `pyzbar`,
`qrcode`) that the SDK itself doesn't need. Keeping it in `check21/`
with its own `requirements.txt` means `pip install validpay` stays
lean while the compliance evidence lives in the same repo as the SDK.
