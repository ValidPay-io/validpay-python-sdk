# Changelog

All notable changes to the ValidPay Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-06-19

### Added

- **Platform delegation — `on_behalf_of`** (Fork B). Platforms that seal on
  behalf of the businesses they serve can declare which business each seal is
  for: pass `on_behalf_of={"ref": ..., "name": ...}` to `create_intent`,
  `create_file_intent`, `create_selective_intent`, or per-item in
  `create_intent_batch`. `ref` is your own id for the business (the dedupe key —
  same `ref` rolls up); `name` is who the verifier sees. The verifier sees that
  business as the issuer, attributed *through* your platform, at the `delegated`
  trust rung. ValidPay stays blind to the document contents — identity only.
- `verify_intent` now surfaces `verification_level` (`none` < `delegated` <
  `domain` < `business`) and `delegated_by` (`{"platform", "platform_level"}` or
  `None`) on `VerifyIntentResult`.

> Requires the ValidPay API with platform-delegation support (live 2026-06-19).

## [1.4.0] - 2026-06-17

### Added

- **QR placement — `embed_qr()`** plus the pure helpers `build_verify_url()`
  and `resolve_qr_rect()`, and the `QrPlacement` contract (anchor + x/y insets
  + width + units + page). Stamps a scannable verify QR onto a PDF so
  integrators stop hand-rolling QR rendering and guessing coordinates; the
  coordinate vocabulary is identical to the Node SDK and the developer
  console's "Try it" tool. Warns below the ~72pt scannable minimum and raises
  on off-page placement.
- New optional extra: `pip install "validpay[pdf]"` (`qrcode`, `Pillow`,
  `reportlab`, `pypdf`). The core SDK stays dependency-light — these load only
  when `embed_qr` is called.

## [1.3.0] - 2026-06-16

### Added

- **File mode — `create_file_intent()`** (Prompt 099). Seal a full document
  file (PDF, image, DOCX, …) end-to-end: pass the raw `bytes`, an optional
  `file_name` and `file_content_type`, and the SDK AES-256-GCM-encrypts the
  bytes locally (split-key by default) and registers them. A verifier decrypts
  back the exact original bytes for a byte-for-byte match.
- Low-level `encrypt_bytes()` / `decrypt_bytes()` helpers for raw-bytes
  payloads (the existing `encrypt()` / `decrypt()` now delegate to them).

## [1.1.0] - 2026-06-12

### Changed

- **Split-key protection (Patent C) is now the default** (Prompt 094).
  `create_intent()` splits the AES key into two XOR shares: Share A is
  returned as `result.key`, Share B is stored on the ValidPay server.
  The full decryption key never exists on any single system after the
  call returns. Pass `split_key=False` for the legacy single-key flow.
- `verify_intent()` now verifies split-key intents transparently: when
  the API marks an intent `split_key`, it fetches Share B from the
  fragment endpoint and XOR-combines it with the key you pass (Share A),
  instead of raising `split_key_required`. Legacy intents verify exactly
  as before.

### Deprecated

- `create_split_key_intent()` — now an alias for `create_intent()` (which
  does split-key by default). Emits `DeprecationWarning`; will be removed
  in 2.0.

## [1.0.1] - 2026-06-08

### Changed

- `DEFAULT_BASE_URL` is now `https://api.validpay.com` (Prompt 086B —
  primary domain migrated from validpay.io). The legacy host keeps
  working via Cloudflare 301 redirects, so 1.0.0 installs are
  unaffected; new installs default to `.com`. The `base_url` constructor
  argument continues to override.
- README + `pyproject.toml` URLs (Homepage, Documentation) now point at
  `validpay.com`.

## [1.0.0] - 2026-05-03

### Added

- **Core client** (`ValidPayClient`) — create, verify, revoke, and reinstate
  document intents via the ValidPay API.
- **AES-256-GCM encryption** — client-side encryption/decryption with
  commitment hash verification (Patent B).
- **Split-key verification** (Patent C) — XOR key splitting into Share A
  (document) and Share B (server). Neither alone decrypts.
- **Time-locked verification** (Patent D) — optional `valid_from` /
  `valid_until` windows with client-side enforcement.
- **Selective field disclosure** (Patent E) — per-field encryption with
  role-based disclosure policies.
- **Physical medium binding** (Patent F) — perceptual hashing and binding
  zone comparison for document-to-physical matching.
  Requires optional `binding` extra (`pip install validpay[binding]`).
- **Chain-of-custody tracking** (Patent G) — verification event audit log
  via the API.
- **Blind revocation** (Patent H) — revoke/reinstate intents without
  decrypting the payload.
- **Offline verification** (`OfflineCache`) — encrypted local cache for
  offline verification with staleness tracking and revocation sync.
- **Batch intent creation** — create up to 100 intents in a single API call.
- **115 automated tests** across 4 test modules.

[1.0.0]: https://github.com/ValidPay-io/validpay-python-sdk/releases/tag/v1.0.0
