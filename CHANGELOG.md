# Changelog

All notable changes to the ValidPay Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
