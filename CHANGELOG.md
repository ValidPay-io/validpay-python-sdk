# Changelog

All notable changes to the ValidPay Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
