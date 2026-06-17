# ValidPay Python SDK

Official Python SDK for the [ValidPay](https://validpay.com) document
verification API. Provides client-side AES-256-GCM encryption and a thin
client around the ValidPay HTTP API.

The encryption format is wire-compatible with the
[Node.js SDK](https://github.com/ValidPay-io/validpay-node-sdk): a payload
encrypted by the Python SDK can be decrypted by the Node SDK and vice
versa.

## Install

```bash
pip install validpay
```

For physical-binding support (Patent F — image-based binding zones), install
the optional extras:

```bash
pip install validpay[binding]
```

Requires Python 3.9+.

## Quick start

```python
from validpay import ValidPayClient

client = ValidPayClient(api_key="vp_live_xxx")

# Create a single intent — the payload is encrypted locally before
# anything leaves your process. Only the ciphertext is sent to ValidPay.
# Split-key protection (Patent C) is the default since 1.1.0: result.key
# is Share A of the AES key; Share B lives on the ValidPay server. The
# full decryption key never exists on any single system.
result = client.create_intent(
    document_type="check",
    payload={"payee": "John Doe", "amount": 1500.00, "check_number": "10042"},
)
print(result.retrieval_id)  # vp_abc123def456
print(result.key)           # base64 key Share A — embed in the QR / deliver out-of-band

# Create up to 100 intents in one round trip.
results = client.create_intent_batch([
    {"document_type": "check", "payload": {"payee": "Alice", "amount": 500}},
    {"document_type": "check", "payload": {"payee": "Bob",   "amount": 750}},
])
for r in results:
    print(r.retrieval_id, r.key)

# Verify (retrieve + decrypt). No API key required for this endpoint.
verification = client.verify_intent(
    retrieval_id="vp_abc123def456",
    key=result.key,
)
print(verification.payload)         # decrypted dict
print(verification.issuer)          # "Acme Corp"
print(verification.issuer_verified) # True
print(verification.status)          # "active"
```

### Placing the QR on a document (`embed_qr`)

To verify a document, a scannable QR encoding the verify URL has to appear **on**
it. `embed_qr` builds that QR and stamps it onto a PDF for you — no QR library
wiring, no base64url juggling, and no fighting PDF coordinates (PDFs measure from
the bottom-left; everything else from the top-left).

It needs the optional PDF extras — the core SDK needs none of them:

```bash
pip install "validpay[pdf]"
```

```python
from validpay import ValidPayClient, QrPlacement, embed_qr

client = ValidPayClient(api_key="vp_live_...")

with open("invoice.pdf", "rb") as f:
    original = f.read()

res = client.create_file_intent(
    document_type="invoice", file=original, file_content_type="application/pdf",
)

sealed = embed_qr(
    original, res.retrieval_id, res.key,
    # 90pt (1.25in) QR, 36pt in from the bottom-right corner.
    QrPlacement(anchor="bottom-right", x=36, y=36, width=90),
)
with open("invoice-sealed.pdf", "wb") as f:
    f.write(sealed)
```

**The placement contract** — identical to the Node SDK and the developer
console's "Try it" tool, so a position you pick in the UI maps here 1:1:

| field    | meaning | default |
| -------- | ------- | ------- |
| `anchor` | which page **corner** the insets are measured from (`top-left`/`top-right`/`bottom-left`/`bottom-right`) | `top-left` |
| `x`      | horizontal inset from that corner's vertical edge | — |
| `y`      | vertical inset from that corner's horizontal edge | — |
| `width`  | QR side length (it's square) | — |
| `units`  | `pt` (1/72in) / `mm` / `in` | `pt` |
| `page`   | 1-based page number | `1` |

Keep the QR **≥ ~72pt (1in)** so it scans once printed — `embed_qr` warns below
that and raises if the placement runs off the page. Using a different PDF
library? The pure helpers `build_verify_url(...)` and
`resolve_qr_rect(placement, page_w_pt, page_h_pt)` have no dependencies.

### Time-Locked Verification (Patent D)

Restrict when a document can be verified by specifying a validity window:

```python
from datetime import datetime, timezone, timedelta

result = client.create_intent(
    document_type="check",
    payload={"payee": "Jane Doe", "amount": 1500.00},
    valid_from=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    valid_until=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
)

# Later, when verifying:
verified = client.verify_intent(result.retrieval_id, result.key)
print(verified.time_lock_status)  # "valid", "not_yet_valid", or "expired"
print(verified.valid_from)        # ISO-8601 timestamp or None
print(verified.valid_until)       # ISO-8601 timestamp or None
```

Time-lock status is informational — the SDK always returns the decrypted
payload regardless of the time window. Your application decides how to
handle `not_yet_valid` or `expired` results. The server stores the
timestamps but never enforces them; this preserves the blind intermediary
model (the server never decides whether a document is "still good").

The same `valid_from` / `valid_until` keyword arguments are accepted by
`create_intent_batch` (per-item) and `create_selective_intent`.

### Split-key intents (Patent C) — the default

All documents created with SDK v1.1+ use split-key by default: the AES
key is split into two XOR shares — Share A is returned to the caller
(typically embedded in the QR code), Share B is stored server-side.
Neither share alone can decrypt the payload, so the full decryption key
never exists on any single system.

```python
result = client.create_intent(
    document_type="ssn_card",
    payload={"ssn": "123-45-6789"},
)
# result.key is Share A — verify_intent pairs it with Share B automatically.

verified = client.verify_intent(result.retrieval_id, result.key)
print(verified.payload)
```

#### Backward compatibility

- `create_intent(..., split_key=False)` gives the legacy single-key flow
  (the returned `key` is the full AES key).
- `create_split_key_intent()` is a deprecated alias for `create_intent()`
  — 1.0.x code keeps working, with a `DeprecationWarning`.
- `verify_intent` detects legacy vs split-key intents from the API
  response, so it verifies both; `verify_split_key_intent()` also still
  works.

### Selective disclosure (Patent E)

Each field is encrypted with its own per-field key. A disclosure policy maps
role names to the fields that role may decrypt. A `full` role with access to
every field is added automatically.

```python
result = client.create_selective_intent(
    document_type="check",
    payload={"payee": "Alice", "amount": 1500.00, "memo": "rent"},
    disclosure_policy={"bank": ["amount"], "auditor": ["amount", "payee"]},
)

# Bank sees only 'amount'; other fields come back as REDACTED markers.
verified = client.verify_selective_intent(result.retrieval_id, result.key, role="bank")
print(verified.payload)
```

`create_selective_intent` accepts `split_key=True` to combine Patents C + E.

### Revocation (Patent H — Blind Revocation)

Issuers can revoke or reinstate an intent without decrypting it. Verifiers
of a revoked intent receive `status="revoked"` and no encrypted payload.

```python
client.revoke_intent("vp_abc123def456", reason="Stop payment")
client.reinstate_intent("vp_abc123def456", reason="False alarm")

history = client.get_revocation_history("vp_abc123def456")
for event in history:
    print(event["action"], event["reason"], event["performed_at"])
```

## API

### `ValidPayClient(api_key, *, base_url=..., timeout=30.0, session=None)`

- `api_key` — your ValidPay API key (required for create endpoints).
- `base_url` — defaults to `https://api.validpay.com`.
- `timeout` — per-request timeout in seconds.
- `session` — optionally provide a `requests.Session` for connection
  pooling, custom adapters, or mocking in tests.

### `client.create_intent(document_type, payload, *, split_key=True) -> CreateIntentResult`

Encrypts `payload` (any JSON-serializable value) under a freshly
generated AES-256 key and registers it with ValidPay. Returns the
retrieval id and the key material: **Share A** of the split key by
default (Share B goes to the server; neither alone decrypts), or the
full AES key with `split_key=False`. **The full key is never sent to
ValidPay** — hand the returned key off out-of-band to whoever needs to
verify the intent.

### `client.create_intent_batch(intents) -> list[CreateIntentResult]`

Bulk version. `intents` is an iterable of mappings shaped
`{"document_type": str, "payload": Any}`, with 1–100 items. Each intent
gets its own unique key. Result order matches input order.

### `client.verify_intent(retrieval_id, key) -> VerifyIntentResult`

Fetches the intent (public endpoint, no API key required), decrypts the
payload locally, and returns issuer metadata + the decrypted payload.

### Errors

All SDK and API errors are raised as `ValidPayError`, which exposes:

- `code` — machine-readable code (e.g. `"unauthorized"`, `"not_found"`,
  `"decryption_failed"`, `"invalid_key"`, `"network_error"`).
- `status` — HTTP status when the error came from the API.
- `details` — raw error body / extra context when available.

### Low-level crypto

For advanced use cases the encryption primitives are exported directly:

```python
from validpay import generate_key, encrypt, decrypt

key = generate_key()
blob = encrypt('{"hello": "world"}', key)
assert decrypt(blob, key) == '{"hello": "world"}'
```

Wire format: `base64(iv[12] || authTag[16] || ciphertext)`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see `LICENSE`.
