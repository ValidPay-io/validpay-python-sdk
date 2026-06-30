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

# Seal with End-Cell (recommended). The payload is encrypted locally; the AES
# key is split THREE ways: result.key is ShareA (rides the QR), one share goes
# to the platform, one to the independent KeyHalve rail. No single party — not
# the platform, not KeyHalve — can read or reassemble the key.
result = client.create_end_cell_intent(
    document_type="check",
    payload={"payee": "John Doe", "amount": 1500.00, "check_number": "10042"},
    # holders defaults to ["keyhalve", "platform"] -> a 3-of-3 split with ShareA
)
print(result.retrieval_id)  # vp_abc123def456
print(result.key)           # ShareA — embed in the QR / deliver out-of-band

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

> **Simpler 2-share option:** `create_split_key_intent()` splits the key between
> the document and the platform only — no independent rail share, so the platform
> alone could reconstruct. `create_intent()` also defaults to split-key. Prefer
> **End-Cell** above when independence from the platform matters. `verify_intent()`
> handles all share models automatically.

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

### Platform delegation — `on_behalf_of`

If you integrate as a **platform** and seal on behalf of the businesses you
serve, name the business on each seal. The verifier sees that business as the
issuer ("who"), attributed *through* your platform ("through whom"), at the
`delegated` trust rung. Those businesses never touch ValidPay — no account, no
login — and ValidPay stays blind to the document contents.

```python
result = client.create_intent(
    document_type="lease",
    payload={"unit": "4B", "term": "12mo"},
    on_behalf_of={
        "ref": "landlord_8675309",       # YOUR id for this business (dedupe key)
        "name": "Smith Properties LLC",  # who the verifier sees
    },
)

verified = client.verify_intent(result.retrieval_id, result.key)
verified.issuer              # "Smith Properties LLC"
verified.verification_level  # "delegated"
verified.delegated_by        # {"platform": "Your Platform", "platform_level": "domain"}
```

Same `ref` ⇒ same tracked business (its documents and verification counts roll
up). A sub-issuer surfaces as `delegated` only once **your** platform account is
domain-verified; until then its documents show as unverified.

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

### `client.create_end_cell_intent(document_type, payload, *, holders=None, valid_from=None, valid_until=None, on_behalf_of=None) -> CreateIntentResult` — recommended

KeyHalve's blind-rail flow. Encrypts `payload` and XOR-splits the AES key into
**ShareA** (returned as `key`, for the QR) plus one share per holder. `holders`
defaults to `["keyhalve", "platform"]` → a **3-of-3** split: the independent
KeyHalve rail share + the platform share + ShareA. No single party can read or
reassemble the key. Verify with `verify_intent`, which fetches the platform +
rail shares, verifies the rail's Ed25519 signature against a **pinned** key
(fail-closed), recombines in memory, and decrypts. **The full key never exists
on any single system.** Requires the API deployment to have End-Cell enabled.

### `client.create_intent(document_type, payload, *, split_key=True) -> CreateIntentResult`

Encrypts `payload` (any JSON-serializable value) under a freshly
generated AES-256 key and registers it. Defaults to **split-key** (2-share):
the returned `key` is **Share A** and Share B goes to the platform — neither
alone decrypts, but there is **no independent rail share** (the platform alone
could reconstruct). For independence from the platform, prefer
**`create_end_cell_intent`** above. `split_key=False` gives the legacy
single-key flow. **The full key is never sent to ValidPay.**

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
