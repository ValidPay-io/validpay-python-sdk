# ValidPay Python SDK

Official Python SDK for the [ValidPay](https://validpay.io) document
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
result = client.create_intent(
    document_type="check",
    payload={"payee": "John Doe", "amount": 1500.00, "check_number": "10042"},
)
print(result.retrieval_id)  # vp_abc123def456
print(result.key)           # base64 AES-256 key — deliver out-of-band

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
`create_intent_batch` (per-item), `create_split_key_intent`, and
`create_selective_intent`.

### Split-key intents (Patent C)

Splits the AES key into two XOR shares: Share A is returned to the caller
(typically embedded in the QR code), Share B is stored server-side. Neither
share alone can decrypt the payload.

```python
result = client.create_split_key_intent(
    document_type="ssn_card",
    payload={"ssn": "123-45-6789"},
)
# result.key is Share A — pair it with Share B at verification time.

verified = client.verify_split_key_intent(result.retrieval_id, result.key)
print(verified.payload)
```

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

### Offline verification (Patent G)

`OfflineCache` lets verifiers cache intents locally and verify them without
network access. Cached entries are encrypted at rest with a caller-supplied
key.

```python
from validpay.offline import OfflineCache

cache = OfflineCache("./offline.db", cache_key="optional-aes-key-base64")
cache.store(retrieval_id="vp_abc123def456", key=result.key,
            encrypted_payload=..., issuer="Acme Bank")

verified = cache.verify_offline("vp_abc123def456", result.key)
print(verified.payload, verified.time_lock_status)
```

`OfflineCache.list_entries()`, `mark_revoked()`, `update_online_check()`, and
`get_stale_entries()` round out the cache lifecycle for verifier devices that
periodically reconcile with the live API.

## API

### `ValidPayClient(api_key, *, base_url=..., timeout=30.0, session=None)`

- `api_key` — your ValidPay API key (required for create endpoints).
- `base_url` — defaults to `https://api.validpay.io`.
- `timeout` — per-request timeout in seconds.
- `session` — optionally provide a `requests.Session` for connection
  pooling, custom adapters, or mocking in tests.

### `client.create_intent(document_type, payload) -> CreateIntentResult`

Encrypts `payload` (any JSON-serializable value) under a freshly
generated AES-256 key and registers it with ValidPay. Returns the
retrieval id and the key. **The key is never sent to ValidPay** — you
must hand it off out-of-band to whoever needs to verify the intent.

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
