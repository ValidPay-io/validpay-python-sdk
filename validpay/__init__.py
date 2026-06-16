"""ValidPay Python SDK.

Public API:
    ValidPayClient — thin client for the ValidPay HTTP API
    ValidPayError  — exception type raised for all SDK / API errors
    CreateIntentResult, VerifyIntentResult — result dataclasses
    generate_key, encrypt, decrypt — low-level crypto helpers
"""

from .binding import (
    BindingComparisonResult,
    compare_binding_hashes,
    compute_binding_hash,
)
from .client import ValidPayClient
from .crypto import (
    build_aad,
    build_key_map,
    combine_key_shares,
    compute_commitment_hash,
    decrypt,
    decrypt_bytes,
    decrypt_fields,
    encrypt,
    encrypt_bytes,
    encrypt_fields,
    generate_key,
    split_key,
)
from .errors import ValidPayError
from .offline import OfflineCache, OfflineVerifyResult
from .types import CreateIntentResult, VerifyIntentResult

__all__ = [
    "ValidPayClient",
    "ValidPayError",
    "CreateIntentResult",
    "VerifyIntentResult",
    "generate_key",
    "encrypt",
    "encrypt_bytes",
    "decrypt",
    "decrypt_bytes",
    "compute_commitment_hash",
    "build_aad",
    "split_key",
    "combine_key_shares",
    "encrypt_fields",
    "build_key_map",
    "decrypt_fields",
    "compute_binding_hash",
    "compare_binding_hashes",
    "BindingComparisonResult",
    "OfflineCache",
    "OfflineVerifyResult",
]

__version__ = "1.3.0"
