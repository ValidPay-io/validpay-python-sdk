"""ValidPay Python SDK.

Public API:
    ValidPayClient — thin client for the ValidPay HTTP API
    ValidPayError  — exception type raised for all SDK / API errors
    CreateIntentResult, VerifyIntentResult — result dataclasses
    generate_key, encrypt, decrypt — low-level crypto helpers
"""

from .client import ValidPayClient
from .crypto import (
    combine_key_shares,
    compute_commitment_hash,
    decrypt,
    encrypt,
    generate_key,
    split_key,
)
from .errors import ValidPayError
from .types import CreateIntentResult, VerifyIntentResult

__all__ = [
    "ValidPayClient",
    "ValidPayError",
    "CreateIntentResult",
    "VerifyIntentResult",
    "generate_key",
    "encrypt",
    "decrypt",
    "compute_commitment_hash",
    "split_key",
    "combine_key_shares",
]

__version__ = "0.1.0"
