"""ValidPay Python SDK.

Public API:
    ValidPayClient — thin client for the ValidPay HTTP API
    ValidPayError  — exception type raised for all SDK / API errors
    CreateIntentResult, VerifyIntentResult — result dataclasses
    generate_key, encrypt, decrypt — low-level crypto helpers
"""

from .client import ValidPayClient
from .crypto import decrypt, encrypt, generate_key
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
]

__version__ = "0.1.0"
