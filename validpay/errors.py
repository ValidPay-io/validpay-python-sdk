from __future__ import annotations

from typing import Any, Optional


class ValidPayError(Exception):
    """Raised for all errors originating from the ValidPay SDK or API.

    Attributes:
        code: Machine-readable error code (e.g. ``"invalid_key"``,
            ``"decryption_failed"``, ``"unauthorized"``).
        message: Human-readable description.
        status: HTTP status code, when the error came from an API response.
        details: Raw error body or extra context, when available.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: Optional[int] = None,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.details = details

    def __repr__(self) -> str:
        return f"ValidPayError(code={self.code!r}, status={self.status!r}, message={self.message!r})"
