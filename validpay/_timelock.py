"""Time-Locked Verification helpers (Patent D, MILU-PAT-004).

Pure-stdlib utilities for parsing ISO-8601 validity windows, validating
ordering, and computing client-side enforcement status. The server stores
the timestamps but never reads them; all decisions live here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from .errors import ValidPayError


def parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp, accepting ``Z`` as UTC."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def validate_time_lock(valid_from: Optional[str], valid_until: Optional[str]) -> None:
    """Raise if both are provided and ``valid_until`` is not strictly after ``valid_from``."""
    if not valid_from or not valid_until:
        return
    try:
        from_dt = parse_iso(valid_from)
        until_dt = parse_iso(valid_until)
    except ValueError as exc:
        raise ValidPayError("invalid_argument", "valid_from / valid_until must be ISO-8601") from exc
    if until_dt <= from_dt:
        raise ValidPayError("invalid_argument", "valid_until must be after valid_from")


def compute_time_lock_status(
    valid_from: Optional[str],
    valid_until: Optional[str],
) -> Optional[str]:
    """Return ``"valid" | "not_yet_valid" | "expired"``, or None if no window is set."""
    if not valid_from and not valid_until:
        return None
    now = datetime.now(timezone.utc)
    if valid_from:
        try:
            if now < parse_iso(valid_from):
                return "not_yet_valid"
        except ValueError:
            return None
    if valid_until:
        try:
            if now > parse_iso(valid_until):
                return "expired"
        except ValueError:
            return None
    return "valid"
