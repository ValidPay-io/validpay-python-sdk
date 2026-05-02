"""Offline Verification — local cache and offline-capable verification.

Provides a local cache of previously-verified intents that can be used
for offline re-verification. The cache is stored as an encrypted JSON
file on disk.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .crypto import (
    combine_key_shares,
    compute_commitment_hash,
    decrypt,
    decrypt_fields,
    encrypt,
    generate_key,
)
from .errors import ValidPayError


class OfflineCache:
    """Encrypted local cache for offline verification.

    Stores previously-verified intent data in an AES-256-GCM encrypted
    file. Each entry contains the encrypted payload, key, and metadata
    needed to re-verify offline.

    Usage::

        cache = OfflineCache("/path/to/cache.vpoc")

        # After online verification, cache the result:
        cache.store(retrieval_id, key, encrypted_payload, ...)

        # Later, verify offline:
        result = cache.verify_offline(retrieval_id, key)
    """

    def __init__(self, cache_path: str, *, cache_key: Optional[str] = None) -> None:
        """Initialize the offline cache.

        Args:
            cache_path: Path to the cache file (.vpoc = ValidPay Offline Cache).
            cache_key: AES-256 key for encrypting the cache file. If not
                provided, a new key is generated and stored alongside the
                cache as ``{cache_path}.key``. For production, pass an
                application-managed key.
        """
        self.cache_path = Path(cache_path)
        self._key_path = Path(f"{cache_path}.key")

        if cache_key:
            self._cache_key = cache_key
        elif self._key_path.exists():
            self._cache_key = self._key_path.read_text().strip()
        else:
            self._cache_key = generate_key()
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_text(self._cache_key)
            try:
                os.chmod(self._key_path, 0o600)
            except (OSError, NotImplementedError):
                # POSIX permissions don't apply on some platforms (Windows).
                pass

        self._entries: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if not self.cache_path.exists():
            self._entries = {}
            return
        try:
            encrypted = self.cache_path.read_text()
            plaintext = decrypt(encrypted, self._cache_key)
            self._entries = json.loads(plaintext)
        except Exception:
            # Corrupted cache — start fresh rather than blocking the user.
            self._entries = {}

    def _save(self) -> None:
        plaintext = json.dumps(self._entries)
        encrypted = encrypt(plaintext, self._cache_key)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(encrypted)

    def store(
        self,
        retrieval_id: str,
        key: str,
        encrypted_payload: str,
        *,
        issuer: Optional[str] = None,
        commitment_hash: Optional[str] = None,
        split_key: bool = False,
        fragment_b: Optional[str] = None,
        selective_disclosure: bool = False,
        encrypted_key_map: Optional[str] = None,
        disclosure_policy: Optional[str] = None,
        status: str = "active",
    ) -> None:
        """Store a verified intent for offline access.

        Call this after a successful online verification to cache the
        intent data locally.
        """
        now = time.time()
        self._entries[retrieval_id] = {
            "key": key,
            "encrypted_payload": encrypted_payload,
            "issuer": issuer,
            "commitment_hash": commitment_hash,
            "split_key": split_key,
            "fragment_b": fragment_b,
            "selective_disclosure": selective_disclosure,
            "encrypted_key_map": encrypted_key_map,
            "disclosure_policy": disclosure_policy,
            "status": status,
            "cached_at": now,
            "last_online_check": now,
        }
        self._save()

    def has(self, retrieval_id: str) -> bool:
        return retrieval_id in self._entries

    def verify_offline(self, retrieval_id: str, key: str) -> "OfflineVerifyResult":
        """Verify an intent using only the local cache.

        Raises:
            ValidPayError: If the intent is not in the cache, decryption
                fails, or the commitment hash doesn't match.
        """
        entry = self._entries.get(retrieval_id)
        if not entry:
            raise ValidPayError(
                "not_cached",
                f"Intent {retrieval_id} is not in the offline cache. "
                "It must be verified online at least once before offline "
                "verification is available.",
            )

        if entry.get("status") == "revoked":
            return OfflineVerifyResult(
                retrieval_id=retrieval_id,
                payload={},
                issuer=entry.get("issuer"),
                status="revoked",
                integrity_verified=False,
                offline=True,
                cached_at=entry.get("cached_at"),
                last_online_check=entry.get("last_online_check"),
                stale=self._is_stale(entry),
            )

        decryption_key = key
        if entry.get("split_key") and entry.get("fragment_b"):
            decryption_key = combine_key_shares(key, entry["fragment_b"])

        encrypted_payload = entry.get("encrypted_payload")
        if not encrypted_payload:
            raise ValidPayError(
                "cache_corrupted",
                "Cached entry has no encrypted payload.",
            )

        integrity_verified = False

        if entry.get("selective_disclosure") and entry.get("encrypted_key_map"):
            key_map_json = decrypt(entry["encrypted_key_map"], decryption_key)
            key_map = json.loads(key_map_json)
            encrypted_fields = json.loads(encrypted_payload)
            field_keys = key_map.get("full", {})
            payload: Any = decrypt_fields(encrypted_fields, field_keys)
        else:
            plaintext = decrypt(encrypted_payload, decryption_key)
            try:
                payload = json.loads(plaintext)
            except json.JSONDecodeError:
                payload = plaintext

            if entry.get("commitment_hash"):
                actual_hash = compute_commitment_hash(plaintext)
                if actual_hash == entry["commitment_hash"]:
                    integrity_verified = True
                else:
                    raise ValidPayError(
                        "integrity_failure",
                        "OFFLINE INTEGRITY CHECK FAILED — the cached payload "
                        "does not match the commitment hash. Cache may be corrupted.",
                    )

        return OfflineVerifyResult(
            retrieval_id=retrieval_id,
            payload=payload,
            issuer=entry.get("issuer"),
            status="active",
            integrity_verified=integrity_verified,
            offline=True,
            cached_at=entry.get("cached_at"),
            last_online_check=entry.get("last_online_check"),
            stale=self._is_stale(entry),
        )

    def mark_revoked(self, retrieval_id: str) -> None:
        """Mark a cached intent as revoked (discovered during sync)."""
        if retrieval_id in self._entries:
            self._entries[retrieval_id]["status"] = "revoked"
            self._save()

    def update_online_check(self, retrieval_id: str) -> None:
        """Update last_online_check after a successful online sync."""
        if retrieval_id in self._entries:
            self._entries[retrieval_id]["last_online_check"] = time.time()
            self._save()

    def get_stale_entries(self, max_age_hours: float = 24) -> List[str]:
        """Get retrieval IDs of entries that haven't been checked online recently."""
        cutoff = time.time() - (max_age_hours * 3600)
        return [
            rid
            for rid, entry in self._entries.items()
            if entry.get("last_online_check", 0) < cutoff
        ]

    def remove(self, retrieval_id: str) -> None:
        self._entries.pop(retrieval_id, None)
        self._save()

    def list_entries(self) -> List[Dict[str, Any]]:
        """List cached entries with metadata. Decryption keys are not exposed."""
        return [
            {
                "retrieval_id": rid,
                "issuer": entry.get("issuer"),
                "status": entry.get("status"),
                "cached_at": entry.get("cached_at"),
                "last_online_check": entry.get("last_online_check"),
                "stale": self._is_stale(entry),
                "split_key": entry.get("split_key", False),
                "selective_disclosure": entry.get("selective_disclosure", False),
            }
            for rid, entry in self._entries.items()
        ]

    def _is_stale(self, entry: Dict[str, Any], max_age_hours: float = 24) -> bool:
        last_check = entry.get("last_online_check", 0)
        return (time.time() - last_check) > (max_age_hours * 3600)

    @property
    def size(self) -> int:
        return len(self._entries)


class OfflineVerifyResult:
    """Result of an offline verification."""

    def __init__(
        self,
        retrieval_id: str,
        payload: Any,
        issuer: Optional[str],
        status: str,
        integrity_verified: bool,
        offline: bool,
        cached_at: Optional[float],
        last_online_check: Optional[float],
        stale: bool,
    ) -> None:
        self.retrieval_id = retrieval_id
        self.payload = payload
        self.issuer = issuer
        self.status = status
        self.integrity_verified = integrity_verified
        self.offline = offline
        self.cached_at = cached_at
        self.last_online_check = last_online_check
        self.stale = stale

    def __repr__(self) -> str:
        stale_str = " [STALE]" if self.stale else ""
        return (
            f"OfflineVerifyResult(status={self.status}, "
            f"integrity={self.integrity_verified}, "
            f"offline={self.offline}{stale_str})"
        )
