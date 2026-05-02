"""Tests for Offline Verification."""
from __future__ import annotations

import json
import os
import tempfile
import time

import pytest

from validpay.crypto import compute_commitment_hash, encrypt, generate_key
from validpay.errors import ValidPayError
from validpay.offline import OfflineCache


@pytest.fixture
def cache_dir():
    """Create a temporary directory for cache files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def cache(cache_dir):
    """Create an OfflineCache instance."""
    return OfflineCache(os.path.join(cache_dir, "test.vpoc"))


@pytest.fixture
def sample_intent():
    """Create a sample intent with encrypted payload."""
    key = generate_key()
    payload = {"amount": 5000, "payee": "John Doe", "date": "2026-05-01"}
    plaintext = json.dumps(payload)
    encrypted = encrypt(plaintext, key)
    commitment_hash = compute_commitment_hash(plaintext)
    return {
        "retrieval_id": "vp_test_offline_001",
        "key": key,
        "encrypted_payload": encrypted,
        "plaintext": plaintext,
        "payload": payload,
        "commitment_hash": commitment_hash,
    }


class TestOfflineCacheBasics:
    def test_create_new_cache(self, cache):
        assert cache.size == 0

    def test_store_and_has(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
            issuer="Test Bank",
            commitment_hash=sample_intent["commitment_hash"],
        )
        assert cache.has(sample_intent["retrieval_id"])
        assert not cache.has("vp_nonexistent")

    def test_persistence_across_instances(self, cache_dir, sample_intent):
        path = os.path.join(cache_dir, "persist.vpoc")
        cache1 = OfflineCache(path)
        cache1.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
        )
        key = cache1._cache_key
        cache2 = OfflineCache(path, cache_key=key)
        assert cache2.has(sample_intent["retrieval_id"])

    def test_remove_entry(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
        )
        cache.remove(sample_intent["retrieval_id"])
        assert not cache.has(sample_intent["retrieval_id"])

    def test_list_entries(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
            issuer="Test Bank",
        )
        entries = cache.list_entries()
        assert len(entries) == 1
        assert entries[0]["retrieval_id"] == sample_intent["retrieval_id"]
        assert entries[0]["issuer"] == "Test Bank"
        assert "key" not in entries[0]


class TestOfflineVerification:
    def test_verify_offline_success(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
            issuer="Test Bank",
            commitment_hash=sample_intent["commitment_hash"],
        )
        result = cache.verify_offline(
            sample_intent["retrieval_id"],
            sample_intent["key"],
        )
        assert result.status == "active"
        assert result.payload == sample_intent["payload"]
        assert result.integrity_verified is True
        assert result.offline is True
        assert result.issuer == "Test Bank"

    def test_verify_offline_not_cached_raises(self, cache):
        with pytest.raises(ValidPayError) as exc:
            cache.verify_offline("vp_nonexistent", "somekey")
        assert exc.value.code == "not_cached"

    def test_verify_offline_revoked(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
            status="revoked",
        )
        result = cache.verify_offline(
            sample_intent["retrieval_id"],
            sample_intent["key"],
        )
        assert result.status == "revoked"
        assert result.payload == {}

    def test_verify_offline_wrong_key_raises(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
        )
        wrong_key = generate_key()
        with pytest.raises(Exception):
            cache.verify_offline(sample_intent["retrieval_id"], wrong_key)

    def test_mark_revoked(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
        )
        cache.mark_revoked(sample_intent["retrieval_id"])
        result = cache.verify_offline(
            sample_intent["retrieval_id"],
            sample_intent["key"],
        )
        assert result.status == "revoked"

    def test_integrity_failure_raises(self, cache, sample_intent):
        # Store with wrong commitment hash — decryption succeeds but the
        # hash check fails.
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
            commitment_hash="a" * 64,
        )
        with pytest.raises(ValidPayError) as exc:
            cache.verify_offline(
                sample_intent["retrieval_id"],
                sample_intent["key"],
            )
        assert exc.value.code == "integrity_failure"


class TestStaleness:
    def test_fresh_entry_not_stale(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
        )
        result = cache.verify_offline(
            sample_intent["retrieval_id"],
            sample_intent["key"],
        )
        assert result.stale is False

    def test_old_entry_is_stale(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
        )
        cache._entries[sample_intent["retrieval_id"]]["last_online_check"] = (
            time.time() - 48 * 3600
        )
        cache._save()
        result = cache.verify_offline(
            sample_intent["retrieval_id"],
            sample_intent["key"],
        )
        assert result.stale is True

    def test_get_stale_entries(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
        )
        assert cache.get_stale_entries() == []
        cache._entries[sample_intent["retrieval_id"]]["last_online_check"] = (
            time.time() - 48 * 3600
        )
        cache._save()
        assert sample_intent["retrieval_id"] in cache.get_stale_entries()

    def test_update_online_check_clears_staleness(self, cache, sample_intent):
        cache.store(
            sample_intent["retrieval_id"],
            sample_intent["key"],
            sample_intent["encrypted_payload"],
        )
        cache._entries[sample_intent["retrieval_id"]]["last_online_check"] = (
            time.time() - 48 * 3600
        )
        cache._save()
        assert cache.get_stale_entries() != []
        cache.update_online_check(sample_intent["retrieval_id"])
        assert cache.get_stale_entries() == []
