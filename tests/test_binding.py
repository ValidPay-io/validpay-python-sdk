"""Tests for Physical Medium Binding (Patent G)."""
from __future__ import annotations

import pytest


def _make_test_image(width=200, height=200, color=128, noise_seed=42):
    """Create a structured grayscale test image: deterministic blurred noise + small per-test noise.

    A pure-noise image averages out to uniform gray after the pHash
    downsample, leaving DCT coefficients near zero — at which point tiny
    noise differences flip bits randomly. We build a *deterministic*
    low-frequency base (blurred Gaussian noise, fixed seed 0) so every
    one of the 64 low-frequency DCT cells has stable amplitude well
    above the noise floor. The ``noise_seed`` then adds a small
    perturbation on top to simulate camera/lighting variation.
    """
    from PIL import Image
    from scipy.ndimage import gaussian_filter
    import numpy as np

    base_rng = np.random.RandomState(0)
    base = base_rng.normal(128, 60, (height, width))
    base = gaussian_filter(base, sigma=12)

    noise_rng = np.random.RandomState(noise_seed)
    noise = noise_rng.normal(0, 2, (height, width))
    pixels = np.clip(base + noise, 0, 255).astype(np.uint8)
    img = Image.fromarray(pixels, mode="L")
    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_different_image(width=200, height=200):
    """Create a clearly different image (different paper stock)."""
    from PIL import Image
    import numpy as np

    rng = np.random.RandomState(99)
    # Different frequency mix + heavy noise — visibly different texture.
    yy, xx = np.meshgrid(
        np.linspace(0, np.pi * 5, height),
        np.linspace(0, np.pi * 5, width),
        indexing="ij",
    )
    pattern = 160 + 50 * np.sin(yy + xx) - 30 * np.cos(3 * xx)
    pixels = np.clip(
        pattern + rng.normal(0, 30, (height, width)),
        0, 255,
    ).astype(np.uint8)
    img = Image.fromarray(pixels, mode="L")
    import io
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


class TestComputeBindingHash:
    def test_returns_16_char_hex(self):
        from validpay.binding import compute_binding_hash
        img = _make_test_image()
        h = compute_binding_hash(img)
        assert len(h) == 16
        assert all(c in "0123456789abcdef" for c in h)

    def test_same_image_same_hash(self):
        from validpay.binding import compute_binding_hash
        img = _make_test_image()
        assert compute_binding_hash(img) == compute_binding_hash(img)

    def test_different_image_different_hash(self):
        from validpay.binding import compute_binding_hash
        img_a = _make_test_image(noise_seed=42)
        img_b = _make_different_image()
        assert compute_binding_hash(img_a) != compute_binding_hash(img_b)

    def test_slight_variation_similar_hash(self):
        """Minor noise variation should produce a similar (not identical) hash."""
        from validpay.binding import compute_binding_hash, compare_binding_hashes
        img_a = _make_test_image(noise_seed=42)
        img_b = _make_test_image(noise_seed=43)
        hash_a = compute_binding_hash(img_a)
        hash_b = compute_binding_hash(img_b)
        result = compare_binding_hashes(hash_a, hash_b, threshold=15)
        assert result.hamming_distance < 25

    def test_invalid_image_raises(self):
        from validpay.binding import compute_binding_hash
        from validpay.errors import ValidPayError
        with pytest.raises(ValidPayError) as exc:
            compute_binding_hash(b"not an image")
        assert exc.value.code == "invalid_image"

    def test_color_image_works(self):
        """Color images should be converted to grayscale automatically."""
        from PIL import Image
        import numpy as np
        import io
        from validpay.binding import compute_binding_hash

        rng = np.random.RandomState(42)
        pixels = rng.randint(0, 255, (200, 200, 3), dtype=np.uint8)
        img = Image.fromarray(pixels, mode="RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        h = compute_binding_hash(buf.getvalue())
        assert len(h) == 16


class TestCompareBindingHashes:
    def test_identical_hashes_match(self):
        from validpay.binding import compare_binding_hashes
        result = compare_binding_hashes("abcdef0123456789", "abcdef0123456789")
        assert result.matches is True
        assert result.hamming_distance == 0
        assert result.similarity_pct == 100.0

    def test_very_different_hashes_mismatch(self):
        from validpay.binding import compare_binding_hashes
        result = compare_binding_hashes("0000000000000000", "ffffffffffffffff")
        assert result.matches is False
        assert result.hamming_distance == 64

    def test_threshold_boundary(self):
        from validpay.binding import compare_binding_hashes
        hash_a = "0000000000000000"
        # 0x03FF = 10 bits set
        hash_b = "00000000000003ff"
        result = compare_binding_hashes(hash_a, hash_b, threshold=10)
        assert result.matches is True
        assert result.hamming_distance == 10

    def test_custom_threshold(self):
        from validpay.binding import compare_binding_hashes
        result = compare_binding_hashes("0000000000000000", "00000000000003ff", threshold=5)
        assert result.matches is False

    def test_mismatched_lengths_raises(self):
        from validpay.binding import compare_binding_hashes
        from validpay.errors import ValidPayError
        with pytest.raises(ValidPayError, match="Hash lengths differ"):
            compare_binding_hashes("abcd", "abcdef")

    def test_repr_shows_status(self):
        from validpay.binding import compare_binding_hashes
        result = compare_binding_hashes("abcdef0123456789", "abcdef0123456789")
        assert "MATCH" in repr(result)


class TestClientBinding:
    def test_create_bound_intent_adds_binding_hash(self):
        """Verify that create_bound_intent adds _binding_hash to the payload."""
        from unittest.mock import patch, MagicMock
        from validpay import ValidPayClient

        client = ValidPayClient(api_key="test_key")
        img = _make_test_image()

        with patch.object(client, "create_intent") as mock_create:
            mock_create.return_value = MagicMock(
                retrieval_id="vp_test123",
                key="dGVzdGtleQ==",
            )
            client.create_bound_intent(
                document_type="check",
                payload={"amount": 100, "payee": "John"},
                binding_zone_image=img,
            )
            call_args = mock_create.call_args
            sent_payload = call_args[1]["payload"] if "payload" in call_args[1] else call_args[0][1]
            assert "_binding_hash" in sent_payload
            assert "_binding_threshold" in sent_payload
            assert len(sent_payload["_binding_hash"]) == 16
            assert sent_payload["_binding_threshold"] == 10

    def test_create_bound_intent_with_split_key(self):
        from unittest.mock import patch, MagicMock
        from validpay import ValidPayClient

        client = ValidPayClient(api_key="test_key")
        img = _make_test_image()

        with patch.object(client, "create_split_key_intent") as mock_create:
            mock_create.return_value = MagicMock(
                retrieval_id="vp_test123",
                key="dGVzdGtleQ==",
            )
            client.create_bound_intent(
                document_type="check",
                payload={"amount": 100},
                binding_zone_image=img,
                split_key=True,
            )
            mock_create.assert_called_once()

    def test_create_bound_intent_with_selective_disclosure(self):
        from unittest.mock import patch, MagicMock
        from validpay import ValidPayClient

        client = ValidPayClient(api_key="test_key")
        img = _make_test_image()

        with patch.object(client, "create_selective_intent") as mock_create:
            mock_create.return_value = MagicMock(
                retrieval_id="vp_test123",
                key="dGVzdGtleQ==",
            )
            client.create_bound_intent(
                document_type="check",
                payload={"amount": 100},
                binding_zone_image=img,
                selective_disclosure=True,
                disclosure_policy={"bank": ["amount"]},
            )
            mock_create.assert_called_once()

    def test_verify_binding_matches_same_image(self):
        from validpay import ValidPayClient
        from validpay.binding import compute_binding_hash

        img = _make_test_image()
        h = compute_binding_hash(img)
        payload = {"amount": 100, "_binding_hash": h, "_binding_threshold": 10}

        result = ValidPayClient.verify_binding(payload, img)
        assert result.matches is True
        assert result.hamming_distance == 0

    def test_verify_binding_rejects_different_image(self):
        from validpay import ValidPayClient
        from validpay.binding import compute_binding_hash

        img_original = _make_test_image(noise_seed=42)
        img_different = _make_different_image()
        h = compute_binding_hash(img_original)
        payload = {"amount": 100, "_binding_hash": h, "_binding_threshold": 10}

        result = ValidPayClient.verify_binding(payload, img_different)
        assert result.matches is False
        assert result.hamming_distance > 10

    def test_verify_binding_no_binding_raises(self):
        from validpay import ValidPayClient
        from validpay.errors import ValidPayError

        payload = {"amount": 100}
        img = _make_test_image()

        with pytest.raises(ValidPayError) as exc:
            ValidPayClient.verify_binding(payload, img)
        assert exc.value.code == "no_binding"
