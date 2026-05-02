"""Physical Medium Binding — perceptual hashing for document-QR binding.

Computes a 64-bit perceptual hash (pHash) of a "binding zone" image.
The hash is robust to minor lighting/angle variations but changes
significantly when the underlying paper stock is different.

Patent G (MILU-PAT-007).
"""
from __future__ import annotations

from .errors import ValidPayError


def compute_binding_hash(
    image_bytes: bytes,
    *,
    hash_size: int = 8,
) -> str:
    """Compute a perceptual hash of a binding zone image.

    Uses a DCT-based perceptual hash (pHash) algorithm:
    1. Convert to grayscale (if not already)
    2. Resize to (hash_size*4) x (hash_size*4)
    3. Apply DCT
    4. Extract top-left hash_size x hash_size coefficients
    5. Compute median and threshold to produce binary hash

    Args:
        image_bytes: Raw bytes of the binding zone image (JPEG/PNG).
        hash_size: Size of the hash grid. 8 produces a 64-bit hash.

    Returns:
        Hex string of the perceptual hash (16 hex chars for 64-bit).

    Raises:
        ValidPayError: If the image cannot be processed.
    """
    try:
        from PIL import Image
        import numpy as np
    except ImportError:
        raise ValidPayError(
            "missing_dependency",
            "Physical Medium Binding requires 'Pillow' and 'numpy'. "
            "Install with: pip install validpay[binding]",
        )

    try:
        from scipy.fft import dct
    except ImportError:
        raise ValidPayError(
            "missing_dependency",
            "Physical Medium Binding requires 'scipy'. "
            "Install with: pip install validpay[binding]",
        )

    import io

    try:
        img = Image.open(io.BytesIO(image_bytes))
    except Exception as e:
        raise ValidPayError("invalid_image", f"Cannot open image: {e}")

    img = img.convert("L")

    resize_dim = hash_size * 4
    img = img.resize((resize_dim, resize_dim), Image.Resampling.LANCZOS)

    pixels = np.array(img, dtype=np.float64)
    dct_result = dct(dct(pixels, axis=0, norm="ortho"), axis=1, norm="ortho")

    low_freq = dct_result[:hash_size, :hash_size]

    flat = low_freq.flatten()
    # Exclude the DC component for median calculation — it captures overall
    # brightness, which leaks across all bits and biases the threshold.
    median_val = np.median(flat[1:])

    bits = (flat > median_val).astype(np.uint8)

    hash_int = 0
    for bit in bits:
        hash_int = (hash_int << 1) | int(bit)

    hex_length = (hash_size * hash_size) // 4
    return format(hash_int, f"0{hex_length}x")


def compare_binding_hashes(
    hash_a: str,
    hash_b: str,
    *,
    threshold: int = 10,
) -> "BindingComparisonResult":
    """Compare two perceptual hashes and determine if they match.

    Uses Hamming distance — the number of bit positions where the two
    hashes differ. A lower distance means more similar images.

    Args:
        hash_a: Hex string of the first perceptual hash.
        hash_b: Hex string of the second perceptual hash.
        threshold: Maximum Hamming distance to consider a match.
            Default 10 (out of 64 bits) allows ~15% variation.

    Returns:
        BindingComparisonResult with match status and distance.
    """
    if len(hash_a) != len(hash_b):
        raise ValidPayError(
            "invalid_argument",
            f"Hash lengths differ: {len(hash_a)} vs {len(hash_b)}",
        )

    int_a = int(hash_a, 16)
    int_b = int(hash_b, 16)
    xor = int_a ^ int_b

    distance = bin(xor).count("1")

    return BindingComparisonResult(
        matches=distance <= threshold,
        hamming_distance=distance,
        threshold=threshold,
        hash_bits=len(hash_a) * 4,
    )


class BindingComparisonResult:
    """Result of comparing two binding zone perceptual hashes."""

    def __init__(
        self,
        matches: bool,
        hamming_distance: int,
        threshold: int,
        hash_bits: int,
    ):
        self.matches = matches
        self.hamming_distance = hamming_distance
        self.threshold = threshold
        self.hash_bits = hash_bits
        self.similarity_pct = round(
            100 * (1 - hamming_distance / hash_bits), 1
        )

    def __repr__(self) -> str:
        status = "MATCH" if self.matches else "MISMATCH"
        return (
            f"BindingComparisonResult({status}, "
            f"distance={self.hamming_distance}/{self.hash_bits}, "
            f"similarity={self.similarity_pct}%, "
            f"threshold={self.threshold})"
        )
