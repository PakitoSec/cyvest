"""
ULID generator for stable investigation identities.

Cyvest uses ULIDs to tag investigations and to stamp provenance on Check↔Observable
links. This implementation is dependency-free and follows the 26-char Crockford
Base32 ULID encoding.
"""

from __future__ import annotations

import secrets
import time

_CROCKFORD_BASE32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def generate_ulid(*, timestamp_ms: int | None = None) -> str:
    """
    Generate a ULID string.

    Args:
        timestamp_ms: Optional millisecond timestamp (48-bit). Defaults to current time.
    """
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)
    if timestamp_ms < 0 or timestamp_ms >= (1 << 48):
        raise ValueError("timestamp_ms must fit in 48 bits")

    randomness = secrets.token_bytes(10)  # 80 bits
    value = (timestamp_ms << 80) | int.from_bytes(randomness, "big")

    chars: list[str] = []
    for _ in range(26):
        chars.append(_CROCKFORD_BASE32_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))
