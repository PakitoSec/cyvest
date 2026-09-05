"""
ULID generator for stable investigation identities.

Cyvest uses ULIDs to tag investigations and as the ``seq`` of every fact — the tiebreaker of the
merge law. This implementation is dependency-free and follows the 26-char Crockford Base32 ULID
encoding, **monotonic within a process**: two ULIDs minted in the same millisecond compare in the
order they were minted, as the ULID specification's monotonic mode prescribes. Without that, two
re-assertions of one fact inside a millisecond — one batch applying operations in sequence — would
be ordered by their random bits, and "freshest wins" would become a coin toss.
"""

from __future__ import annotations

import secrets
import threading
import time

_CROCKFORD_BASE32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_RANDOM_BITS = 80
_RANDOM_MASK = (1 << _RANDOM_BITS) - 1

_lock = threading.Lock()
_last: tuple[int, int] = (-1, 0)  # (timestamp_ms, randomness) of the last ULID minted here


def _randomness(timestamp_ms: int) -> int:
    """Fresh random bits for a new millisecond; the previous value plus one within the same one."""
    global _last
    with _lock:
        last_ms, last_random = _last
        if timestamp_ms == last_ms and last_random < _RANDOM_MASK:
            randomness = last_random + 1
        else:
            randomness = int.from_bytes(secrets.token_bytes(10), "big")
        _last = (timestamp_ms, randomness)
        return randomness


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

    value = (timestamp_ms << _RANDOM_BITS) | _randomness(timestamp_ms)

    chars: list[str] = []
    for _ in range(26):
        chars.append(_CROCKFORD_BASE32_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


_DECODE_TABLE = {char: index for index, char in enumerate(_CROCKFORD_BASE32_ALPHABET)}


def decode_ulid_timestamp(ulid: str) -> int:
    """
    Extract the millisecond timestamp embedded in a ULID.

    Used to check that a fact's ``asserted_at`` agrees with the ordering of its ``seq``.
    """
    if len(ulid) != 26:
        raise ValueError("ULID must be 26 characters long")
    value = 0
    for char in ulid[:10]:
        digit = _DECODE_TABLE.get(char.upper())
        if digit is None:
            raise ValueError(f"Invalid ULID character: {char!r}")
        value = (value << 5) | digit
    # The first 10 characters carry 50 bits: the 48-bit timestamp plus 2 zero padding bits.
    return value & ((1 << 48) - 1)
