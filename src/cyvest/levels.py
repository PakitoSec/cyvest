"""
Level enumeration and scoring logic for Cyvest.

This module defines the security level classification system and the algorithm
for determining levels from scores.
"""

from __future__ import annotations

from decimal import Decimal
from enum import Enum

# Ordering mapping for Level comparisons
_LEVEL_ORDER = {
    "NONE": 0,
    "TRUSTED": 1,
    "INFO": 2,
    "SAFE": 3,
    "NOTABLE": 4,
    "SUSPICIOUS": 5,
    "MALICIOUS": 6,
}


class Level(str, Enum):
    """
    Security level classification for checks, observables, and threat intelligence.

    Levels are ordered from lowest (NONE) to highest (MALICIOUS) severity.
    """

    NONE = "NONE"
    TRUSTED = "TRUSTED"
    INFO = "INFO"
    SAFE = "SAFE"
    NOTABLE = "NOTABLE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Level):
            return NotImplemented
        return _LEVEL_ORDER[self.value] < _LEVEL_ORDER[other.value]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Level):
            return NotImplemented
        return self.value == other.value

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Level):
            return NotImplemented
        return _LEVEL_ORDER[self.value] <= _LEVEL_ORDER[other.value]

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Level):
            return NotImplemented
        return _LEVEL_ORDER[self.value] > _LEVEL_ORDER[other.value]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Level):
            return NotImplemented
        return _LEVEL_ORDER[self.value] >= _LEVEL_ORDER[other.value]

    def __hash__(self) -> int:
        return hash(self.value)

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"Level.{self.name}"


def normalize_level(level: Level | str) -> Level:
    """
    Normalize a level input to the Level enum.

    Accepts either a Level enum instance or a case-insensitive string name
    corresponding to a Level member.

    Args:
        level: Level enum or string representation (e.g., "malicious")

    Returns:
        The corresponding Level enum member

    Raises:
        ValueError: If the string does not match a Level name
        TypeError: If the input type is unsupported
    """
    if isinstance(level, Level):
        return level
    if isinstance(level, str):
        try:
            return Level[level.upper()]
        except KeyError as exc:
            raise ValueError(f"Invalid level name: {level}") from exc
    raise TypeError(f"Expected Level or str for level, got {type(level).__name__}")


def get_level_from_score(score: Decimal) -> Level:
    """
    Calculate the security level from a numeric score.

    Algorithm:
    - score < 0.0  -> TRUSTED
    - score == 0.0 -> INFO
    - score < 3.0  -> NOTABLE
    - score < 5.0  -> SUSPICIOUS
    - score >= 5.0 -> MALICIOUS

    Args:
        score: The numeric score to evaluate

    Returns:
        The appropriate Level based on the score
    """
    if score < Decimal("0.0"):
        return Level.TRUSTED
    if score == Decimal("0.0"):
        return Level.INFO
    if score < Decimal("3.0"):
        return Level.NOTABLE
    if score < Decimal("5.0"):
        return Level.SUSPICIOUS
    if score >= Decimal("5.0"):
        return Level.MALICIOUS
    return Level.NONE


# Color mapping for display purposes
LEVEL_COLORS = {
    Level.NONE: "white",
    Level.TRUSTED: "green",
    Level.INFO: "cyan",
    Level.SAFE: "bright_green",
    Level.NOTABLE: "yellow",
    Level.SUSPICIOUS: "orange3",
    Level.MALICIOUS: "red",
}


def get_color_level(level: Level | str) -> str:
    """
    Get the color associated with a level for display purposes.

    Args:
        level: Level enum or level name string

    Returns:
        Color name for rich console display
    """
    if isinstance(level, str):
        try:
            level = normalize_level(level)
        except (TypeError, ValueError):
            return "white"
    return LEVEL_COLORS.get(level, "white")


def get_color_score(score: Decimal | float) -> str:
    """
    Get the color associated with a score for display purposes.

    Args:
        score: The numeric score

    Returns:
        Color name for rich console display
    """
    if not isinstance(score, Decimal):
        score = Decimal(str(score))
    level = get_level_from_score(score)
    return get_color_level(level)
