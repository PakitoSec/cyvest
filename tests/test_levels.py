"""
Tests for the levels module.
"""

from decimal import Decimal

import pytest

from cyvest.levels import Level, get_color_level, get_color_score, get_level_from_score, normalize_level


def test_level_ordering() -> None:
    """Test that Level enum has correct ordering."""
    assert Level.NONE < Level.TRUSTED
    assert Level.TRUSTED < Level.INFO
    assert Level.INFO < Level.SAFE
    assert Level.SAFE < Level.NOTABLE
    assert Level.NOTABLE < Level.SUSPICIOUS
    assert Level.SUSPICIOUS < Level.MALICIOUS


def test_level_equality() -> None:
    """Test Level equality."""
    assert Level.INFO == Level.INFO
    assert Level.MALICIOUS == Level.MALICIOUS
    assert Level.INFO != Level.MALICIOUS


def test_get_level_from_score() -> None:
    """Test score to level conversion."""
    assert get_level_from_score(Decimal("-1.0")) == Level.TRUSTED
    assert get_level_from_score(Decimal("0.0")) == Level.INFO
    assert get_level_from_score(Decimal("2.5")) == Level.NOTABLE
    assert get_level_from_score(Decimal("4.0")) == Level.SUSPICIOUS
    assert get_level_from_score(Decimal("5.0")) == Level.MALICIOUS
    assert get_level_from_score(Decimal("10.0")) == Level.MALICIOUS


def test_get_color_level() -> None:
    """Test color mapping for levels."""
    assert get_color_level(Level.MALICIOUS) == "red"
    assert get_color_level(Level.SUSPICIOUS) == "orange3"
    assert get_color_level(Level.INFO) == "cyan"
    # Test with string
    assert get_color_level("MALICIOUS") == "red"


def test_get_color_score() -> None:
    """Test color mapping for scores."""
    # Should return color based on level derived from score
    assert get_color_score(Decimal("10.0")) == "red"  # MALICIOUS
    assert get_color_score(Decimal("0.0")) == "cyan"  # INFO
    # Test with float
    assert get_color_score(5.0) == "red"  # MALICIOUS


def test_normalize_level_accepts_strings() -> None:
    """Ensure normalize_level handles enums and case-insensitive strings."""
    assert normalize_level(Level.SAFE) is Level.SAFE
    assert normalize_level("safe") is Level.SAFE
    assert normalize_level("MALICIOUS") is Level.MALICIOUS
    with pytest.raises(ValueError):
        normalize_level("unknown")
