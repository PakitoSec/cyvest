"""
Tests for the keys module.
"""

from cyvest.keys import (
    generate_check_key,
    generate_enrichment_key,
    generate_observable_key,
    generate_tag_key,
    generate_threat_intel_key,
    get_tag_ancestors,
    is_tag_child_of,
    is_tag_descendant_of,
    parse_key_type,
    parse_observable_key,
    validate_key,
)


def test_generate_observable_key() -> None:
    """Test observable key generation."""
    key = generate_observable_key("url", "https://example.com")
    assert key.startswith("obs:")
    assert "url" in key
    # Same inputs should produce same key
    key2 = generate_observable_key("url", "https://example.com")
    assert key == key2
    # Different values should produce different keys
    key3 = generate_observable_key("url", "https://different.com")
    assert key != key3


def test_generate_check_key() -> None:
    """Test check key generation."""
    key = generate_check_key("malware_check")
    assert key.startswith("chk:")
    assert "malware_check" in key


def test_generate_threat_intel_key() -> None:
    """Test threat intel key generation."""
    obs_key = "obs:url:example.com"
    key = generate_threat_intel_key("virustotal", obs_key)
    assert key.startswith("ti:")
    assert "virustotal" in key
    assert obs_key in key


def test_generate_enrichment_key() -> None:
    """Test enrichment key generation."""
    key = generate_enrichment_key("email_headers")
    assert key.startswith("enr:")
    assert "email_headers" in key
    # With context
    key_ctx = generate_enrichment_key("email_headers", "context_data")
    assert key_ctx.startswith("enr:")
    assert key != key_ctx


def test_generate_tag_key() -> None:
    """Test tag key generation."""
    key = generate_tag_key("header:auth")
    assert key.startswith("tag:")
    assert "header:auth" in key


def test_parse_key_type() -> None:
    """Test key type parsing."""
    assert parse_key_type("obs:url:example.com") == "obs"
    assert parse_key_type("chk:test") == "chk"
    assert parse_key_type("ti:vt:obs_key") == "ti"
    assert parse_key_type("enr:name") == "enr"
    assert parse_key_type("tag:header") == "tag"
    assert parse_key_type("invalid") is None


def test_parse_observable_key() -> None:
    """Test observable key parsing."""
    assert parse_observable_key("obs:url:example.com") == ("url", "example.com")
    assert parse_observable_key("obs:url:https://example.com/path") == ("url", "https://example.com/path")
    assert parse_observable_key("obs:url:") is None
    assert parse_observable_key("chk:test") is None
    assert parse_observable_key("invalid") is None


def test_validate_key() -> None:
    """Test key validation."""
    assert validate_key("obs:url:example.com") is True
    assert validate_key("chk:test") is True
    assert validate_key("ti:vt:obs_key") is True
    assert validate_key("invalid") is False
    assert validate_key("obs:url:example.com", "obs") is True
    assert validate_key("obs:url:example.com", "chk") is False


def test_key_determinism() -> None:
    """Test that keys are deterministic."""
    # Same inputs should always produce same keys
    for _ in range(10):
        assert generate_observable_key("ipv4", "192.168.1.1") == "obs:ipv4:192.168.1.1"
        assert generate_check_key("test") == "chk:test"


def test_get_tag_ancestors() -> None:
    """Test tag ancestor extraction from hierarchical names."""
    # Single segment has no ancestors
    assert get_tag_ancestors("header") == []
    # Two segments
    assert get_tag_ancestors("header:auth") == ["header"]
    # Three segments
    assert get_tag_ancestors("header:auth:dkim") == ["header", "header:auth"]
    # Four segments
    assert get_tag_ancestors("a:b:c:d") == ["a", "a:b", "a:b:c"]


def test_is_tag_child_of() -> None:
    """Test direct child relationship check."""
    # Direct child
    assert is_tag_child_of("header:auth", "header") is True
    # Not a child (same tag)
    assert is_tag_child_of("header", "header") is False
    # Not a child (grandchild)
    assert is_tag_child_of("header:auth:dkim", "header") is False
    # Not a child (unrelated)
    assert is_tag_child_of("footer:links", "header") is False
    # Direct child with deeper parent
    assert is_tag_child_of("header:auth:dkim", "header:auth") is True


def test_is_tag_descendant_of() -> None:
    """Test descendant relationship check (any depth)."""
    # Direct child is a descendant
    assert is_tag_descendant_of("header:auth", "header") is True
    # Grandchild is a descendant
    assert is_tag_descendant_of("header:auth:dkim", "header") is True
    # Great-grandchild is a descendant
    assert is_tag_descendant_of("a:b:c:d", "a") is True
    # Not a descendant (same tag)
    assert is_tag_descendant_of("header", "header") is False
    # Not a descendant (unrelated)
    assert is_tag_descendant_of("footer:links", "header") is False
    # Not a descendant (parent-child reversed)
    assert is_tag_descendant_of("header", "header:auth") is False
