"""
Tests for the keys module.
"""

from cyvest.keys import (
    generate_check_key,
    generate_container_key,
    generate_enrichment_key,
    generate_observable_key,
    generate_threat_intel_key,
    parse_key_type,
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
    key = generate_check_key("malware_check", "endpoint")
    assert key.startswith("chk:")
    assert "malware_check" in key
    assert "endpoint" in key


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


def test_generate_container_key() -> None:
    """Test container key generation."""
    key = generate_container_key("network/analysis")
    assert key.startswith("ctr:")
    assert "network/analysis" in key


def test_parse_key_type() -> None:
    """Test key type parsing."""
    assert parse_key_type("obs:url:example.com") == "obs"
    assert parse_key_type("chk:test:scope") == "chk"
    assert parse_key_type("ti:vt:obs_key") == "ti"
    assert parse_key_type("enr:name") == "enr"
    assert parse_key_type("ctr:path") == "ctr"
    assert parse_key_type("invalid") is None


def test_validate_key() -> None:
    """Test key validation."""
    assert validate_key("obs:url:example.com") is True
    assert validate_key("chk:test:scope") is True
    assert validate_key("ti:vt:obs_key") is True
    assert validate_key("invalid") is False
    assert validate_key("obs:url:example.com", "obs") is True
    assert validate_key("obs:url:example.com", "chk") is False


def test_key_determinism() -> None:
    """Test that keys are deterministic."""
    # Same inputs should always produce same keys
    for _ in range(10):
        assert generate_observable_key("ip", "192.168.1.1") == "obs:ip:192.168.1.1"
        assert generate_check_key("test", "scope") == "chk:test:scope"
