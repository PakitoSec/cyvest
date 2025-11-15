"""Tests for STIX2 Observable and Relationship type enums."""

from decimal import Decimal

from cyvest.model import Observable, ObservableType, Relationship, RelationshipType


def test_observable_type_enum_values() -> None:
    """Test that ObservableType enum has expected STIX2 values."""
    # Network types
    assert ObservableType.IPV4_ADDR.value == "ipv4-addr"
    assert ObservableType.IPV6_ADDR.value == "ipv6-addr"
    assert ObservableType.DOMAIN_NAME.value == "domain-name"
    assert ObservableType.URL.value == "url"
    assert ObservableType.MAC_ADDR.value == "mac-addr"

    # Email types
    assert ObservableType.EMAIL_ADDR.value == "email-addr"
    assert ObservableType.EMAIL_MESSAGE.value == "email-message"

    # File types
    assert ObservableType.FILE.value == "file"
    assert ObservableType.DIRECTORY.value == "directory"

    # System types
    assert ObservableType.PROCESS.value == "process"
    assert ObservableType.SOFTWARE.value == "software"


def test_relationship_type_enum_values() -> None:
    """Test that RelationshipType enum has expected STIX2 values."""
    # Network relationships
    assert RelationshipType.RESOLVES_TO.value == "resolves-to"
    assert RelationshipType.BELONGS_TO.value == "belongs-to"
    assert RelationshipType.COMMUNICATES_WITH.value == "communicates-with"

    # File relationships
    assert RelationshipType.CONTAINS.value == "contains"
    assert RelationshipType.DOWNLOADED.value == "downloaded"
    assert RelationshipType.DROPPED.value == "dropped"

    # Email relationships
    assert RelationshipType.FROM.value == "from"
    assert RelationshipType.TO.value == "to"
    assert RelationshipType.SENDER.value == "sender"

    # Process relationships
    assert RelationshipType.CREATED.value == "created"
    assert RelationshipType.PARENT.value == "parent"
    assert RelationshipType.CHILD.value == "child"

    # General relationships
    assert RelationshipType.RELATED_TO.value == "related-to"
    assert RelationshipType.DERIVED_FROM.value == "derived-from"


def test_observable_with_enum_type() -> None:
    """Test creating observable with ObservableType enum."""
    obs = Observable(
        obs_type=ObservableType.URL,
        value="https://example.com",
        score=Decimal("5.0"),
    )

    # Type should be normalized to enum
    assert isinstance(obs.obs_type, ObservableType)
    assert obs.obs_type == ObservableType.URL
    assert obs.obs_type.value == "url"


def test_observable_with_string_type() -> None:
    """Test creating observable with string type (backward compatibility)."""
    obs = Observable(
        obs_type="ipv4-addr",
        value="192.0.2.1",
        score=Decimal("5.0"),
    )

    # String should be normalized to enum if it's a valid STIX2 type
    assert isinstance(obs.obs_type, ObservableType)
    assert obs.obs_type == ObservableType.IPV4_ADDR


def test_observable_with_custom_type() -> None:
    """Test creating observable with custom (non-STIX2) type."""
    obs = Observable(
        obs_type="custom-indicator",
        value="some-value",
        score=Decimal("5.0"),
    )

    # Custom types remain as strings
    assert isinstance(obs.obs_type, str)
    assert obs.obs_type == "custom-indicator"


def test_observable_key_generation_with_enum() -> None:
    """Test that key generation works correctly with enum types."""
    obs = Observable(
        obs_type=ObservableType.DOMAIN_NAME,
        value="example.com",
    )

    # Key should use the enum's string value
    assert "domain-name" in obs.key
    assert "example.com" in obs.key


def test_relationship_with_enum_type() -> None:
    """Test creating relationship with RelationshipType enum."""
    rel = Relationship(
        target_key="obs:ipv4-addr:192.0.2.1",
        relationship_type=RelationshipType.RESOLVES_TO,
    )

    # Type should be normalized to enum
    assert isinstance(rel.relationship_type, RelationshipType)
    assert rel.relationship_type == RelationshipType.RESOLVES_TO
    assert rel.relationship_type.value == "resolves-to"


def test_relationship_with_string_type() -> None:
    """Test creating relationship with string type (backward compatibility)."""
    rel = Relationship(
        target_key="obs:ipv4-addr:192.0.2.1",
        relationship_type="resolves-to",
    )

    # String should be normalized to enum if it's a valid STIX2 type
    assert isinstance(rel.relationship_type, RelationshipType)
    assert rel.relationship_type == RelationshipType.RESOLVES_TO


def test_relationship_with_custom_type() -> None:
    """Test creating relationship with custom (non-STIX2) type."""
    rel = Relationship(
        target_key="obs:custom:value",
        relationship_type="custom-relationship",
    )

    # Custom types remain as strings
    assert isinstance(rel.relationship_type, str)
    assert rel.relationship_type == "custom-relationship"


def test_observable_add_relationship_with_enum() -> None:
    """Test adding relationship to observable using enum."""
    obs = Observable(
        obs_type=ObservableType.URL,
        value="https://example.com",
    )

    obs._add_relationship_internal(
        target_key="obs:ipv4-addr:192.0.2.1",
        relationship_type=RelationshipType.RESOLVES_TO,
    )

    assert len(obs.relationships) == 1
    assert obs.relationships[0].target_key == "obs:ipv4-addr:192.0.2.1"
    assert obs.relationships[0].relationship_type == RelationshipType.RESOLVES_TO


def test_observable_type_enum_is_string() -> None:
    """Test that ObservableType enum values are strings."""
    # This ensures compatibility with string comparisons
    assert isinstance(ObservableType.URL.value, str)
    assert ObservableType.URL == "url"  # Can compare directly with strings


def test_relationship_type_enum_is_string() -> None:
    """Test that RelationshipType enum values are strings."""
    # This ensures compatibility with string comparisons
    assert isinstance(RelationshipType.RESOLVES_TO.value, str)
    assert RelationshipType.RESOLVES_TO == "resolves-to"  # Can compare directly with strings
