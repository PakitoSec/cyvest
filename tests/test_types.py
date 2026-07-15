"""Tests for observable and relationship type enums."""

from decimal import Decimal

from cyvest.model import Observable, ObservableType, Relationship, RelationshipDirection, RelationshipType


def test_observable_type_enum_values() -> None:
    """Test that ObservableType enum has expected values."""
    # Network types
    assert ObservableType.IPV4.value == "ipv4"
    assert ObservableType.IPV6.value == "ipv6"
    assert ObservableType.DOMAIN.value == "domain"
    assert ObservableType.URL.value == "url"
    assert ObservableType.HASH.value == "hash"
    assert ObservableType.EMAIL.value == "email"
    assert ObservableType.FILE.value == "file"
    assert ObservableType.ARTIFACT.value == "artifact"


def test_relationship_type_enum_values() -> None:
    """Test that RelationshipType enum has expected values."""
    assert RelationshipType.RELATED_TO.value == "related-to"
    assert RelationshipType.CONTAINS.value == "contains"
    assert RelationshipType.DERIVED_FROM.value == "derived-from"
    assert RelationshipType.RESOLVES_TO.value == "resolves-to"
    assert RelationshipType.HOSTS.value == "hosts"
    assert RelationshipType.COMMUNICATES_WITH.value == "communicates-with"
    assert RelationshipType.EXECUTES.value == "executes"


def test_relationship_type_semantic_directions() -> None:
    """Built-in relationship types expose useful semantic defaults."""
    assert RelationshipType.RELATED_TO.get_default_direction() == RelationshipDirection.BIDIRECTIONAL
    assert RelationshipType.COMMUNICATES_WITH.get_default_direction() == RelationshipDirection.BIDIRECTIONAL
    assert RelationshipType.CONTAINS.get_default_direction() == RelationshipDirection.OUTBOUND
    assert RelationshipType.RESOLVES_TO.get_default_direction() == RelationshipDirection.OUTBOUND


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
        obs_type="ipv4",
        value="192.0.2.1",
        score=Decimal("5.0"),
    )

    # String should be normalized to enum if it's a known type
    assert isinstance(obs.obs_type, ObservableType)
    assert obs.obs_type == ObservableType.IPV4


def test_observable_with_custom_type() -> None:
    """Test creating observable with custom type."""
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
        obs_type=ObservableType.DOMAIN,
        value="example.com",
    )

    # Key should use the enum's string value
    assert "domain" in obs.key
    assert "example.com" in obs.key


def test_relationship_with_enum_type() -> None:
    """Test creating relationship with RelationshipType enum."""
    rel = Relationship(
        target_key="obs:ipv4:192.0.2.1",
        relationship_type=RelationshipType.RELATED_TO,
    )

    # Type should be normalized to enum
    assert isinstance(rel.relationship_type, RelationshipType)
    assert rel.relationship_type == RelationshipType.RELATED_TO
    assert rel.relationship_type.value == "related-to"


def test_relationship_with_string_type() -> None:
    """Test creating relationship with string type (backward compatibility)."""
    rel = Relationship(
        target_key="obs:ipv4:192.0.2.1",
        relationship_type="related-to",
    )

    # String should be normalized to enum if it's a known type
    assert isinstance(rel.relationship_type, RelationshipType)
    assert rel.relationship_type == RelationshipType.RELATED_TO


def test_relationship_with_custom_type() -> None:
    """Test creating relationship with custom type."""
    rel = Relationship(
        target_key="obs:custom:value",
        relationship_type="custom-relationship",
    )

    # Custom types remain as strings
    assert isinstance(rel.relationship_type, str)
    assert rel.relationship_type == "custom-relationship"


def test_observable_add_relationship_with_enum() -> None:
    """Test adding relationship to observable using enum."""
    from cyvest.investigation import Investigation

    inv = Investigation(root_data={})
    obs = Observable(
        obs_type=ObservableType.URL,
        value="https://example.com",
    )

    target = Observable(obs_type=ObservableType.IPV4, value="192.0.2.1")
    inv.add_observable(obs)
    inv.add_observable(target)
    inv.add_relationship(obs, target, RelationshipType.RELATED_TO)

    assert len(obs.relationships) == 1
    assert obs.relationships[0].target_key == target.key
    assert obs.relationships[0].relationship_type == RelationshipType.RELATED_TO


def test_observable_type_enum_is_string() -> None:
    """Test that ObservableType enum values are strings."""
    # This ensures compatibility with string comparisons
    assert isinstance(ObservableType.URL.value, str)
    assert ObservableType.URL == "url"  # Can compare directly with strings


def test_relationship_type_enum_is_string() -> None:
    """Test that RelationshipType enum values are strings."""
    # This ensures compatibility with string comparisons
    assert isinstance(RelationshipType.RELATED_TO.value, str)
    assert RelationshipType.RELATED_TO == "related-to"  # Can compare directly with strings
