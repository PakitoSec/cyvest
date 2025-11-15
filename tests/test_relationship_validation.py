"""
Tests for relationship validation through Investigation layer.
"""

from cyvest import Cyvest
from cyvest.model import Observable


def test_add_relationship_with_valid_target() -> None:
    """Test adding relationship when both source and target exist."""
    cv = Cyvest()
    
    source = cv.observable_create("domain", "example.com")
    target = cv.observable_create("ip", "192.0.2.1")
    
    result = cv.observable_add_relationship(source, target, "resolves-to")
    
    assert result is not None
    assert result.key == source.key
    assert len(source.relationships) == 1
    assert source.relationships[0].target_key == target.key


def test_add_relationship_with_keys() -> None:
    """Test adding relationship using string keys."""
    cv = Cyvest()
    
    source = cv.observable_create("domain", "example.com")
    target = cv.observable_create("ip", "192.0.2.1")
    
    result = cv.observable_add_relationship(source.key, target.key, "resolves-to")
    
    assert result is not None
    assert result.key == source.key
    assert len(source.relationships) == 1
    assert source.relationships[0].target_key == target.key


def test_add_relationship_mixed_params() -> None:
    """Test adding relationship with mixed Observable and string parameters."""
    cv = Cyvest()
    
    source = cv.observable_create("domain", "example.com")
    target = cv.observable_create("ip", "192.0.2.1")
    
    # Source as Observable, target as string
    result = cv.observable_add_relationship(source, target.key, "resolves-to")
    assert result is not None
    assert len(source.relationships) == 1
    
    source2 = cv.observable_create("domain", "test.com")
    # Source as string, target as Observable
    result2 = cv.observable_add_relationship(source2.key, target, "resolves-to")
    assert result2 is not None
    assert len(source2.relationships) == 1


def test_add_relationship_nonexistent_source() -> None:
    """Test adding relationship when source doesn't exist returns None."""
    cv = Cyvest()
    
    target = cv.observable_create("ip", "192.0.2.1")
    
    result = cv.observable_add_relationship("obs:domain:nonexistent.com", target, "resolves-to")
    
    assert result is None


def test_add_relationship_nonexistent_target() -> None:
    """Test adding relationship when target doesn't exist returns None and doesn't add relationship."""
    cv = Cyvest()
    
    source = cv.observable_create("domain", "example.com")
    
    result = cv.observable_add_relationship(source, "obs:ip:192.0.2.1", "resolves-to")
    
    assert result is None
    assert len(source.relationships) == 0  # Relationship was not added


def test_add_relationship_both_nonexistent() -> None:
    """Test adding relationship when both don't exist returns None."""
    cv = Cyvest()
    
    result = cv.observable_add_relationship(
        "obs:domain:nonexistent.com",
        "obs:ip:192.0.2.1",
        "resolves-to"
    )
    
    assert result is None


def test_relationship_deduplication() -> None:
    """Test that duplicate relationships are not added."""
    cv = Cyvest()
    
    source = cv.observable_create("domain", "example.com")
    target = cv.observable_create("ip", "192.0.2.1")
    
    # Add same relationship twice
    cv.observable_add_relationship(source, target, "resolves-to")
    cv.observable_add_relationship(source, target, "resolves-to")
    
    # Should only have one relationship
    assert len(source.relationships) == 1


def test_merge_filters_invalid_relationships() -> None:
    """Test that merging filters out relationships to non-existent targets."""
    cv = Cyvest()
    
    # Create observable with relationship to non-existent target
    obs = Observable(obs_type="domain", value="example.com")
    obs._add_relationship_internal("obs:ip:nonexistent", "resolves-to")
    
    # Add it to investigation - the relationship should be filtered during merge
    cv.observable_create("domain", "example.com")
    merged = cv._investigation.add_observable(obs)
    
    # The relationship should not have been merged
    assert len(merged.relationships) == 0


def test_merge_keeps_valid_relationships() -> None:
    """Test that merging keeps relationships to existing targets."""
    cv = Cyvest()
    
    # Create target first
    target = cv.observable_create("ip", "192.0.2.1")
    
    # Create observable with relationship to existing target
    obs = Observable(obs_type="domain", value="example.com")
    obs._add_relationship_internal(target.key, "resolves-to")
    
    # Add it to investigation - the relationship should be kept
    merged = cv._investigation.add_observable(obs)
    
    # The relationship should have been merged
    assert len(merged.relationships) == 1
    assert merged.relationships[0].target_key == target.key


def test_investigation_add_relationship_with_observables() -> None:
    """Test Investigation.add_relationship with Observable objects."""
    cv = Cyvest()
    
    source = cv.observable_create("domain", "example.com")
    target = cv.observable_create("ip", "192.0.2.1")
    
    result = cv._investigation.add_relationship(source, target, "resolves-to")
    
    assert result is not None
    assert result.key == source.key
    assert len(source.relationships) == 1
