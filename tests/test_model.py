"""
Tests for the core model classes.
"""

from decimal import Decimal

from cyvest.levels import Level
from cyvest.model import Check, Container, Enrichment, Observable, RelationshipDirection, ThreatIntel


def test_observable_creation() -> None:
    """Test creating an observable."""
    obs = Observable(obs_type="url", value="https://example.com")
    assert obs.obs_type == "url"
    assert obs.value == "https://example.com"
    assert obs.score == Decimal("0")
    assert obs.level == Level.INFO
    assert obs.internal is True
    assert obs.whitelisted is False
    assert obs.key.startswith("obs:")


def test_observable_score_update() -> None:
    """Test updating observable score."""
    obs = Observable(obs_type="ip", value="192.168.1.1")
    initial_score = obs.score
    obs.update_score(Decimal("5.0"), "Test update")
    assert obs.score == Decimal("5.0")
    assert obs.score != initial_score
    assert obs.level == Level.MALICIOUS  # Should auto-update
    assert len(obs._score_history) == 1


def test_observable_relationships() -> None:
    """Test observable relationships."""
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")
    obs1._add_relationship_internal(obs2.key, "resolves-to")
    assert len(obs1.relationships) == 1
    assert obs1.relationships[0].target_key == obs2.key
    assert obs1.relationships[0].relationship_type == "resolves-to"


def test_check_creation() -> None:
    """Test creating a check."""
    check = Check(check_id="test_check", scope="network", description="Test description")
    assert check.check_id == "test_check"
    assert check.scope == "network"
    assert check.description == "Test description"
    assert check.score == Decimal("0")
    assert check.level == Level.NONE
    assert check.key.startswith("chk:")


def test_check_score_update() -> None:
    """Test updating check score."""
    check = Check(check_id="test", scope="scope", description="desc")
    check.update_score(Decimal("3.5"), "Update reason")
    assert check.score == Decimal("3.5")
    assert check.level == Level.SUSPICIOUS  # 3.5 is in range [3.0, 5.0) -> SUSPICIOUS
    assert len(check._score_history) == 1


def test_check_add_observable_upgrades_level() -> None:
    """Test that adding an observable to a check with level NONE upgrades it to INFO."""
    check = Check(check_id="test", scope="scope", description="desc")
    assert check.level == Level.NONE  # Default level for new checks
    
    obs = Observable(obs_type="url", value="https://example.com")
    check.add_observable(obs)
    
    assert check.level == Level.INFO  # Should auto-upgrade from NONE to INFO
    assert len(check.observables) == 1
    assert check.observables[0] == obs


def test_check_add_observable_preserves_higher_level() -> None:
    """Test that adding an observable doesn't downgrade an existing higher level."""
    check = Check(check_id="test", scope="scope", description="desc")
    check.set_level(Level.SUSPICIOUS)
    
    obs = Observable(obs_type="url", value="https://example.com")
    check.add_observable(obs)
    
    assert check.level == Level.SUSPICIOUS  # Should preserve existing higher level
    assert len(check.observables) == 1


def test_check_add_observable_no_duplicate() -> None:
    """Test that adding the same observable twice doesn't create duplicates."""
    check = Check(check_id="test", scope="scope", description="desc")
    obs = Observable(obs_type="url", value="https://example.com")
    
    check.add_observable(obs)
    check.add_observable(obs)  # Add same observable again
    
    assert len(check.observables) == 1  # Should only have one instance
    assert check.level == Level.INFO  # Level should still be INFO


def test_threat_intel_creation() -> None:
    """Test creating threat intel."""
    ti = ThreatIntel(source="virustotal", observable_key="obs:url:example.com", score=Decimal("8.0"))
    assert ti.source == "virustotal"
    assert ti.observable_key == "obs:url:example.com"
    assert ti.score == Decimal("8.0")
    assert ti.level == Level.MALICIOUS  # Auto-calculated from score
    assert ti.key.startswith("ti:")


def test_enrichment_creation() -> None:
    """Test creating enrichment."""
    enr = Enrichment(name="email_headers", data={"from": "test@example.com"})
    assert enr.name == "email_headers"
    assert enr.data == {"from": "test@example.com"}
    assert enr.key.startswith("enr:")


def test_container_creation() -> None:
    """Test creating container."""
    ctr = Container(path="network/analysis", description="Network analysis container")
    assert ctr.path == "network/analysis"
    assert ctr.description == "Network analysis container"
    assert ctr.key.startswith("ctr:")
    assert len(ctr.checks) == 0
    assert len(ctr.sub_containers) == 0


def test_container_aggregated_score() -> None:
    """Test container score aggregation."""
    ctr = Container(path="test")
    check1 = Check(check_id="c1", scope="s1", description="d1", score=Decimal("3.0"))
    check2 = Check(check_id="c2", scope="s2", description="d2", score=Decimal("5.0"))
    ctr.add_check(check1)
    ctr.add_check(check2)
    assert ctr.get_aggregated_score() == Decimal("8.0")
    assert ctr.get_aggregated_level() == Level.MALICIOUS


def test_container_nested_aggregation() -> None:
    """Test nested container score aggregation."""
    parent = Container(path="parent")
    child = Container(path="parent/child")
    check1 = Check(check_id="c1", scope="s", description="d", score=Decimal("2.0"))
    check2 = Check(check_id="c2", scope="s", description="d", score=Decimal("3.0"))
    parent.add_check(check1)
    child.add_check(check2)
    parent.add_sub_container(child)
    # Should sum both parent and child checks
    assert parent.get_aggregated_score() == Decimal("5.0")


def test_explicit_level_setting() -> None:
    """Test explicit level setting overrides calculation."""
    obs = Observable(obs_type="url", value="test.com")
    obs.set_level(Level.SAFE)
    assert obs.level == Level.SAFE
    assert obs._explicit_level is True
    # Updating score to high value shouldn't change explicitly set level
    # unless new calculated level is higher
    obs.update_score(Decimal("6.0"))
    assert obs.level == Level.MALICIOUS  # Higher level wins


def test_relationship_direction_default() -> None:
    """Test relationship direction defaults to OUTBOUND."""
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")
    obs1._add_relationship_internal(obs2.key, "resolves-to")
    assert len(obs1.relationships) == 1
    assert obs1.relationships[0].direction == RelationshipDirection.OUTBOUND


def test_relationship_direction_explicit() -> None:
    """Test setting explicit relationship direction."""
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")

    # Test outbound
    obs1._add_relationship_internal(obs2.key, "resolves-to", RelationshipDirection.OUTBOUND)
    assert obs1.relationships[0].direction == RelationshipDirection.OUTBOUND

    # Test inbound
    obs1._add_relationship_internal(obs2.key, "belongs-to", RelationshipDirection.INBOUND)
    assert obs1.relationships[1].direction == RelationshipDirection.INBOUND

    # Test bidirectional
    obs1._add_relationship_internal(obs2.key, "communicates-with", RelationshipDirection.BIDIRECTIONAL)
    assert obs1.relationships[2].direction == RelationshipDirection.BIDIRECTIONAL


def test_relationship_direction_string() -> None:
    """Test relationship direction with string values."""
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")

    obs1._add_relationship_internal(obs2.key, "resolves-to", "inbound")
    assert obs1.relationships[0].direction == RelationshipDirection.INBOUND

    obs1._add_relationship_internal(obs2.key, "communicates-with", "bidirectional")
    assert obs1.relationships[1].direction == RelationshipDirection.BIDIRECTIONAL


def test_relationship_semantic_defaults() -> None:
    """Test that relationship types get correct semantic default directions."""
    from cyvest.model import RelationshipType

    # Test network relationships
    assert RelationshipType.RESOLVES_TO.get_default_direction() == RelationshipDirection.OUTBOUND
    assert RelationshipType.BELONGS_TO.get_default_direction() == RelationshipDirection.OUTBOUND
    assert RelationshipType.COMMUNICATES_WITH.get_default_direction() == RelationshipDirection.BIDIRECTIONAL

    # Test file relationships
    assert RelationshipType.CONTAINS.get_default_direction() == RelationshipDirection.OUTBOUND
    assert RelationshipType.DOWNLOADED.get_default_direction() == RelationshipDirection.INBOUND
    assert RelationshipType.DROPPED.get_default_direction() == RelationshipDirection.INBOUND

    # Test email relationships
    assert RelationshipType.FROM.get_default_direction() == RelationshipDirection.INBOUND
    assert RelationshipType.SENDER.get_default_direction() == RelationshipDirection.INBOUND
    assert RelationshipType.TO.get_default_direction() == RelationshipDirection.OUTBOUND
    assert RelationshipType.CC.get_default_direction() == RelationshipDirection.OUTBOUND
    assert RelationshipType.BCC.get_default_direction() == RelationshipDirection.OUTBOUND

    # Test process relationships
    assert RelationshipType.CREATED.get_default_direction() == RelationshipDirection.OUTBOUND
    assert RelationshipType.PARENT.get_default_direction() == RelationshipDirection.OUTBOUND
    assert RelationshipType.CHILD.get_default_direction() == RelationshipDirection.INBOUND

    # Test general relationships
    assert RelationshipType.RELATED_TO.get_default_direction() == RelationshipDirection.BIDIRECTIONAL
    assert RelationshipType.DERIVED_FROM.get_default_direction() == RelationshipDirection.INBOUND
    assert RelationshipType.DUPLICATE_OF.get_default_direction() == RelationshipDirection.BIDIRECTIONAL


def test_relationship_auto_direction() -> None:
    """Test that relationships automatically get semantic defaults when direction not specified."""
    from cyvest.model import RelationshipType

    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")

    # No direction specified - should use semantic default (OUTBOUND for RESOLVES_TO)
    obs1._add_relationship_internal(obs2.key, RelationshipType.RESOLVES_TO)
    assert obs1.relationships[0].direction == RelationshipDirection.OUTBOUND

    # No direction specified - should use semantic default (INBOUND for DOWNLOADED)
    obs1._add_relationship_internal(obs2.key, RelationshipType.DOWNLOADED)
    assert obs1.relationships[1].direction == RelationshipDirection.INBOUND

    # No direction specified - should use semantic default (BIDIRECTIONAL for COMMUNICATES_WITH)
    obs1._add_relationship_internal(obs2.key, RelationshipType.COMMUNICATES_WITH)
    assert obs1.relationships[2].direction == RelationshipDirection.BIDIRECTIONAL


def test_relationship_override_default() -> None:
    """Test that explicit direction overrides semantic default."""
    from cyvest.model import RelationshipType

    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")

    # Override default: RESOLVES_TO normally OUTBOUND, force INBOUND
    obs1._add_relationship_internal(obs2.key, RelationshipType.RESOLVES_TO, RelationshipDirection.INBOUND)
    assert obs1.relationships[0].direction == RelationshipDirection.INBOUND
