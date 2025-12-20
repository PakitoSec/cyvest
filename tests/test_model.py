"""
Tests for the core model classes.
"""

from decimal import Decimal

from cyvest.investigation import Investigation
from cyvest.levels import Level
from cyvest.model import Check, Container, Enrichment, Observable, RelationshipDirection, ThreatIntel

_ORIGIN = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


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


def test_observable_creation_with_score() -> None:
    """Test creating an observable."""
    obs = Observable(obs_type="url", value="https://example.com", score=0.3)
    assert obs.obs_type == "url"
    assert obs.value == "https://example.com"
    assert obs.score == Decimal("0.3")
    assert obs.level == Level.NOTABLE
    assert obs.internal is True
    assert obs.whitelisted is False
    assert obs.key.startswith("obs:")


def test_observable_score_update() -> None:
    """Test updating observable score."""
    inv = Investigation(data={})
    obs = Observable(obs_type="ip", value="192.168.1.1")
    inv.add_observable(obs)
    initial_score = obs.score
    inv.apply_score_change(obs, Decimal("5.0"), reason="Test update")
    assert obs.score == Decimal("5.0")
    assert obs.score != initial_score
    assert obs.level == Level.MALICIOUS  # Should auto-update


def test_observable_relationships() -> None:
    """Test observable relationships."""
    inv = Investigation(data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")
    inv.add_observable(obs1)
    inv.add_observable(obs2)
    inv.add_relationship(obs1, obs2, "related-to")
    assert len(obs1.relationships) == 1
    assert obs1.relationships[0].target_key == obs2.key
    assert obs1.relationships[0].relationship_type == "related-to"


def test_check_creation() -> None:
    """Test creating a check."""
    check = Check(
        check_id="test_check",
        scope="network",
        description="Test description",
        origin_investigation_id=_ORIGIN,
    )
    assert check.check_id == "test_check"
    assert check.scope == "network"
    assert check.description == "Test description"
    assert check.score == Decimal("0")
    assert check.level == Level.NONE
    assert check.key.startswith("chk:")


def test_check_creation_with_score() -> None:
    """Test creating a check."""
    check = Check(
        check_id="test_check",
        scope="network",
        description="Test description",
        score=0.3,
        origin_investigation_id=_ORIGIN,
    )
    assert check.check_id == "test_check"
    assert check.scope == "network"
    assert check.description == "Test description"
    assert check.score == Decimal("0.3")
    assert check.level == Level.NOTABLE
    assert check.key.startswith("chk:")


def test_check_score_update() -> None:
    """Test updating check score."""
    inv = Investigation(data={})
    check = Check(check_id="test", scope="scope", description="desc", origin_investigation_id=inv.investigation_id)
    inv.add_check(check)
    inv.apply_score_change(check, Decimal("3.5"), reason="Update reason")
    assert check.score == Decimal("3.5")
    assert check.level == Level.SUSPICIOUS  # 3.5 is in range [3.0, 5.0) -> SUSPICIOUS


def test_check_add_observable_link_upgrades_level() -> None:
    """Test that adding an effective observable link to a check with level NONE upgrades it to INFO."""
    inv = Investigation(data={})
    check = Check(check_id="test", scope="scope", description="desc", origin_investigation_id=inv.investigation_id)
    inv.add_check(check)
    assert check.level == Level.NONE  # Default level for new checks

    obs = Observable(obs_type="url", value="https://example.com")
    inv.add_observable(obs)
    inv.link_check_observable(check.key, obs.key)

    assert check.level == Level.INFO  # Should auto-upgrade from NONE to INFO
    assert len(check.observable_links) == 1
    assert check.observable_links[0].observable_key == obs.key


def test_check_add_observable_link_preserves_higher_level() -> None:
    """Test that adding an observable link doesn't downgrade an existing higher level."""
    inv = Investigation(data={})
    check = Check(
        check_id="test",
        scope="scope",
        description="desc",
        level=Level.SUSPICIOUS,
        origin_investigation_id=inv.investigation_id,
    )
    inv.add_check(check)

    obs = Observable(obs_type="url", value="https://example.com")
    inv.add_observable(obs)
    inv.link_check_observable(check.key, obs.key)

    assert check.level == Level.SUSPICIOUS  # Should preserve existing higher level
    assert len(check.observable_links) == 1


def test_check_add_observable_link_no_duplicate() -> None:
    """Test that adding the same observable link twice doesn't create duplicates."""
    inv = Investigation(data={})
    check = Check(check_id="test", scope="scope", description="desc", origin_investigation_id=inv.investigation_id)
    inv.add_check(check)
    obs = Observable(obs_type="url", value="https://example.com")
    inv.add_observable(obs)
    inv.link_check_observable(check.key, obs.key)
    inv.link_check_observable(check.key, obs.key)  # Add same link again

    assert len(check.observable_links) == 1  # Should only have one instance
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
    inv = Investigation(data={})
    ctr = inv.add_container(Container(path="test"))
    check1 = Check(
        check_id="c1",
        scope="s1",
        description="d1",
        score=Decimal("3.0"),
        origin_investigation_id=inv.investigation_id,
    )
    check2 = Check(
        check_id="c2",
        scope="s2",
        description="d2",
        score=Decimal("5.0"),
        origin_investigation_id=inv.investigation_id,
    )
    inv.add_check(check1)
    inv.add_check(check2)
    inv.add_check_to_container(ctr.key, check1.key)
    inv.add_check_to_container(ctr.key, check2.key)
    assert ctr.get_aggregated_score() == Decimal("8.0")
    assert ctr.get_aggregated_level() == Level.MALICIOUS


def test_container_nested_aggregation() -> None:
    """Test nested container score aggregation."""
    inv = Investigation(data={})
    parent = inv.add_container(Container(path="parent"))
    child = inv.add_container(Container(path="parent/child"))
    check1 = Check(
        check_id="c1",
        scope="s",
        description="d",
        score=Decimal("2.0"),
        origin_investigation_id=inv.investigation_id,
    )
    check2 = Check(
        check_id="c2",
        scope="s",
        description="d",
        score=Decimal("3.0"),
        origin_investigation_id=inv.investigation_id,
    )
    inv.add_check(check1)
    inv.add_check(check2)
    inv.add_check_to_container(parent.key, check1.key)
    inv.add_check_to_container(child.key, check2.key)
    inv.add_sub_container(parent.key, child.key)
    # Should sum both parent and child checks
    assert parent.get_aggregated_score() == Decimal("5.0")


def test_explicit_level_setting() -> None:
    """Test SAFE level stays sticky unless upgraded by score."""
    inv = Investigation(data={})
    obs = Observable(obs_type="url", value="test.com")
    inv.add_observable(obs)
    inv.apply_level_change(obs, Level.SAFE)
    assert obs.level == Level.SAFE
    # Updating score to high value should upgrade SAFE.
    inv.apply_score_change(obs, Decimal("6.0"))
    assert obs.level == Level.MALICIOUS  # Higher level wins


def test_string_level_inputs_are_normalized() -> None:
    """String level values should be accepted and normalized."""
    inv = Investigation(data={})
    obs = Observable(obs_type="domain-name", value="example.com", level="suspicious")
    assert obs.level == Level.SUSPICIOUS
    inv.add_observable(obs)
    inv.apply_level_change(obs, "malicious")
    assert obs.level == Level.MALICIOUS

    check = Check(
        check_id="string_level",
        scope="scope",
        description="desc",
        level="notable",
        origin_investigation_id=inv.investigation_id,
    )
    assert check.level == Level.NOTABLE
    inv.add_check(check)
    inv.apply_level_change(check, "trusted")
    assert check.level == Level.TRUSTED

    ti = ThreatIntel(source="src", observable_key="obs:test", score=Decimal("0"), level="safe")
    assert ti.level == Level.SAFE
    inv.apply_level_change(ti, "info")
    assert ti.level == Level.INFO


def test_relationship_direction_default() -> None:
    """Test relationship direction defaults follow semantic mapping."""
    inv = Investigation(data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")
    inv.add_observable(obs1)
    inv.add_observable(obs2)
    inv.add_relationship(obs1, obs2, "indicates")
    assert len(obs1.relationships) == 1
    assert obs1.relationships[0].direction == RelationshipDirection.OUTBOUND


def test_relationship_direction_explicit() -> None:
    """Test setting explicit relationship direction."""
    inv = Investigation(data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")
    inv.add_observable(obs1)
    inv.add_observable(obs2)

    # Test outbound
    inv.add_relationship(obs1, obs2, "indicates", RelationshipDirection.OUTBOUND)
    assert obs1.relationships[0].direction == RelationshipDirection.OUTBOUND

    # Test inbound
    inv.add_relationship(obs1, obs2, "owned-by", RelationshipDirection.INBOUND)
    assert obs1.relationships[1].direction == RelationshipDirection.INBOUND

    # Test bidirectional
    inv.add_relationship(obs1, obs2, "related-to", RelationshipDirection.BIDIRECTIONAL)
    assert obs1.relationships[2].direction == RelationshipDirection.BIDIRECTIONAL


def test_relationship_direction_string() -> None:
    """Test relationship direction with string values."""
    inv = Investigation(data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")
    inv.add_observable(obs1)
    inv.add_observable(obs2)

    inv.add_relationship(obs1, obs2, "indicates", "inbound")
    assert obs1.relationships[0].direction == RelationshipDirection.INBOUND

    inv.add_relationship(obs1, obs2, "related-to", "bidirectional")
    assert obs1.relationships[1].direction == RelationshipDirection.BIDIRECTIONAL


def test_relationship_semantic_defaults() -> None:
    """Test that relationship types get correct default directions."""
    from cyvest.model import RelationshipType

    assert RelationshipType.RELATED_TO.get_default_direction() == RelationshipDirection.BIDIRECTIONAL


def test_relationship_auto_direction() -> None:
    """Test that relationships automatically get semantic defaults when direction not specified."""
    from cyvest.model import RelationshipType

    inv = Investigation(data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")
    inv.add_observable(obs1)
    inv.add_observable(obs2)

    # No direction specified - should use semantic default (BIDIRECTIONAL for RELATED_TO)
    inv.add_relationship(obs1, obs2, RelationshipType.RELATED_TO)
    assert obs1.relationships[0].direction == RelationshipDirection.BIDIRECTIONAL


def test_relationship_override_default() -> None:
    """Test that explicit direction overrides semantic default."""
    from cyvest.model import RelationshipType

    inv = Investigation(data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ip", value="192.168.1.1")
    inv.add_observable(obs1)
    inv.add_observable(obs2)

    # Override default: RELATED_TO normally BIDIRECTIONAL, force INBOUND
    inv.add_relationship(obs1, obs2, RelationshipType.RELATED_TO, RelationshipDirection.INBOUND)
    assert obs1.relationships[0].direction == RelationshipDirection.INBOUND
