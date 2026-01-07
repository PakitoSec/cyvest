"""
Tests for the core model classes.
"""

from decimal import Decimal

import pytest

from cyvest.investigation import Investigation
from cyvest.levels import Level
from cyvest.model import (
    Check,
    Enrichment,
    Observable,
    RelationshipDirection,
    Tag,
    ThreatIntel,
    _format_score_decimal,
)

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


def test_score_display_drops_negative_zero() -> None:
    """Test that formatting does not show negative zero."""
    assert _format_score_decimal(Decimal("-0.004")) == "0.00"


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
    inv = Investigation(root_data={})
    obs = Observable(obs_type="ipv4", value="192.168.1.1")
    inv.add_observable(obs)
    initial_score = obs.score
    inv.apply_score_change(obs, Decimal("5.0"), reason="Test update")
    assert obs.score == Decimal("5.0")
    assert obs.score != initial_score
    assert obs.level == Level.MALICIOUS  # Should auto-update


def test_observable_relationships() -> None:
    """Test observable relationships."""
    inv = Investigation(root_data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ipv4", value="192.168.1.1")
    inv.add_observable(obs1)
    inv.add_observable(obs2)
    inv.add_relationship(obs1, obs2, "related-to")
    assert len(obs1.relationships) == 1
    assert obs1.relationships[0].target_key == obs2.key
    assert obs1.relationships[0].relationship_type == "related-to"


def test_check_creation() -> None:
    """Test creating a check."""
    check = Check(
        check_name="test_check",
        description="Test description",
        origin_investigation_id=_ORIGIN,
    )
    assert check.check_name == "test_check"
    assert check.description == "Test description"
    assert check.score == Decimal("0")
    assert check.level == Level.NONE
    assert check.key.startswith("chk:")


def test_check_creation_with_score() -> None:
    """Test creating a check."""
    check = Check(
        check_name="test_check",
        description="Test description",
        score=0.3,
        origin_investigation_id=_ORIGIN,
    )
    assert check.check_name == "test_check"
    assert check.description == "Test description"
    assert check.score == Decimal("0.3")
    assert check.level == Level.NOTABLE
    assert check.key.startswith("chk:")


def test_check_score_update() -> None:
    """Test updating check score."""
    inv = Investigation(root_data={})
    check = Check(check_name="test", description="desc", origin_investigation_id=inv.investigation_id)
    inv.add_check(check)
    inv.apply_score_change(check, Decimal("3.5"), reason="Update reason")
    assert check.score == Decimal("3.5")
    assert check.level == Level.SUSPICIOUS  # 3.5 is in range [3.0, 5.0) -> SUSPICIOUS


def test_check_add_observable_link_upgrades_level() -> None:
    """Test that adding an effective observable link to a check with level NONE upgrades it to INFO."""
    inv = Investigation(root_data={})
    check = Check(check_name="test", description="desc", origin_investigation_id=inv.investigation_id)
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
    inv = Investigation(root_data={})
    check = Check(
        check_name="test",
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
    inv = Investigation(root_data={})
    check = Check(check_name="test", description="desc", origin_investigation_id=inv.investigation_id)
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


def test_threat_intel_unbound_creation() -> None:
    """ThreatIntel can be created in an unbound/draft state."""
    ti = ThreatIntel(source="virustotal", score=Decimal("8.0"))
    assert ti.observable_key == ""
    assert ti.key == ""
    assert ti.level == Level.MALICIOUS  # Auto-calculated from score


def test_threat_intel_taxonomy_names_unique() -> None:
    """ThreatIntel should reject duplicate taxonomy names."""
    with pytest.raises(ValueError):
        ThreatIntel(
            source="virustotal",
            observable_key="obs:url:example.com",
            score=Decimal("8.0"),
            taxonomies=[
                {"level": Level.INFO, "name": "malware-type", "value": "trojan"},
                {"level": Level.INFO, "name": "malware-type", "value": "worm"},
            ],
        )


def test_enrichment_creation() -> None:
    """Test creating enrichment."""
    enr = Enrichment(name="email_headers", data={"from": "test@example.com"})
    assert enr.name == "email_headers"
    assert enr.data == {"from": "test@example.com"}
    assert enr.key.startswith("enr:")


def test_tag_creation() -> None:
    """Test creating tag."""
    tag = Tag(name="network:analysis", description="Network analysis tag")
    assert tag.name == "network:analysis"
    assert tag.description == "Network analysis tag"
    assert tag.key.startswith("tag:")
    assert len(tag.checks) == 0


def test_tag_direct_score() -> None:
    """Test tag direct score calculation."""
    inv = Investigation(root_data={})
    tag = inv.add_tag(Tag(name="test"))
    check1 = Check(
        check_name="c1",
        description="d1",
        score=Decimal("3.0"),
        origin_investigation_id=inv.investigation_id,
    )
    check2 = Check(
        check_name="c2",
        description="d2",
        score=Decimal("5.0"),
        origin_investigation_id=inv.investigation_id,
    )
    inv.add_check(check1)
    inv.add_check(check2)
    inv.add_check_to_tag(tag.key, check1.key)
    inv.add_check_to_tag(tag.key, check2.key)
    assert tag.get_direct_score() == Decimal("8.0")
    assert tag.get_direct_level() == Level.MALICIOUS


def test_tag_hierarchical_aggregation() -> None:
    """Test tag hierarchical score aggregation."""
    inv = Investigation(root_data={})
    # Creating a child tag auto-creates parent
    child = inv.add_tag(Tag(name="parent:child"))
    parent = inv.get_tag("tag:parent")
    assert parent is not None

    check1 = Check(
        check_name="c1",
        description="d",
        score=Decimal("2.0"),
        origin_investigation_id=inv.investigation_id,
    )
    check2 = Check(
        check_name="c2",
        description="d",
        score=Decimal("3.0"),
        origin_investigation_id=inv.investigation_id,
    )
    inv.add_check(check1)
    inv.add_check(check2)
    inv.add_check_to_tag(parent.key, check1.key)
    inv.add_check_to_tag(child.key, check2.key)
    # Aggregated should sum parent + child checks
    assert inv.get_tag_aggregated_score("parent") == Decimal("5.0")
    # Direct should only be parent's checks
    assert parent.get_direct_score() == Decimal("2.0")


def test_explicit_level_setting() -> None:
    """Test SAFE level stays sticky unless upgraded by score."""
    inv = Investigation(root_data={})
    obs = Observable(obs_type="url", value="test.com")
    inv.add_observable(obs)
    inv.apply_level_change(obs, Level.SAFE)
    assert obs.level == Level.SAFE
    # Updating score to high value should upgrade SAFE.
    inv.apply_score_change(obs, Decimal("6.0"))
    assert obs.level == Level.MALICIOUS  # Higher level wins


def test_string_level_inputs_are_normalized() -> None:
    """String level values should be accepted and normalized."""
    inv = Investigation(root_data={})
    obs = Observable(obs_type="domain", value="example.com", level="suspicious")
    assert obs.level == Level.SUSPICIOUS
    inv.add_observable(obs)
    inv.apply_level_change(obs, "malicious")
    assert obs.level == Level.MALICIOUS

    check = Check(
        check_name="string_level",
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
    inv = Investigation(root_data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ipv4", value="192.168.1.1")
    inv.add_observable(obs1)
    inv.add_observable(obs2)
    inv.add_relationship(obs1, obs2, "indicates")
    assert len(obs1.relationships) == 1
    assert obs1.relationships[0].direction == RelationshipDirection.OUTBOUND


def test_relationship_direction_explicit() -> None:
    """Test setting explicit relationship direction."""
    inv = Investigation(root_data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ipv4", value="192.168.1.1")
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
    inv = Investigation(root_data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ipv4", value="192.168.1.1")
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

    inv = Investigation(root_data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ipv4", value="192.168.1.1")
    inv.add_observable(obs1)
    inv.add_observable(obs2)

    # No direction specified - should use semantic default (BIDIRECTIONAL for RELATED_TO)
    inv.add_relationship(obs1, obs2, RelationshipType.RELATED_TO)
    assert obs1.relationships[0].direction == RelationshipDirection.BIDIRECTIONAL


def test_relationship_override_default() -> None:
    """Test that explicit direction overrides semantic default."""
    from cyvest.model import RelationshipType

    inv = Investigation(root_data={})
    obs1 = Observable(obs_type="url", value="https://example.com")
    obs2 = Observable(obs_type="ipv4", value="192.168.1.1")
    inv.add_observable(obs1)
    inv.add_observable(obs2)

    # Override default: RELATED_TO normally BIDIRECTIONAL, force INBOUND
    inv.add_relationship(obs1, obs2, RelationshipType.RELATED_TO, RelationshipDirection.INBOUND)
    assert obs1.relationships[0].direction == RelationshipDirection.INBOUND


def test_observable_serializes_with_type_alias() -> None:
    """Observable.model_dump() should output 'type' not 'obs_type' by default."""
    obs = Observable(obs_type="url", value="https://example.com")

    # Default model_dump() should use by_alias=True
    dumped = obs.model_dump()
    assert "type" in dumped
    assert "obs_type" not in dumped
    assert dumped["type"] == "url"

    # model_dump_json() should also use alias
    json_str = obs.model_dump_json()
    assert '"type":' in json_str or '"type": ' in json_str
    assert '"obs_type"' not in json_str

    # Explicit by_alias=False should use field name
    dumped_no_alias = obs.model_dump(by_alias=False)
    assert "obs_type" in dumped_no_alias
    assert "type" not in dumped_no_alias
