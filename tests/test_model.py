"""
Tests for the core model classes.
"""

from decimal import Decimal

from cyvest.levels import Level
from cyvest.model import Check, Container, Enrichment, Observable, ThreatIntel


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
    obs1.add_relationship(obs2.key, "resolves-to")
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
