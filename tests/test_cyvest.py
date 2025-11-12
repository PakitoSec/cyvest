"""
Tests for the Cyvest facade.
"""

from decimal import Decimal

from cyvest import Cyvest, Level, RelationshipDirection


def test_cyvest_initialization() -> None:
    """Test Cyvest initialization."""
    cv = Cyvest(data={"test": "data"})
    assert cv.data == {"test": "data"}
    root = cv.observable_get_root()
    assert root is not None
    assert root.obs_type == "file"


def test_context_manager() -> None:
    """Test Cyvest as context manager."""
    with Cyvest() as cv:
        assert cv is not None
        obs = cv.observable_create("ip", "192.168.1.1")
        assert obs is not None


def test_observable_creation() -> None:
    """Test creating observables via facade."""
    cv = Cyvest()
    obs = cv.observable_create("url", "https://example.com", internal=False)
    assert obs.obs_type == "url"
    assert obs.value == "https://example.com"
    assert obs.internal is False
    # Should be registered
    assert cv.observable_get(obs.key) is not None


def test_observable_retrieval() -> None:
    """Test retrieving observables."""
    cv = Cyvest()
    obs = cv.observable_create("ip", "10.0.0.1")
    retrieved = cv.observable_get(obs.key)
    assert retrieved is obs


def test_threat_intel_addition() -> None:
    """Test adding threat intel to observable."""
    cv = Cyvest()
    obs = cv.observable_create("hash", "abc123")
    ti = cv.observable_add_threat_intel(
        obs.key, source="virustotal", score=Decimal("8.0"), comment="Malicious"
    )
    assert ti is not None
    assert ti.source == "virustotal"
    assert ti.score == Decimal("8.0")
    assert obs.score == Decimal("8.0")  # Should propagate


def test_check_creation() -> None:
    """Test creating checks."""
    cv = Cyvest()
    check = cv.check_create("test_check", "network", "Test description", score=Decimal("5.0"))
    assert check.check_id == "test_check"
    assert check.scope == "network"
    assert check.score == Decimal("5.0")
    assert cv.check_get(check.key) is not None


def test_check_observable_linking() -> None:
    """Test linking observables to checks."""
    cv = Cyvest()
    obs = cv.observable_create("url", "https://bad.com")
    check = cv.check_create("url_check", "analysis", "Check URL")
    cv.check_link_observable(check.key, obs.key)
    assert obs in check.observables


def test_container_creation() -> None:
    """Test creating containers."""
    cv = Cyvest()
    ctr = cv.container_create("network_analysis", "Network analysis container")
    assert ctr.path == "network_analysis"
    assert cv.container_get(ctr.key) is not None


def test_container_check_addition() -> None:
    """Test adding checks to containers."""
    cv = Cyvest()
    check = cv.check_create("c1", "s1", "d1")
    ctr = cv.container_create("test_container")
    cv.container_add_check(ctr.key, check.key)
    assert check in ctr.checks


def test_enrichment_creation() -> None:
    """Test creating enrichments."""
    cv = Cyvest()
    enr = cv.enrichment_create("metadata", {"key": "value"})
    assert enr.name == "metadata"
    assert enr.data == {"key": "value"}
    assert cv.enrichment_get(enr.key) is not None


def test_global_score_calculation() -> None:
    """Test global score calculation."""
    cv = Cyvest()
    cv.check_create("c1", "s1", "d1", score=Decimal("3.0"))
    cv.check_create("c2", "s2", "d2", score=Decimal("5.0"))
    assert cv.get_global_score() == Decimal("8.0")
    assert cv.get_global_level() == Level.MALICIOUS


def test_statistics() -> None:
    """Test statistics gathering."""
    cv = Cyvest()
    cv.observable_create("url", "https://example.com")
    cv.observable_create("ip", "192.168.1.1")
    cv.check_create("c1", "network", "desc")
    stats = cv.get_statistics()
    assert stats["total_observables"] >= 2  # Plus root
    assert stats["total_checks"] == 1


def test_investigation_merge() -> None:
    """Test merging investigations."""
    cv1 = Cyvest()
    cv1.observable_create("url", "https://example.com")
    cv1.check_create("c1", "s1", "d1", score=Decimal("3.0"))

    cv2 = Cyvest()
    cv2.observable_create("ip", "192.168.1.1")
    cv2.check_create("c2", "s2", "d2", score=Decimal("2.0"))

    # Merge cv2 into cv1
    cv1.merge_investigation(cv2)

    # Should have observables from both (plus roots)
    all_obs = cv1.get_all_observables()
    assert len(all_obs) >= 3
    all_checks = cv1.get_all_checks()
    assert len(all_checks) == 2
    assert cv1.get_global_score() == Decimal("5.0")


def test_root_observable() -> None:
    """Test root observable access."""
    cv = Cyvest()
    root = cv.observable_get_root()
    assert root is not None
    # Root should be accessible through API
    assert cv.observable_get(root.key) is root


def test_relationship_with_direction() -> None:
    """Test adding relationships with direction via Cyvest API."""
    cv = Cyvest()
    obs1 = cv.observable_create("url", "https://example.com")
    obs2 = cv.observable_create("ip", "192.168.1.1")
    
    # Default direction (outbound)
    cv.observable_add_relationship(obs1.key, obs2.key, "resolves-to")
    assert obs1.relationships[0].direction == RelationshipDirection.OUTBOUND
    
    # Explicit inbound
    cv.observable_add_relationship(obs1.key, obs2.key, "belongs-to", "inbound")
    assert obs1.relationships[1].direction == RelationshipDirection.INBOUND
    
    # Explicit bidirectional
    cv.observable_add_relationship(obs1.key, obs2.key, "communicates-with", "bidirectional")
    assert obs1.relationships[2].direction == RelationshipDirection.BIDIRECTIONAL


def test_relationship_semantic_defaults_via_api() -> None:
    """Test that Cyvest API uses semantic defaults for relationship directions."""
    from cyvest import RelationshipType
    
    cv = Cyvest()
    obs1 = cv.observable_create("url", "https://example.com")
    obs2 = cv.observable_create("ip", "192.168.1.1")
    
    # No direction specified - should use OUTBOUND for RESOLVES_TO
    cv.observable_add_relationship(obs1.key, obs2.key, RelationshipType.RESOLVES_TO)
    assert obs1.relationships[0].direction == RelationshipDirection.OUTBOUND
    
    # No direction specified - should use INBOUND for DOWNLOADED
    cv.observable_add_relationship(obs1.key, obs2.key, RelationshipType.DOWNLOADED)
    assert obs1.relationships[1].direction == RelationshipDirection.INBOUND
    
    # No direction specified - should use BIDIRECTIONAL for COMMUNICATES_WITH
    cv.observable_add_relationship(obs1.key, obs2.key, RelationshipType.COMMUNICATES_WITH)
    assert obs1.relationships[2].direction == RelationshipDirection.BIDIRECTIONAL


