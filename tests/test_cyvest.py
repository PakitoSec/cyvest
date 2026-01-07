"""
Tests for the Cyvest facade.
"""

import tempfile
from decimal import Decimal
from pathlib import Path

import pytest

from cyvest import Cyvest


def test_cyvest_initialization() -> None:
    """Test Cyvest initialization."""
    cv = Cyvest(root_data={"test": "data"})
    root = cv.observable_get_root()
    assert root is not None
    assert root.obs_type == "file"


def test_cyvest_deterministic_investigation_id() -> None:
    """Test that investigation_id parameter sets deterministic ID."""
    # Without investigation_id, a ULID is auto-generated
    cv_auto = Cyvest()
    assert cv_auto._investigation.investigation_id is not None
    assert len(cv_auto._investigation.investigation_id) == 26  # ULID length

    # With investigation_id, the provided ID is used
    cv_custom = Cyvest(investigation_id="my-custom-id")
    assert cv_custom._investigation.investigation_id == "my-custom-id"

    # Verify it persists through JSON serialization
    schema = cv_custom.io_to_invest()
    assert schema.investigation_id == "my-custom-id"

    # Verify roundtrip through JSON save/load
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = f.name

    try:
        cv_custom.io_save_json(temp_path)
        cv_loaded = Cyvest.io_load_json(temp_path)
        assert cv_loaded._investigation.investigation_id == "my-custom-id"
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_observable_creation() -> None:
    """Test creating observables via facade."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.URL, "https://example.com", internal=False)
    assert obs.obs_type == "url"
    assert obs.value == "https://example.com"
    assert obs.internal is False
    # Should be registered
    assert cv.observable_get(obs.key) is not None


def test_observable_retrieval() -> None:
    """Test retrieving observables."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    retrieved = cv.observable_get(obs.key)
    assert retrieved is not None
    assert retrieved.key == obs.key


def test_facade_getters_accept_component_parameters() -> None:
    """Facade getters should accept key components where available."""
    cv = Cyvest()

    obs = cv.observable_create(Cyvest.OBS.URL, "https://example.com")
    assert cv.observable_get(Cyvest.OBS.URL, "https://example.com") is not None
    assert cv.observable_get(cv.OBS.URL, "https://example.com") is not None
    assert cv.observable_get(obs.key) is not None

    check = cv.check_create("check_id", "desc")
    assert cv.check_get(check.key) is not None

    ctr = cv.container_create("path/to/container")
    assert cv.container_get("path/to/container") is not None
    assert cv.container_get(ctr.key) is not None

    enr = cv.enrichment_create("metadata", {"key": "value"})
    assert cv.enrichment_get("metadata") is not None
    assert cv.enrichment_get(enr.key) is not None

    enr_ctx = cv.enrichment_create("metadata_ctx", {"k": "v"}, context="source")
    assert cv.enrichment_get("metadata_ctx", "source") is not None
    assert cv.enrichment_get(enr_ctx.key) is not None


def test_threat_intel_addition() -> None:
    """Test adding threat intel to observable."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.ARTIFACT, "abc123")
    ti = cv.observable_add_threat_intel(obs.key, source="virustotal", score=Decimal("8.0"), comment="Malicious")
    assert ti is not None
    assert ti.source == "virustotal"
    assert ti.score == Decimal("8.0")
    assert obs.score == Decimal("8.0")  # Should propagate


def test_threat_intel_binding() -> None:
    """Test binding unbound threat intel to observable."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    draft = cv.threat_intel_draft(source="vt", score=Decimal("4.2"))

    bound = cv.observable_with_ti_draft(obs.key, draft)
    assert bound is not None
    assert draft.observable_key == obs.key
    assert bound.key == draft.key
    assert {ti.key for ti in obs.threat_intels} == {draft.key}


def test_string_levels_are_accepted_by_api() -> None:
    """Cyvest APIs should accept string level values."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com", level="safe")
    assert obs.level == Cyvest.LVL.SAFE

    check = cv.check_create("string_level", "desc", level="notable")
    assert check.level == Cyvest.LVL.NOTABLE

    ti = cv.observable_add_threat_intel(obs.key, source="vt", score=Decimal("5.0"), level="malicious")
    assert ti is not None
    assert ti.level == Cyvest.LVL.MALICIOUS

    cv.observable_set_level(obs.key, "trusted")
    assert cv.observable_get_all()[obs.key].level == Cyvest.LVL.TRUSTED


def test_check_creation() -> None:
    """Test creating checks."""
    cv = Cyvest()
    check = cv.check_create("test_check", "Test description", score=Decimal("5.0"))
    assert check.check_name == "test_check"
    assert check.score == Decimal("5.0")
    assert cv.check_get(check.key) is not None


def test_check_observable_linking() -> None:
    """Test linking observables to checks."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.URL, "https://bad.com")
    check = cv.check_create("url_check", "Check URL")
    cv.check_link_observable(check.key, obs.key)
    assert any(link.observable_key == obs.key for link in check.observable_links)


def test_container_creation() -> None:
    """Test creating containers."""
    cv = Cyvest()
    ctr = cv.container_create("network_analysis", "Network analysis container")
    assert ctr.path == "network_analysis"
    assert cv.container_get(ctr.key) is not None


def test_container_check_addition() -> None:
    """Test adding checks to containers."""
    cv = Cyvest()
    check = cv.check_create("c1", "d1")
    ctr = cv.container_create("test_container")
    cv.container_add_check(ctr.key, check.key)
    assert any(c.key == check.key for c in ctr.checks)


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
    assert cv.get_global_level() == Cyvest.LVL.MALICIOUS


def test_statistics() -> None:
    """Test statistics gathering."""
    cv = Cyvest()
    cv.observable_create(Cyvest.OBS.URL, "https://example.com")
    cv.observable_create(Cyvest.OBS.IPV4, "192.168.1.1")
    cv.check_create("c1", "network", "desc")
    stats = cv.get_statistics()
    assert stats.total_observables >= 2  # Plus root
    assert stats.total_checks == 1


def test_investigation_whitelisting_flag() -> None:
    """Investigation can hold multiple whitelist entries and remove them."""
    cv = Cyvest()
    assert cv.investigation_is_whitelisted() is False
    assert cv.investigation_get_whitelists() == ()

    cv.investigation_add_whitelist("id-1", "False positive", "Sandbox reason")
    cv.investigation_add_whitelist("id-2", "Customer allowlist")

    whitelists = cv.investigation_get_whitelists()
    assert len(whitelists) == 2
    assert any(entry.identifier == "id-1" and entry.justification == "Sandbox reason" for entry in whitelists)
    assert cv.investigation_is_whitelisted() is True

    removed = cv.investigation_remove_whitelist("id-1")
    assert removed is True
    assert len(cv.investigation_get_whitelists()) == 1

    cv.investigation_clear_whitelists()
    assert cv.investigation_is_whitelisted() is False
    assert cv.investigation_get_whitelists() == ()


def test_investigation_merge() -> None:
    """Test merging investigations."""
    cv1 = Cyvest()
    cv1.observable_create(Cyvest.OBS.URL, "https://example.com")
    cv1.check_create("c1", "s1", "d1", score=Decimal("3.0"))

    cv2 = Cyvest()
    cv2.observable_create(Cyvest.OBS.IPV4, "192.168.1.1")
    cv2.check_create("c2", "s2", "d2", score=Decimal("2.0"))

    # Merge cv2 into cv1
    cv1.merge_investigation(cv2)

    # Should have observables from both (plus roots)
    all_obs = cv1.observable_get_all()
    assert len(all_obs) >= 3
    all_checks = cv1.check_get_all()
    assert len(all_checks) == 2
    assert cv1.get_global_score() == Decimal("5.0")


def test_merge_investigation_copies_incoming_objects() -> None:
    """Merged investigations should not share object references."""
    cv_main = Cyvest()
    cv_other = Cyvest()
    obs = cv_other.observable_create(Cyvest.OBS.IPV4, "192.0.2.1")

    cv_main.merge_investigation(cv_other)

    assert cv_other.observable_get(obs.key) is not None
    assert len(cv_other.observable_get(obs.key).threat_intels) == 0

    cv_main.observable_add_threat_intel(obs.key, source="source1", score=Decimal("9.0"))

    assert len(cv_other.observable_get(obs.key).threat_intels) == 0


def test_root_observable() -> None:
    """Test root observable access."""
    cv = Cyvest()
    root = cv.observable_get_root()
    assert root is not None
    # Root should be accessible through API
    retrieved = cv.observable_get(root.key)
    assert retrieved is not None
    assert retrieved.key == root.key


def test_relationship_with_direction() -> None:
    """Test adding relationships with direction via Cyvest API."""
    cv = Cyvest()
    obs1 = cv.observable_create(Cyvest.OBS.URL, "https://example.com")
    obs2 = cv.observable_create(Cyvest.OBS.IPV4, "192.168.1.1")

    # Default direction (bidirectional)
    cv.observable_add_relationship(obs1.key, obs2.key, "related-to")
    assert obs1.relationships[0].direction == Cyvest.DIR.BIDIRECTIONAL

    # Explicit outbound
    cv.observable_add_relationship(obs1.key, obs2.key, "related-to", "outbound")
    assert obs1.relationships[1].direction == Cyvest.DIR.OUTBOUND

    # Explicit inbound
    cv.observable_add_relationship(obs1.key, obs2.key, "related-to", "inbound")
    assert obs1.relationships[2].direction == Cyvest.DIR.INBOUND


def test_relationship_semantic_defaults_via_api() -> None:
    """Test that Cyvest API uses semantic defaults for relationship directions."""
    cv = Cyvest()
    obs1 = cv.observable_create(Cyvest.OBS.URL, "https://example.com")
    obs2 = cv.observable_create(Cyvest.OBS.IPV4, "192.168.1.1")

    # No direction specified - uses BIDIRECTIONAL by default
    cv.observable_add_relationship(obs1.key, obs2.key, Cyvest.REL.RELATED_TO)
    assert obs1.relationships[0].direction == Cyvest.DIR.BIDIRECTIONAL


def test_finalize_relationships_single_orphan() -> None:
    """Test that finalize_relationships links single orphan observables to root."""
    cv = Cyvest()
    root = cv.observable_get_root()

    # Create an observable with no relationships
    orphan = cv.observable_create(Cyvest.OBS.IPV4, "192.168.1.1")

    # Finalize relationships
    cv.finalize_relationships()

    # Root should now have a relationship to the orphan
    root_targets = {rel.target_key for rel in root.relationships}
    assert orphan.key in root_targets

    # Check that the relationship type is RELATED_TO
    orphan_rel = next(rel for rel in root.relationships if rel.target_key == orphan.key)
    assert orphan_rel.relationship_type == Cyvest.REL.RELATED_TO


def test_finalize_relationships_orphan_subgraph() -> None:
    """Test that finalize_relationships links orphan sub-graphs to root."""
    cv = Cyvest()
    root = cv.observable_get_root()

    # Create a connected sub-graph: obs1 -> obs2 -> obs3
    obs1 = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    obs2 = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    obs3 = cv.observable_create(Cyvest.OBS.URL, "https://example.com/path")

    cv.observable_add_relationship(obs1.key, obs2.key, Cyvest.REL.RELATED_TO)
    cv.observable_add_relationship(obs2.key, obs3.key, Cyvest.REL.RELATED_TO)

    # This sub-graph is not connected to root
    # Finalize should link the starting node (obs1) to root
    cv.finalize_relationships()

    # Root should have a relationship to obs1 (the starting node)
    root_targets = {rel.target_key for rel in root.relationships}
    assert obs1.key in root_targets

    # obs2 and obs3 should NOT be directly linked to root
    assert obs2.key not in root_targets
    assert obs3.key not in root_targets


def test_finalize_relationships_multiple_orphan_subgraphs() -> None:
    """Test that finalize_relationships handles multiple orphan sub-graphs."""
    cv = Cyvest()
    root = cv.observable_get_root()

    # First sub-graph: sg1_a -> sg1_b
    sg1_a = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    sg1_b = cv.observable_create(Cyvest.OBS.DOMAIN, "sub1.com")
    cv.observable_add_relationship(sg1_a.key, sg1_b.key, Cyvest.REL.RELATED_TO)

    # Second sub-graph: sg2_a -> sg2_b -> sg2_c
    sg2_a = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.2")
    sg2_b = cv.observable_create(Cyvest.OBS.DOMAIN, "sub2.com")
    sg2_c = cv.observable_create(Cyvest.OBS.URL, "https://sub2.com")
    cv.observable_add_relationship(sg2_a.key, sg2_b.key, Cyvest.REL.RELATED_TO)
    cv.observable_add_relationship(sg2_b.key, sg2_c.key, Cyvest.REL.RELATED_TO)

    # Third isolated orphan
    sg3_orphan = cv.observable_create(Cyvest.OBS.ARTIFACT, "abc123")

    cv.finalize_relationships()

    # Root should link to the starting node of each sub-graph
    root_targets = {rel.target_key for rel in root.relationships}
    assert sg1_a.key in root_targets  # Starting node of sub-graph 1
    assert sg2_a.key in root_targets  # Starting node of sub-graph 2
    assert sg3_orphan.key in root_targets  # Isolated orphan

    # Non-starting nodes should not be directly linked
    assert sg1_b.key not in root_targets
    assert sg2_b.key not in root_targets
    assert sg2_c.key not in root_targets


def test_finalize_relationships_preconnected_graph() -> None:
    """Test that finalize_relationships doesn't modify already connected graphs."""
    cv = Cyvest()
    root = cv.observable_get_root()

    # Create a graph already connected to root
    obs1 = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    obs2 = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")

    # Connect to root
    cv.observable_add_relationship(root.key, obs1.key, Cyvest.REL.RELATED_TO)
    cv.observable_add_relationship(obs1.key, obs2.key, Cyvest.REL.RELATED_TO)

    # Count relationships before finalize
    rel_count_before = len(root.relationships)

    cv.finalize_relationships()

    # Should not add any new relationships since everything is connected
    assert len(root.relationships) == rel_count_before


def test_finalize_relationships_complex_subgraph_selection() -> None:
    """Test that finalize_relationships selects the best starting node in complex sub-graphs."""
    cv = Cyvest()
    root = cv.observable_get_root()

    # Create a sub-graph with multiple potential starting nodes
    # Structure: source -> hub1 -> leaf1
    #                  -> hub2 -> leaf2
    source = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    hub1 = cv.observable_create(Cyvest.OBS.DOMAIN, "hub1.com")
    hub2 = cv.observable_create(Cyvest.OBS.DOMAIN, "hub2.com")
    leaf1 = cv.observable_create(Cyvest.OBS.URL, "https://hub1.com/page")
    leaf2 = cv.observable_create(Cyvest.OBS.URL, "https://hub2.com/page")

    cv.observable_add_relationship(source.key, hub1.key, Cyvest.REL.RELATED_TO)
    cv.observable_add_relationship(source.key, hub2.key, Cyvest.REL.RELATED_TO)
    cv.observable_add_relationship(hub1.key, leaf1.key, Cyvest.REL.RELATED_TO)
    cv.observable_add_relationship(hub2.key, leaf2.key, Cyvest.REL.RELATED_TO)

    cv.finalize_relationships()

    # Root should link to 'source' as it has no incoming edges and multiple outgoing
    root_targets = {rel.target_key for rel in root.relationships}
    assert source.key in root_targets

    # Other nodes should not be directly linked to root
    assert hub1.key not in root_targets
    assert hub2.key not in root_targets
    assert leaf1.key not in root_targets
    assert leaf2.key not in root_targets


def test_merge_safe_observable_preserves_safe_with_low_score() -> None:
    """Test that merging SAFE observable with low-score incoming preserves SAFE."""
    cv1 = Cyvest()
    # Create SAFE observable in first investigation
    obs1 = cv1.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.SAFE)
    assert obs1.level == Cyvest.LVL.SAFE

    cv2 = Cyvest()
    # Create same observable with INFO level (score=0) in second investigation
    obs2 = cv2.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.INFO)
    cv2.observable_add_threat_intel(obs2.key, source="ti_source", score=Decimal("0"))
    assert obs2.level == Cyvest.LVL.INFO

    # Merge cv2 into cv1
    cv1.merge_investigation(cv2)

    # SAFE level should be preserved
    merged_obs = cv1.observable_get(obs1.key)
    assert merged_obs.level == Cyvest.LVL.SAFE
    assert merged_obs.score == Decimal("0")


def test_merge_safe_observable_with_trusted_score() -> None:
    """Test that merging SAFE observable with TRUSTED-level incoming preserves SAFE."""
    cv1 = Cyvest()
    # Create SAFE observable
    obs1 = cv1.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.SAFE)

    cv2 = Cyvest()
    # Create same observable with negative score (TRUSTED level)
    obs2 = cv2.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com")
    cv2.observable_add_threat_intel(obs2.key, source="ti_source", score=Decimal("-1.0"))
    assert obs2.level == Cyvest.LVL.TRUSTED

    # Merge cv2 into cv1
    cv1.merge_investigation(cv2)

    # SAFE level should be preserved
    merged_obs = cv1.observable_get(obs1.key)
    assert merged_obs.level == Cyvest.LVL.SAFE
    # Score updates to reflect merged TI (max of TI sources = -1.0)
    assert merged_obs.score == Decimal("-1.0")


def test_merge_safe_observable_upgrades_with_notable() -> None:
    """Test that merging SAFE observable with NOTABLE-level incoming upgrades to NOTABLE."""
    cv1 = Cyvest()
    # Create SAFE observable
    obs1 = cv1.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.SAFE)

    cv2 = Cyvest()
    # Create same observable with NOTABLE level
    obs2 = cv2.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com")
    cv2.observable_add_threat_intel(obs2.key, source="ti_source", score=Decimal("2.0"))
    assert obs2.level == Cyvest.LVL.NOTABLE

    # Merge cv2 into cv1
    cv1.merge_investigation(cv2)

    # Should upgrade to NOTABLE
    merged_obs = cv1.observable_get(obs1.key)
    assert merged_obs.level == Cyvest.LVL.NOTABLE
    assert merged_obs.score == Decimal("2.0")


def test_merge_safe_observable_upgrades_with_malicious() -> None:
    """Test that merging SAFE observable with MALICIOUS-level incoming upgrades to MALICIOUS."""
    cv1 = Cyvest()
    # Create SAFE observable
    obs1 = cv1.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.SAFE)

    cv2 = Cyvest()
    # Create same observable with MALICIOUS level
    obs2 = cv2.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com")
    cv2.observable_add_threat_intel(obs2.key, source="ti_source", score=Decimal("6.0"))
    assert obs2.level == Cyvest.LVL.MALICIOUS

    # Merge cv2 into cv1
    cv1.merge_investigation(cv2)

    # Should upgrade to MALICIOUS
    merged_obs = cv1.observable_get(obs1.key)
    assert merged_obs.level == Cyvest.LVL.MALICIOUS
    assert merged_obs.score == Decimal("6.0")


def test_merge_non_safe_explicit_level_normal_behavior() -> None:
    """Test that merging keeps the highest score/derived level."""
    cv1 = Cyvest()
    # Create observable and raise its score to SUSPICIOUS.
    obs1 = cv1.observable_create(Cyvest.OBS.DOMAIN, "test.example.com")
    cv1.observable_set_level(obs1.key, Cyvest.LVL.SUSPICIOUS)
    cv1.observable_add_threat_intel(obs1.key, source="source1", score=Decimal("4.0"))

    cv2 = Cyvest()
    # Create same observable with lower score
    obs2 = cv2.observable_create(Cyvest.OBS.DOMAIN, "test.example.com")
    cv2.observable_add_threat_intel(obs2.key, source="source2", score=Decimal("2.0"))

    # Merge cv2 into cv1
    cv1.merge_investigation(cv2)

    merged_obs = cv1.observable_get(obs1.key)
    # Score should be max(4.0, 2.0) = 4.0
    assert merged_obs.score == Decimal("4.0")
    # Level stays SUSPICIOUS (score=4.0 => SUSPICIOUS)
    assert merged_obs.level == Cyvest.LVL.SUSPICIOUS


def test_observable_proxy_is_read_only() -> None:
    """Observable proxies should block direct attribute mutation."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.IPV4, "203.0.113.5")

    with pytest.raises(AttributeError):
        obs.score = Decimal("5")  # type: ignore[misc]

    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("4.0"))
    assert obs.score == Decimal("4.0")


def test_check_proxy_is_read_only() -> None:
    """Check proxies should only change through Cyvest services."""
    cv = Cyvest()
    check_proxy = cv.check("chk-1", "scoped", "desc").with_score(Decimal("2.0"))

    with pytest.raises(AttributeError):
        check_proxy.score = Decimal("3.0")  # type: ignore[misc]

    cv.check_update_score(check_proxy.key, Decimal("3.0"))
    assert check_proxy.score == Decimal("3.0")


def test_io_save_load_json_roundtrip() -> None:
    """Test saving and loading investigation from JSON."""
    # Create investigation with various components
    cv = Cyvest()
    obs1 = cv.observable_create(Cyvest.OBS.IPV4, "192.168.1.1", internal=False)
    cv.observable_add_threat_intel(obs1.key, source="virustotal", score=Decimal("7.5"), comment="Malicious IP")

    obs2 = cv.observable_create(Cyvest.OBS.DOMAIN, "evil.com", internal=False)
    cv.observable_add_threat_intel(obs2.key, source="urlscan", score=Decimal("8.0"))

    cv.observable_add_relationship(obs1.key, obs2.key, "related-to")

    check = cv.check_create("malware_check", "Detected malware communication", score=Decimal("9.0"))
    cv.check_link_observable(check.key, obs1.key)

    cv.enrichment_create("whois", {"registrar": "Evil Corp"}, context="Domain registration")

    # Save to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = f.name

    try:
        saved_path = cv.io_save_json(temp_path)
        assert Path(saved_path).exists()

        # Load and verify
        loaded_cv = Cyvest.io_load_json(temp_path)

        # Verify observables
        assert len(loaded_cv.observable_get_all()) == len(cv.observable_get_all())
        loaded_obs1 = loaded_cv.observable_get(obs1.key)
        assert loaded_obs1 is not None
        assert loaded_obs1.value == "192.168.1.1"
        assert loaded_obs1.score == Decimal("7.5")

        # Verify threat intel
        assert len(loaded_cv.threat_intel_get_all()) == len(cv.threat_intel_get_all())

        # Verify checks
        assert len(loaded_cv.check_get_all()) == len(cv.check_get_all())
        loaded_check = loaded_cv.check_get(check.key)
        assert loaded_check is not None
        assert loaded_check.check_name == "malware_check"
        assert any(link.observable_key == obs1.key for link in loaded_check.observable_links)

        # Verify enrichments
        assert len(loaded_cv.enrichment_get_all()) == len(cv.enrichment_get_all())

        # Verify scores match
        assert loaded_cv.get_global_score() == cv.get_global_score()
        assert loaded_cv.get_global_level() == cv.get_global_level()
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_io_save_json_returns_absolute_path() -> None:
    """Test that io_save_json returns absolute path."""
    cv = Cyvest()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        temp_path = f.name

    try:
        # Use relative path notation
        relative_path = Path(temp_path).name
        saved_path = cv.io_save_json(relative_path)

        # Should return absolute path
        assert Path(saved_path).is_absolute()
        assert saved_path.endswith(relative_path)
    finally:
        # Clean up both the relative and absolute paths
        Path(relative_path).unlink(missing_ok=True)
        Path(temp_path).unlink(missing_ok=True)


def test_io_save_markdown_returns_absolute_path() -> None:
    """Test that io_save_markdown returns absolute path."""
    cv = Cyvest()
    cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        temp_path = f.name

    try:
        saved_path = cv.io_save_markdown(temp_path)

        # Should return absolute path
        assert Path(saved_path).is_absolute()
        assert Path(saved_path).exists()

        # Verify content
        content = Path(saved_path).read_text()
        assert "# Cybersecurity Investigation Report" in content
        assert "10.0.0.1" in content
    finally:
        Path(temp_path).unlink(missing_ok=True)


def test_io_to_invest_serialization() -> None:
    """Test InvestigationSchema serialization contains expected fields."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.URL, "https://malicious.com")
    cv.observable_add_threat_intel(obs.key, source="virustotal", score=Decimal("6.0"))
    cv.check_create("url_check", "network", "URL analysis")

    schema = cv.io_to_invest()

    # Verify all expected fields exist via attribute access
    assert hasattr(schema, "investigation_id")
    assert hasattr(schema, "score")
    assert hasattr(schema, "level")
    assert hasattr(schema, "observables")
    assert hasattr(schema, "checks")
    assert hasattr(schema, "threat_intels")
    assert hasattr(schema, "enrichments")
    assert hasattr(schema, "containers")
    assert hasattr(schema, "stats")
    assert hasattr(schema, "whitelists")

    # Verify values
    assert schema.score >= 0
    assert schema.level in Cyvest.LVL

    # Test model_dump() for dict compatibility
    data = schema.model_dump(by_alias=True)
    assert "investigation_id" in data
    assert "score" in data
    assert "observables" in data

    # Verify data structure
    assert isinstance(data["observables"], dict)
    assert isinstance(data["checks"], dict)
    assert isinstance(data["threat_intels"], dict)
    assert isinstance(data["whitelists"], list)

    # Verify content
    assert obs.key in data["observables"]
    assert data["observables"][obs.key]["value"] == "https://malicious.com"


def test_io_to_invest_include_audit_log_default() -> None:
    """Test that io_to_invest includes audit_log by default."""
    cv = Cyvest()
    cv.observable_create(Cyvest.OBS.URL, "https://example.com")

    schema = cv.io_to_invest()

    # By default, audit_log should be a list with events
    assert schema.audit_log is not None
    assert isinstance(schema.audit_log, list)
    assert len(schema.audit_log) > 0  # At least INVESTIGATION_STARTED event


def test_io_to_invest_exclude_audit_log() -> None:
    """Test that io_to_invest can exclude audit_log."""
    cv = Cyvest()
    cv.observable_create(Cyvest.OBS.URL, "https://example.com")

    schema = cv.io_to_invest(include_audit_log=False)

    # audit_log should be None when disabled
    assert schema.audit_log is None

    # Verify JSON output has null
    data = schema.model_dump(mode="json", by_alias=True)
    assert data["audit_log"] is None


def test_io_save_json_exclude_audit_log(tmp_path) -> None:
    """Test that io_save_json can exclude audit_log from output."""
    import json

    cv = Cyvest()
    cv.observable_create(Cyvest.OBS.DOMAIN, "test.com")

    filepath = tmp_path / "investigation.json"

    # Save without audit_log
    cv.io_save_json(str(filepath), include_audit_log=False)

    # Verify JSON content
    with open(filepath) as f:
        data = json.load(f)

    assert data["audit_log"] is None


def test_io_save_json_include_audit_log_default(tmp_path) -> None:
    """Test that io_save_json includes audit_log by default."""
    import json

    cv = Cyvest()
    cv.observable_create(Cyvest.OBS.DOMAIN, "test.com")

    filepath = tmp_path / "investigation.json"

    # Save with default (include audit_log)
    cv.io_save_json(str(filepath))

    # Verify JSON content
    with open(filepath) as f:
        data = json.load(f)

    assert data["audit_log"] is not None
    assert isinstance(data["audit_log"], list)
    assert len(data["audit_log"]) > 0


def test_io_to_markdown_generates_report() -> None:
    """Test Markdown report generation."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "test.com", internal=False)
    cv.observable_add_threat_intel(obs.key, source="abuse.ch", score=Decimal("5.0"))
    check = cv.check_create("domain_check", "DNS analysis", score=Decimal("4.0"), level=Cyvest.LVL.SUSPICIOUS)
    cv.check_link_observable(check.key, obs.key)

    markdown = cv.io_to_markdown()

    # Verify markdown structure
    assert "# Cybersecurity Investigation Report" in markdown
    assert "## Statistics" in markdown
    assert "## Observables" in markdown
    assert "## Checks" in markdown

    # Verify content
    assert "test.com" in markdown
    assert "abuse.ch" in markdown
    assert "DNS analysis" in markdown
    assert "domain_check" in markdown


def test_io_load_json_with_nonexistent_file() -> None:
    """Test that loading nonexistent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        Cyvest.io_load_json("/nonexistent/path/to/file.json")


def test_io_save_json_with_invalid_path() -> None:
    """Test that saving to invalid path raises OSError."""
    cv = Cyvest()

    # Try to write to a directory that doesn't exist
    with pytest.raises(OSError):
        cv.io_save_json("/nonexistent/directory/investigation.json")
