"""
Tests for the reworked score algorithm.

Tests MAX vs SUM modes, finding score calculation, and hierarchical propagation.
"""

from decimal import Decimal

from cyvest import Cyvest
from cyvest.score import ScoreMode


def test_observable_starts_with_zero_score_info_level() -> None:
    """Test that observables start with score 0 and level INFO."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.IPV4, "192.168.1.1")

    assert obs.score == Decimal("0")
    assert obs.level == Cyvest.LVL.INFO


def test_max_mode_threat_intel_scores() -> None:
    """Test MAX mode: observable score = max(all TI scores, all child scores)."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    # Create observable with multiple threat intel sources
    obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("3.0"))
    cv.observable_add_threat_intel(obs.key, source="source2", score=Decimal("7.0"))
    cv.observable_add_threat_intel(obs.key, source="source3", score=Decimal("2.0"))

    # In MAX mode, observable score should be max of TI scores = 7.0
    assert obs.score == Decimal("7.0")
    assert obs.level == Cyvest.LVL.MALICIOUS


def test_sum_mode_threat_intel_scores() -> None:
    """Test SUM mode: observable score = max(TI scores) + sum(child scores)."""
    cv = Cyvest(score_mode_obs=ScoreMode.SUM)

    # Create observable with multiple threat intel sources
    obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("3.0"))
    cv.observable_add_threat_intel(obs.key, source="source2", score=Decimal("7.0"))
    cv.observable_add_threat_intel(obs.key, source="source3", score=Decimal("2.0"))

    # In SUM mode with no children, score should be max of TI scores = 7.0
    assert obs.score == Decimal("7.0")
    assert obs.level == Cyvest.LVL.MALICIOUS


def test_max_mode_hierarchical_scoring() -> None:
    """Test MAX mode with hierarchical relationships."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    # Create domain with TI score 2.0
    domain = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    cv.observable_add_threat_intel(domain.key, source="source1", score=Decimal("2.0"))

    # Create IP with TI score 8.0
    ip = cv.observable_create(Cyvest.OBS.IPV4, "1.2.3.4")
    cv.observable_add_threat_intel(ip.key, source="source2", score=Decimal("8.0"))

    # Domain relates to IP (hierarchical via outbound direction)
    cv.observable_add_relationship(domain.key, ip.key, "related-to", "outbound")

    # In MAX mode, domain score = max(domain TI=2.0, ip score=8.0) = 8.0
    assert domain.score == Decimal("8.0")
    assert domain.level == Cyvest.LVL.MALICIOUS


def test_sum_mode_hierarchical_scoring() -> None:
    """Test SUM mode with hierarchical relationships."""
    cv = Cyvest(score_mode_obs=ScoreMode.SUM)

    # Create domain with TI score 2.0
    domain = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    cv.observable_add_threat_intel(domain.key, source="source1", score=Decimal("2.0"))

    # Create IP with TI score 8.0
    ip = cv.observable_create(Cyvest.OBS.IPV4, "1.2.3.4")
    cv.observable_add_threat_intel(ip.key, source="source2", score=Decimal("8.0"))

    # Domain relates to IP (hierarchical via outbound direction)
    cv.observable_add_relationship(domain.key, ip.key, "related-to", "outbound")

    # In SUM mode, domain score = max(domain TI=2.0) + sum(child scores=8.0) = 10.0
    assert domain.score == Decimal("10.0")
    assert domain.level == Cyvest.LVL.MALICIOUS


def test_max_mode_multiple_children() -> None:
    """Test MAX mode with multiple child observables."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    # Create parent with TI score 1.0
    parent = cv.observable_create(Cyvest.OBS.DOMAIN, "parent.com")
    cv.observable_add_threat_intel(parent.key, source="source1", score=Decimal("1.0"))

    # Create children with different scores
    child1 = cv.observable_create(Cyvest.OBS.IPV4, "1.1.1.1")
    cv.observable_add_threat_intel(child1.key, source="source2", score=Decimal("3.0"))

    child2 = cv.observable_create(Cyvest.OBS.IPV4, "2.2.2.2")
    cv.observable_add_threat_intel(child2.key, source="source3", score=Decimal("6.0"))

    child3 = cv.observable_create(Cyvest.OBS.IPV4, "3.3.3.3")
    cv.observable_add_threat_intel(child3.key, source="source4", score=Decimal("2.0"))

    # Connect parent to children
    cv.observable_add_relationship(parent.key, child1.key, "related-to", "outbound")
    cv.observable_add_relationship(parent.key, child2.key, "related-to", "outbound")
    cv.observable_add_relationship(parent.key, child3.key, "related-to", "outbound")

    # In MAX mode, parent score = max(1.0, 3.0, 6.0, 2.0) = 6.0
    assert parent.score == Decimal("6.0")
    assert parent.level == Cyvest.LVL.MALICIOUS


def test_sum_mode_multiple_children() -> None:
    """Test SUM mode with multiple child observables."""
    cv = Cyvest(score_mode_obs=ScoreMode.SUM)

    # Create parent with TI score 1.0
    parent = cv.observable_create(Cyvest.OBS.DOMAIN, "parent.com")
    cv.observable_add_threat_intel(parent.key, source="source1", score=Decimal("1.0"))

    # Create children with different scores
    child1 = cv.observable_create(Cyvest.OBS.IPV4, "1.1.1.1")
    cv.observable_add_threat_intel(child1.key, source="source2", score=Decimal("3.0"))

    child2 = cv.observable_create(Cyvest.OBS.IPV4, "2.2.2.2")
    cv.observable_add_threat_intel(child2.key, source="source3", score=Decimal("6.0"))

    child3 = cv.observable_create(Cyvest.OBS.IPV4, "3.3.3.3")
    cv.observable_add_threat_intel(child3.key, source="source4", score=Decimal("2.0"))

    # Connect parent to children
    cv.observable_add_relationship(parent.key, child1.key, "related-to", "outbound")
    cv.observable_add_relationship(parent.key, child2.key, "related-to", "outbound")
    cv.observable_add_relationship(parent.key, child3.key, "related-to", "outbound")

    # In SUM mode, parent score = max(parent TI=1.0) + sum(children=3.0+6.0+2.0) = 1.0 + 11.0 = 12.0
    assert parent.score == Decimal("12.0")
    assert parent.level == Cyvest.LVL.MALICIOUS


def test_finding_score_from_single_observable() -> None:
    """Test finding score calculation from a single linked observable."""
    cv = Cyvest()

    # Create finding with initial score 0
    finding = cv.finding_create("finding1", "test", "Test finding")
    assert finding.score == Decimal("0")
    assert finding.level == Cyvest.LVL.NONE

    # Create observable and add TI
    obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("5.0"))

    # Link observable to finding
    cv.finding_link_observable(finding.key, obs.key)

    # Finding score should be max of linked observable scores and finding's current score
    # max([5.0, 0.0]) = 5.0
    assert finding.score == Decimal("5.0")
    assert finding.level == Cyvest.LVL.MALICIOUS


def test_finding_score_from_multiple_observables() -> None:
    """Test finding score calculation from multiple linked observables."""
    cv = Cyvest()

    # Create finding
    finding = cv.finding_create("finding1", "test", "Test finding")

    # Create multiple observables with different scores
    obs1 = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.observable_add_threat_intel(obs1.key, source="source1", score=Decimal("3.0"))

    obs2 = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.2")
    cv.observable_add_threat_intel(obs2.key, source="source2", score=Decimal("7.0"))

    obs3 = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.3")
    cv.observable_add_threat_intel(obs3.key, source="source3", score=Decimal("2.0"))

    # Link all observables to finding
    cv.finding_link_observable(finding.key, obs1.key)
    cv.finding_link_observable(finding.key, obs2.key)
    cv.finding_link_observable(finding.key, obs3.key)

    # Finding score should be max of all linked observable scores
    # max([3.0, 7.0, 2.0, 0.0]) = 7.0
    assert finding.score == Decimal("7.0")
    assert finding.level == Cyvest.LVL.MALICIOUS


def test_finding_score_preserves_higher_current_score() -> None:
    """Test that finding score includes its current score in max calculation."""
    cv = Cyvest()

    # Create finding with initial score 5.0
    finding = cv.finding_create("finding1", "test", "Test finding", score=Decimal("5.0"))
    assert finding.score == Decimal("5.0")

    # Create observable with lower score
    obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("3.0"))

    # Link observable to finding
    cv.finding_link_observable(finding.key, obs.key)

    # Finding score should remain at max([3.0, 5.0]) = 5.0 (no change)
    assert finding.score == Decimal("5.0")

    # Now add a higher scoring observable
    obs2 = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.2")
    cv.observable_add_threat_intel(obs2.key, source="source2", score=Decimal("8.0"))
    cv.finding_link_observable(finding.key, obs2.key)

    # Finding score should now be max([3.0, 8.0, 5.0]) = 8.0
    assert finding.score == Decimal("8.0")
    assert finding.level == Cyvest.LVL.MALICIOUS


def test_score_propagation_through_hierarchy() -> None:
    """Test score propagation through multi-level hierarchy in MAX mode."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    # Create 3-level hierarchy: grandparent -> parent -> child
    grandparent = cv.observable_create(Cyvest.OBS.DOMAIN, "grandparent.com")
    cv.observable_add_threat_intel(grandparent.key, source="source1", score=Decimal("1.0"))

    parent = cv.observable_create(Cyvest.OBS.DOMAIN, "parent.com")
    cv.observable_add_threat_intel(parent.key, source="source2", score=Decimal("2.0"))

    child = cv.observable_create(Cyvest.OBS.IPV4, "1.2.3.4")
    cv.observable_add_threat_intel(child.key, source="source3", score=Decimal("9.0"))

    # Connect hierarchy
    cv.observable_add_relationship(grandparent.key, parent.key, "related-to", "outbound")
    cv.observable_add_relationship(parent.key, child.key, "related-to", "outbound")

    # In MAX mode:
    # child score = 9.0 (its own TI)
    # parent score = max(2.0, 9.0) = 9.0
    # grandparent score = max(1.0, 9.0) = 9.0
    assert child.score == Decimal("9.0")
    assert parent.score == Decimal("9.0")
    assert grandparent.score == Decimal("9.0")
    assert grandparent.level == Cyvest.LVL.MALICIOUS


def test_score_propagation_updates_parent() -> None:
    """Test that updating child score propagates to parent."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    # Create parent and child
    parent = cv.observable_create(Cyvest.OBS.DOMAIN, "parent.com")
    cv.observable_add_threat_intel(parent.key, source="source1", score=Decimal("1.0"))

    child = cv.observable_create(Cyvest.OBS.IPV4, "1.2.3.4")
    cv.observable_add_threat_intel(child.key, source="source2", score=Decimal("2.0"))

    # Connect them
    cv.observable_add_relationship(parent.key, child.key, "related-to", "outbound")

    # Parent score should be max(1.0, 2.0) = 2.0
    assert parent.score == Decimal("2.0")

    # Add more threat intel to child
    cv.observable_add_threat_intel(child.key, source="source3", score=Decimal("8.0"))

    # Parent score should update to max(1.0, 8.0) = 8.0
    assert child.score == Decimal("8.0")
    assert parent.score == Decimal("8.0")
    assert parent.level == Cyvest.LVL.MALICIOUS


def test_inbound_relationship_propagation() -> None:
    """Test that INBOUND relationships correctly identify parents for score propagation."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    # Create file with INBOUND relationship to URL (file ← URL means URL is parent)
    malware_file = cv.observable_create(Cyvest.OBS.FILE, "malware.exe")
    cv.observable_add_threat_intel(malware_file.key, source="av", score=Decimal("9.0"))

    download_url = cv.observable_create(Cyvest.OBS.URL, "http://evil.com/malware.exe")
    cv.observable_add_threat_intel(download_url.key, source="urlscan", score=Decimal("2.0"))

    # Add INBOUND relationship: file ← URL (URL downloaded the file, URL is parent)
    cv.observable_add_relationship(malware_file.key, download_url.key, "downloaded", Cyvest.DIR.INBOUND)

    # File has INBOUND to URL, so URL is parent and should get file's score
    # URL score = max(2.0, 9.0) = 9.0
    assert malware_file.score == Decimal("9.0")
    assert download_url.score == Decimal("9.0")
    assert download_url.level == Cyvest.LVL.MALICIOUS


def test_bidirectional_relationship_no_propagation() -> None:
    """Test that BIDIRECTIONAL relationships do not participate in hierarchical score propagation."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    # Create two hosts with bidirectional communication
    host1 = cv.observable_create(Cyvest.OBS.IPV4, "10.0.1.10")
    cv.observable_add_threat_intel(host1.key, source="ids", score=Decimal("8.0"))

    host2 = cv.observable_create(Cyvest.OBS.IPV4, "10.0.1.20")
    cv.observable_add_threat_intel(host2.key, source="ids", score=Decimal("1.0"))

    # Add BIDIRECTIONAL relationship (symmetric, no hierarchy)
    cv.observable_add_relationship(host1.key, host2.key, "communicates-with", Cyvest.DIR.BIDIRECTIONAL)

    # Bidirectional relationships should NOT propagate scores hierarchically
    # Each host keeps only its own TI score
    assert host1.score == Decimal("8.0")
    assert host2.score == Decimal("1.0")


def test_outbound_vs_inbound_direction_semantics() -> None:
    """Test that OUTBOUND and INBOUND create opposite parent-child relationships."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    # Scenario 1: OUTBOUND - domain → IP (IP is child of domain)
    domain1 = cv.observable_create(Cyvest.OBS.DOMAIN, "example1.com")
    cv.observable_add_threat_intel(domain1.key, source="source1", score=Decimal("1.0"))

    ip1 = cv.observable_create(Cyvest.OBS.IPV4, "1.1.1.1")
    cv.observable_add_threat_intel(ip1.key, source="source2", score=Decimal("7.0"))

    cv.observable_add_relationship(domain1.key, ip1.key, "related-to", Cyvest.DIR.OUTBOUND)

    # Domain has OUTBOUND to IP, so IP is child, domain gets child's score
    # domain1 score = max(1.0, 7.0) = 7.0
    assert domain1.score == Decimal("7.0")
    assert ip1.score == Decimal("7.0")

    # Scenario 2: INBOUND - domain ← IP (IP is parent of domain)
    domain2 = cv.observable_create(Cyvest.OBS.DOMAIN, "example2.com")
    cv.observable_add_threat_intel(domain2.key, source="source3", score=Decimal("8.0"))

    ip2 = cv.observable_create(Cyvest.OBS.IPV4, "2.2.2.2")
    cv.observable_add_threat_intel(ip2.key, source="source4", score=Decimal("2.0"))

    cv.observable_add_relationship(domain2.key, ip2.key, "related-to", Cyvest.DIR.INBOUND)

    # Domain has INBOUND to IP, so IP is parent, IP gets domain's score
    # ip2 score = max(2.0, 8.0) = 8.0
    assert domain2.score == Decimal("8.0")
    assert ip2.score == Decimal("8.0")


def test_mixed_directions_in_hierarchy() -> None:
    """Test score propagation with mixed OUTBOUND and INBOUND relationships."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    # Create a chain: A → B ← C
    # A has OUTBOUND to B (B is child of A)
    # C has INBOUND to B (B is parent of C)

    obs_a = cv.observable_create(Cyvest.OBS.DOMAIN, "a.com")
    cv.observable_add_threat_intel(obs_a.key, source="source1", score=Decimal("2.0"))

    obs_b = cv.observable_create(Cyvest.OBS.IPV4, "1.1.1.1")
    cv.observable_add_threat_intel(obs_b.key, source="source2", score=Decimal("3.0"))

    obs_c = cv.observable_create(Cyvest.OBS.URL, "http://c.com")
    cv.observable_add_threat_intel(obs_c.key, source="source3", score=Decimal("9.0"))

    # A → B (B is child of A)
    cv.observable_add_relationship(obs_a.key, obs_b.key, "related-to", Cyvest.DIR.OUTBOUND)

    # C has INBOUND to B (B is parent of C)
    cv.observable_add_relationship(obs_c.key, obs_b.key, "related-to", Cyvest.DIR.INBOUND)

    # obs_c score = 9.0 (its own TI)
    # obs_b is parent of obs_c, so gets max(3.0, 9.0) = 9.0
    # obs_a has obs_b as child, so gets max(2.0, 9.0) = 9.0
    assert obs_c.score == Decimal("9.0")
    assert obs_b.score == Decimal("9.0")
    assert obs_a.score == Decimal("9.0")


def test_explicit_direction_override() -> None:
    """Test that explicitly setting direction overrides semantic defaults."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    domain = cv.observable_create(Cyvest.OBS.DOMAIN, "override.com")
    cv.observable_add_threat_intel(domain.key, source="source1", score=Decimal("1.0"))

    ip = cv.observable_create(Cyvest.OBS.IPV4, "3.3.3.3")
    cv.observable_add_threat_intel(ip.key, source="source2", score=Decimal("8.0"))

    # Override default BIDIRECTIONAL to OUTBOUND to enable hierarchy
    cv.observable_add_relationship(domain.key, ip.key, Cyvest.REL.RELATED_TO, Cyvest.DIR.OUTBOUND)

    # OUTBOUND means ip is a child; its score propagates to the domain
    assert domain.score == Decimal("8.0")
    assert ip.score == Decimal("8.0")

    # Verify the relationship has OUTBOUND direction
    assert domain.relationships[0].direction == Cyvest.DIR.OUTBOUND


def test_sum_mode_with_direction_based_children() -> None:
    """Test SUM mode score calculation with direction-based child detection."""
    cv = Cyvest(score_mode_obs=ScoreMode.SUM)

    # Parent with multiple children via OUTBOUND relationships
    parent = cv.observable_create(Cyvest.OBS.DOMAIN, "parent.com")
    cv.observable_add_threat_intel(parent.key, source="source1", score=Decimal("1.0"))

    child1 = cv.observable_create(Cyvest.OBS.IPV4, "1.1.1.1")
    cv.observable_add_threat_intel(child1.key, source="source2", score=Decimal("3.0"))

    child2 = cv.observable_create(Cyvest.OBS.IPV4, "2.2.2.2")
    cv.observable_add_threat_intel(child2.key, source="source3", score=Decimal("5.0"))

    # Add OUTBOUND relationships
    cv.observable_add_relationship(parent.key, child1.key, "related-to", Cyvest.DIR.OUTBOUND)
    cv.observable_add_relationship(parent.key, child2.key, "related-to", Cyvest.DIR.OUTBOUND)

    # Also add one BIDIRECTIONAL that should be ignored
    noise_obs = cv.observable_create(Cyvest.OBS.IPV4, "9.9.9.9")
    cv.observable_add_threat_intel(noise_obs.key, source="source4", score=Decimal("100.0"))
    cv.observable_add_relationship(parent.key, noise_obs.key, "related-to", Cyvest.DIR.BIDIRECTIONAL)

    # In SUM mode: parent score = max(parent TI=1.0) + sum(OUTBOUND children = 3.0 + 5.0) = 9.0
    # BIDIRECTIONAL relationship should NOT contribute
    assert parent.score == Decimal("9.0")
    assert noise_obs.score == Decimal("100.0")  # Keeps its own score


def test_safe_level_explicit_creation() -> None:
    """Test that observable created with level=SAFE is SAFE."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.SAFE)

    assert obs.score == Decimal("0")
    assert obs.level == Cyvest.LVL.SAFE


def test_safe_level_prevents_info_downgrade() -> None:
    """Test that SAFE observable stays SAFE when receiving INFO level threat intel."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.SAFE)

    # Add threat intel with score=0 (would be INFO level)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("0"))

    # Score updates but level stays SAFE
    assert obs.score == Decimal("0")
    assert obs.level == Cyvest.LVL.SAFE


def test_safe_level_prevents_trusted_downgrade() -> None:
    """Test that SAFE observable stays SAFE when receiving TRUSTED level threat intel."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.SAFE)

    # Add threat intel with negative score (would be TRUSTED level)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("-1.0"))

    # Score updates but level stays SAFE (TRUSTED < SAFE)
    assert obs.score == Decimal("-1.0")
    assert obs.level == Cyvest.LVL.SAFE


def test_safe_level_allows_notable_upgrade() -> None:
    """Test that SAFE observable upgrades to NOTABLE with appropriate threat intel."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.SAFE)

    # Add threat intel with score=2.0 (NOTABLE level, which is > SAFE)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("2.0"))

    # Both score and level upgrade
    assert obs.score == Decimal("2.0")
    assert obs.level == Cyvest.LVL.NOTABLE


def test_safe_level_allows_suspicious_upgrade() -> None:
    """Test that SAFE observable upgrades to SUSPICIOUS with appropriate threat intel."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.SAFE)

    # Add threat intel with score=4.0 (SUSPICIOUS level)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("4.0"))

    # Both score and level upgrade
    assert obs.score == Decimal("4.0")
    assert obs.level == Cyvest.LVL.SUSPICIOUS


def test_safe_level_allows_malicious_upgrade() -> None:
    """Test that SAFE observable upgrades to MALICIOUS with appropriate threat intel."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=0, level=Cyvest.LVL.SAFE)

    # Add threat intel with score=6.0 (MALICIOUS level)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("6.0"))

    # Both score and level upgrade
    assert obs.score == Decimal("6.0")
    assert obs.level == Cyvest.LVL.MALICIOUS


def test_safe_level_score_updates_with_frozen_level() -> None:
    """Test that SAFE observable score updates even when level stays SAFE."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", score=Decimal("-1.0"), level=Cyvest.LVL.SAFE)

    # Initial state: score=-1.0 (would be TRUSTED), level=SAFE
    assert obs.score == Decimal("-1.0")
    assert obs.level == Cyvest.LVL.SAFE

    # Add threat intel with score=0 (would be INFO, still < SAFE)
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("0"))

    # Score should update to 0 (max of -1.0 and 0), but level stays SAFE
    assert obs.score == Decimal("0")
    assert obs.level == Cyvest.LVL.SAFE  # Level frozen at SAFE even though score=0 would be INFO


def test_non_safe_levels_recalculate_and_can_downgrade() -> None:
    """Non-SAFE levels are recalculated from score and can downgrade."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "test.example.com")

    # Manually set to SUSPICIOUS through Cyvest service layer
    cv.observable_set_level(obs.key, Cyvest.LVL.SUSPICIOUS)
    assert obs.level == Cyvest.LVL.SUSPICIOUS

    # Add threat intel with lower score (NOTABLE)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("2.0"))

    # Score=2.0 gives NOTABLE which is < SUSPICIOUS, so level downgrades to NOTABLE.
    assert obs.score == Decimal("2.0")
    assert obs.level == Cyvest.LVL.NOTABLE


def test_threat_intel_with_safe_level_upgrades_info_observable() -> None:
    """Test that threat intel with SAFE level upgrades an INFO observable to SAFE."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com")

    # Observable starts with INFO level
    assert obs.level == Cyvest.LVL.INFO

    # Add threat intel with SAFE level
    cv.observable_add_threat_intel(obs.key, source="whitelist_db", score=Decimal("0"), level=Cyvest.LVL.SAFE)

    # Observable should now be SAFE
    assert obs.level == Cyvest.LVL.SAFE


def test_threat_intel_with_safe_level_upgrades_trusted_observable() -> None:
    """Test that threat intel with SAFE level upgrades a TRUSTED observable to SAFE."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")

    # Add TI with negative score to get TRUSTED level
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("-1.0"))
    assert obs.level == Cyvest.LVL.TRUSTED

    # Add threat intel with SAFE level
    cv.observable_add_threat_intel(obs.key, source="whitelist_db", score=Decimal("0"), level=Cyvest.LVL.SAFE)

    # Observable should now be SAFE
    assert obs.level == Cyvest.LVL.SAFE


def test_threat_intel_with_safe_level_does_not_downgrade_notable() -> None:
    """Test that threat intel with SAFE level doesn't downgrade NOTABLE observable."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")

    # Add TI to get NOTABLE level
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("2.0"))
    assert obs.level == Cyvest.LVL.NOTABLE

    # Add threat intel with SAFE level (lower than NOTABLE)
    cv.observable_add_threat_intel(obs.key, source="whitelist_db", score=Decimal("0"), level=Cyvest.LVL.SAFE)

    # Observable should stay NOTABLE (SAFE < NOTABLE, so no downgrade)
    assert obs.level == Cyvest.LVL.NOTABLE


def test_threat_intel_with_safe_level_does_not_downgrade_malicious() -> None:
    """Test that threat intel with SAFE level doesn't downgrade MALICIOUS observable."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")

    # Add TI to get MALICIOUS level
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("6.0"))
    assert obs.level == Cyvest.LVL.MALICIOUS

    # Add threat intel with SAFE level (lower than MALICIOUS)
    cv.observable_add_threat_intel(obs.key, source="whitelist_db", score=Decimal("0"), level=Cyvest.LVL.SAFE)

    # Observable should stay MALICIOUS (no downgrade from SAFE TI)
    assert obs.level == Cyvest.LVL.MALICIOUS


def test_threat_intel_safe_then_malicious_upgrades() -> None:
    """Test that SAFE observable can still be upgraded by MALICIOUS threat intel."""
    cv = Cyvest()
    obs = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")

    # Add threat intel with SAFE level
    cv.observable_add_threat_intel(obs.key, source="whitelist_db", score=Decimal("0"), level=Cyvest.LVL.SAFE)
    assert obs.level == Cyvest.LVL.SAFE

    # Add threat intel with MALICIOUS score
    cv.observable_add_threat_intel(obs.key, source="virustotal", score=Decimal("8.0"))

    # Observable should upgrade to MALICIOUS
    assert obs.score == Decimal("8.0")
    assert obs.level == Cyvest.LVL.MALICIOUS


def test_threat_intel_safe_level_with_none_observable() -> None:
    """Test that threat intel with SAFE level upgrades NONE level observable."""
    cv = Cyvest()

    # Create a finding with NONE level
    finding = cv.finding_create("test_finding", "scope", "description")
    assert finding.level == Cyvest.LVL.NONE

    # Create observable starting at INFO
    obs = cv.observable_create(Cyvest.OBS.IPV4, "192.168.1.1")
    assert obs.level == Cyvest.LVL.INFO

    # Add threat intel with SAFE level to observable
    cv.observable_add_threat_intel(obs.key, source="whitelist", score=Decimal("0"), level=Cyvest.LVL.SAFE)

    # Observable should be SAFE
    assert obs.level == Cyvest.LVL.SAFE


def test_finding_inherits_safe_from_single_observable() -> None:
    """Test that a finding inherits SAFE level from a single SAFE observable."""
    cv = Cyvest()

    # Create finding
    finding = cv.finding_create("safe_finding", "test", "Test SAFE inheritance")
    assert finding.level == Cyvest.LVL.NONE

    # Create SAFE observable and link to finding
    safe_obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", level=Cyvest.LVL.SAFE)
    cv.finding_link_observable(finding.key, safe_obs.key)

    # Finding should inherit SAFE level
    assert finding.level == Cyvest.LVL.SAFE


def test_finding_inherits_safe_from_multiple_observables_all_lower() -> None:
    """Test that a finding inherits SAFE when has SAFE observable and others are lower."""
    cv = Cyvest()

    # Create finding
    finding = cv.finding_create("safe_finding", "test", "Test SAFE inheritance")

    # Create mixed observables: SAFE, INFO, TRUSTED
    safe_obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", level=Cyvest.LVL.SAFE)
    info_obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")  # default INFO level
    trusted_obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.2")
    cv.observable_add_threat_intel(trusted_obs.key, "source", score=Decimal("-1.0"))  # TRUSTED level

    # Link all to finding
    cv.finding_link_observable(finding.key, safe_obs.key)
    cv.finding_link_observable(finding.key, info_obs.key)
    cv.finding_link_observable(finding.key, trusted_obs.key)

    # Finding should inherit SAFE level (all observables <= SAFE)
    assert finding.level == Cyvest.LVL.SAFE


def test_finding_does_not_inherit_safe_when_notable_present() -> None:
    """Test that a finding does NOT inherit SAFE when any observable is NOTABLE or higher."""
    cv = Cyvest()

    # Create finding
    finding = cv.finding_create("finding1", "test", "Test finding")

    # Create mixed observables: SAFE and NOTABLE
    safe_obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", level=Cyvest.LVL.SAFE)
    notable_obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.observable_add_threat_intel(notable_obs.key, "source", score=Decimal("2.0"))  # NOTABLE level

    # Link both to finding
    cv.finding_link_observable(finding.key, safe_obs.key)
    cv.finding_link_observable(finding.key, notable_obs.key)

    # Finding should be NOTABLE (not SAFE) because one observable is NOTABLE
    assert finding.level == Cyvest.LVL.NOTABLE


def test_finding_safe_preserved_when_adding_low_level_observables() -> None:
    """Test that finding SAFE level is preserved when adding INFO/TRUSTED observables."""
    cv = Cyvest()

    # Create finding with SAFE observable
    finding = cv.finding_create("safe_finding", "test", "Test SAFE preservation")
    safe_obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", level=Cyvest.LVL.SAFE)
    cv.finding_link_observable(finding.key, safe_obs.key)

    # Finding should be SAFE
    assert finding.level == Cyvest.LVL.SAFE

    # Add INFO observable
    info_obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.finding_link_observable(finding.key, info_obs.key)

    # Finding should remain SAFE
    assert finding.level == Cyvest.LVL.SAFE


def test_finding_safe_upgrades_to_malicious_when_malicious_observable_added() -> None:
    """Test that finding can upgrade from SAFE to MALICIOUS when MALICIOUS observable is linked."""
    cv = Cyvest()

    # Create finding with SAFE observable
    finding = cv.finding_create("finding1", "test", "Test SAFE upgrade")
    safe_obs = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted.example.com", level=Cyvest.LVL.SAFE)
    cv.finding_link_observable(finding.key, safe_obs.key)

    # Finding should be SAFE
    assert finding.level == Cyvest.LVL.SAFE

    # Add MALICIOUS observable
    malicious_obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.observable_add_threat_intel(malicious_obs.key, "source", score=Decimal("6.0"))  # MALICIOUS
    cv.finding_link_observable(finding.key, malicious_obs.key)

    # Finding should upgrade to MALICIOUS
    assert finding.level == Cyvest.LVL.MALICIOUS


def test_finding_safe_with_multiple_safe_observables() -> None:
    """Test that finding inherits SAFE when multiple observables are all SAFE."""
    cv = Cyvest()

    # Create finding
    finding = cv.finding_create("safe_finding", "test", "Test multiple SAFE")

    # Create multiple SAFE observables
    safe_obs1 = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted1.example.com", level=Cyvest.LVL.SAFE)
    safe_obs2 = cv.observable_create(Cyvest.OBS.DOMAIN, "trusted2.example.com", level=Cyvest.LVL.SAFE)

    # Link all to finding
    cv.finding_link_observable(finding.key, safe_obs1.key)
    cv.finding_link_observable(finding.key, safe_obs2.key)

    # Finding should be SAFE
    assert finding.level == Cyvest.LVL.SAFE


def test_max_mode_hierarchical_root_barrier_scoring() -> None:
    """Test MAX mode with root observable as a score propagation barrier."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    root = cv.root()

    # Create domain with TI score 2.0
    domain = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    cv.observable_add_threat_intel(domain.key, source="source1", score=Decimal("2.0"))

    # Create IP with TI score 8.0
    ip = cv.observable_create(Cyvest.OBS.IPV4, "1.2.3.4")
    cv.observable_add_threat_intel(ip.key, source="source2", score=Decimal("8.0"))

    # Link both through root: root → IP (OUTBOUND), domain → root (INBOUND)
    cv.observable_add_relationship(root.key, ip.key, "related-to", direction="outbound")
    cv.observable_add_relationship(domain.key, root.key, "related-to", direction="inbound")

    # Verify root barrier behavior:
    # - Domain keeps its own TI score (2.0), not affected by root
    # - IP keeps its own TI score (8.0), not affected by root
    # - Root DOES aggregate child scores: max(0.0 TI, 8.0 child) = 8.0 (MAX mode)
    # - Domain does NOT receive propagation from root (barrier blocks upward)
    assert domain.score == Decimal("2.0")
    assert domain.level == Cyvest.LVL.NOTABLE
    assert ip.score == Decimal("8.0")
    assert ip.level == Cyvest.LVL.MALICIOUS
    assert root.score == Decimal("8.0")  # Aggregates child IP score
    assert root.level == Cyvest.LVL.MALICIOUS


def test_sum_mode_hierarchical_root_barrier_scoring() -> None:
    """Test SUM mode with root observable as a score propagation barrier."""
    cv = Cyvest(score_mode_obs=ScoreMode.SUM)

    root = cv.root()

    # Create domain with TI score 3.0
    domain = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    cv.observable_add_threat_intel(domain.key, source="source1", score=Decimal("3.0"))

    # Create IP with TI score 5.0
    ip = cv.observable_create(Cyvest.OBS.IPV4, "1.2.3.4")
    cv.observable_add_threat_intel(ip.key, source="source2", score=Decimal("5.0"))

    # Link both through root: root → IP (OUTBOUND), domain → root (INBOUND)
    cv.observable_add_relationship(root.key, ip.key, "related-to", direction="outbound")
    cv.observable_add_relationship(domain.key, root.key, "related-to", direction="inbound")

    # Verify root barrier in SUM mode:
    # - Domain keeps its own TI score (3.0), not receiving propagation from root
    # - IP keeps its own TI score (5.0), not receiving propagation from root
    # - Root DOES aggregate both children: max(0.0 TI) + sum(5.0 IP + 3.0 domain) = 8.0 (SUM mode)
    #   (domain has INBOUND to root, making domain a child of root via Method 2)
    # - Domain does NOT receive propagation from root (barrier blocks upward)
    assert domain.score == Decimal("3.0")
    assert ip.score == Decimal("5.0")
    assert root.score == Decimal("8.0")  # Aggregates both child scores via SUM mode


def test_root_with_threat_intel_only_affects_root() -> None:
    """Test that threat intel added to root only affects root's score."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    root = cv.root()

    # Create observables linked to root
    obs1 = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.observable_add_threat_intel(obs1.key, source="source1", score=Decimal("2.0"))

    obs2 = cv.observable_create(Cyvest.OBS.DOMAIN, "example.com")
    cv.observable_add_threat_intel(obs2.key, source="source2", score=Decimal("3.0"))

    # Link to root
    cv.observable_add_relationship(root.key, obs1.key, "related-to", direction="outbound")
    cv.observable_add_relationship(root.key, obs2.key, "related-to", direction="outbound")

    # Add threat intel to root
    cv.observable_add_threat_intel(root.key, source="root_source", score=Decimal("7.0"))

    # Verify root barrier:
    # - Root score = max(7.0 TI, 3.0 child obs2) = 7.0 (MAX mode, aggregates children)
    # - obs1 and obs2 keep their own scores, NOT affected by root's TI (barrier blocks upward)
    assert root.score == Decimal("7.0")  # max(7.0 TI, 2.0 obs1, 3.0 obs2)
    assert root.level == Cyvest.LVL.MALICIOUS
    assert obs1.score == Decimal("2.0")
    assert obs1.level == Cyvest.LVL.NOTABLE
    assert obs2.score == Decimal("3.0")
    assert obs2.level == Cyvest.LVL.SUSPICIOUS


def test_root_updates_when_child_score_changes() -> None:
    """Ensure root aggregates child score updates while remaining a barrier upward."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    root = cv.root()
    child = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.observable_add_relationship(root.key, child.key, "related-to", direction="outbound")

    cv.observable_add_threat_intel(child.key, source="source1", score=Decimal("2.0"))
    assert root.score == Decimal("2.0")

    # Increase child score and ensure root follows without needing a full recalculation
    cv.observable_add_threat_intel(child.key, source="source2", score=Decimal("5.0"))
    assert root.score == Decimal("5.0")


def test_root_barrier_with_multiple_levels() -> None:
    """Test root barrier with multi-level observable hierarchy."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    root = cv.root()

    # Create 3-level hierarchy: domain → IP → URL
    domain = cv.observable_create(Cyvest.OBS.DOMAIN, "malicious.com")
    cv.observable_add_threat_intel(domain.key, source="source1", score=Decimal("9.0"))

    ip = cv.observable_create(Cyvest.OBS.IPV4, "1.2.3.4")
    cv.observable_add_threat_intel(ip.key, source="source2", score=Decimal("8.0"))

    url = cv.observable_create(Cyvest.OBS.URL, "http://malicious.com/evil")
    cv.observable_add_threat_intel(url.key, source="source3", score=Decimal("7.0"))

    # Build hierarchy: domain → IP → URL
    cv.observable_add_relationship(domain.key, ip.key, "related-to", direction="outbound")
    cv.observable_add_relationship(ip.key, url.key, "related-to", direction="outbound")

    # Link root to domain
    cv.observable_add_relationship(root.key, domain.key, "related-to", direction="outbound")

    # Verify normal hierarchical propagation works (domain inherits max from children)
    assert domain.score == Decimal("9.0")  # max(9.0, 8.0, 7.0) = 9.0
    assert ip.score == Decimal("8.0")  # max(8.0, 7.0) = 8.0
    assert url.score == Decimal("7.0")  # only its TI

    # Verify root DOES aggregate domain's score, but doesn't propagate upward
    assert root.score == Decimal("9.0")  # max(0.0 TI, 9.0 child domain)
    assert root.level == Cyvest.LVL.MALICIOUS


def test_root_propagates_to_findings_not_parents() -> None:
    """Test that root observable score DOES propagate to findings, but NOT to parent observables."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    root = cv.root()

    # Create a finding and link root to it
    finding = cv.finding_create("root_finding", "test", "Test root finding")
    cv.finding_link_observable(finding.key, root.key)

    # Add threat intel to root
    cv.observable_add_threat_intel(root.key, source="root_ti", score=Decimal("8.0"))

    # Verify root has the score from its TI
    assert root.score == Decimal("8.0")
    assert root.level == Cyvest.LVL.MALICIOUS

    # Verify finding DOES get root's score (root propagates to findings)
    assert finding.score == Decimal("8.0")
    assert finding.level == Cyvest.LVL.MALICIOUS

    # Now create a non-root observable and link to the same finding
    obs = cv.observable_create(Cyvest.OBS.IPV4, "10.0.0.1")
    cv.observable_add_threat_intel(obs.key, source="ip_ti", score=Decimal("5.0"))
    cv.finding_link_observable(finding.key, obs.key)

    # Finding should now get max of both observables (root=8.0, ip=5.0)
    assert finding.score == Decimal("8.0")
    assert finding.level == Cyvest.LVL.MALICIOUS


def _build_shared_subtree(cv: Cyvest, reversed_branches: bool) -> tuple[Decimal, Decimal, Decimal]:
    """Build parent → (branch_a, branch_b) → shared → leaf and return the three upper scores."""
    parent = cv.observable_create(Cyvest.OBS.FILE, "report.eml")
    branch_a = cv.observable_create(Cyvest.OBS.DOMAIN, "a.example")
    cv.observable_add_threat_intel(branch_a.key, source="vt", score=Decimal("1.0"))
    branch_b = cv.observable_create(Cyvest.OBS.DOMAIN, "b.example")
    cv.observable_add_threat_intel(branch_b.key, source="vt", score=Decimal("2.0"))
    shared = cv.observable_create(Cyvest.OBS.IPV4, "192.0.2.9")
    cv.observable_add_threat_intel(shared.key, source="vt", score=Decimal("1.0"))
    leaf = cv.observable_create(Cyvest.OBS.HASH, "MD5:deadbeef")
    cv.observable_add_threat_intel(leaf.key, source="vt", score=Decimal("10.0"))

    cv.observable_add_relationship(shared.key, leaf.key, "pivot", Cyvest.DIR.OUTBOUND)
    for branch in [branch_b, branch_a] if reversed_branches else [branch_a, branch_b]:
        cv.observable_add_relationship(parent.key, branch.key, "extraction", Cyvest.DIR.OUTBOUND)
        cv.observable_add_relationship(branch.key, shared.key, "pivot", Cyvest.DIR.OUTBOUND)

    return parent.score, branch_a.score, branch_b.score


def test_shared_subtree_counts_in_every_branch() -> None:
    """An observable reachable from two branches expands fully in each of them."""
    cv = Cyvest(score_mode_obs=ScoreMode.SUM)

    parent_score, branch_a_score, branch_b_score = _build_shared_subtree(cv, reversed_branches=False)

    # shared subtree = 1.0 + 10.0, so each branch carries it entirely
    assert branch_a_score == Decimal("12.0")
    assert branch_b_score == Decimal("13.0")
    # The parent score stays compositional: max(TI) + sum(children)
    assert parent_score == branch_a_score + branch_b_score


def test_shared_subtree_score_is_independent_of_branch_order() -> None:
    """Score must not depend on the order observables and relationships were inserted."""
    direct = _build_shared_subtree(Cyvest(score_mode_obs=ScoreMode.SUM), reversed_branches=False)
    reversed_order = _build_shared_subtree(Cyvest(score_mode_obs=ScoreMode.SUM), reversed_branches=True)

    assert direct == reversed_order


def test_relationship_cycle_is_cut_without_infinite_recursion() -> None:
    """A cycle stops at the revisited ancestor, which keeps only its own threat intel."""
    cv = Cyvest(score_mode_obs=ScoreMode.SUM)

    first = cv.observable_create(Cyvest.OBS.DOMAIN, "x.example")
    cv.observable_add_threat_intel(first.key, source="vt", score=Decimal("1.0"))
    second = cv.observable_create(Cyvest.OBS.DOMAIN, "y.example")
    cv.observable_add_threat_intel(second.key, source="vt", score=Decimal("2.0"))

    cv.observable_add_relationship(first.key, second.key, "pivot", Cyvest.DIR.OUTBOUND)
    cv.observable_add_relationship(second.key, first.key, "pivot", Cyvest.DIR.OUTBOUND)

    # first = 1.0 + (2.0 + first truncated to its own TI 1.0)
    assert first.score == Decimal("4.0")
    assert second.score == Decimal("5.0")
