"""
Tests for the reworked score algorithm.

Tests MAX vs SUM modes, check score calculation, hierarchical propagation,
and score history access.
"""

from decimal import Decimal

from cyvest import Cyvest, Level
from cyvest.score import ScoreMode


def test_observable_starts_with_zero_score_info_level() -> None:
    """Test that observables start with score 0 and level INFO."""
    cv = Cyvest()
    obs = cv.observable_create("ip", "192.168.1.1")

    assert obs.score == Decimal("0")
    assert obs.level == Level.INFO


def test_max_mode_threat_intel_scores() -> None:
    """Test MAX mode: observable score = max(all TI scores, all child scores)."""
    cv = Cyvest(score_mode=ScoreMode.MAX)

    # Create observable with multiple threat intel sources
    obs = cv.observable_create("ip", "10.0.0.1")
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("3.0"))
    cv.observable_add_threat_intel(obs.key, source="source2", score=Decimal("7.0"))
    cv.observable_add_threat_intel(obs.key, source="source3", score=Decimal("2.0"))

    # In MAX mode, observable score should be max of TI scores = 7.0
    assert obs.score == Decimal("7.0")
    assert obs.level == Level.MALICIOUS


def test_sum_mode_threat_intel_scores() -> None:
    """Test SUM mode: observable score = max(TI scores) + sum(child scores)."""
    cv = Cyvest(score_mode=ScoreMode.SUM)

    # Create observable with multiple threat intel sources
    obs = cv.observable_create("ip", "10.0.0.1")
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("3.0"))
    cv.observable_add_threat_intel(obs.key, source="source2", score=Decimal("7.0"))
    cv.observable_add_threat_intel(obs.key, source="source3", score=Decimal("2.0"))

    # In SUM mode with no children, score should be max of TI scores = 7.0
    assert obs.score == Decimal("7.0")
    assert obs.level == Level.MALICIOUS


def test_max_mode_hierarchical_scoring() -> None:
    """Test MAX mode with hierarchical relationships."""
    cv = Cyvest(score_mode=ScoreMode.MAX)

    # Create domain with TI score 2.0
    domain = cv.observable_create("domain", "example.com")
    cv.observable_add_threat_intel(domain.key, source="source1", score=Decimal("2.0"))

    # Create IP with TI score 8.0
    ip = cv.observable_create("ip", "1.2.3.4")
    cv.observable_add_threat_intel(ip.key, source="source2", score=Decimal("8.0"))

    # Domain resolves to IP
    cv.observable_add_relationship(domain.key, ip.key, "resolves-to")

    # In MAX mode, domain score = max(domain TI=2.0, ip score=8.0) = 8.0
    assert domain.score == Decimal("8.0")
    assert domain.level == Level.MALICIOUS


def test_sum_mode_hierarchical_scoring() -> None:
    """Test SUM mode with hierarchical relationships."""
    cv = Cyvest(score_mode=ScoreMode.SUM)

    # Create domain with TI score 2.0
    domain = cv.observable_create("domain", "example.com")
    cv.observable_add_threat_intel(domain.key, source="source1", score=Decimal("2.0"))

    # Create IP with TI score 8.0
    ip = cv.observable_create("ip", "1.2.3.4")
    cv.observable_add_threat_intel(ip.key, source="source2", score=Decimal("8.0"))

    # Domain resolves to IP
    cv.observable_add_relationship(domain.key, ip.key, "resolves-to")

    # In SUM mode, domain score = max(domain TI=2.0) + sum(child scores=8.0) = 10.0
    assert domain.score == Decimal("10.0")
    assert domain.level == Level.MALICIOUS


def test_max_mode_multiple_children() -> None:
    """Test MAX mode with multiple child observables."""
    cv = Cyvest(score_mode=ScoreMode.MAX)

    # Create parent with TI score 1.0
    parent = cv.observable_create("domain", "parent.com")
    cv.observable_add_threat_intel(parent.key, source="source1", score=Decimal("1.0"))

    # Create children with different scores
    child1 = cv.observable_create("ip", "1.1.1.1")
    cv.observable_add_threat_intel(child1.key, source="source2", score=Decimal("3.0"))

    child2 = cv.observable_create("ip", "2.2.2.2")
    cv.observable_add_threat_intel(child2.key, source="source3", score=Decimal("6.0"))

    child3 = cv.observable_create("ip", "3.3.3.3")
    cv.observable_add_threat_intel(child3.key, source="source4", score=Decimal("2.0"))

    # Connect parent to children
    cv.observable_add_relationship(parent.key, child1.key, "resolves-to")
    cv.observable_add_relationship(parent.key, child2.key, "resolves-to")
    cv.observable_add_relationship(parent.key, child3.key, "resolves-to")

    # In MAX mode, parent score = max(1.0, 3.0, 6.0, 2.0) = 6.0
    assert parent.score == Decimal("6.0")
    assert parent.level == Level.MALICIOUS


def test_sum_mode_multiple_children() -> None:
    """Test SUM mode with multiple child observables."""
    cv = Cyvest(score_mode=ScoreMode.SUM)

    # Create parent with TI score 1.0
    parent = cv.observable_create("domain", "parent.com")
    cv.observable_add_threat_intel(parent.key, source="source1", score=Decimal("1.0"))

    # Create children with different scores
    child1 = cv.observable_create("ip", "1.1.1.1")
    cv.observable_add_threat_intel(child1.key, source="source2", score=Decimal("3.0"))

    child2 = cv.observable_create("ip", "2.2.2.2")
    cv.observable_add_threat_intel(child2.key, source="source3", score=Decimal("6.0"))

    child3 = cv.observable_create("ip", "3.3.3.3")
    cv.observable_add_threat_intel(child3.key, source="source4", score=Decimal("2.0"))

    # Connect parent to children
    cv.observable_add_relationship(parent.key, child1.key, "resolves-to")
    cv.observable_add_relationship(parent.key, child2.key, "resolves-to")
    cv.observable_add_relationship(parent.key, child3.key, "resolves-to")

    # In SUM mode, parent score = max(parent TI=1.0) + sum(children=3.0+6.0+2.0) = 1.0 + 11.0 = 12.0
    assert parent.score == Decimal("12.0")
    assert parent.level == Level.MALICIOUS


def test_check_score_from_single_observable() -> None:
    """Test check score calculation from a single linked observable."""
    cv = Cyvest()

    # Create check with initial score 0
    check = cv.check_create("check1", "test", "Test check")
    assert check.score == Decimal("0")
    assert check.level == Level.NONE

    # Create observable and add TI
    obs = cv.observable_create("ip", "10.0.0.1")
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("5.0"))

    # Link observable to check
    cv.check_link_observable(check.key, obs.key)

    # Check score should be max of linked observable scores and check's current score
    # max([5.0, 0.0]) = 5.0
    assert check.score == Decimal("5.0")
    assert check.level == Level.MALICIOUS


def test_check_score_from_multiple_observables() -> None:
    """Test check score calculation from multiple linked observables."""
    cv = Cyvest()

    # Create check
    check = cv.check_create("check1", "test", "Test check")

    # Create multiple observables with different scores
    obs1 = cv.observable_create("ip", "10.0.0.1")
    cv.observable_add_threat_intel(obs1.key, source="source1", score=Decimal("3.0"))

    obs2 = cv.observable_create("ip", "10.0.0.2")
    cv.observable_add_threat_intel(obs2.key, source="source2", score=Decimal("7.0"))

    obs3 = cv.observable_create("ip", "10.0.0.3")
    cv.observable_add_threat_intel(obs3.key, source="source3", score=Decimal("2.0"))

    # Link all observables to check
    cv.check_link_observable(check.key, obs1.key)
    cv.check_link_observable(check.key, obs2.key)
    cv.check_link_observable(check.key, obs3.key)

    # Check score should be max of all linked observable scores
    # max([3.0, 7.0, 2.0, 0.0]) = 7.0
    assert check.score == Decimal("7.0")
    assert check.level == Level.MALICIOUS


def test_check_score_preserves_higher_current_score() -> None:
    """Test that check score includes its current score in max calculation."""
    cv = Cyvest()

    # Create check with initial score 5.0
    check = cv.check_create("check1", "test", "Test check", score=Decimal("5.0"))
    assert check.score == Decimal("5.0")

    # Create observable with lower score
    obs = cv.observable_create("ip", "10.0.0.1")
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("3.0"))

    # Link observable to check
    cv.check_link_observable(check.key, obs.key)

    # Check score should remain at max([3.0, 5.0]) = 5.0 (no change)
    assert check.score == Decimal("5.0")

    # Now add a higher scoring observable
    obs2 = cv.observable_create("ip", "10.0.0.2")
    cv.observable_add_threat_intel(obs2.key, source="source2", score=Decimal("8.0"))
    cv.check_link_observable(check.key, obs2.key)

    # Check score should now be max([3.0, 8.0, 5.0]) = 8.0
    assert check.score == Decimal("8.0")
    assert check.level == Level.MALICIOUS


def test_observable_score_history() -> None:
    """Test that observable score history can be retrieved."""
    cv = Cyvest()

    # Create observable
    obs = cv.observable_create("ip", "10.0.0.1")

    # Initial history should have 0 entries (no changes yet)
    history = obs.get_score_history()
    assert isinstance(history, list)
    assert len(history) == 0

    # Add threat intel (triggers score change)
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("5.0"))

    # History should now have 1 entry
    history = obs.get_score_history()
    assert len(history) == 1
    assert history[0].old_score == Decimal("0")
    assert history[0].new_score == Decimal("5.0")
    assert history[0].old_level == Level.INFO
    assert history[0].new_level == Level.MALICIOUS
    assert "source1" in history[0].reason

    # Add another threat intel
    cv.observable_add_threat_intel(obs.key, source="source2", score=Decimal("8.0"))

    # History should now have 2 entries
    history = obs.get_score_history()
    assert len(history) == 2
    assert history[1].old_score == Decimal("5.0")
    assert history[1].new_score == Decimal("8.0")
    assert "source2" in history[1].reason


def test_check_score_history() -> None:
    """Test that check score history can be retrieved."""
    cv = Cyvest()

    # Create check
    check = cv.check_create("check1", "test", "Test check")

    # Initial history should have 0 entries
    history = check.get_score_history()
    assert isinstance(history, list)
    assert len(history) == 0

    # Create observable and link to check
    obs = cv.observable_create("ip", "10.0.0.1")
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("5.0"))
    cv.check_link_observable(check.key, obs.key)

    # History should now have entries from score updates
    history = check.get_score_history()
    assert len(history) >= 1
    assert any(entry.new_score == Decimal("5.0") for entry in history)


def test_score_propagation_through_hierarchy() -> None:
    """Test score propagation through multi-level hierarchy in MAX mode."""
    cv = Cyvest(score_mode=ScoreMode.MAX)

    # Create 3-level hierarchy: grandparent -> parent -> child
    grandparent = cv.observable_create("domain", "grandparent.com")
    cv.observable_add_threat_intel(grandparent.key, source="source1", score=Decimal("1.0"))

    parent = cv.observable_create("domain", "parent.com")
    cv.observable_add_threat_intel(parent.key, source="source2", score=Decimal("2.0"))

    child = cv.observable_create("ip", "1.2.3.4")
    cv.observable_add_threat_intel(child.key, source="source3", score=Decimal("9.0"))

    # Connect hierarchy
    cv.observable_add_relationship(grandparent.key, parent.key, "resolves-to")
    cv.observable_add_relationship(parent.key, child.key, "resolves-to")

    # In MAX mode:
    # child score = 9.0 (its own TI)
    # parent score = max(2.0, 9.0) = 9.0
    # grandparent score = max(1.0, 9.0) = 9.0
    assert child.score == Decimal("9.0")
    assert parent.score == Decimal("9.0")
    assert grandparent.score == Decimal("9.0")
    assert grandparent.level == Level.MALICIOUS


def test_score_propagation_updates_parent() -> None:
    """Test that updating child score propagates to parent."""
    cv = Cyvest(score_mode=ScoreMode.MAX)

    # Create parent and child
    parent = cv.observable_create("domain", "parent.com")
    cv.observable_add_threat_intel(parent.key, source="source1", score=Decimal("1.0"))

    child = cv.observable_create("ip", "1.2.3.4")
    cv.observable_add_threat_intel(child.key, source="source2", score=Decimal("2.0"))

    # Connect them
    cv.observable_add_relationship(parent.key, child.key, "resolves-to")

    # Parent score should be max(1.0, 2.0) = 2.0
    assert parent.score == Decimal("2.0")

    # Add more threat intel to child
    cv.observable_add_threat_intel(child.key, source="source3", score=Decimal("8.0"))

    # Parent score should update to max(1.0, 8.0) = 8.0
    assert child.score == Decimal("8.0")
    assert parent.score == Decimal("8.0")
    assert parent.level == Level.MALICIOUS


def test_inbound_relationship_propagation() -> None:
    """Test that INBOUND relationships correctly identify parents for score propagation."""
    from cyvest import RelationshipDirection

    cv = Cyvest(score_mode=ScoreMode.MAX)

    # Create file with INBOUND relationship to URL (file ← URL means URL is parent)
    malware_file = cv.observable_create("file", "malware.exe")
    cv.observable_add_threat_intel(malware_file.key, source="av", score=Decimal("9.0"))

    download_url = cv.observable_create("url", "http://evil.com/malware.exe")
    cv.observable_add_threat_intel(download_url.key, source="urlscan", score=Decimal("2.0"))

    # Add INBOUND relationship: file ← URL (URL downloaded the file, URL is parent)
    cv.observable_add_relationship(malware_file.key, download_url.key, "downloaded", RelationshipDirection.INBOUND)

    # File has INBOUND to URL, so URL is parent and should get file's score
    # URL score = max(2.0, 9.0) = 9.0
    assert malware_file.score == Decimal("9.0")
    assert download_url.score == Decimal("9.0")
    assert download_url.level == Level.MALICIOUS


def test_bidirectional_relationship_no_propagation() -> None:
    """Test that BIDIRECTIONAL relationships do not participate in hierarchical score propagation."""
    from cyvest import RelationshipDirection

    cv = Cyvest(score_mode=ScoreMode.MAX)

    # Create two hosts with bidirectional communication
    host1 = cv.observable_create("ip", "10.0.1.10")
    cv.observable_add_threat_intel(host1.key, source="ids", score=Decimal("8.0"))

    host2 = cv.observable_create("ip", "10.0.1.20")
    cv.observable_add_threat_intel(host2.key, source="ids", score=Decimal("1.0"))

    # Add BIDIRECTIONAL relationship (symmetric, no hierarchy)
    cv.observable_add_relationship(host1.key, host2.key, "communicates-with", RelationshipDirection.BIDIRECTIONAL)

    # Bidirectional relationships should NOT propagate scores hierarchically
    # Each host keeps only its own TI score
    assert host1.score == Decimal("8.0")
    assert host2.score == Decimal("1.0")


def test_outbound_vs_inbound_direction_semantics() -> None:
    """Test that OUTBOUND and INBOUND create opposite parent-child relationships."""
    from cyvest import RelationshipDirection

    cv = Cyvest(score_mode=ScoreMode.MAX)

    # Scenario 1: OUTBOUND - domain → IP (IP is child of domain)
    domain1 = cv.observable_create("domain", "example1.com")
    cv.observable_add_threat_intel(domain1.key, source="source1", score=Decimal("1.0"))

    ip1 = cv.observable_create("ip", "1.1.1.1")
    cv.observable_add_threat_intel(ip1.key, source="source2", score=Decimal("7.0"))

    cv.observable_add_relationship(domain1.key, ip1.key, "resolves-to", RelationshipDirection.OUTBOUND)

    # Domain has OUTBOUND to IP, so IP is child, domain gets child's score
    # domain1 score = max(1.0, 7.0) = 7.0
    assert domain1.score == Decimal("7.0")
    assert ip1.score == Decimal("7.0")

    # Scenario 2: INBOUND - domain ← IP (IP is parent of domain)
    domain2 = cv.observable_create("domain", "example2.com")
    cv.observable_add_threat_intel(domain2.key, source="source3", score=Decimal("8.0"))

    ip2 = cv.observable_create("ip", "2.2.2.2")
    cv.observable_add_threat_intel(ip2.key, source="source4", score=Decimal("2.0"))

    cv.observable_add_relationship(domain2.key, ip2.key, "resolves-to", RelationshipDirection.INBOUND)

    # Domain has INBOUND to IP, so IP is parent, IP gets domain's score
    # ip2 score = max(2.0, 8.0) = 8.0
    assert domain2.score == Decimal("8.0")
    assert ip2.score == Decimal("8.0")


def test_mixed_directions_in_hierarchy() -> None:
    """Test score propagation with mixed OUTBOUND and INBOUND relationships."""
    from cyvest import RelationshipDirection

    cv = Cyvest(score_mode=ScoreMode.MAX)

    # Create a chain: A → B ← C
    # A has OUTBOUND to B (B is child of A)
    # C has INBOUND to B (B is parent of C)

    obs_a = cv.observable_create("domain", "a.com")
    cv.observable_add_threat_intel(obs_a.key, source="source1", score=Decimal("2.0"))

    obs_b = cv.observable_create("ip", "1.1.1.1")
    cv.observable_add_threat_intel(obs_b.key, source="source2", score=Decimal("3.0"))

    obs_c = cv.observable_create("url", "http://c.com")
    cv.observable_add_threat_intel(obs_c.key, source="source3", score=Decimal("9.0"))

    # A → B (B is child of A)
    cv.observable_add_relationship(obs_a.key, obs_b.key, "resolves-to", RelationshipDirection.OUTBOUND)

    # C has INBOUND to B (B is parent of C)
    cv.observable_add_relationship(obs_c.key, obs_b.key, "related-to", RelationshipDirection.INBOUND)

    # obs_c score = 9.0 (its own TI)
    # obs_b is parent of obs_c, so gets max(3.0, 9.0) = 9.0
    # obs_a has obs_b as child, so gets max(2.0, 9.0) = 9.0
    assert obs_c.score == Decimal("9.0")
    assert obs_b.score == Decimal("9.0")
    assert obs_a.score == Decimal("9.0")


def test_explicit_direction_override() -> None:
    """Test that explicitly setting direction overrides semantic defaults."""
    from cyvest import RelationshipDirection, RelationshipType

    cv = Cyvest(score_mode=ScoreMode.MAX)

    # RESOLVES_TO normally defaults to OUTBOUND, but we can override
    domain = cv.observable_create("domain", "override.com")
    cv.observable_add_threat_intel(domain.key, source="source1", score=Decimal("1.0"))

    ip = cv.observable_create("ip", "3.3.3.3")
    cv.observable_add_threat_intel(ip.key, source="source2", score=Decimal("8.0"))

    # Override RESOLVES_TO to be BIDIRECTIONAL (no hierarchy)
    cv.observable_add_relationship(
        domain.key, ip.key, RelationshipType.RESOLVES_TO, RelationshipDirection.BIDIRECTIONAL
    )

    # Bidirectional means no hierarchical propagation
    # Each keeps only its own score
    assert domain.score == Decimal("1.0")
    assert ip.score == Decimal("8.0")

    # Verify the relationship has BIDIRECTIONAL direction
    assert domain.relationships[0].direction == RelationshipDirection.BIDIRECTIONAL


def test_sum_mode_with_direction_based_children() -> None:
    """Test SUM mode score calculation with direction-based child detection."""
    from cyvest import RelationshipDirection

    cv = Cyvest(score_mode=ScoreMode.SUM)

    # Parent with multiple children via OUTBOUND relationships
    parent = cv.observable_create("domain", "parent.com")
    cv.observable_add_threat_intel(parent.key, source="source1", score=Decimal("1.0"))

    child1 = cv.observable_create("ip", "1.1.1.1")
    cv.observable_add_threat_intel(child1.key, source="source2", score=Decimal("3.0"))

    child2 = cv.observable_create("ip", "2.2.2.2")
    cv.observable_add_threat_intel(child2.key, source="source3", score=Decimal("5.0"))

    # Add OUTBOUND relationships
    cv.observable_add_relationship(parent.key, child1.key, "resolves-to", RelationshipDirection.OUTBOUND)
    cv.observable_add_relationship(parent.key, child2.key, "resolves-to", RelationshipDirection.OUTBOUND)

    # Also add one BIDIRECTIONAL that should be ignored
    noise_obs = cv.observable_create("ip", "9.9.9.9")
    cv.observable_add_threat_intel(noise_obs.key, source="source4", score=Decimal("100.0"))
    cv.observable_add_relationship(parent.key, noise_obs.key, "related-to", RelationshipDirection.BIDIRECTIONAL)

    # In SUM mode: parent score = max(parent TI=1.0) + sum(OUTBOUND children = 3.0 + 5.0) = 9.0
    # BIDIRECTIONAL relationship should NOT contribute
    assert parent.score == Decimal("9.0")
    assert noise_obs.score == Decimal("100.0")  # Keeps its own score


def test_safe_level_explicit_creation() -> None:
    """Test that observable created with level=SAFE has _explicit_level=True."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "trusted.example.com", score=0, level=Level.SAFE)

    assert obs.score == Decimal("0")
    assert obs.level == Level.SAFE
    assert obs._explicit_level is True


def test_safe_level_prevents_info_downgrade() -> None:
    """Test that SAFE observable stays SAFE when receiving INFO level threat intel."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "trusted.example.com", score=0, level=Level.SAFE)

    # Add threat intel with score=0 (would be INFO level)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("0"))

    # Score updates but level stays SAFE
    assert obs.score == Decimal("0")
    assert obs.level == Level.SAFE


def test_safe_level_prevents_trusted_downgrade() -> None:
    """Test that SAFE observable stays SAFE when receiving TRUSTED level threat intel."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "trusted.example.com", score=0, level=Level.SAFE)

    # Add threat intel with negative score (would be TRUSTED level)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("-1.0"))

    # Score updates but level stays SAFE (TRUSTED < SAFE)
    assert obs.score == Decimal("-1.0")
    assert obs.level == Level.SAFE


def test_safe_level_allows_notable_upgrade() -> None:
    """Test that SAFE observable upgrades to NOTABLE with appropriate threat intel."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "trusted.example.com", score=0, level=Level.SAFE)

    # Add threat intel with score=2.0 (NOTABLE level, which is > SAFE)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("2.0"))

    # Both score and level upgrade
    assert obs.score == Decimal("2.0")
    assert obs.level == Level.NOTABLE


def test_safe_level_allows_suspicious_upgrade() -> None:
    """Test that SAFE observable upgrades to SUSPICIOUS with appropriate threat intel."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "trusted.example.com", score=0, level=Level.SAFE)

    # Add threat intel with score=4.0 (SUSPICIOUS level)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("4.0"))

    # Both score and level upgrade
    assert obs.score == Decimal("4.0")
    assert obs.level == Level.SUSPICIOUS


def test_safe_level_allows_malicious_upgrade() -> None:
    """Test that SAFE observable upgrades to MALICIOUS with appropriate threat intel."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "trusted.example.com", score=0, level=Level.SAFE)

    # Add threat intel with score=6.0 (MALICIOUS level)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("6.0"))

    # Both score and level upgrade
    assert obs.score == Decimal("6.0")
    assert obs.level == Level.MALICIOUS


def test_safe_level_score_updates_with_frozen_level() -> None:
    """Test that SAFE observable score updates even when level stays SAFE."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "trusted.example.com", score=Decimal("-1.0"), level=Level.SAFE)

    # Initial state: score=-1.0 (would be TRUSTED), level=SAFE
    assert obs.score == Decimal("-1.0")
    assert obs.level == Level.SAFE

    # Add threat intel with score=0 (would be INFO, still < SAFE)
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("0"))

    # Score should update to 0 (max of -1.0 and 0), but level stays SAFE
    assert obs.score == Decimal("0")
    assert obs.level == Level.SAFE  # Level frozen at SAFE even though score=0 would be INFO

    # Verify score history tracked the changes
    history = obs.get_score_history()
    assert len(history) > 0


def test_non_safe_explicit_levels_allow_downgrades() -> None:
    """Test that explicit levels other than SAFE still allow downgrades."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "test.example.com")

    # Manually set to SUSPICIOUS
    obs.set_level(Level.SUSPICIOUS)
    assert obs._explicit_level is True
    assert obs.level == Level.SUSPICIOUS

    # Add threat intel with lower score (NOTABLE)
    cv.observable_add_threat_intel(obs.key, source="ti_source", score=Decimal("2.0"))

    # For non-SAFE levels, the existing logic still applies
    # (level only upgrades if calculated > current)
    # Score=2.0 gives NOTABLE which is < SUSPICIOUS, so level stays SUSPICIOUS
    assert obs.score == Decimal("2.0")
    assert obs.level == Level.SUSPICIOUS


def test_threat_intel_with_safe_level_upgrades_info_observable() -> None:
    """Test that threat intel with SAFE level upgrades an INFO observable to SAFE."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "trusted.example.com")

    # Observable starts with INFO level
    assert obs.level == Level.INFO

    # Add threat intel with SAFE level
    cv.observable_add_threat_intel(obs.key, source="whitelist_db", score=Decimal("0"), level=Level.SAFE)

    # Observable should now be SAFE
    assert obs.level == Level.SAFE
    assert obs._explicit_level is True


def test_threat_intel_with_safe_level_upgrades_trusted_observable() -> None:
    """Test that threat intel with SAFE level upgrades a TRUSTED observable to SAFE."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "example.com")

    # Add TI with negative score to get TRUSTED level
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("-1.0"))
    assert obs.level == Level.TRUSTED

    # Add threat intel with SAFE level
    cv.observable_add_threat_intel(obs.key, source="whitelist_db", score=Decimal("0"), level=Level.SAFE)

    # Observable should now be SAFE
    assert obs.level == Level.SAFE
    assert obs._explicit_level is True


def test_threat_intel_with_safe_level_does_not_downgrade_notable() -> None:
    """Test that threat intel with SAFE level doesn't downgrade NOTABLE observable."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "example.com")

    # Add TI to get NOTABLE level
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("2.0"))
    assert obs.level == Level.NOTABLE

    # Add threat intel with SAFE level (lower than NOTABLE)
    cv.observable_add_threat_intel(obs.key, source="whitelist_db", score=Decimal("0"), level=Level.SAFE)

    # Observable should stay NOTABLE (SAFE < NOTABLE, so no downgrade)
    assert obs.level == Level.NOTABLE


def test_threat_intel_with_safe_level_does_not_downgrade_malicious() -> None:
    """Test that threat intel with SAFE level doesn't downgrade MALICIOUS observable."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "example.com")

    # Add TI to get MALICIOUS level
    cv.observable_add_threat_intel(obs.key, source="source1", score=Decimal("6.0"))
    assert obs.level == Level.MALICIOUS

    # Add threat intel with SAFE level (lower than MALICIOUS)
    cv.observable_add_threat_intel(obs.key, source="whitelist_db", score=Decimal("0"), level=Level.SAFE)

    # Observable should stay MALICIOUS (no downgrade from SAFE TI)
    assert obs.level == Level.MALICIOUS


def test_threat_intel_safe_then_malicious_upgrades() -> None:
    """Test that SAFE observable can still be upgraded by MALICIOUS threat intel."""
    cv = Cyvest()
    obs = cv.observable_create("domain", "example.com")

    # Add threat intel with SAFE level
    cv.observable_add_threat_intel(obs.key, source="whitelist_db", score=Decimal("0"), level=Level.SAFE)
    assert obs.level == Level.SAFE

    # Add threat intel with MALICIOUS score
    cv.observable_add_threat_intel(obs.key, source="virustotal", score=Decimal("8.0"))

    # Observable should upgrade to MALICIOUS
    assert obs.score == Decimal("8.0")
    assert obs.level == Level.MALICIOUS


def test_threat_intel_safe_level_with_none_observable() -> None:
    """Test that threat intel with SAFE level upgrades NONE level observable."""
    cv = Cyvest()

    # Create a check with NONE level
    check = cv.check_create("test_check", "scope", "description")
    assert check.level == Level.NONE

    # Create observable starting at INFO
    obs = cv.observable_create("ip", "192.168.1.1")
    assert obs.level == Level.INFO

    # Add threat intel with SAFE level to observable
    cv.observable_add_threat_intel(obs.key, source="whitelist", score=Decimal("0"), level=Level.SAFE)

    # Observable should be SAFE
    assert obs.level == Level.SAFE


def test_check_inherits_safe_from_single_observable() -> None:
    """Test that a check inherits SAFE level from a single SAFE observable."""
    cv = Cyvest()

    # Create check
    check = cv.check_create("safe_check", "test", "Test SAFE inheritance")
    assert check.level == Level.NONE

    # Create SAFE observable and link to check
    safe_obs = cv.observable_create("domain", "trusted.example.com", level=Level.SAFE)
    cv.check_link_observable(check.key, safe_obs.key)

    # Check should inherit SAFE level
    assert check.level == Level.SAFE


def test_check_inherits_safe_from_multiple_observables_all_lower() -> None:
    """Test that a check inherits SAFE when has SAFE observable and others are lower."""
    cv = Cyvest()

    # Create check
    check = cv.check_create("safe_check", "test", "Test SAFE inheritance")

    # Create mixed observables: SAFE, INFO, TRUSTED
    safe_obs = cv.observable_create("domain", "trusted.example.com", level=Level.SAFE)
    info_obs = cv.observable_create("ip", "10.0.0.1")  # default INFO level
    trusted_obs = cv.observable_create("ip", "10.0.0.2")
    cv.observable_add_threat_intel(trusted_obs.key, "source", score=Decimal("-1.0"))  # TRUSTED level

    # Link all to check
    cv.check_link_observable(check.key, safe_obs.key)
    cv.check_link_observable(check.key, info_obs.key)
    cv.check_link_observable(check.key, trusted_obs.key)

    # Check should inherit SAFE level (all observables <= SAFE)
    assert check.level == Level.SAFE


def test_check_does_not_inherit_safe_when_notable_present() -> None:
    """Test that a check does NOT inherit SAFE when any observable is NOTABLE or higher."""
    cv = Cyvest()

    # Create check
    check = cv.check_create("check1", "test", "Test check")

    # Create mixed observables: SAFE and NOTABLE
    safe_obs = cv.observable_create("domain", "trusted.example.com", level=Level.SAFE)
    notable_obs = cv.observable_create("ip", "10.0.0.1")
    cv.observable_add_threat_intel(notable_obs.key, "source", score=Decimal("2.0"))  # NOTABLE level

    # Link both to check
    cv.check_link_observable(check.key, safe_obs.key)
    cv.check_link_observable(check.key, notable_obs.key)

    # Check should be NOTABLE (not SAFE) because one observable is NOTABLE
    assert check.level == Level.NOTABLE


def test_check_safe_preserved_when_adding_low_level_observables() -> None:
    """Test that check SAFE level is preserved when adding INFO/TRUSTED observables."""
    cv = Cyvest()

    # Create check with SAFE observable
    check = cv.check_create("safe_check", "test", "Test SAFE preservation")
    safe_obs = cv.observable_create("domain", "trusted.example.com", level=Level.SAFE)
    cv.check_link_observable(check.key, safe_obs.key)

    # Check should be SAFE
    assert check.level == Level.SAFE

    # Add INFO observable
    info_obs = cv.observable_create("ip", "10.0.0.1")
    cv.check_link_observable(check.key, info_obs.key)

    # Check should remain SAFE
    assert check.level == Level.SAFE


def test_check_safe_upgrades_to_malicious_when_malicious_observable_added() -> None:
    """Test that check can upgrade from SAFE to MALICIOUS when MALICIOUS observable is linked."""
    cv = Cyvest()

    # Create check with SAFE observable
    check = cv.check_create("check1", "test", "Test SAFE upgrade")
    safe_obs = cv.observable_create("domain", "trusted.example.com", level=Level.SAFE)
    cv.check_link_observable(check.key, safe_obs.key)

    # Check should be SAFE
    assert check.level == Level.SAFE

    # Add MALICIOUS observable
    malicious_obs = cv.observable_create("ip", "10.0.0.1")
    cv.observable_add_threat_intel(malicious_obs.key, "source", score=Decimal("6.0"))  # MALICIOUS
    cv.check_link_observable(check.key, malicious_obs.key)

    # Check should upgrade to MALICIOUS
    assert check.level == Level.MALICIOUS


def test_check_safe_with_multiple_safe_observables() -> None:
    """Test that check inherits SAFE when multiple observables are all SAFE."""
    cv = Cyvest()

    # Create check
    check = cv.check_create("safe_check", "test", "Test multiple SAFE")

    # Create multiple SAFE observables
    safe_obs1 = cv.observable_create("domain", "trusted1.example.com", level=Level.SAFE)
    safe_obs2 = cv.observable_create("domain", "trusted2.example.com", level=Level.SAFE)

    # Link all to check
    cv.check_link_observable(check.key, safe_obs1.key)
    cv.check_link_observable(check.key, safe_obs2.key)

    # Check should be SAFE
    assert check.level == Level.SAFE
