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
