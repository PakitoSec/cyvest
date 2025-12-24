"""
Test that root observable is skipped when it appears as a child in score calculations.

This test demonstrates the expected behavior:
- Root CAN aggregate its own children (normal behavior)
- Root should NOT be included when other observables calculate their child scores
- This prevents score contamination through root relationships
"""

from decimal import Decimal

from cyvest import Cyvest
from cyvest.score import ScoreMode


def test_root_not_included_as_child_in_max_mode() -> None:
    """Test that root is skipped when appearing as a child in MAX mode."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    root = cv.root()

    # Add threat intel to root
    cv.observable_add_threat_intel(root.key, source="root_source", score=Decimal("9.0"))

    # Create an observable that has root as a child
    parent_obs = cv.observable_create(Cyvest.OBS.DOMAIN_NAME, "parent.com")
    cv.observable_add_threat_intel(parent_obs.key, source="parent_source", score=Decimal("2.0"))

    # Link parent -> root (root is child of parent via OUTBOUND)
    cv.observable_add_relationship(parent_obs.key, root.key, "related-to", direction="outbound")

    # Expected behavior:
    # - Root score = 9.0 (from its own TI, doesn't aggregate children)
    # - Parent score = 2.0 (from its own TI, root should be SKIPPED as child)
    #
    # Current (incorrect) behavior without barrier:
    # - Parent score would be max(2.0, 9.0) = 9.0 (includes root as child)

    assert root.score == Decimal("9.0")
    assert root.level == Cyvest.LVL.MALICIOUS

    # This will FAIL without the barrier - parent shouldn't include root's score
    assert parent_obs.score == Decimal("2.0"), (
        f"Expected parent to skip root as child (score=2.0), but got {parent_obs.score}"
    )
    assert parent_obs.level == Cyvest.LVL.NOTABLE


def test_root_not_included_as_child_in_sum_mode() -> None:
    """Test that root is skipped when appearing as a child in SUM mode."""
    cv = Cyvest(score_mode_obs=ScoreMode.SUM)

    root = cv.root()

    # Add threat intel to root
    cv.observable_add_threat_intel(root.key, source="root_source", score=Decimal("5.0"))

    # Create an observable that has root as a child via INBOUND relationship
    child_obs = cv.observable_create(Cyvest.OBS.IPV4_ADDR, "10.0.0.1")
    cv.observable_add_threat_intel(child_obs.key, source="child_source", score=Decimal("3.0"))

    # child -> root (INBOUND), meaning root is parent, but from Method 2 perspective,
    # child has INBOUND to root, so root could be seen as aggregating child
    # Let's test the opposite: parent with OUTBOUND to root
    parent_obs = cv.observable_create(Cyvest.OBS.DOMAIN_NAME, "parent.com")
    cv.observable_add_threat_intel(parent_obs.key, source="parent_source", score=Decimal("1.0"))

    cv.observable_add_relationship(parent_obs.key, root.key, "related-to", direction="outbound")

    # Expected behavior in SUM mode:
    # - Root score = 5.0 (from its own TI only)
    # - Parent score = max(parent TI=1.0) + sum(children excluding root) = 1.0 + 0 = 1.0
    #
    # Current (incorrect) behavior without barrier:
    # - Parent score would be 1.0 + 5.0 = 6.0

    assert root.score == Decimal("5.0")

    # This will FAIL without the barrier
    assert parent_obs.score == Decimal("1.0"), (
        f"Expected parent to skip root as child in SUM mode (score=1.0), but got {parent_obs.score}"
    )


def test_root_aggregates_its_own_children_normally() -> None:
    """Test that root CAN still aggregate its own children (barrier is one-way)."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    root = cv.root()

    # Create children of root
    child1 = cv.observable_create(Cyvest.OBS.IPV4_ADDR, "10.0.0.1")
    cv.observable_add_threat_intel(child1.key, source="source1", score=Decimal("6.0"))

    child2 = cv.observable_create(Cyvest.OBS.DOMAIN_NAME, "example.com")
    cv.observable_add_threat_intel(child2.key, source="source2", score=Decimal("8.0"))

    # Link root -> children
    cv.observable_add_relationship(root.key, child1.key, "related-to", direction="outbound")
    cv.observable_add_relationship(root.key, child2.key, "related-to", direction="outbound")

    # Root SHOULD aggregate its children normally
    # Root score = max(0.0 TI, 6.0 child1, 8.0 child2) = 8.0
    assert root.score == Decimal("8.0")
    assert root.level == Cyvest.LVL.MALICIOUS


def test_root_barrier_prevents_cross_contamination() -> None:
    """Test that observables linked through root don't contaminate each other."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    root = cv.root()

    # Create two branches connected through root
    branch1 = cv.observable_create(Cyvest.OBS.DOMAIN_NAME, "branch1.com")
    cv.observable_add_threat_intel(branch1.key, source="source1", score=Decimal("9.0"))

    branch2 = cv.observable_create(Cyvest.OBS.DOMAIN_NAME, "branch2.com")
    cv.observable_add_threat_intel(branch2.key, source="source2", score=Decimal("1.0"))

    # Root has both branches as children: root -> branch1, root -> branch2
    cv.observable_add_relationship(root.key, branch1.key, "related-to", direction="outbound")
    cv.observable_add_relationship(root.key, branch2.key, "related-to", direction="outbound")

    # Expected:
    # - branch1 score = 9.0 (its own TI only)
    # - branch2 score = 1.0 (its own TI only)
    # - root score = max(0.0 TI, 9.0 branch1, 1.0 branch2) = 9.0 (root aggregates normally)

    assert branch1.score == Decimal("9.0")
    assert branch2.score == Decimal("1.0")
    assert root.score == Decimal("9.0")

    # This is the key test: if other observables try to use root as a child, they shouldn't
    # receive contamination from root's aggregated score
    parent_of_root = cv.observable_create(Cyvest.OBS.DOMAIN_NAME, "parent.com")
    cv.observable_add_threat_intel(parent_of_root.key, source="source3", score=Decimal("0.5"))

    # Parent has root as child: parent -> root
    cv.observable_add_relationship(parent_of_root.key, root.key, "related-to", direction="outbound")

    # parent_of_root should NOT include root's score (9.0), preventing contamination
    assert parent_of_root.score == Decimal("0.5")


def test_multi_level_hierarchy_with_root_as_child() -> None:
    """Test complex hierarchy where root appears as a child in the middle."""
    cv = Cyvest(score_mode_obs=ScoreMode.MAX)

    root = cv.root()
    cv.observable_add_threat_intel(root.key, source="root_source", score=Decimal("5.0"))

    # Create hierarchy: grandparent -> parent -> root -> child
    grandparent = cv.observable_create(Cyvest.OBS.DOMAIN_NAME, "grandparent.com")
    cv.observable_add_threat_intel(grandparent.key, source="gp_source", score=Decimal("1.0"))

    parent = cv.observable_create(Cyvest.OBS.DOMAIN_NAME, "parent.com")
    cv.observable_add_threat_intel(parent.key, source="p_source", score=Decimal("2.0"))

    child = cv.observable_create(Cyvest.OBS.IPV4_ADDR, "10.0.0.1")
    cv.observable_add_threat_intel(child.key, source="c_source", score=Decimal("8.0"))

    # Build hierarchy
    cv.observable_add_relationship(grandparent.key, parent.key, "related-to", direction="outbound")
    cv.observable_add_relationship(parent.key, root.key, "related-to", direction="outbound")
    cv.observable_add_relationship(root.key, child.key, "related-to", direction="outbound")

    # Expected scores:
    # - child: 8.0 (own TI)
    # - root: max(5.0 TI, 8.0 child) = 8.0 (aggregates child normally)
    # - parent: 2.0 (own TI, root is SKIPPED as child)
    # - grandparent: max(1.0 TI, 2.0 parent) = 2.0 (parent propagates, but parent doesn't include root)

    assert child.score == Decimal("8.0")
    assert root.score == Decimal("8.0")
    assert parent.score == Decimal("2.0"), f"Expected parent to skip root as child, but got {parent.score}"
    assert grandparent.score == Decimal("2.0"), (
        f"Expected grandparent to not receive root contamination, but got {grandparent.score}"
    )
