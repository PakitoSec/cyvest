"""
Scoring and propagation engine for Cyvest.

Handles automatic score calculation and propagation between threat intelligence,
observables, and findings based on relationships and hierarchies.

Score Calculation:
    - MAX mode: Score = max(all TI scores, all child observable scores)
    - SUM mode: Score = max(TI scores) + sum(child observable scores)
    - Children are determined by relationship direction (OUTBOUND = hierarchical child)

Root Observable Barrier:
    The root observable (identified by value="root") acts as a special barrier
    to prevent cross-contamination of observables while maintaining normal scoring:

    Calculation Phase:
        - Root is SKIPPED when appearing as a child in other observables' calculations
        - This prevents observables linked through root from contaminating each other
        - Root's own score calculation works normally (aggregates its children)

    Propagation Phase:
        - Root CAN be updated when its children's scores change (normal parent update)
        - Root does NOT propagate upward beyond itself (stops recursive propagation)
        - Root DOES propagate to linked findings (normal finding propagation)

    Example:
        domain -> root <- ip  (domain and ip both have root as child)
        - domain score: only its own TI (root skipped as child)
        - ip score: only its own TI (root skipped as child)
        - root score: max(root TI, domain score, ip score) - normal calculation
        - Result: domain and ip remain isolated despite shared root connection
"""

from __future__ import annotations

from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING, Literal, Protocol

from cyvest.levels import Level, get_level_from_score
from cyvest.model_enums import PropagationMode, RelationshipDirection


class ScoreMode(Enum):
    """Score calculation mode for observables."""

    MAX = "max"  # Score = max(all TI scores, all child scores)
    SUM = "sum"  # Score = max(TI scores) + sum(child scores)

    @classmethod
    def normalize(cls, value: ScoreMode | Literal["max", "sum"] | str | None) -> ScoreMode:
        """
        Normalize a score mode value to ScoreMode enum.

        Accepts enum instances or strings "max"/"sum" (case-insensitive).
        Returns MAX as default for None.
        """
        if value is None:
            return cls.MAX
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls(value.lower())
            except ValueError as exc:
                raise ValueError(f"Invalid score_mode_obs: {value}. Must be 'max' or 'sum'.") from exc
        raise TypeError(f"score_mode_obs must be ScoreMode, str, or None, got {type(value)}")


if TYPE_CHECKING:
    from cyvest.model import Finding, Observable, ThreatIntel


class ScoreChangeSink(Protocol):
    """Interface for applying score/level changes with optional side effects."""

    investigation_id: str

    def apply_score_change(
        self,
        obj: object,
        new_score: Decimal,
        *,
        reason: str,
        event_type: str = "SCORE_CHANGED",
        contributing_investigation_ids: set[str] | None = None,
    ) -> bool: ...

    def apply_level_change(
        self,
        obj: object,
        level: Level | str,
        *,
        reason: str,
        event_type: str = "LEVEL_UPDATED",
    ) -> bool: ...


class ScoreEngine:
    """
    Engine for managing score calculation and propagation.

    Handles:
    - Threat intel scores propagating to observables
    - Observable scores propagating through relationships based on direction
    - Observable scores propagating to findings

    Hierarchical relationships:
    - OUTBOUND (→): source → target, target is a child of source
    - INBOUND (←): source ← target, target is a parent of source
    - BIDIRECTIONAL (↔): excluded from hierarchical propagation

    Root Observable Barrier:
    The root observable (value="root") has asymmetric barrier behavior:

    1. In Score Calculation (_calculate_observable_score):
       - When root appears as a child, it is SKIPPED (not included in parent's score)
       - Root's own calculation works normally (aggregates its children)
       - Prevents cross-contamination between observables linked through root

    2. In Score Propagation (_propagate_to_parent_observables):
       - Root CAN be updated when children change (receives propagation as parent)
       - Root does NOT propagate beyond itself (stops upward recursive propagation)
       - Maintains root as aggregation point while preventing upward flow

    3. In Finding Propagation (_propagate_observable_to_findings):
       - Root propagates to findings normally (no special handling)
       - Ensures findings linked to root receive updated scores
    """

    def __init__(
        self,
        score_mode_obs: ScoreMode | Literal["max", "sum"] = ScoreMode.MAX,
        *,
        sink: ScoreChangeSink,
    ) -> None:
        """Initialize the score engine.

        Args:
            score_mode_obs: Observable score calculation mode (MAX or SUM)
            sink: Sink used to apply score/level changes
        """
        self._observables: dict[str, Observable] = {}
        self._findings: dict[str, Finding] = {}
        self._finding_keys_by_observable_key: dict[str, set[str]] = {}
        self._score_mode_obs = ScoreMode.normalize(score_mode_obs)
        self._sink = sink
        self._investigation_id = sink.investigation_id

    def register_observable(self, observable: Observable) -> None:
        """
        Register an observable for score tracking.

        Args:
            observable: Observable to register
        """
        self._observables[observable.key] = observable

    def register_finding(self, finding: Finding) -> None:
        """
        Register a finding for score tracking.

        Args:
            finding: Finding to register
        """
        self._findings[finding.key] = finding
        for link in getattr(finding, "observable_links", []):
            self._finding_keys_by_observable_key.setdefault(link.observable_key, set()).add(finding.key)

    def rebuild_link_index(self) -> None:
        """Rebuild the finding↔observable link index from scratch."""
        self._finding_keys_by_observable_key.clear()
        for finding in self._findings.values():
            for link in getattr(finding, "observable_links", []):
                self._finding_keys_by_observable_key.setdefault(link.observable_key, set()).add(finding.key)

    def register_finding_observable_link(self, *, finding_key: str, observable_key: str) -> None:
        """Register a newly created finding↔observable link in the propagation index."""
        self._finding_keys_by_observable_key.setdefault(observable_key, set()).add(finding_key)

    def get_finding_links_for_observable(self, observable_key: str) -> list[str]:
        """Return sorted finding keys that currently link to the observable."""
        return sorted(self._finding_keys_by_observable_key.get(observable_key, set()))

    def propagate_threat_intel_to_observable(self, ti: ThreatIntel, observable: Observable) -> None:
        """
        Propagate threat intel score to its observable.

        Args:
            ti: The threat intel providing the score
            observable: The observable to update
        """
        # Special handling for SAFE level threat intel
        # If TI has SAFE level and observable level is lower, upgrade observable to SAFE
        if ti.level == Level.SAFE and observable.level < Level.SAFE:
            self._sink.apply_level_change(
                observable,
                Level.SAFE,
                reason=f"Threat intel update from {ti.source}",
            )

        # Calculate the new observable score (includes TI scores and child scores)
        new_score = self._calculate_observable_score(observable)

        if new_score != observable.score:
            self._sink.apply_score_change(
                observable,
                new_score,
                reason=f"Threat intel update from {ti.source}",
            )

            # Root observable barrier: stop upward propagation at root level
            # Root does NOT propagate to parent observables, but DOES propagate to findings
            if observable.value == "root":
                # Allow root to propagate to findings only
                self._propagate_observable_to_findings(observable.key)
                return

            # Propagate to parent observables
            self._propagate_to_parent_observables(observable)

            # Propagate to linked findings
            self._propagate_observable_to_findings(observable.key)

    def _calculate_observable_score(self, observable: Observable) -> Decimal:
        """
        Calculate the complete observable score based on threat intel and hierarchical relationships.

        Hierarchical relationships are determined by direction:
        - OUTBOUND relationships: target is a hierarchical child
        - INBOUND relationships: source has inbound to this observable (source is child)
        - BIDIRECTIONAL relationships: excluded from hierarchy

        The score is compositional: it depends only on the observable's own threat
        intel and on its subtree, never on the traversal order. An observable
        reachable through several independent deduction chains contributes to each
        of them, which is corroboration rather than double counting.

        Root Barrier in Calculation:
        When collecting child scores, observables with value="root" (root) are SKIPPED.
        This prevents:
        - Observables from including root's aggregated score when root appears as their child
        - Cross-contamination between separate branches connected through root

        Example: If parent -> root and root -> child1, child2:
        - parent's child collection will skip root (barrier)
        - root's child collection includes child1, child2 (normal)
        - Result: parent score = only parent's TI (isolated from child1, child2)

        Args:
            observable: The observable to calculate score for

        Returns:
            Calculated score based on score_mode:
            - MAX mode: max(all TI scores, all child scores)
            - SUM mode: max(TI scores) + sum(child scores)
        """
        score, _ = self._calculate_subtree_score(observable, frozenset(), {})
        return score

    def _calculate_subtree_score(
        self,
        observable: Observable,
        path: frozenset[str],
        memo: dict[str, Decimal],
    ) -> tuple[Decimal, bool]:
        """
        Compute the subtree score of an observable along one traversal path.

        `path` holds the ancestors of the current traversal only, so it cuts cycles
        without deduplicating observables shared by sibling branches. Because an
        acyclic subtree score is path-independent, it is memoized in `memo` and the
        traversal stays linear on directed acyclic hierarchies.

        Args:
            observable: The observable to score
            path: Keys of the ancestors on the current traversal path
            memo: Cache of subtree scores that were computed without cutting a cycle

        Returns:
            The subtree score, and whether it was computed without cutting a cycle
        """
        # Get max threat intel score for this observable
        max_ti_score = max((ti.score for ti in observable.threat_intels), default=Decimal("0"))

        # Cycle barrier: an ancestor is revisited, stop at its own TI score
        if observable.key in path:
            return max_ti_score, False

        cached = memo.get(observable.key)
        if cached is not None:
            return cached, True

        child_path = path | {observable.key}

        # Collect child observable scores recursively
        # Children are defined two ways:
        # 1. Targets of this observable's OUTBOUND relationships (source → target)
        # 2. Sources of INBOUND relationships where this observable is the target (child ← this)
        #
        # Root Barrier Note: Root (value="root") is SKIPPED when appearing as a child
        # to prevent cross-contamination between observables linked through root
        child_scores = []
        cycle_free = True

        # Method 1: OUTBOUND relationships from this observable
        for rel in observable.relationships:
            # Only OUTBOUND relationships define hierarchical children
            if rel.direction == RelationshipDirection.OUTBOUND:
                child = self._observables.get(rel.target_key)
                if child:
                    # Root barrier: skip root observable (value="root") when it appears as a child
                    if child.value == "root":
                        continue
                    # Recursively calculate child's complete score
                    child_score, child_cycle_free = self._calculate_subtree_score(child, child_path, memo)
                    child_scores.append(child_score)
                    cycle_free = cycle_free and child_cycle_free

        # Method 2: Other observables with INBOUND relationships pointing to this observable
        # If obs_x has INBOUND to this observable, then obs_x is a child
        for other_key, other_obs in self._observables.items():
            if other_key == observable.key:
                continue
            # Root barrier: skip root observable (value="root") when it appears as a child
            if other_obs.value == "root":
                continue
            for rel in other_obs.relationships:
                if rel.direction == RelationshipDirection.INBOUND and rel.target_key == observable.key:
                    # other_obs has INBOUND to this observable, so other_obs is a child
                    child_score, child_cycle_free = self._calculate_subtree_score(other_obs, child_path, memo)
                    child_scores.append(child_score)
                    cycle_free = cycle_free and child_cycle_free

        # Calculate final score based on mode
        if self._score_mode_obs == ScoreMode.MAX:
            # MAX mode: take maximum of all scores (TI + children)
            score = max([max_ti_score] + child_scores, default=Decimal("0"))
        else:
            # SUM mode: max TI score + sum of child scores
            score = max_ti_score + sum(child_scores, Decimal("0"))

        # Only a cycle-free subtree has a path-independent score, so only it is cacheable
        if cycle_free:
            memo[observable.key] = score

        return score, cycle_free

    def _propagate_to_parent_observables(self, observable: Observable) -> None:
        """
        Propagate score changes up to parent observables.

        Parents are found through two mechanisms:
        1. INBOUND relationships: source ← target (target is parent)
        2. Other observables with OUTBOUND relationships to this observable (they are parents)

        Root Barrier in Propagation:
        The root observable (value="root") has special propagation behavior:

        1. Root CAN be updated (receives propagation):
           - When children's scores change, root is recalculated as a parent
           - Ensures root's aggregated score stays current
           - Uses helper function _update_parent to avoid duplicate processing

        2. Root does NOT propagate further (stops recursion):
           - After root is updated, propagation stops (no recursive call)
           - Prevents root from updating its parents (if any exist)
           - Maintains root as terminal node in upward propagation

        This creates an asymmetric barrier: updates flow TO root but not THROUGH root.

        Args:
            observable: The observable whose score changed
        """
        processed_parents: set[str] = set()

        def _update_parent(parent_obs: Observable) -> None:
            """Helper to update a parent and optionally propagate beyond it."""
            # Avoid double-processing the same parent when reached via both methods
            if parent_obs.key in processed_parents:
                return
            processed_parents.add(parent_obs.key)

            # Recalculate parent's score
            new_parent_score = self._calculate_observable_score(parent_obs)

            if new_parent_score != parent_obs.score:
                self._sink.apply_score_change(
                    parent_obs,
                    new_parent_score,
                    reason=f"Child observable {observable.key} updated",
                )
                # Propagate to findings even for root; root barrier only stops upward flow
                self._propagate_observable_to_findings(parent_obs.key)

                # Stop upward propagation at root (value="root")
                if parent_obs.value != "root":
                    self._propagate_to_parent_observables(parent_obs)

        # Method 1: Find parents through INBOUND relationships
        # For INBOUND: source ← target, target is the parent
        for rel in observable.relationships:
            if rel.direction == RelationshipDirection.INBOUND:
                parent_obs = self._observables.get(rel.target_key)
                if parent_obs and parent_obs.key != observable.key:
                    _update_parent(parent_obs)

        # Method 2: Find observables that have OUTBOUND relationships TO this observable
        # Those observables are parents (they point to this observable as their child)
        for parent_key, parent_obs in self._observables.items():
            if parent_key == observable.key:
                continue

            # Check if parent has an OUTBOUND relationship to this observable
            for rel in parent_obs.relationships:
                if rel.direction == RelationshipDirection.OUTBOUND and rel.target_key == observable.key:
                    _update_parent(parent_obs)

    def _propagate_observable_to_findings(self, observable_key: str) -> None:
        """
        Propagate observable score to linked findings.

        Args:
            observable_key: Key of the observable that changed
        """
        candidate_finding_keys = self._finding_keys_by_observable_key.get(observable_key, set())
        for finding_key in candidate_finding_keys:
            finding = self._findings.get(finding_key)
            if finding is None:
                continue

            eligible_observables: list[Observable] = []
            for link in getattr(finding, "observable_links", []):
                if link.propagation_mode == PropagationMode.GLOBAL:
                    is_effective = True
                else:
                    is_effective = finding.origin_investigation_id == self._investigation_id
                if not is_effective:
                    continue
                obs = self._observables.get(link.observable_key)
                if obs is not None:
                    eligible_observables.append(obs)

            if not eligible_observables:
                continue

            max_obs_score = max(obs.score for obs in eligible_observables)
            max_obs_level = max((obs.level for obs in eligible_observables), default=finding.level)

            new_score = max(finding.score, max_obs_score)
            if new_score != finding.score:
                self._sink.apply_score_change(
                    finding,
                    new_score,
                    reason=f"Linked observable {observable_key} updated",
                )

            new_level = max(finding.level, max_obs_level)
            if new_level != finding.level:
                self._sink.apply_level_change(
                    finding,
                    new_level,
                    reason=f"Linked observable {observable_key} updated",
                )

    def recalculate_all(self) -> None:
        """
        Recalculate all scores from scratch.

        Useful after merging investigations or bulk updates.
        """
        # First, recalculate all observables from their threat intel and relationships
        for obs in self._observables.values():
            new_score = self._calculate_observable_score(obs)
            if new_score != obs.score:
                self._sink.apply_score_change(
                    obs,
                    new_score,
                    reason="Recalculation",
                    event_type="SCORE_RECALCULATED",
                )

        # Then propagate to all findings (not just MALICIOUS observables)
        for obs in self._observables.values():
            self._propagate_observable_to_findings(obs.key)

    def get_global_score(self) -> Decimal:
        """
        Calculate the global investigation score.

        The global score is the sum of all finding scores.

        Returns:
            Total investigation score
        """
        return sum((finding.score for finding in self._findings.values()), Decimal("0"))

    def get_global_level(self) -> Level:
        """
        Calculate the global investigation level.

        The global level is determined from the global score.

        Returns:
            Investigation level
        """
        return get_level_from_score(self.get_global_score())
