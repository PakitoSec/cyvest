"""
Scoring and propagation engine for Cyvest.

Handles automatic score calculation and propagation between threat intelligence,
observables, and checks based on relationships and hierarchies.
"""

from decimal import Decimal
from enum import Enum
from typing import TYPE_CHECKING

from cyvest.levels import Level, get_level_from_score
from cyvest.model import RelationshipDirection


class ScoreMode(Enum):
    """Score calculation mode for observables."""

    MAX = "max"  # Score = max(all TI scores, all child scores)
    SUM = "sum"  # Score = max(TI scores) + sum(child scores)


if TYPE_CHECKING:
    from cyvest.model import Check, Observable, ThreatIntel


class ScoreEngine:
    """
    Engine for managing score calculation and propagation.

    Handles:
    - Threat intel scores propagating to observables
    - Observable scores propagating through relationships based on direction
    - Observable scores propagating to checks

    Hierarchical relationships:
    - OUTBOUND (→): source → target, target is a child of source
    - INBOUND (←): source ← target, target is a parent of source
    - BIDIRECTIONAL (↔): excluded from hierarchical propagation
    """

    def __init__(self, score_mode: ScoreMode = ScoreMode.MAX) -> None:
        """Initialize the score engine.

        Args:
            score_mode: Score calculation mode (MAX or SUM)
        """
        self._observables: dict[str, Observable] = {}
        self._checks: dict[str, Check] = {}
        self._score_mode = score_mode

    def register_observable(self, observable: "Observable") -> None:
        """
        Register an observable for score tracking.

        Args:
            observable: Observable to register
        """
        self._observables[observable.key] = observable

    def register_check(self, check: "Check") -> None:
        """
        Register a check for score tracking.

        Args:
            check: Check to register
        """
        self._checks[check.key] = check

    def propagate_threat_intel_to_observable(self, ti: "ThreatIntel", observable: "Observable") -> None:
        """
        Propagate threat intel score to its observable.

        Args:
            ti: The threat intel providing the score
            observable: The observable to update
        """
        # Special handling for SAFE level threat intel
        # If TI has SAFE level and observable level is lower, upgrade observable to SAFE
        if ti.level == Level.SAFE and observable.level < Level.SAFE:
            observable.set_level(Level.SAFE)
        
        # Calculate the new observable score (includes TI scores and child scores)
        new_score = self._calculate_observable_score(observable)

        if new_score != observable.score:
            observable.update_score(new_score, reason=f"Threat intel update from {ti.source}")

            # Propagate to parent observables
            self._propagate_to_parent_observables(observable)

            # Propagate to linked checks
            self._propagate_observable_to_checks(observable)

    def _calculate_observable_score(self, observable: "Observable", visited: set[str] | None = None) -> Decimal:
        """
        Calculate the complete observable score based on threat intel and hierarchical relationships.

        Hierarchical relationships are determined by direction:
        - OUTBOUND relationships: target is a hierarchical child
        - INBOUND relationships: not considered for child score calculation
        - BIDIRECTIONAL relationships: excluded from hierarchy

        Args:
            observable: The observable to calculate score for
            visited: Set of visited observable keys to prevent cycles

        Returns:
            Calculated score based on score_mode:
            - MAX mode: max(all TI scores, all child scores)
            - SUM mode: max(TI scores) + sum(child scores)
        """
        # Initialize visited set for cycle detection
        if visited is None:
            visited = set()

        # Prevent infinite recursion
        if observable.key in visited:
            # Return only the observable's own TI score (don't recurse)
            return max((ti.score for ti in observable.threat_intels), default=Decimal("0"))

        # Mark this observable as visited
        visited.add(observable.key)

        # Get max threat intel score for this observable
        max_ti_score = max((ti.score for ti in observable.threat_intels), default=Decimal("0"))

        # Collect child observable scores recursively
        # Children are defined two ways:
        # 1. Targets of this observable's OUTBOUND relationships (source → target)
        # 2. Sources of INBOUND relationships where this observable is the target (child ← this)
        child_scores = []

        # Method 1: OUTBOUND relationships from this observable
        for rel in observable.relationships:
            # Only OUTBOUND relationships define hierarchical children
            if rel.direction == RelationshipDirection.OUTBOUND:
                child = self._observables.get(rel.target_key)
                if child:
                    # Recursively calculate child's complete score
                    child_score = self._calculate_observable_score(child, visited)
                    child_scores.append(child_score)

        # Method 2: Other observables with INBOUND relationships pointing to this observable
        # If obs_x has INBOUND to this observable, then obs_x is a child
        for other_key, other_obs in self._observables.items():
            if other_key == observable.key:
                continue
            for rel in other_obs.relationships:
                if rel.direction == RelationshipDirection.INBOUND and rel.target_key == observable.key:
                    # other_obs has INBOUND to this observable, so other_obs is a child
                    child_score = self._calculate_observable_score(other_obs, visited)
                    child_scores.append(child_score)

        # Calculate final score based on mode
        if self._score_mode == ScoreMode.MAX:
            # MAX mode: take maximum of all scores (TI + children)
            all_scores = [max_ti_score] + child_scores
            return max(all_scores, default=Decimal("0"))
        else:
            # SUM mode: max TI score + sum of child scores
            sum_children = sum(child_scores, Decimal("0"))
            return max_ti_score + sum_children

    def _propagate_to_parent_observables(self, observable: "Observable") -> None:
        """
        Propagate score changes up to parent observables.

        Parents are found through two mechanisms:
        1. INBOUND relationships: source ← target (target is parent)
        2. Other observables with OUTBOUND relationships to this observable (they are parents)

        Args:
            observable: The observable whose score changed
        """
        # Method 1: Find parents through INBOUND relationships
        # For INBOUND: source ← target, target is the parent
        for rel in observable.relationships:
            if rel.direction == RelationshipDirection.INBOUND:
                parent_obs = self._observables.get(rel.target_key)
                if parent_obs and parent_obs.key != observable.key:
                    # Recalculate parent's score
                    new_parent_score = self._calculate_observable_score(parent_obs)

                    if new_parent_score != parent_obs.score:
                        parent_obs.update_score(new_parent_score, reason=f"Child observable {observable.key} updated")
                        # Recursively propagate upwards
                        self._propagate_to_parent_observables(parent_obs)
                        # Propagate to checks linked to parent
                        self._propagate_observable_to_checks(parent_obs)

        # Method 2: Find observables that have OUTBOUND relationships TO this observable
        # Those observables are parents (they point to this observable as their child)
        for parent_key, parent_obs in self._observables.items():
            if parent_key == observable.key:
                continue

            # Check if parent has an OUTBOUND relationship to this observable
            for rel in parent_obs.relationships:
                if rel.direction == RelationshipDirection.OUTBOUND and rel.target_key == observable.key:
                    # Recalculate parent's score
                    new_parent_score = self._calculate_observable_score(parent_obs)

                    if new_parent_score != parent_obs.score:
                        parent_obs.update_score(new_parent_score, reason=f"Child observable {observable.key} updated")
                        # Recursively propagate upwards
                        self._propagate_to_parent_observables(parent_obs)
                        # Propagate to checks linked to parent
                        self._propagate_observable_to_checks(parent_obs)

    def _propagate_observable_to_checks(self, observable: "Observable") -> None:
        """
        Propagate observable score to linked checks.

        Check score is calculated as the maximum of all linked observables' scores
        and the check's current score.

        Check level inherits SAFE if any linked observable is SAFE and all others are
        lower than or equal to SAFE (NONE, TRUSTED, INFO, SAFE).

        Args:
            observable: The observable to check
        """
        for check in self._checks.values():
            # Check if this observable is linked to the check (directly or through relationships)
            if self._is_observable_linked_to_check(observable, check):
                # Collect all linked observable scores and observables
                linked_scores = []
                linked_observables = []
                for obs in self._observables.values():
                    if self._is_observable_linked_to_check(obs, check):
                        linked_scores.append(obs.score)
                        linked_observables.append(obs)

                # Calculate new check score as max of all linked observables and current check score
                if linked_scores:
                    new_check_score = max(linked_scores + [check.score])

                    if new_check_score != check.score:
                        check.update_score(new_check_score, reason=f"Linked observable {observable.key} updated")

                # Check SAFE level propagation: if any observable is SAFE and all are <= SAFE,
                # set check to SAFE (overrides any previous level)
                if linked_observables:
                    has_safe = any(obs.level == Level.SAFE for obs in linked_observables)
                    all_lower_or_safe = all(obs.level <= Level.SAFE for obs in linked_observables)

                    if has_safe and all_lower_or_safe and check.level < Level.SAFE:
                        check.set_level(Level.SAFE)

    def _is_observable_linked_to_check(self, observable: "Observable", check: "Check", indirect: bool = False) -> bool:
        """
        Check if an observable is linked to a check (directly or indirectly).

        Args:
            observable: The observable to check
            check: The check to verify linkage with

        Returns:
            True if linked, False otherwise
        """
        # Direct linkage
        if observable in check.observables:
            return True

        if indirect is False:
            return False

        # Indirect linkage through relationships
        for obs in check.observables:
            if self._is_related(obs, observable):
                return True

        return False

    def _is_related(self, obs1: "Observable", obs2: "Observable", visited: set[str] | None = None) -> bool:
        """
        Check if two observables are related through relationships.

        Args:
            obs1: First observable
            obs2: Second observable
            visited: Set of visited observable keys to avoid cycles

        Returns:
            True if related, False otherwise
        """
        if visited is None:
            visited = set()

        if obs1.key == obs2.key:
            return True

        if obs1.key in visited:
            return False

        visited.add(obs1.key)

        # Check relationships
        for rel in obs1.relationships:
            if rel.target_key == obs2.key:
                return True
            # Recursively check related observables
            related_obs = self._observables.get(rel.target_key)
            if related_obs and self._is_related(related_obs, obs2, visited):
                return True

        return False

    def recalculate_all(self) -> None:
        """
        Recalculate all scores from scratch.

        Useful after merging investigations or bulk updates.
        """
        # First, recalculate all observables from their threat intel and relationships
        for obs in self._observables.values():
            new_score = self._calculate_observable_score(obs)
            if new_score != obs.score:
                obs.update_score(new_score, reason="Recalculation")

        # Then propagate to all checks (not just MALICIOUS observables)
        for obs in self._observables.values():
            self._propagate_observable_to_checks(obs)

    def get_global_score(self) -> Decimal:
        """
        Calculate the global investigation score.

        The global score is the sum of all check scores.

        Returns:
            Total investigation score
        """
        return sum((check.score for check in self._checks.values()), Decimal("0"))

    def get_global_level(self) -> Level:
        """
        Calculate the global investigation level.

        The global level is determined from the global score.

        Returns:
            Investigation level
        """
        return get_level_from_score(self.get_global_score())
