"""
Scoring and propagation engine for Cyvest.

Handles automatic score calculation and propagation between threat intelligence,
observables, and checks based on relationships and hierarchies.
"""

from decimal import Decimal
from typing import TYPE_CHECKING

from cyvest.levels import Level, get_level_from_score

if TYPE_CHECKING:
    from cyvest.model import Check, Observable, ThreatIntel


class ScoreEngine:
    """
    Engine for managing score calculation and propagation.

    Handles:
    - Threat intel scores propagating to observables
    - Observable scores propagating through relationships
    - Observable scores propagating to checks
    """

    def __init__(self) -> None:
        """Initialize the score engine."""
        self._observables: dict[str, Observable] = {}
        self._checks: dict[str, Check] = {}

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
        # Calculate the new observable score as sum of all threat intel scores
        total_ti_score = sum((threat.score for threat in observable.threat_intels), Decimal("0"))

        # Also include scores from child observables (hierarchical relationships)
        child_score = self._calculate_child_observable_score(observable)

        new_score = total_ti_score + child_score

        if new_score != observable.score:
            observable.update_score(new_score, reason=f"Threat intel update from {ti.source}")

            # Propagate to parent observables
            self._propagate_to_parent_observables(observable)

            # Propagate to linked checks
            self._propagate_observable_to_checks(observable)

    def _calculate_child_observable_score(self, observable: "Observable") -> Decimal:
        """
        Calculate the total score from hierarchically inferior observables.

        Args:
            observable: The parent observable

        Returns:
            Total score from children
        """
        total = Decimal("0")
        hierarchical_types = {
            "resolves-to",
            "resolves-from",
            "contains",
            "extracted-from",
            "downloaded-from",
            "uses",
            "communicates-with",
        }

        for rel in observable.relationships:
            if rel.relationship_type in hierarchical_types:
                child = self._observables.get(rel.target_key)
                if child:
                    # Recursively get child's score (includes their threat intel + their children)
                    child_ti_score = sum((ti.score for ti in child.threat_intels), Decimal("0"))
                    child_children_score = self._calculate_child_observable_score(child)
                    total += child_ti_score + child_children_score

        return total

    def _propagate_to_parent_observables(self, observable: "Observable") -> None:
        """
        Propagate score changes up to parent observables.

        Args:
            observable: The observable whose score changed
        """
        # Find all observables that have this one as a child
        for parent_key, parent_obs in self._observables.items():
            if parent_key == observable.key:
                continue

            # Check if parent has a relationship to this observable
            for rel in parent_obs.relationships:
                if rel.target_key == observable.key:
                    # Recalculate parent's score
                    parent_ti_score = sum((ti.score for ti in parent_obs.threat_intels), Decimal("0"))
                    parent_child_score = self._calculate_child_observable_score(parent_obs)
                    new_parent_score = parent_ti_score + parent_child_score

                    if new_parent_score != parent_obs.score:
                        parent_obs.update_score(
                            new_parent_score, reason=f"Child observable {observable.key} updated"
                        )
                        # Recursively propagate upwards
                        self._propagate_to_parent_observables(parent_obs)
                        # Propagate to checks linked to parent
                        self._propagate_observable_to_checks(parent_obs)

    def _propagate_observable_to_checks(self, observable: "Observable") -> None:
        """
        Propagate observable score to linked checks if observable is MALICIOUS.

        Args:
            observable: The observable to check
        """
        # If observable level is MALICIOUS (score >= 5.0), propagate to checks
        if observable.level == Level.MALICIOUS:
            for check in self._checks.values():
                # Check if this observable is linked to the check (directly or through relationships)
                if self._is_observable_linked_to_check(observable, check):
                    # Update check score and level to match observable
                    if check.score != observable.score or check.level != Level.MALICIOUS:
                        check.update_score(observable.score, reason=f"Observable {observable.key} is MALICIOUS")
                        check.set_level(Level.MALICIOUS)

    def _is_observable_linked_to_check(self, observable: "Observable", check: "Check") -> bool:
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
        # First, recalculate all observables from their threat intel
        for obs in self._observables.values():
            ti_score = sum((ti.score for ti in obs.threat_intels), Decimal("0"))
            child_score = self._calculate_child_observable_score(obs)
            new_score = ti_score + child_score
            if new_score != obs.score:
                obs.update_score(new_score, reason="Recalculation")

        # Then propagate to checks
        for obs in self._observables.values():
            if obs.level == Level.MALICIOUS:
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
