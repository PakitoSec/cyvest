"""
Core data models for Cyvest investigation framework.

Defines the base classes for Check, Observable, ThreatIntel, Enrichment, and Container.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any

from cyvest import keys
from cyvest.levels import Level, get_level_from_score


@dataclass
class ScoreChange:
    """Record of a score change for audit trail."""

    timestamp: datetime
    old_score: Decimal
    new_score: Decimal
    old_level: Level
    new_level: Level
    reason: str


@dataclass
class Check:
    """
    Represents a verification step in the investigation.

    A check validates a specific aspect of the data under investigation
    and contributes to the overall investigation score.
    """

    check_id: str
    scope: str
    description: str
    comment: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    score: Decimal = field(default_factory=lambda: Decimal("0"))
    level: Level = Level.NONE
    observables: list[Observable] = field(default_factory=list)
    key: str = field(default="", init=False)
    _explicit_level: bool = field(default=False, init=False)
    _score_history: list[ScoreChange] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        """Generate key and normalize types."""
        if not self.key:
            self.key = keys.generate_check_key(self.check_id, self.scope)
        if not isinstance(self.score, Decimal):
            self.score = Decimal(str(self.score))

    def update_score(self, new_score: Decimal, reason: str = "") -> None:
        """
        Update the check's score and recalculate level if needed.

        Args:
            new_score: The new score value
            reason: Reason for the score change
        """
        if not isinstance(new_score, Decimal):
            new_score = Decimal(str(new_score))

        old_score = self.score
        old_level = self.level

        self.score = new_score

        # Calculate new level from score if not explicitly set or if new level is higher
        calculated_level = get_level_from_score(self.score)

        # Special case: if score was 0 and level was NONE, and something happened, set to INFO
        if old_score == Decimal("0") and old_level == Level.NONE and new_score != Decimal("0"):
            if calculated_level == Level.INFO or calculated_level == Level.NONE:
                calculated_level = Level.INFO

        # Update level only if calculated is higher or level wasn't explicitly set
        if not self._explicit_level or calculated_level > self.level:
            self.level = calculated_level

        # Record the change
        change = ScoreChange(
            timestamp=datetime.now(),
            old_score=old_score,
            new_score=new_score,
            old_level=old_level,
            new_level=self.level,
            reason=reason,
        )
        self._score_history.append(change)

    def set_level(self, level: Level) -> None:
        """
        Explicitly set the level (overrides automatic calculation).

        Args:
            level: The level to set
        """
        self.level = level
        self._explicit_level = True

    def add_observable(self, observable: Observable) -> None:
        """
        Add an observable to this check.

        Args:
            observable: The observable to link
        """
        if observable not in self.observables:
            self.observables.append(observable)


@dataclass
class Relationship:
    """Represents a relationship between observables following STIX2 conventions."""

    target_key: str  # Key of the target observable
    relationship_type: str  # STIX2 relationship type (e.g., "resolves-to", "related-to")


@dataclass
class Observable:
    """
    Represents a cyber observable (IP, URL, domain, hash, etc.).

    Observables can be linked to threat intelligence, checks, and other observables
    through relationships.
    """

    obs_type: str
    value: str
    internal: bool = True
    whitelisted: bool = False
    comment: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    score: Decimal = field(default_factory=lambda: Decimal("0"))
    level: Level = Level.INFO
    threat_intels: list[ThreatIntel] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    key: str = field(default="", init=False)
    _explicit_level: bool = field(default=False, init=False)
    _score_history: list[ScoreChange] = field(default_factory=list, init=False)
    _generated_by_checks: list[str] = field(default_factory=list, init=False)  # Check keys

    def __post_init__(self) -> None:
        """Generate key and normalize types."""
        if not self.key:
            self.key = keys.generate_observable_key(self.obs_type, self.value)
        if not isinstance(self.score, Decimal):
            self.score = Decimal(str(self.score))

    def update_score(self, new_score: Decimal, reason: str = "") -> None:
        """
        Update the observable's score and recalculate level if needed.

        Args:
            new_score: The new score value
            reason: Reason for the score change
        """
        if not isinstance(new_score, Decimal):
            new_score = Decimal(str(new_score))

        old_score = self.score
        old_level = self.level

        self.score = new_score

        # Calculate new level from score
        calculated_level = get_level_from_score(self.score)

        # Update level only if calculated is higher or level wasn't explicitly set
        if not self._explicit_level or calculated_level > self.level:
            self.level = calculated_level

        # Record the change
        change = ScoreChange(
            timestamp=datetime.now(),
            old_score=old_score,
            new_score=new_score,
            old_level=old_level,
            new_level=self.level,
            reason=reason,
        )
        self._score_history.append(change)

    def set_level(self, level: Level) -> None:
        """
        Explicitly set the level (overrides automatic calculation).

        Args:
            level: The level to set
        """
        self.level = level
        self._explicit_level = True

    def add_threat_intel(self, ti: ThreatIntel) -> None:
        """
        Add threat intelligence to this observable.

        Args:
            ti: The threat intel to add
        """
        if ti not in self.threat_intels:
            self.threat_intels.append(ti)

    def add_relationship(self, target_key: str, relationship_type: str) -> None:
        """
        Add a relationship to another observable.

        Args:
            target_key: Key of the target observable
            relationship_type: Type of relationship (STIX2 convention)
        """
        rel = Relationship(target_key=target_key, relationship_type=relationship_type)
        if rel not in self.relationships:
            self.relationships.append(rel)

    def mark_generated_by_check(self, check_key: str) -> None:
        """
        Mark this observable as generated by a specific check.

        Args:
            check_key: Key of the check that generated this observable
        """
        if check_key not in self._generated_by_checks:
            self._generated_by_checks.append(check_key)


@dataclass
class ThreatIntel:
    """
    Represents threat intelligence from an external source.

    Threat intelligence provides verdicts about observables from sources
    like VirusTotal, URLScan.io, etc.
    """

    source: str
    observable_key: str
    comment: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    score: Decimal = field(default_factory=lambda: Decimal("0"))
    level: Level = Level.INFO
    taxonomies: list[dict[str, Any]] = field(default_factory=list)
    key: str = field(default="", init=False)
    _explicit_level: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        """Generate key and normalize types."""
        if not self.key:
            self.key = keys.generate_threat_intel_key(self.source, self.observable_key)
        if not isinstance(self.score, Decimal):
            self.score = Decimal(str(self.score))
        # Recalculate level from score if not explicitly set
        if not self._explicit_level and self.level == Level.INFO:
            calculated_level = get_level_from_score(self.score)
            if calculated_level != Level.NONE:
                self.level = calculated_level

    def set_level(self, level: Level) -> None:
        """
        Explicitly set the level (overrides automatic calculation).

        Args:
            level: The level to set
        """
        self.level = level
        self._explicit_level = True


@dataclass
class Enrichment:
    """
    Represents structured data enrichment for the investigation.

    Enrichments store arbitrary structured data that provides additional
    context but doesn't directly contribute to scoring.
    """

    name: str
    data: dict[str, Any] = field(default_factory=dict)
    context: str = ""
    key: str = field(default="", init=False)

    def __post_init__(self) -> None:
        """Generate key."""
        if not self.key:
            self.key = keys.generate_enrichment_key(self.name, self.context)


@dataclass
class Container:
    """
    Groups checks and sub-containers for hierarchical organization.

    Containers allow structuring the investigation into logical sections
    with aggregated scores and levels.
    """

    path: str
    description: str = ""
    checks: list[Check] = field(default_factory=list)
    sub_containers: dict[str, Container] = field(default_factory=dict)
    key: str = field(default="", init=False)

    def __post_init__(self) -> None:
        """Generate key."""
        if not self.key:
            self.key = keys.generate_container_key(self.path)

    def add_check(self, check: Check) -> None:
        """
        Add a check to this container.

        Args:
            check: The check to add
        """
        if check not in self.checks:
            self.checks.append(check)

    def add_sub_container(self, container: Container) -> None:
        """
        Add a sub-container.

        Args:
            container: The sub-container to add
        """
        self.sub_containers[container.key] = container

    def get_aggregated_score(self) -> Decimal:
        """
        Calculate the aggregated score from all checks and sub-containers.

        Returns:
            Total aggregated score
        """
        total = Decimal("0")
        # Sum scores from direct checks
        for check in self.checks:
            total += check.score
        # Sum scores from sub-containers
        for sub in self.sub_containers.values():
            total += sub.get_aggregated_score()
        return total

    def get_aggregated_level(self) -> Level:
        """
        Calculate the aggregated level from the aggregated score.

        Returns:
            Level based on aggregated score
        """
        return get_level_from_score(self.get_aggregated_score())
