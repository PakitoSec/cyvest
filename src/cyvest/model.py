"""
Core data models for Cyvest investigation framework.

Defines the base classes for Check, Observable, ThreatIntel, Enrichment, and Container.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from cyvest import keys
from cyvest.levels import Level, get_level_from_score, normalize_level


class ObservableType(str, Enum):
    """Cyber observable types."""

    # Network observables
    IPV4_ADDR = "ipv4-addr"
    IPV6_ADDR = "ipv6-addr"
    DOMAIN_NAME = "domain-name"
    URL = "url"
    NETWORK_TRAFFIC = "network-traffic"
    MAC_ADDR = "mac-addr"

    # File observables
    FILE = "file"
    DIRECTORY = "directory"

    # Email observables
    EMAIL_ADDR = "email-addr"
    EMAIL_MESSAGE = "email-message"
    EMAIL_MIME_PART = "email-mime-part"

    # Identity and account
    USER_ACCOUNT = "user-account"

    # System observables
    PROCESS = "process"
    SOFTWARE = "software"
    WINDOWS_REGISTRY_KEY = "windows-registry-key"

    # Artifact observables
    ARTIFACT = "artifact"

    # Autonomous System
    AUTONOMOUS_SYSTEM = "autonomous-system"

    # Mutex
    MUTEX = "mutex"

    # X509 Certificate
    X509_CERTIFICATE = "x509-certificate"


class RelationshipType(str, Enum):
    """Relationship types supported by Cyvest."""

    RELATED_TO = "related-to"

    def get_default_direction(self) -> RelationshipDirection:
        """
        Get the default direction for this relationship type.
        """
        return RelationshipDirection.BIDIRECTIONAL


class RelationshipDirection(str, Enum):
    """Direction of a relationship between observables."""

    OUTBOUND = "outbound"  # Source → Target
    INBOUND = "inbound"  # Source ← Target
    BIDIRECTIONAL = "bidirectional"  # Source ↔ Target


@dataclass
class ScoreChange:
    """Record of a score change for audit trail."""

    timestamp: datetime
    old_score: Decimal
    new_score: Decimal
    old_level: Level
    new_level: Level
    reason: str


class CheckScorePolicy(str, Enum):
    """Controls how a check reacts to linked observables."""

    AUTO = "auto"  # Default: observables can update the check score/level
    MANUAL = "manual"  # Score/level only change via explicit check updates


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
    score_policy: CheckScorePolicy = CheckScorePolicy.AUTO
    key: str = field(default="", init=False)
    _explicit_level: bool = field(default=False, init=False)
    _score_history: list[ScoreChange] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        """Generate key and normalize types."""
        if not self.key:
            self.key = keys.generate_check_key(self.check_id, self.scope)
        if not isinstance(self.score, Decimal):
            self.score = Decimal(str(self.score))
        self.level = normalize_level(self.level)
        if isinstance(self.score_policy, str):
            self.score_policy = CheckScorePolicy(self.score_policy)

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

    def set_level(self, level: Level | str) -> None:
        """
        Explicitly set the level (overrides automatic calculation).

        Args:
            level: The level to set
        """
        self.level = normalize_level(level)
        self._explicit_level = True

    def set_score_policy(self, policy: CheckScorePolicy | str) -> None:
        """
        Control whether observables can update this check's score/level.
        """
        self.score_policy = CheckScorePolicy(policy)

    def add_observable(self, observable: Observable) -> None:
        """
        Add an observable to this check.

        When an observable is added to a check with level NONE, the check's level
        is automatically upgraded to INFO to indicate that the check is now classified.

        Args:
            observable: The observable to link
        """
        if observable not in self.observables:
            self.observables.append(observable)

            # Auto-upgrade level from NONE to INFO when first observable is added
            if self.level == Level.NONE:
                self.set_level(Level.INFO)

    def get_score_history(self) -> list[ScoreChange]:
        """
        Get the score history for this check.

        Returns:
            List of score changes with timestamps, old/new scores and levels, and reasons
        """
        return self._score_history


@dataclass
class Relationship:
    """Represents a relationship between observables."""

    target_key: str  # Key of the target observable
    relationship_type: RelationshipType | str  # Relationship type label
    direction: RelationshipDirection | str | None = None  # Relationship direction (None = auto-detect)

    def __post_init__(self) -> None:
        """Normalize relationship type and direction to enum if possible."""
        # First normalize relationship type
        if isinstance(self.relationship_type, str):
            try:
                self.relationship_type = RelationshipType(self.relationship_type)
            except ValueError:
                # Keep as string if not a recognized relationship type
                pass

        # Then handle direction with smart defaults
        if self.direction is None:
            # No direction specified - use semantic default based on relationship type
            if isinstance(self.relationship_type, RelationshipType):
                self.direction = self.relationship_type.get_default_direction()
            else:
                # Custom relationship type - default to OUTBOUND
                self.direction = RelationshipDirection.OUTBOUND
        elif isinstance(self.direction, str):
            try:
                self.direction = RelationshipDirection(self.direction)
            except ValueError:
                # Invalid direction string - use semantic default or OUTBOUND
                if isinstance(self.relationship_type, RelationshipType):
                    self.direction = self.relationship_type.get_default_direction()
                else:
                    self.direction = RelationshipDirection.OUTBOUND

    @property
    def relationship_type_name(self):
        return (
            self.relationship_type.value
            if isinstance(self.relationship_type, RelationshipType)
            else self.relationship_type
        )


@dataclass
class Observable:
    """
    Represents a cyber observable (IP, URL, domain, hash, etc.).

    Observables can be linked to threat intelligence, checks, and other observables
    through relationships.
    """

    obs_type: ObservableType | str
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
        # Normalize obs_type to enum if possible
        if isinstance(self.obs_type, str):
            try:
                self.obs_type = ObservableType(self.obs_type)
            except ValueError:
                # Keep as string if not a recognized observable type
                pass

        if not self.key:
            # Use string value of obs_type for key generation
            obs_type_str = self.obs_type.value if isinstance(self.obs_type, ObservableType) else self.obs_type
            self.key = keys.generate_observable_key(obs_type_str, self.value)
        if not isinstance(self.score, Decimal):
            self.score = Decimal(str(self.score))
        self.level = normalize_level(self.level)

        # If level is explicitly set to SAFE, mark it as explicit to prevent downgrades
        if self.level == Level.SAFE:
            self.set_level(Level.SAFE)

        # Initialize shared context marker (will be set to True for copies from registry)
        if not hasattr(self, "_from_shared_context"):
            self._from_shared_context = False

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

        # Special protection for SAFE level: only allow upgrades, not downgrades
        if self._explicit_level and self.level == Level.SAFE:
            # SAFE can only be upgraded to higher levels (NOTABLE, SUSPICIOUS, MALICIOUS)
            if calculated_level >= Level.SAFE:
                self.level = calculated_level
            # Otherwise keep SAFE level even if score suggests lower level
        # Update level only if calculated is higher or level wasn't explicitly set
        elif not self._explicit_level or calculated_level > self.level:
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

    def set_level(self, level: Level | str) -> None:
        """
        Explicitly set the level (overrides automatic calculation).

        Args:
            level: The level to set
        """
        self.level = normalize_level(level)
        self._explicit_level = True

    def add_threat_intel(self, ti: ThreatIntel) -> None:
        """
        Add threat intelligence to this observable.

        Args:
            ti: The threat intel to add
        """
        if ti not in self.threat_intels:
            self.threat_intels.append(ti)

    def _add_relationship_internal(
        self,
        target_key: str,
        relationship_type: RelationshipType | str,
        direction: RelationshipDirection | str | None = None,
    ) -> None:
        """
        Internal method to add a relationship without validation.

        This should only be called by the Investigation layer after validating
        that the target observable exists.

        Args:
            target_key: Key of the target observable
            relationship_type: Type of relationship
            direction: Direction of the relationship (None = use semantic default for relationship type)
        """
        rel = Relationship(target_key=target_key, relationship_type=relationship_type, direction=direction)
        # Check for duplicates using target_key, relationship_type, and direction
        rel_tuple = (rel.target_key, rel.relationship_type, rel.direction)
        existing_rels = {(r.target_key, r.relationship_type, r.direction) for r in self.relationships}
        if rel_tuple not in existing_rels:
            self.relationships.append(rel)

    def mark_generated_by_check(self, check_key: str) -> None:
        """
        Mark this observable as generated by a specific check.

        Args:
            check_key: Key of the check that generated this observable
        """
        if check_key not in self._generated_by_checks:
            self._generated_by_checks.append(check_key)

    def get_score_history(self) -> list[ScoreChange]:
        """
        Get the score history for this observable.

        Returns:
            List of score changes with timestamps, old/new scores and levels, and reasons
        """
        return self._score_history


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
        self.level = normalize_level(self.level)
        # Recalculate level from score if not explicitly set
        if not self._explicit_level and self.level == Level.INFO:
            calculated_level = get_level_from_score(self.score)
            if calculated_level != Level.NONE:
                self.level = calculated_level

    def set_level(self, level: Level | str) -> None:
        """
        Explicitly set the level (overrides automatic calculation).

        Args:
            level: The level to set
        """
        self.level = normalize_level(level)
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
