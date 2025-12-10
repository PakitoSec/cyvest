"""
Core data models for Cyvest investigation framework.

Defines the base classes for Check, Observable, ThreatIntel, Enrichment, and Container.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from cyvest import keys
from cyvest.levels import Level, get_level_from_score, normalize_level
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator


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


class ScoreChange(BaseModel):
    """Record of a score change for audit trail."""

    model_config = ConfigDict(validate_assignment=True)

    timestamp: datetime
    old_score: Decimal
    new_score: Decimal
    old_level: Level
    new_level: Level
    reason: str

    @field_validator("old_score", "new_score", mode="before")
    @classmethod
    def _coerce_decimal(cls, value: Any) -> Decimal:
        return value if isinstance(value, Decimal) else Decimal(str(value))

    @field_validator("old_level", "new_level", mode="before")
    @classmethod
    def _normalize_level(cls, value: Level | str) -> Level:
        return normalize_level(value)


class CheckScorePolicy(str, Enum):
    """Controls how a check reacts to linked observables."""

    AUTO = "auto"  # Default: observables can update the check score/level
    MANUAL = "manual"  # Score/level only change via explicit check updates


class Check(BaseModel):
    """
    Represents a verification step in the investigation.

    A check validates a specific aspect of the data under investigation
    and contributes to the overall investigation score.
    """

    model_config = ConfigDict(validate_assignment=True)

    check_id: str
    scope: str
    description: str
    comment: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)
    score: Decimal = Field(default_factory=lambda: Decimal("0"))
    level: Level = Level.NONE
    observables: list["Observable"] = Field(default_factory=list)
    score_policy: CheckScorePolicy = CheckScorePolicy.AUTO
    key: str = ""

    _explicit_level: bool = PrivateAttr(default=False)
    _score_history: list[ScoreChange] = PrivateAttr(default_factory=list)

    @field_validator("score", mode="before")
    @classmethod
    def _coerce_score(cls, value: Any) -> Decimal:
        return value if isinstance(value, Decimal) else Decimal(str(value))

    @field_validator("level", mode="before")
    @classmethod
    def _normalize_level(cls, value: Level | str) -> Level:
        return normalize_level(value)

    @field_validator("score_policy", mode="before")
    @classmethod
    def _normalize_policy(cls, value: CheckScorePolicy | str) -> CheckScorePolicy:
        return CheckScorePolicy(value)

    @model_validator(mode="after")
    def _finalize(self) -> "Check":
        if not self.key:
            self.key = keys.generate_check_key(self.check_id, self.scope)
        return self

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


class Relationship(BaseModel):
    """Represents a relationship between observables."""

    target_key: str  # Key of the target observable
    relationship_type: RelationshipType | str  # Relationship type label
    direction: RelationshipDirection | str | None = None  # Relationship direction (None = auto-detect)

    model_config = ConfigDict(validate_assignment=True)

    @field_validator("relationship_type", mode="before")
    @classmethod
    def _normalize_relationship_type(cls, value: RelationshipType | str) -> RelationshipType | str:
        if isinstance(value, RelationshipType):
            return value
        try:
            return RelationshipType(value)
        except ValueError:
            return value

    @field_validator("direction", mode="before")
    @classmethod
    def _normalize_direction(cls, value: RelationshipDirection | str | None) -> RelationshipDirection | str | None:
        if value is None or isinstance(value, RelationshipDirection):
            return value
        try:
            return RelationshipDirection(value)
        except ValueError:
            return value

    @model_validator(mode="after")
    def _finalize_direction(self) -> "Relationship":
        if self.direction is None:
            if isinstance(self.relationship_type, RelationshipType):
                self.direction = self.relationship_type.get_default_direction()
            else:
                self.direction = RelationshipDirection.OUTBOUND
        elif isinstance(self.direction, str):
            try:
                self.direction = RelationshipDirection(self.direction)
            except ValueError:
                self.direction = (
                    self.relationship_type.get_default_direction()
                    if isinstance(self.relationship_type, RelationshipType)
                    else RelationshipDirection.OUTBOUND
                )
        return self

    @property
    def relationship_type_name(self):
        return (
            self.relationship_type.value
            if isinstance(self.relationship_type, RelationshipType)
            else self.relationship_type
        )


class Observable(BaseModel):
    """
    Represents a cyber observable (IP, URL, domain, hash, etc.).

    Observables can be linked to threat intelligence, checks, and other observables
    through relationships.
    """

    model_config = ConfigDict(validate_assignment=True)

    obs_type: ObservableType | str
    value: str
    internal: bool = True
    whitelisted: bool = False
    comment: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)
    score: Decimal = Field(default_factory=lambda: Decimal("0"))
    level: Level = Level.INFO
    threat_intels: list[ThreatIntel] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    key: str = ""

    _explicit_level: bool = PrivateAttr(default=False)
    _score_history: list[ScoreChange] = PrivateAttr(default_factory=list)
    _generated_by_checks: list[str] = PrivateAttr(default_factory=list)
    _from_shared_context: bool = PrivateAttr(default=False)

    @field_validator("obs_type", mode="before")
    @classmethod
    def _normalize_obs_type(cls, value: ObservableType | str) -> ObservableType | str:
        if isinstance(value, ObservableType):
            return value
        try:
            return ObservableType(value)
        except ValueError:
            return value

    @field_validator("score", mode="before")
    @classmethod
    def _coerce_score(cls, value: Any) -> Decimal:
        return value if isinstance(value, Decimal) else Decimal(str(value))

    @field_validator("level", mode="before")
    @classmethod
    def _normalize_level(cls, value: Level | str) -> Level:
        return normalize_level(value)

    @model_validator(mode="after")
    def _finalize(self) -> "Observable":
        if not self.key:
            obs_type_str = self.obs_type.value if isinstance(self.obs_type, ObservableType) else self.obs_type
            self.key = keys.generate_observable_key(obs_type_str, self.value)

        if self.level == Level.SAFE:
            self.set_level(Level.SAFE)

        return self

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


class ThreatIntel(BaseModel):
    """
    Represents threat intelligence from an external source.

    Threat intelligence provides verdicts about observables from sources
    like VirusTotal, URLScan.io, etc.
    """

    model_config = ConfigDict(validate_assignment=True)

    source: str
    observable_key: str
    comment: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)
    score: Decimal = Field(default_factory=lambda: Decimal("0"))
    level: Level = Level.INFO
    taxonomies: list[dict[str, Any]] = Field(default_factory=list)
    key: str = ""

    _explicit_level: bool = PrivateAttr(default=False)

    @field_validator("score", mode="before")
    @classmethod
    def _coerce_score(cls, value: Any) -> Decimal:
        return value if isinstance(value, Decimal) else Decimal(str(value))

    @field_validator("level", mode="before")
    @classmethod
    def _normalize_level(cls, value: Level | str) -> Level:
        return normalize_level(value)

    @model_validator(mode="after")
    def _finalize(self) -> "ThreatIntel":
        if not self.key:
            self.key = keys.generate_threat_intel_key(self.source, self.observable_key)

        if not self._explicit_level and self.level == Level.INFO:
            calculated_level = get_level_from_score(self.score)
            if calculated_level != Level.NONE:
                self.level = calculated_level

        return self

    def set_level(self, level: Level | str) -> None:
        """
        Explicitly set the level (overrides automatic calculation).

        Args:
            level: The level to set
        """
        self.level = normalize_level(level)
        self._explicit_level = True


class Enrichment(BaseModel):
    """
    Represents structured data enrichment for the investigation.

    Enrichments store arbitrary structured data that provides additional
    context but doesn't directly contribute to scoring.
    """

    model_config = ConfigDict(validate_assignment=True)

    name: str
    data: dict[str, Any] = Field(default_factory=dict)
    context: str = ""
    key: str = ""

    @model_validator(mode="after")
    def _finalize(self) -> "Enrichment":
        if not self.key:
            self.key = keys.generate_enrichment_key(self.name, self.context)
        return self


class Container(BaseModel):
    """
    Groups checks and sub-containers for hierarchical organization.

    Containers allow structuring the investigation into logical sections
    with aggregated scores and levels.
    """

    model_config = ConfigDict(validate_assignment=True)

    path: str
    description: str = ""
    checks: list[Check] = Field(default_factory=list)
    sub_containers: dict[str, "Container"] = Field(default_factory=dict)
    key: str = ""

    @model_validator(mode="after")
    def _finalize(self) -> "Container":
        if not self.key:
            self.key = keys.generate_container_key(self.path)
        return self

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


# Resolve forward references for models that reference each other
Check.model_rebuild()
Observable.model_rebuild()
ThreatIntel.model_rebuild()
Enrichment.model_rebuild()
Container.model_rebuild()
