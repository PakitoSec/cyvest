"""
Core data models for Cyvest investigation framework.

Defines the base classes for Check, Observable, ThreatIntel, Enrichment, Container,
and InvestigationWhitelist using Pydantic BaseModel.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)
from typing_extensions import Self

from cyvest import keys
from cyvest.level_score_rules import apply_creation_score_level_defaults, recalculate_level_for_score
from cyvest.levels import Level, get_level_from_score, normalize_level
from cyvest.model_enums import (
    CheckScorePolicy,
    ObservableType,
    RelationshipDirection,
    RelationshipType,
)


class ScoreChange(BaseModel):
    """Record of a score change for audit trail."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime
    old_score: Decimal
    new_score: Decimal
    old_level: Level
    new_level: Level
    reason: str

    @field_serializer("old_score", "new_score")
    def serialize_decimal(self, v: Decimal) -> float:
        return float(v)


class InvestigationWhitelist(BaseModel):
    """Represents a whitelist entry on an investigation."""

    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    identifier: Annotated[str, Field(min_length=1)]
    name: Annotated[str, Field(min_length=1)]
    justification: str | None = None


class Relationship(BaseModel):
    """Represents a relationship between observables."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    target_key: str = Field(...)
    relationship_type: RelationshipType | str = Field(...)
    direction: RelationshipDirection = Field(...)

    @model_validator(mode="before")
    @classmethod
    def ensure_defaults(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        if values.get("direction") is None:
            rel_type = values.get("relationship_type")

            # Use semantic default when relationship type is known, otherwise fall back to outbound.
            default_direction = RelationshipDirection.OUTBOUND
            if isinstance(rel_type, RelationshipType):
                default_direction = rel_type.get_default_direction()
            else:
                try:
                    rel_enum = RelationshipType(rel_type)
                    default_direction = rel_enum.get_default_direction()
                    values["relationship_type"] = rel_enum
                except Exception:
                    # Unknown type: keep fallback outbound
                    pass

            values["direction"] = default_direction
        return values

    @field_validator("relationship_type", mode="before")
    @classmethod
    def coerce_relationship_type(cls, v: Any) -> RelationshipType | str:
        """Normalize relationship type to enum if possible."""
        if isinstance(v, RelationshipType):
            return v
        if isinstance(v, str):
            try:
                return RelationshipType(v)
            except ValueError:
                # Keep as string if not a recognized relationship type
                return v
        return v

    @field_serializer("relationship_type")
    def serialize_relationship_type(self, v: RelationshipType | str) -> str:
        return v.value if isinstance(v, RelationshipType) else v

    @field_validator("direction", mode="before")
    @classmethod
    def coerce_direction(cls, v: Any) -> RelationshipDirection:
        if v is None:
            return RelationshipDirection.OUTBOUND
        if isinstance(v, RelationshipDirection):
            return v
        if isinstance(v, str):
            return RelationshipDirection(v)
        raise TypeError("Invalid direction type")

    @property
    def relationship_type_name(self) -> str:
        return (
            self.relationship_type.value
            if isinstance(self.relationship_type, RelationshipType)
            else self.relationship_type
        )


# Forward references for type hints
class ThreatIntel(BaseModel):
    """
    Represents threat intelligence from an external source.

    Threat intelligence provides verdicts about observables from sources
    like VirusTotal, URLScan.io, etc.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    source: str
    observable_key: str
    comment: str = Field(...)
    extra: dict[str, Any] = Field(...)
    score: Decimal = Field(...)
    level: Level = Field(...)
    taxonomies: list[dict[str, Any]] = Field(...)
    key: str = Field(...)

    @field_validator("extra", mode="before")
    @classmethod
    def coerce_extra(cls, v: Any) -> dict[str, Any]:
        if v is None:
            return {}
        return v

    @field_validator("score", mode="before")
    @classmethod
    def coerce_score(cls, v: Any) -> Decimal:
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))

    @field_validator("level", mode="before")
    @classmethod
    def coerce_level(cls, v: Any) -> Level:
        return normalize_level(v)

    @model_validator(mode="before")
    @classmethod
    def ensure_defaults(cls, values: Any) -> Any:
        values = apply_creation_score_level_defaults(values, default_level_no_score=Level.INFO)
        if not isinstance(values, dict):
            return values

        if "extra" not in values:
            values["extra"] = {}
        if "comment" not in values:
            values["comment"] = ""
        if "taxonomies" not in values:
            values["taxonomies"] = []
        if "key" not in values:
            values["key"] = ""
        return values

    @model_validator(mode="after")
    def generate_key(self) -> Self:
        """Generate key."""
        if not self.key:
            self.key = keys.generate_threat_intel_key(self.source, self.observable_key)

        return self

    @field_serializer("score")
    def serialize_score(self, v: Decimal) -> float:
        return float(v)

    def set_level(self, level: Level | str) -> None:
        """
        Set the level.

        Args:
            level: The level to set
        """
        self.level = normalize_level(level)


class Observable(BaseModel):
    """
    Represents a cyber observable (IP, URL, domain, hash, etc.).

    Observables can be linked to threat intelligence, checks, and other observables
    through relationships.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)

    obs_type: ObservableType | str = Field(..., alias="type")
    value: str
    internal: bool = Field(...)
    whitelisted: bool = Field(...)
    comment: str = Field(...)
    extra: dict[str, Any] = Field(...)
    score: Decimal = Field(...)
    level: Level = Field(...)
    threat_intels: list[ThreatIntel] = Field(...)
    relationships: list[Relationship] = Field(...)
    key: str = Field(...)
    _score_history: list[ScoreChange] = PrivateAttr(default_factory=list)
    _generated_by_checks: list[str] = PrivateAttr(default_factory=list)
    _from_shared_context: bool = PrivateAttr(default=False)

    @field_validator("obs_type", mode="before")
    @classmethod
    def coerce_obs_type(cls, v: Any) -> ObservableType | str:
        if isinstance(v, ObservableType):
            return v
        if isinstance(v, str):
            try:
                # Try case-insensitive match first
                return ObservableType(v.lower())
            except ValueError:
                # Keep as string if not a recognized observable type
                return v
        return v

    @field_validator("extra", mode="before")
    @classmethod
    def coerce_extra(cls, v: Any) -> dict[str, Any]:
        if v is None:
            return {}
        return v

    @field_validator("score", mode="before")
    @classmethod
    def coerce_score(cls, v: Any) -> Decimal:
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))

    @field_validator("level", mode="before")
    @classmethod
    def coerce_level(cls, v: Any) -> Level:
        return normalize_level(v)

    @model_validator(mode="before")
    @classmethod
    def ensure_defaults(cls, values: Any) -> Any:
        values = apply_creation_score_level_defaults(values, default_level_no_score=Level.INFO)
        if not isinstance(values, dict):
            return values

        if "extra" not in values:
            values["extra"] = {}
        if "comment" not in values:
            values["comment"] = ""
        if "internal" not in values:
            values["internal"] = True
        if "whitelisted" not in values:
            values["whitelisted"] = False
        if "threat_intels" not in values:
            values["threat_intels"] = []
        if "relationships" not in values:
            values["relationships"] = []
        if "key" not in values:
            values["key"] = ""
        return values

    @model_validator(mode="after")
    def generate_key(self) -> Self:
        """Generate key."""
        if not self.key:
            # Use string value of obs_type for key generation
            obs_type_str = self.obs_type.value if isinstance(self.obs_type, ObservableType) else self.obs_type
            self.key = keys.generate_observable_key(obs_type_str, self.value)

        return self

    @field_serializer("obs_type")
    def serialize_obs_type(self, v: ObservableType | str) -> str:
        return v.value if isinstance(v, ObservableType) else v

    @field_serializer("score")
    def serialize_score(self, v: Decimal) -> float:
        return float(v)

    @field_serializer("threat_intels")
    def serialize_threat_intels(self, value: list[ThreatIntel]) -> list[str]:
        """Serialize threat intels as keys only."""
        return [ti.key for ti in value]

    @computed_field
    @property
    def generated_by_checks(self) -> list[str]:
        """Checks that generated this observable."""
        return self._generated_by_checks

    def update_score(self, new_score: Decimal, reason: str = "", *, record_history: bool = True) -> None:
        """
        Update the observable's score and recalculate level.

        Args:
            new_score: The new score value
            reason: Reason for the score change
        """
        if not isinstance(new_score, Decimal):
            new_score = Decimal(str(new_score))

        old_score = self.score
        old_level = self.level

        self.score = new_score
        self.level = recalculate_level_for_score(old_level, new_score)

        if record_history:
            change = ScoreChange(
                timestamp=datetime.now(timezone.utc),
                old_score=old_score,
                new_score=new_score,
                old_level=old_level,
                new_level=self.level,
                reason=reason,
            )
            self._score_history.append(change)

    def set_level(self, level: Level | str) -> None:
        """
        Set the level.

        Args:
            level: The level to set
        """
        self.level = normalize_level(level)

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


class Check(BaseModel):
    """
    Represents a verification step in the investigation.

    A check validates a specific aspect of the data under investigation
    and contributes to the overall investigation score.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    check_id: str
    scope: str
    description: str
    comment: str = Field(...)
    extra: dict[str, Any] = Field(...)
    score: Decimal = Field(...)
    level: Level = Field(...)
    observables: list[Observable] = Field(...)
    score_policy: CheckScorePolicy = CheckScorePolicy.AUTO
    key: str = Field(...)
    _score_history: list[ScoreChange] = PrivateAttr(default_factory=list)

    @field_validator("extra", mode="before")
    @classmethod
    def coerce_extra(cls, v: Any) -> dict[str, Any]:
        if v is None:
            return {}
        return v

    @field_validator("score", mode="before")
    @classmethod
    def coerce_score(cls, v: Any) -> Decimal:
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))

    @field_validator("level", mode="before")
    @classmethod
    def coerce_level(cls, v: Any) -> Level:
        return normalize_level(v)

    @model_validator(mode="before")
    @classmethod
    def ensure_defaults(cls, values: Any) -> Any:
        values = apply_creation_score_level_defaults(values, default_level_no_score=Level.NONE)
        if not isinstance(values, dict):
            return values

        if "extra" not in values:
            values["extra"] = {}
        if "comment" not in values:
            values["comment"] = ""
        if "observables" not in values:
            values["observables"] = []
        if "key" not in values:
            values["key"] = ""
        return values

    @field_validator("score_policy", mode="before")
    @classmethod
    def coerce_score_policy(cls, v: Any) -> CheckScorePolicy:
        if isinstance(v, CheckScorePolicy):
            return v
        return CheckScorePolicy(v)

    @model_validator(mode="after")
    def generate_key(self) -> Self:
        """Generate key."""
        if not self.key:
            self.key = keys.generate_check_key(self.check_id, self.scope)
        return self

    @field_serializer("score")
    def serialize_score(self, v: Decimal) -> float:
        return float(v)

    @field_serializer("observables")
    def serialize_observables(self, value: list[Observable]) -> list[str]:
        """Serialize observables as keys only."""
        return [obs.key for obs in value]

    def update_score(self, new_score: Decimal, reason: str = "", *, record_history: bool = True) -> None:
        """
        Update the check's score and recalculate level.

        Args:
            new_score: The new score value
            reason: Reason for the score change
        """
        if not isinstance(new_score, Decimal):
            new_score = Decimal(str(new_score))

        old_score = self.score
        old_level = self.level

        self.score = new_score
        self.level = recalculate_level_for_score(old_level, new_score)

        if record_history:
            change = ScoreChange(
                timestamp=datetime.now(timezone.utc),
                old_score=old_score,
                new_score=new_score,
                old_level=old_level,
                new_level=self.level,
                reason=reason,
            )
            self._score_history.append(change)

    def set_level(self, level: Level | str) -> None:
        """
        Set the level.

        Args:
            level: The level to set
        """
        self.level = normalize_level(level)

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


class Enrichment(BaseModel):
    """
    Represents structured data enrichment for the investigation.

    Enrichments store arbitrary structured data that provides additional
    context but doesn't directly contribute to scoring.
    """

    model_config = ConfigDict()

    name: str
    data: Any = Field(...)
    context: str = Field(...)
    key: str = Field(...)

    @model_validator(mode="after")
    def generate_key(self) -> Self:
        """Generate key."""
        if not self.key:
            self.key = keys.generate_enrichment_key(self.name, self.context)
        return self

    @model_validator(mode="before")
    @classmethod
    def ensure_defaults(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        if "data" not in values:
            values["data"] = {}
        if "context" not in values:
            values["context"] = ""
        if "key" not in values:
            values["key"] = ""
        return values


class Container(BaseModel):
    """
    Groups checks and sub-containers for hierarchical organization.

    Containers allow structuring the investigation into logical sections
    with aggregated scores and levels.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    path: str
    description: str = ""
    checks: list[Check] = Field(...)
    sub_containers: dict[str, Container] = Field(...)
    key: str = Field(...)

    @model_validator(mode="after")
    def generate_key(self) -> Self:
        """Generate key."""
        if not self.key:
            self.key = keys.generate_container_key(self.path)
        return self

    @model_validator(mode="before")
    @classmethod
    def ensure_defaults(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        if "checks" not in values:
            values["checks"] = []
        if "sub_containers" not in values:
            values["sub_containers"] = {}
        if "key" not in values:
            values["key"] = ""
        return values

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

    @computed_field(return_type=Decimal)
    @property
    def aggregated_score(self) -> Decimal:
        return self.get_aggregated_score()

    @field_serializer("aggregated_score")
    def serialize_aggregated_score(self, v: Decimal) -> float:
        return float(v)

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

    @computed_field(return_type=Level)
    @property
    def aggregated_level(self) -> Level:
        """
        Calculate the aggregated level from the aggregated score.

        Returns:
            Level based on aggregated score
        """
        return self.get_aggregated_level()

    @field_serializer("checks")
    def serialize_checks(self, value: list[Check]) -> list[str]:
        """Serialize checks as keys only."""
        return [check.key for check in value]

    @field_serializer("sub_containers")
    def serialize_sub_containers(self, value: dict[str, Container]) -> dict[str, Container]:
        """Serialize sub-containers recursively."""
        return {key: sub.model_dump() for key, sub in value.items()}

    def get_aggregated_level(self) -> Level:
        """
        Calculate the aggregated level from the aggregated score.

        Returns:
            Level based on aggregated score
        """
        return get_level_from_score(self.get_aggregated_score())
