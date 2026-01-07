"""
Core data models for Cyvest investigation framework.

Defines the base classes for Check, Observable, ThreatIntel, Enrichment, Tag,
and InvestigationWhitelist using Pydantic BaseModel.
"""

from __future__ import annotations

from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictStr,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)
from typing_extensions import Self

from cyvest import keys
from cyvest.level_score_rules import apply_creation_score_level_defaults
from cyvest.levels import Level, get_level_from_score, normalize_level
from cyvest.model_enums import (
    ObservableType,
    PropagationMode,
    RelationshipDirection,
    RelationshipType,
)

_DEFAULT_SCORE_PLACES = 2


class AliasDumpModel(BaseModel):
    """Base model that defaults to by_alias=True for JSON-compatible serialization."""

    def model_dump(self, *, by_alias: bool = True, **kwargs: Any) -> dict[str, Any]:
        """Serialize to dict, defaulting to by_alias=True for JSON compatibility."""
        return super().model_dump(by_alias=by_alias, **kwargs)

    def model_dump_json(self, *, by_alias: bool = True, **kwargs: Any) -> str:
        """Serialize to JSON string, defaulting to by_alias=True."""
        return super().model_dump_json(by_alias=by_alias, **kwargs)


def _format_score_decimal(value: Decimal | None, *, places: int = _DEFAULT_SCORE_PLACES) -> str:
    if value is None:
        return "-"
    if places < 0:
        raise ValueError("places must be >= 0")
    quantizer = Decimal("1").scaleb(-places)
    try:
        quantized = value.quantize(quantizer, rounding=ROUND_HALF_UP)
        if quantized == 0:
            quantized = Decimal("0").quantize(quantizer)
        return format(quantized, "f")
    except InvalidOperation:
        return str(value)


class AuditEvent(BaseModel):
    """Centralized audit event for investigation-level changes."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    event_id: str
    timestamp: datetime
    event_type: str
    actor: str | None = None
    reason: str | None = None
    tool: str | None = None
    object_type: str | None = None
    object_key: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


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


class Taxonomy(BaseModel):
    """Represents a structured taxonomy entry for threat intelligence."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    level: Level = Field(...)
    name: StrictStr = Field(...)
    value: StrictStr = Field(...)

    @field_validator("level", mode="before")
    @classmethod
    def coerce_level(cls, v: Any) -> Level:
        return normalize_level(v)


class ThreatIntel(BaseModel):
    """
    Represents threat intelligence from an external source.

    Threat intelligence provides verdicts about observables from sources
    like VirusTotal, URLScan.io, etc.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    source: str = Field(...)
    observable_key: str = Field(...)
    comment: str = Field(...)
    extra: dict[str, Any] = Field(...)
    score: Decimal = Field(...)
    level: Level = Field(...)
    taxonomies: list[Taxonomy] = Field(...)
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

    @field_validator("taxonomies")
    @classmethod
    def ensure_unique_taxonomy_names(cls, v: list[Taxonomy]) -> list[Taxonomy]:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for taxonomy in v:
            if taxonomy.name in seen:
                duplicates.add(taxonomy.name)
            seen.add(taxonomy.name)
        if duplicates:
            dupes = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate taxonomy name(s): {dupes}")
        return v

    @model_validator(mode="before")
    @classmethod
    def ensure_defaults(cls, values: Any) -> Any:
        values = apply_creation_score_level_defaults(
            values,
            default_level_no_score=Level.INFO,
            require_score=True,
        )
        if not isinstance(values, dict):
            return values

        if values.get("observable_key") is None:
            values["observable_key"] = ""
        if "extra" not in values:
            values["extra"] = {}
        if "comment" not in values:
            values["comment"] = ""
        if values.get("taxonomies") is None:
            values["taxonomies"] = []
        if "key" not in values:
            values["key"] = ""
        return values

    @model_validator(mode="after")
    def generate_key(self) -> Self:
        """Generate key."""
        if not self.key and self.observable_key:
            self.key = keys.generate_threat_intel_key(self.source, self.observable_key)

        return self

    @field_serializer("score")
    def serialize_score(self, v: Decimal) -> float:
        return float(v)

    @computed_field(return_type=str)
    @property
    def score_display(self) -> str:
        return _format_score_decimal(self.score)


class Observable(AliasDumpModel):
    """
    Represents a cyber observable (IP, URL, domain, hash, etc.).

    Observables can be linked to threat intelligence, checks, and other observables
    through relationships.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)

    obs_type: ObservableType | str = Field(..., alias="type")
    value: str = Field(...)
    internal: bool = Field(...)
    whitelisted: bool = Field(...)
    comment: str = Field(...)
    extra: dict[str, Any] = Field(...)
    score: Decimal = Field(...)
    level: Level = Field(...)
    threat_intels: list[ThreatIntel] = Field(...)
    relationships: list[Relationship] = Field(...)
    key: str = Field(...)
    _check_links: list[str] = PrivateAttr(default_factory=list)
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
    def check_links(self) -> list[str]:
        """Checks that currently link to this observable (navigation-only)."""
        return list(self._check_links)

    @computed_field(return_type=str)
    @property
    def score_display(self) -> str:
        return _format_score_decimal(self.score)


class ObservableLink(BaseModel):
    """Edge metadata for a Check↔Observable association."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observable_key: str = Field(...)
    propagation_mode: PropagationMode = PropagationMode.LOCAL_ONLY


class Check(BaseModel):
    """
    Represents a verification step in the investigation.

    A check validates a specific aspect of the data under investigation
    and contributes to the overall investigation score.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    check_name: str = Field(...)
    description: str = Field(...)
    comment: str = Field(...)
    extra: dict[str, Any] = Field(...)
    score: Decimal = Field(...)
    level: Level = Field(...)
    origin_investigation_id: str = Field(...)
    observable_links: list[ObservableLink] = Field(...)
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
        values = apply_creation_score_level_defaults(values, default_level_no_score=Level.NONE)
        if not isinstance(values, dict):
            return values

        if "extra" not in values:
            values["extra"] = {}
        if "comment" not in values:
            values["comment"] = ""
        if "observable_links" not in values:
            values["observable_links"] = []
        if "key" not in values:
            values["key"] = ""
        return values

    @model_validator(mode="after")
    def generate_key(self) -> Self:
        """Generate key."""
        if not self.key:
            self.key = keys.generate_check_key(self.check_name)
        return self

    @field_serializer("score")
    def serialize_score(self, v: Decimal) -> float:
        return float(v)

    @computed_field(return_type=str)
    @property
    def score_display(self) -> str:
        return _format_score_decimal(self.score)


class Enrichment(BaseModel):
    """
    Represents structured data enrichment for the investigation.

    Enrichments store arbitrary structured data that provides additional
    context but doesn't directly contribute to scoring.
    """

    model_config = ConfigDict()

    name: str = Field(...)
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


class Tag(BaseModel):
    """
    Groups checks for categorical organization.

    Tags allow structuring the investigation into logical sections
    with aggregated scores and levels. Hierarchy is automatic based on
    the ":" delimiter in tag names (e.g., "header:auth:dkim").
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str
    description: str = ""
    checks: list[Check] = Field(...)
    key: str = Field(...)

    @model_validator(mode="after")
    def generate_key(self) -> Self:
        """Generate key."""
        if not self.key:
            self.key = keys.generate_tag_key(self.name)
        return self

    @model_validator(mode="before")
    @classmethod
    def ensure_defaults(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        if "checks" not in values:
            values["checks"] = []
        if "key" not in values:
            values["key"] = ""
        return values

    @field_serializer("checks")
    def serialize_checks(self, value: list[Check]) -> list[str]:
        """Serialize checks as keys only."""
        return [check.key for check in value]

    @computed_field(return_type=Decimal)
    @property
    def direct_score(self) -> Decimal:
        """
        Calculate the score from direct checks only (no hierarchy).

        For hierarchical aggregation (including descendant tags), use
        Investigation.get_tag_aggregated_score() or TagProxy.get_aggregated_score().

        Returns:
            Total score from direct checks
        """
        return self.get_direct_score()

    @field_serializer("direct_score")
    def serialize_direct_score(self, v: Decimal) -> float:
        return float(v)

    def get_direct_score(self) -> Decimal:
        """
        Calculate the score from direct checks only.

        Returns:
            Total score from direct checks
        """
        total = Decimal("0")
        for check in self.checks:
            total += check.score
        return total

    @computed_field(return_type=Level)
    @property
    def direct_level(self) -> Level:
        """
        Calculate the level from direct checks only (no hierarchy).

        For hierarchical aggregation (including descendant tags), use
        Investigation.get_tag_aggregated_level() or TagProxy.get_aggregated_level().

        Returns:
            Level based on direct score
        """
        return self.get_direct_level()

    def get_direct_level(self) -> Level:
        """
        Calculate the level from direct score only.

        Returns:
            Level based on direct score
        """
        return get_level_from_score(self.get_direct_score())
