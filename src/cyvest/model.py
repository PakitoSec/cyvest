"""
Core data models for Cyvest investigation framework.

Defines the base classes for Finding, Observable, ThreatIntel, Enrichment, Tag,
and InvestigationWhitelist using Pydantic BaseModel.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
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
    ObservableSubtype,
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


def round_score_decimal(value: Decimal, *, places: int = _DEFAULT_SCORE_PLACES) -> Decimal:
    """Round a Decimal score to *places* decimal places (ROUND_HALF_UP)."""
    if places < 0:
        raise ValueError("places must be >= 0")
    quantizer = Decimal("1").scaleb(-places)
    quantized = value.quantize(quantizer, rounding=ROUND_HALF_UP)
    if quantized == 0:
        quantized = Decimal("0").quantize(quantizer)
    return quantized


def _format_score_decimal(value: Decimal | None, *, places: int = _DEFAULT_SCORE_PLACES) -> str:
    if value is None:
        return "-"
    try:
        return format(round_score_decimal(value, places=places), "f")
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


class _ObservableIdentityBase(AliasDumpModel):
    """Shared typed observable identity fields."""

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)

    obs_type: ObservableType | str = Field(..., alias="type")
    subtype: ObservableSubtype | str | None = Field(default=None)
    namespace: str | None = Field(default=None)
    value: str = Field(...)

    @field_validator("obs_type", mode="before")
    @classmethod
    def coerce_obs_type(cls, v: Any) -> ObservableType | str:
        return Observable.coerce_obs_type(v)

    @field_validator("subtype", mode="before")
    @classmethod
    def coerce_subtype(cls, v: Any) -> ObservableSubtype | str | None:
        return Observable.coerce_subtype(v)

    @field_validator("namespace", mode="before")
    @classmethod
    def coerce_namespace(cls, v: Any) -> str | None:
        return Observable.coerce_namespace(v)

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        Observable(
            obs_type=self.obs_type,
            subtype=self.subtype,
            namespace=self.namespace,
            value=self.value,
        )
        return self

    @property
    def identity_tuple(self) -> tuple[ObservableType | str, ObservableSubtype | str | None, str | None, str]:
        return (self.obs_type, self.subtype, self.namespace, self.value)

    @field_serializer("obs_type")
    def serialize_obs_type(self, v: ObservableType | str) -> str:
        return v.value if isinstance(v, ObservableType) else v

    @field_serializer("subtype")
    def serialize_subtype(self, v: ObservableSubtype | str | None) -> str | None:
        return v.value if isinstance(v, ObservableSubtype) else v


class ObservableIdentity(_ObservableIdentityBase):
    """Canonical observable identity returned by observable resolvers."""


class ObservableAlias(_ObservableIdentityBase):
    """Source observable identity attached to a canonical observable."""

    count: int = Field(default=1, ge=1)


class Observable(AliasDumpModel):
    """
    Represents a cyber observable (IP, URL, domain, hash, etc.).

    Observables can be linked to threat intelligence, findings, and other observables
    through relationships.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)

    obs_type: ObservableType | str = Field(..., alias="type")
    subtype: ObservableSubtype | str | None = Field(default=None)
    namespace: str | None = Field(default=None)
    value: str = Field(...)
    internal: bool = Field(...)
    whitelisted: bool = Field(...)
    comment: str = Field(...)
    extra: dict[str, Any] = Field(...)
    score: Decimal = Field(...)
    level: Level = Field(...)
    aliases: list[ObservableAlias] = Field(...)
    occurrence_count: int = Field(default=1, ge=1)
    threat_intels: list[ThreatIntel] = Field(...)
    relationships: list[Relationship] = Field(...)
    key: str = Field(...)
    _finding_links: list[str] = PrivateAttr(default_factory=list)
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

    @field_validator("subtype", mode="before")
    @classmethod
    def coerce_subtype(cls, v: Any) -> ObservableSubtype | str | None:
        if v is None or isinstance(v, ObservableSubtype):
            return v
        if isinstance(v, str):
            normalized = v.strip().lower()
            try:
                return ObservableSubtype(normalized)
            except ValueError:
                return normalized
        return v

    @field_validator("namespace", mode="before")
    @classmethod
    def coerce_namespace(cls, v: Any) -> str | None:
        if v is None:
            return None
        normalized = str(v).strip()
        return normalized or None

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
        if "aliases" not in values:
            values["aliases"] = []
        if "occurrence_count" not in values:
            values["occurrence_count"] = 1
        if "key" not in values:
            values["key"] = ""
        return values

    @model_validator(mode="after")
    def validate_identity_and_generate_key(self) -> Self:
        """Validate type-specific identity fields and generate the key."""
        obs_type = self.obs_type.value if isinstance(self.obs_type, ObservableType) else str(self.obs_type).lower()
        subtype = self.subtype.value if isinstance(self.subtype, ObservableSubtype) else self.subtype
        allowed_subtypes = {
            ObservableType.USER.value: {"email", "sid", "upn", "okta_id", "username", "uid"},
            ObservableType.HOST.value: {"hostname", "fqdn", "netbios", "device_id"},
            ObservableType.PROCESS.value: {"pid", "process_guid"},
            ObservableType.FILE.value: {"path"},
            ObservableType.CLOUD_RESOURCE.value: {
                "aws_arn",
                "azure_resource_id",
                "gcp_resource_name",
            },
        }
        if (
            obs_type
            in {
                ObservableType.USER.value,
                ObservableType.HOST.value,
                ObservableType.PROCESS.value,
                ObservableType.CLOUD_RESOURCE.value,
            }
            and not subtype
        ):
            raise ValueError(f"Observable type '{obs_type}' requires a subtype")
        if obs_type == ObservableType.COMMAND_LINE.value and subtype is not None:
            raise ValueError("COMMAND_LINE observables do not accept a subtype")
        if isinstance(self.subtype, ObservableSubtype) and subtype not in allowed_subtypes.get(obs_type, set()):
            raise ValueError(f"Subtype '{subtype}' is not valid for observable type '{obs_type}'")

        namespace_required = {
            (ObservableType.USER.value, "okta_id"),
            (ObservableType.USER.value, "username"),
            (ObservableType.USER.value, "uid"),
            (ObservableType.HOST.value, "hostname"),
            (ObservableType.HOST.value, "netbios"),
            (ObservableType.HOST.value, "device_id"),
            (ObservableType.PROCESS.value, "pid"),
            (ObservableType.FILE.value, "path"),
        }
        if (obs_type, subtype) in namespace_required and not self.namespace:
            raise ValueError(f"Observable {obs_type}/{subtype} requires a namespace")

        if not self.key:
            self.key = keys.generate_observable_key(
                obs_type,
                self.value,
                subtype=subtype,
                namespace=self.namespace,
            )

        return self

    @model_validator(mode="after")
    def dedupe_aliases(self) -> Self:
        alias_key_type = tuple[ObservableType | str, ObservableSubtype | str | None, str | None, str]
        aliases_by_key: dict[alias_key_type, ObservableAlias] = {}
        for alias in self.aliases:
            alias_key = alias.identity_tuple
            existing = aliases_by_key.get(alias_key)
            if existing is None:
                aliases_by_key[alias_key] = alias
            else:
                existing.count += alias.count
        self.aliases = list(aliases_by_key.values())
        return self

    @field_serializer("obs_type")
    def serialize_obs_type(self, v: ObservableType | str) -> str:
        return v.value if isinstance(v, ObservableType) else v

    @field_serializer("subtype")
    def serialize_subtype(self, v: ObservableSubtype | str | None) -> str | None:
        return v.value if isinstance(v, ObservableSubtype) else v

    @field_serializer("score")
    def serialize_score(self, v: Decimal) -> float:
        return float(v)

    @field_serializer("threat_intels")
    def serialize_threat_intels(self, value: list[ThreatIntel]) -> list[str]:
        """Serialize threat intels as keys only."""
        return [ti.key for ti in value]

    @computed_field
    @property
    def finding_links(self) -> list[str]:
        """Findings that currently link to this observable (navigation-only)."""
        return list(self._finding_links)

    @computed_field(return_type=str)
    @property
    def score_display(self) -> str:
        return _format_score_decimal(self.score)


class ObservableLink(BaseModel):
    """Edge metadata for a Finding↔Observable association."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    observable_key: str = Field(...)
    propagation_mode: PropagationMode = PropagationMode.LOCAL_ONLY


class EvidenceLink(BaseModel):
    """Edge metadata for a Finding↔Evidence association."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_key: str = Field(...)


class Evidence(AliasDumpModel):
    """Structured material supporting one or more findings."""

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)

    evidence_type: str = Field(..., alias="type")
    title: str = Field(...)
    description: str = Field(...)
    source: str = Field(...)
    external_id: str | None = Field(...)
    content: Any | None = Field(...)
    uri: str | None = Field(...)
    captured_at: datetime = Field(...)
    extra: dict[str, Any] = Field(...)
    key: str = Field(...)
    _finding_links: list[str] = PrivateAttr(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def ensure_defaults(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        values.setdefault("description", "")
        values.setdefault("external_id", None)
        values.setdefault("content", None)
        values.setdefault("uri", None)
        values.setdefault("captured_at", datetime.now(timezone.utc))
        values.setdefault("extra", {})
        values.setdefault("key", "")
        return values

    @field_validator("captured_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("captured_at must include timezone information")
        return value

    @model_validator(mode="after")
    def validate_payload_and_generate_key(self) -> Self:
        if self.content is None and not self.uri:
            raise ValueError("Evidence requires at least one of content or uri")
        try:
            json.dumps(self.content, ensure_ascii=False)
            json.dumps(self.extra, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("Evidence content and extra must be JSON-compatible") from exc
        if not self.key:
            self.key = keys.generate_evidence_key(
                source=self.source,
                external_id=self.external_id,
                evidence_type=self.evidence_type,
                content=self.content,
                uri=self.uri,
            )
        return self

    @computed_field
    @property
    def finding_links(self) -> list[str]:
        """Findings that currently link to this evidence (navigation-only)."""
        return list(self._finding_links)


class Finding(BaseModel):
    """
    Represents a verification step in the investigation.

    A finding validates a specific aspect of the data under investigation
    and contributes to the overall investigation score.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    finding_name: str = Field(...)
    description: str = Field(...)
    comment: str = Field(...)
    extra: dict[str, Any] = Field(...)
    score: Decimal = Field(...)
    level: Level = Field(...)
    origin_investigation_id: str = Field(...)
    observable_links: list[ObservableLink] = Field(...)
    evidence_links: list[EvidenceLink] = Field(...)
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
        if "evidence_links" not in values:
            values["evidence_links"] = []
        if "key" not in values:
            values["key"] = ""
        return values

    @model_validator(mode="after")
    def generate_key(self) -> Self:
        """Generate key."""
        if not self.key:
            self.key = keys.generate_finding_key(self.finding_name)
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
    Groups findings for categorical organization.

    Tags allow structuring the investigation into logical sections
    with aggregated scores and levels. Hierarchy is automatic based on
    the ":" delimiter in tag names (e.g., "header:auth:dkim").
    """

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str
    description: str = ""
    findings: list[Finding] = Field(...)
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
        if "findings" not in values:
            values["findings"] = []
        if "key" not in values:
            values["key"] = ""
        return values

    @field_serializer("findings")
    def serialize_findings(self, value: list[Finding]) -> list[str]:
        """Serialize findings as keys only."""
        return [finding.key for finding in value]

    @computed_field(return_type=Decimal)
    @property
    def direct_score(self) -> Decimal:
        """
        Calculate the score from direct findings only (no hierarchy).

        For hierarchical aggregation (including descendant tags), use
        Investigation.get_tag_aggregated_score() or TagProxy.get_aggregated_score().

        Returns:
            Total score from direct findings
        """
        return self.get_direct_score()

    @field_serializer("direct_score")
    def serialize_direct_score(self, v: Decimal) -> float:
        return float(v)

    def get_direct_score(self) -> Decimal:
        """
        Calculate the score from direct findings only.

        Returns:
            Total score from direct findings
        """
        total = Decimal("0")
        for finding in self.findings:
            total += finding.score
        return total

    @computed_field(return_type=Level)
    @property
    def direct_level(self) -> Level:
        """
        Calculate the level from direct findings only (no hierarchy).

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
