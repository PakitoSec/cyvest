"""
Pydantic models for JSON Schema generation of serialized Cyvest investigations.

These models describe the output structure of `serialize_investigation()` and other
serialization functions. They are used with `model_json_schema(mode='serialization')`
to generate JSON Schema that matches the actual serialized output.

Entity types reference the runtime models directly from `model.py`. When generating
schemas with `mode='serialization'`, Pydantic respects field_serializer decorators
and produces schemas matching the actual model_dump() output.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_serializer, model_validator

from cyvest.levels import Level
from cyvest.model import (
    AuditEvent,
    Check,
    Container,
    Enrichment,
    InvestigationWhitelist,
    Observable,
    ThreatIntel,
    _format_score_decimal,
)
from cyvest.model_enums import ObservableType
from cyvest.score import ScoreMode


class StatisticsSchema(BaseModel):
    """
    Schema for investigation statistics.

    Mirrors the output of `InvestigationStats.get_summary()`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_observables: Annotated[int, Field(ge=0)]
    internal_observables: Annotated[int, Field(ge=0)]
    external_observables: Annotated[int, Field(ge=0)]
    whitelisted_observables: Annotated[int, Field(ge=0)]
    observables_by_type: dict[str, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)
    observables_by_level: dict[str, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)
    observables_by_type_and_level: dict[str, dict[str, Annotated[int, Field(ge=0)]]] = Field(default_factory=dict)
    total_checks: Annotated[int, Field(ge=0)]
    applied_checks: Annotated[int, Field(ge=0)]
    checks_by_scope: dict[str, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)
    checks_by_level: dict[str, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)
    total_threat_intel: Annotated[int, Field(ge=0)]
    threat_intel_by_source: dict[str, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)
    threat_intel_by_level: dict[str, Annotated[int, Field(ge=0)]] = Field(default_factory=dict)
    total_containers: Annotated[int, Field(ge=0)]


class DataExtractionSchema(BaseModel):
    """Schema for data extraction metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    root_type: Literal[ObservableType.FILE, ObservableType.ARTIFACT] | None = Field(
        default=None,
        description="Root observable type used during data extraction.",
    )
    score_mode_obs: ScoreMode = Field(
        description="Observable score aggregation mode: 'max' takes highest score, 'sum' adds all scores.",
    )


class InvestigationSchema(BaseModel):
    """
    Schema for a complete serialized investigation.

    This model describes the output of `serialize_investigation()` from
    `cyvest.io_serialization`. It is the top-level schema for exported investigations.

    Entity types reference the runtime models directly. When generating schemas with
    `mode='serialization'`, Pydantic respects field_serializer decorators and produces
    schemas matching the actual model_dump() output.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        json_schema_extra={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://cyvest.io/schema/investigation.json",
            "title": "Cyvest Investigation",
        },
    )

    investigation_id: str = Field(..., description="Stable investigation identity (ULID).")
    investigation_name: str | None = Field(
        default=None,
        description="Optional human-readable investigation name.",
    )
    started_at: datetime = Field(..., description="Investigation start time (UTC).")
    score: Decimal = Field(..., description="Global investigation score.")
    level: Level = Field(
        ...,
        description="Security level classification from NONE (lowest) to MALICIOUS (highest).",
    )
    whitelisted: bool = Field(description="Whether the investigation is whitelisted.")
    whitelists: list[InvestigationWhitelist] = Field(
        ...,
        description="List of whitelist entries applied to this investigation.",
    )
    event_log: list[AuditEvent] = Field(
        default_factory=list,
        description="Append-only investigation audit log.",
    )
    observables: dict[str, Observable] = Field(
        ...,
        description="Observables keyed by their unique key.",
    )
    checks: dict[str, list[Check]] = Field(
        ...,
        description="Checks organized by scope.",
    )
    checks_by_level: dict[str, list[str]] = Field(
        ...,
        description="Check keys organized by level name.",
    )
    threat_intels: dict[str, ThreatIntel] = Field(
        ...,
        description="Threat intelligence entries keyed by their unique key.",
    )
    enrichments: dict[str, Enrichment] = Field(
        ...,
        description="Enrichment entries keyed by their unique key.",
    )
    containers: dict[str, Container] = Field(
        ...,
        description="Containers keyed by their unique key.",
    )
    stats: StatisticsSchema = Field(description="Investigation statistics summary.")
    data_extraction: DataExtractionSchema = Field(description="Data extraction metadata.")

    @field_serializer("score")
    def serialize_score(self, v: Decimal) -> float:
        return float(v)

    @computed_field(return_type=str)
    @property
    def score_display(self) -> str:
        """Global investigation score formatted as fixed-point x.xx."""
        return _format_score_decimal(self.score)

    @model_validator(mode="before")
    @classmethod
    def ensure_defaults(cls, v: Any) -> Any:
        if not isinstance(v, dict):
            return v

        v.setdefault("level", Level.NONE)
        v.setdefault("whitelists", [])
        v.setdefault("event_log", [])
        v.setdefault("observables", {})
        v.setdefault("checks", {})
        v.setdefault("checks_by_level", {})
        v.setdefault("threat_intels", {})
        v.setdefault("enrichments", {})
        v.setdefault("containers", {})

        return v
