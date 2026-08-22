"""
Relations between observables.

In v6 a relationship was carried *by* an observable, so it had to be expressed from that
observable's point of view — hence ``INBOUND`` to mean "this one is my parent". A v7 relation is
a standalone fact holding both keys, so there is no point of view left to invert and
``RelationshipDirection`` disappears: ``source_key`` is the parent, ``target_key`` the child.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import Field, field_validator, model_validator

from cyvest import keys
from cyvest.enums import Confidence, RelationKind
from cyvest.facts.base import Fact


class Relation(Fact):
    """A directed edge between two observables, labelled by the analyst pivot that produced it."""

    source_key: str = Field(..., min_length=1)
    target_key: str = Field(..., min_length=1)
    kind: RelationKind = Field(default=RelationKind.RELATED_TO)
    observed_at: datetime | None = Field(default=None)
    confidence: Annotated[float, Field(gt=0.0, le=1.0)] = Field(default=Confidence.HIGH.value)
    comment: str = Field(default="")

    @field_validator("confidence", mode="before")
    @classmethod
    def _coerce_confidence(cls, value: Any) -> Any:
        return float(value) if isinstance(value, Confidence) else value

    @model_validator(mode="before")
    @classmethod
    def _derive_key(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        if values.get("observed_at") and not values.get("occurred_at"):
            values["occurred_at"] = values["observed_at"]
        if values.get("key"):
            return values
        kind = values.get("kind") or RelationKind.RELATED_TO
        kind_value = kind.value if isinstance(kind, RelationKind) else str(kind)
        values["key"] = keys.generate_relation_key(
            str(values.get("source_key", "")),
            str(values.get("target_key", "")),
            kind_value,
            external_id=values.get("external_id"),
        )
        return values

    @model_validator(mode="after")
    def _reject_self_loop(self) -> Relation:
        if self.source_key == self.target_key:
            raise ValueError("A relation cannot link an observable to itself")
        return self

    @property
    def propagates(self) -> bool:
        return self.kind.propagates


__all__ = ["Relation"]
