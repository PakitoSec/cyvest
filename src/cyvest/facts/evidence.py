"""
Evidence: raw material, not a judgment.

Evidence has no verdict, no confidence, no weight and no outgoing edges. It is what a claim
points *at*, never a claim itself. The v6 ``Enrichment`` collapses into it as
``evidence_type="enrichment"``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, model_validator

from cyvest import keys
from cyvest.facts.base import Fact


class Evidence(Fact):
    """A captured artefact: an API response, a header dump, an enrichment payload."""

    evidence_type: str = Field(..., min_length=1)
    title: str = Field(default="")
    content: Any = Field(default=None)
    uri: str | None = Field(default=None)
    captured_at: datetime | None = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def _derive_key(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        if values.get("captured_at") and not values.get("occurred_at"):
            values["occurred_at"] = values["captured_at"]
        if values.get("key"):
            return values
        source = values.get("source")
        source_name = source.get("name") if isinstance(source, dict) else getattr(source, "name", "")
        values["key"] = keys.generate_evidence_key(
            source=str(source_name or ""),
            external_id=values.get("external_id"),
            evidence_type=str(values.get("evidence_type", "")),
            content=values.get("content"),
            uri=values.get("uri"),
        )
        return values


__all__ = ["Evidence"]
