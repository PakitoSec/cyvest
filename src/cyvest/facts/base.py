"""
The fact envelope: one immutable family, one identity law.

Every fact is identified by a deterministic **semantic key** — never by a ULID, never by a hash
of raw content. The ULID becomes ``seq``, an ordering attribute and the ultimate tiebreaker.
That single choice is what makes merging idempotent, commutative and associative by
construction, instead of by convention.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyvest.enums import Confidence, SourceClass, Verdict, Weight
from cyvest.ulid import decode_ulid_timestamp, generate_ulid

# A fact carries both a readable datetime and a ULID; they must agree on when it was asserted.
# The tolerance absorbs the sub-second drift between generating one and the other.
_SEQ_CONSISTENCY_TOLERANCE_MS = 1_000


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


class SourceRef(BaseModel):
    """Who or what asserted a fact."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(..., min_length=1)
    source_class: SourceClass = Field(default=SourceClass.UNKNOWN)

    @field_validator("name", mode="before")
    @classmethod
    def _normalize_name(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value


class Label(BaseModel):
    """A typed tag on a fact: ``axis`` says what kind of statement ``value`` makes."""

    model_config = ConfigDict(frozen=True)

    axis: str = Field(..., min_length=1)
    value: str = Field(..., min_length=1)


class Fact(BaseModel):
    """
    Base envelope shared by every fact.

    ``key`` is the identity. ``seq`` orders and breaks ties. Both are set at construction and
    never change: facts are appended, superseded, but not edited.
    """

    model_config = ConfigDict(frozen=True, populate_by_name=True, extra="forbid")

    key: str = Field(..., min_length=1)
    seq: str = Field(..., min_length=26, max_length=26)
    asserted_at: datetime = Field(...)
    occurred_at: datetime | None = Field(default=None)
    source: SourceRef = Field(...)
    fragment_id: str = Field(...)
    external_id: str | None = Field(default=None)
    evidence_keys: tuple[str, ...] = Field(default=())

    @field_validator("asserted_at", "occurred_at")
    @classmethod
    def _ensure_tz_aware(cls, value: datetime | None) -> datetime | None:
        return _as_utc(value) if value is not None else None

    @model_validator(mode="before")
    @classmethod
    def _fill_envelope(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        asserted_at = values.get("asserted_at")
        if asserted_at is None:
            asserted_at = utc_now()
            values["asserted_at"] = asserted_at
        if not values.get("seq"):
            stamp = asserted_at if isinstance(asserted_at, datetime) else utc_now()
            values["seq"] = generate_ulid(timestamp_ms=int(_as_utc(stamp).timestamp() * 1000))
        if values.get("evidence_keys") is None:
            values["evidence_keys"] = ()
        return values

    @model_validator(mode="after")
    def _check_seq_matches_asserted_at(self) -> Fact:
        embedded_ms = decode_ulid_timestamp(self.seq)
        asserted_ms = int(self.asserted_at.timestamp() * 1000)
        if abs(embedded_ms - asserted_ms) > _SEQ_CONSISTENCY_TOLERANCE_MS:
            raise ValueError(
                f"seq timestamp ({embedded_ms} ms) disagrees with asserted_at ({asserted_ms} ms); "
                "generate the ULID from asserted_at"
            )
        return self

    @property
    def effective_at(self) -> datetime:
        """
        Timestamp merge conflicts are settled on.

        Observation time wins over assertion time, so a slow worker asserting stale data late
        does not overwrite fresher data.
        """
        return self.occurred_at or self.asserted_at

    def merge_rank(self) -> tuple[datetime, str]:
        """Lexicographic rank used to pick the winner when two facts share a key."""
        return (self.effective_at, self.seq)


class Judgment(BaseModel):
    """
    The triplet every engine reads: direction, certainty, force.

    Shared by ``ObservableSignal`` and ``Finding`` — same abstraction, two uses. ``weight=None``
    defers to the policy, which assumes a magnitude for ``verdict`` so that stating a verdict
    alone is enough.

    What the judgment is *about* is not here: a signal names an observable subject, a finding
    names none and states its observables as links instead.

    ``weight`` is an unsigned magnitude: direction is the verdict's job alone. Allowing a
    negative one would let a fact read ``MALICIOUS`` while scoring ``SAFE``.
    """

    verdict: Verdict = Field(default=Verdict.INFO)
    confidence: Annotated[float, Field(gt=0.0, le=1.0)] = Field(default=Confidence.HIGH.value)
    weight: Annotated[float, Field(ge=0.0)] | None = Field(default=None)

    @field_validator("confidence", "weight", mode="before")
    @classmethod
    def _coerce_ordinal(cls, value: Any) -> Any:
        return float(value) if isinstance(value, (Confidence, Weight)) else value


__all__ = ["Fact", "Judgment", "Label", "SourceRef", "utc_now"]
