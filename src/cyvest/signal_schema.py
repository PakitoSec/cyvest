"""
The contract an external system must honour to hand Cyvest a signal.

This is deliberately **not** the shape of a stored fact: it is an envelope a scanner, a SOAR
playbook or a feed connector fills in, without knowing which observable it will be attached to.
It is validated strictly — there is no tolerant parsing and no ``preprocessor`` hook, because a
malformed payload should fail at the boundary rather than silently score zero.

Two v6 escape hatches are gone on purpose. ``safe_getter`` / ``safe_values`` existed only because
v6 had no way to say "benign": a source now answers ``verdict: "SAFE"``. And the raw response
lives in ``payload``, which never enters an identity, so a volatile field — a request timestamp,
a quota counter, a correlation id — cannot turn one signal into two.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cyvest.enums import SourceClass, Verdict

SIGNAL_SCHEMA_VERSION = "7.0.0"
SIGNAL_SCHEMA_ID = "https://cyvest.io/schema/signal-7.json"


class SignalEnvelope(BaseModel):
    """
    One judgment about one observable, as produced by an external system.

    ``verdict`` and ``weight`` are the two halves of a magnitude and either one is enough: a
    source that only knows "this is bad" states the verdict, a source that returns a number
    states the weight, and the missing half is completed from the score bands.
    """

    model_config = ConfigDict(extra="forbid", json_schema_extra={"$id": SIGNAL_SCHEMA_ID})

    schema_version: Literal["7.0.0"] = Field(default=SIGNAL_SCHEMA_VERSION)
    kind: Literal["threat_intel"] = Field(default="threat_intel")

    source: str = Field(..., min_length=1)
    source_class: SourceClass = Field(default=SourceClass.VENDOR_FEED)

    verdict: Verdict | None = Field(default=None)
    weight: float | None = Field(default=None)
    confidence: float = Field(default=1.0, gt=0.0, le=1.0)

    observed_at: datetime | None = Field(default=None)
    # Set it to keep successive scans apart; leave it out and re-ingesting is a no-op.
    external_id: str | None = Field(default=None)
    comment: str = Field(default="")
    taxonomies: tuple[str, ...] = Field(default=())
    payload: dict[str, Any] = Field(default_factory=dict)

    def as_draft(self) -> dict[str, Any]:
        """The keyword form ``ObservableProxy.with_ti`` consumes, once a subject is known."""
        draft = self.model_dump(exclude_none=True)
        draft.pop("schema_version", None)
        draft.pop("kind", None)
        return draft


__all__ = ["SIGNAL_SCHEMA_ID", "SIGNAL_SCHEMA_VERSION", "SignalEnvelope"]
