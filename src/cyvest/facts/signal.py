"""
Observable signals: everything that carries a judgment *about an observable*.

``ObservableSignal`` is an open family discriminated on ``kind``. Only ``ThreatIntel`` ships in
v7, but the discriminator is in place from day one — adding it later would force a migration of
every serialized document, which is the one reservation the plan considers truly binding.

Invariant: a signal's ``subject_key`` is **always** an observable.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from cyvest import keys
from cyvest.enums import SourceClass
from cyvest.facts.base import Fact, Judgment, Label


class ObservableSignal(Fact, Judgment):
    """
    Base for anything asserting a verdict about an observable.

    ``observed_at`` belongs here rather than on ``ThreatIntel``: it is meaningful for any signal,
    and it is what merge conflicts are settled on.
    """

    kind: str = Field(...)
    observed_at: datetime | None = Field(default=None)
    labels: tuple[Label, ...] = Field(default=())
    payload: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _derive_envelope(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        if values.get("observed_at") and not values.get("occurred_at"):
            values["occurred_at"] = values["observed_at"]
        if not values.get("key"):
            source = values.get("source")
            source_name = source.get("name") if isinstance(source, dict) else getattr(source, "name", "")
            values["key"] = keys.generate_signal_key(
                str(source_name or ""),
                str(values.get("subject_key", "")),
                external_id=values.get("external_id"),
            )
        return values

    @model_validator(mode="after")
    def _subject_must_be_observable(self) -> ObservableSignal:
        if keys.parse_key_type(self.subject_key) != "obs":
            raise ValueError(f"A signal's subject must be an observable, got {self.subject_key!r}")
        return self


class ThreatIntel(ObservableSignal):
    """
    A verdict from a threat-intelligence source.

    Identity is ``(source, subject_key)`` — byte-identical to v6 — so a source re-asserting the
    same observable updates in place instead of piling up duplicates. Pass ``external_id`` to
    keep history on purpose.
    """

    kind: Literal["threat_intel"] = "threat_intel"
    source_class: SourceClass = Field(default=SourceClass.VENDOR_FEED)
    taxonomies: tuple[str, ...] = Field(default=())
    comment: str = Field(default="")


# Discriminated union — one member today, extensible without touching the schema shape.
AnyObservableSignal = ThreatIntel

__all__ = ["AnyObservableSignal", "ObservableSignal", "ThreatIntel"]
