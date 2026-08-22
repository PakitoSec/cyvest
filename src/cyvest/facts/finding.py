"""
Findings: what a rule concluded, and which observables back it.

A finding's score comes from its observables. Its own judgment is a **floor** that can only
raise, never whitewash. Overriding the computation outright is a :class:`Decision`, not an
inflated weight.

A finding carrying :attr:`Effect.FLOOR` is the one exception: it is a conclusion *about* the
investigation, so it has no score of its own — it floors the total instead.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cyvest import keys
from cyvest.enums import Effect, Scope, Status, Verdict
from cyvest.facts.base import Fact, Judgment, Label

_VERDICTS_WITHOUT_FLOOR = (Verdict.SAFE, Verdict.INFO)

CONCLUSION_TAKES_NO_WEIGHT = (
    "a conclusion takes its magnitude from the floor of the verdict it asserts, never from a "
    "weight; drop the weight or make the finding ADDITIVE"
)


class ObservableLink(BaseModel):
    """
    A link from a finding to one of its observables, with the scope it is evaluated in.

    Scope is **per link**, exactly like v6's ``propagation_mode``: a finding may mix scopes, and
    may even link the same observable twice under two scopes. Deduplication is on the tuple.
    """

    model_config = ConfigDict(frozen=True)

    observable_key: str = Field(..., min_length=1)
    scope: Scope = Field(default=Scope.OWN_FRAGMENT)


class Finding(Fact, Judgment):
    """
    A rule outcome. Identity is ``(rule_id, subject_key)``.

    ``subject_key`` may be an observable *or* the investigation itself — unlike a signal, which
    always targets an observable.
    """

    rule_id: str = Field(..., min_length=1)
    rule_version: str = Field(default="1")
    name: str = Field(default="")
    comment: str = Field(default="")
    status: Status = Field(default=Status.EVALUATED)
    effect: Effect = Field(default=Effect.ADDITIVE)
    observable_links: tuple[ObservableLink, ...] = Field(default=())
    labels: tuple[Label, ...] = Field(default=())
    extra: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _derive_key(cls, values: Any) -> Any:
        if not isinstance(values, dict) or values.get("key"):
            return values
        values["key"] = keys.generate_finding_key(
            str(values.get("rule_id", "")),
            str(values.get("subject_key", "")),
            external_id=values.get("external_id"),
        )
        return values

    @model_validator(mode="after")
    def _dedupe_links(self) -> Finding:
        seen: dict[tuple[str, Scope], ObservableLink] = {}
        for link in self.observable_links:
            seen.setdefault((link.observable_key, link.scope), link)
        if len(seen) != len(self.observable_links):
            object.__setattr__(self, "observable_links", tuple(seen.values()))
        return self

    @model_validator(mode="after")
    def _check_conclusion(self) -> Finding:
        if self.effect is not Effect.FLOOR:
            return self
        # Refused rather than ignored: both combinations would be silent no-ops at evaluation.
        if self.verdict in _VERDICTS_WITHOUT_FLOOR:
            raise ValueError(
                f"a conclusion must assert a verdict that has a floor, got {self.verdict.value}; "
                "SAFE and INFO have none, and a conclusion may only escalate"
            )
        if self.weight is not None:
            raise ValueError(CONCLUSION_TAKES_NO_WEIGHT)
        return self

    @property
    def is_evaluated(self) -> bool:
        return self.status is Status.EVALUATED

    @property
    def is_conclusion(self) -> bool:
        return self.effect is Effect.FLOOR


__all__ = ["CONCLUSION_TAKES_NO_WEIGHT", "Finding", "ObservableLink"]
