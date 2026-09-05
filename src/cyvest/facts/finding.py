"""
Findings: what a rule concluded, and which observables back it.

A finding's score comes from its observables. Its own judgment is a **floor** that can only
raise, never whitewash. Overriding the computation outright is a :class:`Decision`, not an
inflated weight.

A conclusion (:attr:`Effect.FLOOR` or :attr:`Effect.CEILING`) is the one exception: it is a
verdict *about* the investigation, so it has no score of its own — it bounds the total instead.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cyvest import keys
from cyvest.enums import Effect, LinkBasis, Status, Tactic, Verdict
from cyvest.facts.base import Fact, Judgment, Label

_VERDICTS_WITHOUT_FLOOR = (Verdict.SAFE, Verdict.INFO)
_VERDICTS_WITHOUT_CEILING = (Verdict.MALICIOUS,)

CONCLUSION_TAKES_NO_WEIGHT = (
    "a conclusion takes its magnitude from the band of the verdict it asserts, never from a "
    "weight; drop the weight or make the finding ADDITIVE"
)

SIGNALS_BASIS_TAKES_KEYS = (
    "a SIGNALS link scores on the signals it names, so it must name at least one; pass "
    "signal_keys, or pick the OBSERVABLE basis to score on the observable itself"
)

OBSERVABLE_BASIS_TAKES_NO_KEYS = (
    "signal_keys only applies to the SIGNALS basis; an OBSERVABLE link scores on the observable "
    "as a whole and a NONE link scores nothing, so naming signals would be silently ignored"
)


class ObservableLink(BaseModel):
    """
    A link from a finding to one of its observables, with the basis it is evaluated on.

    Basis is **per link**, exactly like v6's ``propagation_mode``: a finding may mix bases, and
    may even link the same observable twice under two of them. Deduplication is on the triple
    ``(observable_key, basis, signal_keys)``.

    ``signal_keys`` is sorted and deduplicated so that two links naming the same signals in a
    different order are the same link, and merging stays idempotent.
    """

    model_config = ConfigDict(frozen=True)

    observable_key: str = Field(..., min_length=1)
    basis: LinkBasis = Field(default=LinkBasis.OBSERVABLE)
    signal_keys: tuple[str, ...] = Field(default=())

    @model_validator(mode="after")
    def _check_basis(self) -> ObservableLink:
        if self.basis is LinkBasis.SIGNALS:
            if not self.signal_keys:
                raise ValueError(SIGNALS_BASIS_TAKES_KEYS)
            normalized = tuple(sorted(set(self.signal_keys)))
            if normalized != self.signal_keys:
                object.__setattr__(self, "signal_keys", normalized)
        elif self.signal_keys:
            raise ValueError(OBSERVABLE_BASIS_TAKES_NO_KEYS)
        return self


class Finding(Fact, Judgment):
    """
    A rule outcome. Identity is ``rule_id`` alone, plus ``external_id`` when one is given.

    A finding names no subject: what it is about is its ``observable_links``, which are also what
    it scores on. Use ``external_id`` when the same rule must yield several findings — typically
    once per observable, ``external_id=url.key``.

    A finding that describes an activity is **dated** through the envelope's ``occurred_at`` —
    when the activity happened, as opposed to when the rule fired — and may name the ATT&CK
    ``tactic`` it demonstrates. Both are what the timeline reads; neither enters the score.
    """

    rule_id: str = Field(..., min_length=1)
    rule_version: str = Field(default="1")
    name: str = Field(default="")
    comment: str = Field(default="")
    status: Status = Field(default=Status.EVALUATED)
    effect: Effect = Field(default=Effect.ADDITIVE)
    observable_links: tuple[ObservableLink, ...] = Field(default=())
    labels: tuple[Label, ...] = Field(default=())
    tactic: Tactic | None = Field(default=None)
    extra: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _derive_key(cls, values: Any) -> Any:
        if not isinstance(values, dict) or values.get("key"):
            return values
        values["key"] = keys.generate_finding_key(
            str(values.get("rule_id", "")),
            external_id=values.get("external_id"),
        )
        return values

    @model_validator(mode="after")
    def _dedupe_links(self) -> Finding:
        seen: dict[tuple[str, LinkBasis, tuple[str, ...]], ObservableLink] = {}
        for link in self.observable_links:
            seen.setdefault((link.observable_key, link.basis, link.signal_keys), link)
        if len(seen) != len(self.observable_links):
            object.__setattr__(self, "observable_links", tuple(seen.values()))
        return self

    @model_validator(mode="after")
    def _check_conclusion(self) -> Finding:
        if not self.effect.concludes:
            return self
        # Refused rather than ignored: each combination would be a silent no-op at evaluation.
        if self.effect is Effect.FLOOR and self.verdict in _VERDICTS_WITHOUT_FLOOR:
            raise ValueError(
                f"a FLOOR conclusion must assert a verdict that has a floor, got {self.verdict.value}; "
                "SAFE and INFO have none, and a floor may only escalate — use CEILING to de-escalate"
            )
        if self.effect is Effect.CEILING and self.verdict in _VERDICTS_WITHOUT_CEILING:
            raise ValueError(
                f"a CEILING conclusion must assert a verdict that has a ceiling, got {self.verdict.value}; "
                "MALICIOUS is unbounded above, and a ceiling may only de-escalate — use FLOOR to escalate"
            )
        if self.weight is not None:
            raise ValueError(CONCLUSION_TAKES_NO_WEIGHT)
        return self

    @property
    def is_evaluated(self) -> bool:
        return self.status is Status.EVALUATED

    @property
    def is_conclusion(self) -> bool:
        return self.effect.concludes


__all__ = ["CONCLUSION_TAKES_NO_WEIGHT", "Finding", "ObservableLink"]
