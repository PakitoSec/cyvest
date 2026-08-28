"""
The report contract.

This is the public interface of the evaluation layer — not the engines. Everything a display
layer needs to show must live here: a JS consumer reads the report and never reimplements a
scoring rule, so anything kept in ``raw`` is by definition something nobody outside the
producing engine may depend on.

Written with a second, probabilistic engine explicitly in mind: ``score`` is optional because a
posterior-based engine has no native magnitude, and ``confidence`` is informational for
``basic-v1`` but becomes determining for such an engine.
"""

from __future__ import annotations

import math
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cyvest.enums import Effect, Status, Verdict


def round_half_up(value: float, precision: int) -> float:
    """
    Round half away from zero.

    Python's built-in ``round`` does banker's rounding (``round(2.5) == 2``), which surprises
    every analyst who checks a total by hand.
    """
    factor = 10**precision
    scaled = value * factor
    rounded = math.floor(scaled + 0.5) if scaled >= 0 else math.ceil(scaled - 0.5)
    return rounded / factor


class Contribution(BaseModel):
    """One named term that fed a result, kept so the report can explain itself."""

    model_config = ConfigDict(frozen=True)

    source_key: str = Field(...)
    label: str = Field(...)
    value: float = Field(...)
    retained: bool = Field(default=True)
    detail: str = Field(default="")


class _ResultBase(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str = Field(...)
    verdict: Verdict = Field(default=Verdict.INFO)
    confidence: float = Field(default=1.0)
    score: float | None = Field(default=None)
    contributions: tuple[Contribution, ...] = Field(default=())
    suppressed_by_decision: bool = Field(default=False)
    raw: dict[str, Any] = Field(default_factory=dict)


class ObservableResult(_ResultBase):
    """An observable's verdict. One per observable: the graph holds every fact anyone contributed."""


class FindingResult(_ResultBase):
    """
    A finding's verdict.

    ``own_term_suppressed`` flags that the rule's own claim was overridden by a stronger link —
    a contradiction worth surfacing rather than silently dropping.

    Three combinations of ``(counted, score)`` are meaningful, and a consumer must not conflate
    the last two:

    - ``(True, float)`` — an additive finding, a term of the total;
    - ``(False, None)`` — dismissed or not evaluated: visible, but out of the evaluation;
    - ``(True, None)`` — a conclusion (``effect`` is ``FLOOR`` or ``CEILING``): it takes part, but
      it has no magnitude of its own. Its effect is a bound on the investigation total, reported
      as a contribution of :class:`InvestigationResult`.
    """

    status: Status = Field(default=Status.EVALUATED)
    effect: Effect = Field(default=Effect.ADDITIVE)
    own_term_suppressed: bool = Field(default=False)
    counted: bool = Field(default=True)


#: Label prefixes of the investigation-level contribution a conclusion produces. Published so a
#: consumer recognises the term a floor or a ceiling actually moved without hardcoding the string.
CONCLUSION_BOUND_LABELS = ("conclusion floor", "conclusion ceiling")


class InvestigationResult(_ResultBase):
    """The investigation-level verdict."""


class Report(BaseModel):
    """A full evaluation. Derived, never stored on the facts, recomputed from them."""

    model_config = ConfigDict(frozen=True)

    engine_id: str = Field(...)
    policy_version: str = Field(...)
    investigation: InvestigationResult = Field(...)
    findings: dict[str, FindingResult] = Field(default_factory=dict)
    observables: dict[str, ObservableResult] = Field(default_factory=dict)

    def observable(self, key: str) -> ObservableResult | None:
        return self.observables.get(key)

    def finding(self, key: str) -> FindingResult | None:
        return self.findings.get(key)


__all__ = [
    "CONCLUSION_BOUND_LABELS",
    "Contribution",
    "FindingResult",
    "InvestigationResult",
    "ObservableResult",
    "Report",
    "round_half_up",
]
