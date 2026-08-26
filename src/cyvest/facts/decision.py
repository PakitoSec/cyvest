"""
Decisions: the named override.

Overriding a computation must be a declared act — traceable, justified, dated and attributed —
never the side effect of an inflated weight. Because a decision is a fact, most of that comes
from the envelope: ``source`` is the who, ``occurred_at``/``asserted_at`` the when.

There is deliberately no ``expires_at``: evaluation never reads the clock. A stance that no
longer holds is withdrawn by an act — ``VACATED`` — not by the passage of time.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field, model_validator

from cyvest import keys
from cyvest.enums import DecisionKind
from cyvest.facts.base import Fact

#: Families a decision may target. A stance is taken on a scored entity or on a claim; taking
#: one on a tag or a piece of evidence is meaningless, and silently ignoring it at evaluation
#: would hide a typo behind a decision that never applies.
DECIDABLE_KEY_TYPES = frozenset({"obs", "fnd"})


class Decision(Fact):
    """
    A human (or automated) call that overrides the computed result for one target.

    ``UPHOLD`` forces the target to the policy floor, ``REFUTE`` neutralises it, ``VACATED``
    withdraws a previous stance and restores the computed value. How each is applied depends on
    the family of the target — an observable is bounded, a claim is taken out of the count — but
    that is the engine's dispatch, not a second axis of this model.

    ``justification`` is required: an override whose reason is optional is an override that
    cannot be audited, which defeats the point of recording it as a fact at all.
    """

    target_key: str = Field(..., min_length=1)
    kind: DecisionKind = Field(...)
    justification: str = Field(..., min_length=1)

    @model_validator(mode="before")
    @classmethod
    def _derive_key(cls, values: Any) -> Any:
        if not isinstance(values, dict) or values.get("key"):
            return values
        values["key"] = keys.generate_decision_key(str(values.get("target_key", "")))
        return values

    @model_validator(mode="after")
    def _target_is_decidable(self) -> Decision:
        target_type = keys.parse_key_type(self.target_key)
        if target_type not in DECIDABLE_KEY_TYPES:
            raise ValueError(f"a decision targets an observable or a finding, got {self.target_key!r}")
        return self


__all__ = ["DECIDABLE_KEY_TYPES", "DECISION_LABELS", "Decision", "decision_label"]


#: The analyst's word for a stance, rebuilt from the intent and the family of its target.
#: The model carries one axis on purpose; the vocabulary that reads naturally carries two, and
#: rendering is the right place to pay for that — not the identity of a fact.
DECISION_LABELS: dict[tuple[DecisionKind, str], str] = {
    (DecisionKind.REFUTE, "obs"): "ALLOWLISTED",
    (DecisionKind.UPHOLD, "obs"): "BLOCKLISTED",
    (DecisionKind.UPHOLD, "fnd"): "CONFIRMED",
    (DecisionKind.REFUTE, "fnd"): "DISMISSED",
}


def decision_label(decision: Decision) -> str:
    """Name a decision the way the analyst who took it would."""
    if decision.kind is DecisionKind.VACATED:
        return "VACATED"
    family = keys.parse_key_type(decision.target_key) or ""
    return DECISION_LABELS.get((decision.kind, family), decision.kind.value)
