"""
Decisions: the named override.

Overriding a computation must be a declared act — traceable, justified, dated and attributed —
never the side effect of an inflated weight. Because a decision is a fact, all of that comes
from the envelope: ``source`` is the who, ``occurred_at``/``asserted_at`` the when.

There is deliberately no ``expires_at``: evaluation never reads the clock.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field, model_validator

from cyvest import keys
from cyvest.enums import DecisionKind
from cyvest.facts.base import Fact


class Decision(Fact):
    """
    A human (or automated) call that overrides the computed result for one target.

    ``ALLOWLISTED``/``BLOCKLISTED`` bound an observable's score; ``CONFIRMED``/``DISMISSED``
    force a finding. The kind and the target family must agree.
    """

    target_key: str = Field(..., min_length=1)
    kind: DecisionKind = Field(...)
    justification: str | None = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def _derive_key(cls, values: Any) -> Any:
        if not isinstance(values, dict) or values.get("key"):
            return values
        kind = values.get("kind")
        kind_value = kind.value if isinstance(kind, DecisionKind) else str(kind or "")
        values["key"] = keys.generate_decision_key(str(values.get("target_key", "")), kind_value)
        return values

    @model_validator(mode="after")
    def _kind_matches_target(self) -> Decision:
        target_type = keys.parse_key_type(self.target_key)
        if self.kind.targets_observable and target_type != "obs":
            raise ValueError(f"{self.kind.value} targets an observable, got {self.target_key!r}")
        if self.kind.targets_finding and target_type != "fnd":
            raise ValueError(f"{self.kind.value} targets a finding, got {self.target_key!r}")
        return self


__all__ = ["Decision"]
