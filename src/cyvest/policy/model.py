"""
Policy: the declarative, versioned parameters of an evaluation.

Parameters are distinct from the **combination law**, which is the engine's business. v7 ships a
single policy set and does **not** serialize its body — a document carries only
``policy_version``, which is enough to replay it identically. A custom-policy section would be
an additive root key later, with no migration.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cyvest.enums import Aggregation, RelationKind, Verdict, Weight


class Policy(BaseModel):
    """Everything an engine reads besides the facts themselves."""

    model_config = ConfigDict(frozen=True)

    version: str = Field(default="default-v1")
    engine_id: str = Field(default="basic-v1")
    aggregation: Aggregation = Field(default=Aggregation.MAX)

    # Used whenever a fact states a verdict but no weight: the representative of the verdict's
    # own band. Without it, asserting MALICIOUS with no weight would report INFO. Retuning these
    # five values recalibrates a whole corpus without touching a single rule.
    weight_by_verdict: dict[Verdict, float] = Field(
        default_factory=lambda: {
            Verdict.SAFE: Weight.LOW.value,
            Verdict.INFO: 0.0,
            Verdict.NOTABLE: Weight.LOW.value,
            Verdict.SUSPICIOUS: Weight.MEDIUM.value,
            Verdict.MALICIOUS: Weight.HIGH.value,
        }
    )

    # Both default to 1.0, which makes basic-v1 strictly iso-v6.
    attenuation: dict[RelationKind, float] = Field(
        default_factory=lambda: {
            RelationKind.EXTRACTION: 1.0,
            RelationKind.PIVOT: 1.0,
            RelationKind.RELATED_TO: 0.0,
        }
    )

    allowlist_ceiling: float = Field(default=-1.0)
    blocklist_floor: float = Field(default=9.0)
    confirmed_floor: float = Field(default=9.0)

    salience_threshold: float = Field(default=3.0)
    output_precision: int = Field(default=2, ge=0, le=12)

    def resolve_weight(
        self,
        *,
        verdict: Verdict,
        weight: float | None,
    ) -> float:
        """
        Resolve the magnitude of a judgment.

        An explicit weight wins; otherwise the judgment takes the band representative of its
        verdict. Per-rule and per-source defaults were removed in v7: keyed on the rule alone,
        they applied the same magnitude to that rule's exculpatory and inculpatory conclusions
        alike, and silently overruled the intent of whoever wrote the rule.
        """
        if weight is not None:
            return float(weight)
        return self.weight_by_verdict.get(verdict, 0.0)


__all__ = ["Policy"]
