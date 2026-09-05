"""Descriptive entries on threat intel, never judgments used by the scoring engine."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictStr, model_validator

from cyvest.enums import Verdict


class Taxonomy(BaseModel):
    """A named value with a display verdict. No weight, confidence or scoring effect."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: StrictStr
    value: StrictStr
    verdict: Verdict = Field(default=Verdict.INFO, description="Descriptive only; never affects scoring")

    @model_validator(mode="before")
    @classmethod
    def _read_v7_text(cls, value: Any) -> Any:
        # 7.0 stored free text. Keep it whole: a colon is not necessarily a name/value separator.
        if isinstance(value, str):
            return {"name": value, "value": "", "verdict": Verdict.INFO}
        return value


def _unique_names(entries: tuple[Taxonomy, ...]) -> tuple[Taxonomy, ...]:
    names: set[str] = set()
    for entry in entries:
        if entry.name in names:
            raise ValueError(f"Duplicate taxonomy name: {entry.name}")
        names.add(entry.name)
    return entries


Taxonomies = Annotated[tuple[Taxonomy, ...], AfterValidator(_unique_names)]

__all__ = ["Taxonomies", "Taxonomy"]
