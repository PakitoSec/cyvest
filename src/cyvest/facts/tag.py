"""
Tags: a named grouping of findings, hierarchical through the ``:`` delimiter.

``Tag.findings`` held whole objects by value in v6; it now holds keys. Scores are views on the
report, never stored on the tag.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field, model_validator

from cyvest import keys
from cyvest.facts.base import Fact


class Tag(Fact):
    """A label grouping findings. Merging two tags unions their finding keys."""

    name: str = Field(..., min_length=1)
    description: str = Field(default="")
    finding_keys: tuple[str, ...] = Field(default=())

    @model_validator(mode="before")
    @classmethod
    def _derive_key(cls, values: Any) -> Any:
        if not isinstance(values, dict) or values.get("key"):
            return values
        values["key"] = keys.generate_tag_key(str(values.get("name", "")))
        return values

    @model_validator(mode="after")
    def _dedupe_findings(self) -> Tag:
        deduped = tuple(dict.fromkeys(self.finding_keys))
        if len(deduped) != len(self.finding_keys):
            object.__setattr__(self, "finding_keys", deduped)
        return self

    @property
    def ancestors(self) -> list[str]:
        return keys.get_tag_ancestors(self.name)


__all__ = ["Tag"]
