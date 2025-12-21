"""
Policy rules that map scores/levels to model state changes.

This module intentionally holds "rules" (creation defaults, score mutation behavior)
on top of the pure mapping in ``cyvest.levels.get_level_from_score``.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from cyvest.levels import Level, get_level_from_score


def _coerce_decimal(value: Decimal | float | int | str | None) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))


def apply_creation_score_level_defaults(
    values: Any,
    *,
    default_level_no_score: Level,
    require_score: bool = False,
) -> Any:
    """
    Apply Cyvest score/level creation rules to a pre-validation dict.

    Rules:
    - If ``require_score`` is True, ``score`` must be provided.
    - If ``level`` is provided, keep it (other rules do not apply).
    - Else if ``score`` is provided, set ``level = get_level_from_score(score)``.
    - Else (no score/level provided), set ``level = default_level_no_score``.
    """
    if not isinstance(values, dict):
        return values

    has_score = "score" in values and values.get("score") is not None
    has_level = "level" in values and values.get("level") is not None
    if require_score and not has_score:
        raise ValueError("score is required")

    score = _coerce_decimal(values.get("score")) if has_score else None
    if score is None:
        if require_score:
            raise ValueError("score is required")
        score = Decimal("0")
        values["score"] = score
    else:
        values["score"] = score

    if has_level:
        return values

    if has_score:
        values["level"] = get_level_from_score(score)
        return values

    values["level"] = default_level_no_score
    return values


def recalculate_level_for_score(current_level: Level | None, new_score: Decimal) -> Level:
    """
    Apply Cyvest score -> level rules when a score mutates.

    Rules:
    - Level is recalculated using ``get_level_from_score``.
    - SAFE is "sticky" against downgrades: keep SAFE unless the new calculated level is greater than SAFE.
    """
    calculated = get_level_from_score(new_score)
    if current_level == Level.SAFE and calculated <= current_level:
        return current_level
    return calculated
