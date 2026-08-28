"""
Pure evaluation layer.

Nothing here reads the clock. ``evaluate`` is a function of ``(facts, policy, engine)`` and
nothing else, which is what makes a frozen ``engine_id``, a ``policy_version`` and replayability
mean something.
"""

from __future__ import annotations

from cyvest.evaluation.engines import DEFAULT_ENGINE_ID, ScoringEngine, get_engine, resolve_engine_alias
from cyvest.evaluation.projection import verdict_from_score
from cyvest.evaluation.report import (
    Contribution,
    FindingResult,
    InvestigationResult,
    ObservableResult,
    Report,
    round_half_up,
)
from cyvest.evaluation.timeline import TimelineEntry, build_timeline
from cyvest.facts.store import FactStore
from cyvest.policy import DEFAULT_POLICY, Policy


def evaluate(store: FactStore, policy: Policy | None = None, engine: str | ScoringEngine | None = None) -> Report:
    """Run an evaluation. Pure: same inputs, same report, forever."""
    resolved_policy = policy or DEFAULT_POLICY
    if engine is None:
        engine = resolved_policy.engine_id
    resolved_engine = get_engine(engine) if isinstance(engine, str) else engine
    return resolved_engine.evaluate(store, resolved_policy)


__all__ = [
    "DEFAULT_ENGINE_ID",
    "Contribution",
    "FindingResult",
    "InvestigationResult",
    "ObservableResult",
    "Report",
    "ScoringEngine",
    "TimelineEntry",
    "build_timeline",
    "evaluate",
    "get_engine",
    "resolve_engine_alias",
    "round_half_up",
    "verdict_from_score",
]
