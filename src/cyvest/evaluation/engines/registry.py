"""
Engine registry.

Ids are versioned and frozen for life; aliases are not. You *write* the alias (``"basic"``) and
the store records the *resolved* id (``"basic-v1"``) — the mechanics of a Docker tag. An old
investigation therefore replays exactly even after a newer stable engine ships, while new
investigations follow the current stable.
"""

from __future__ import annotations

from cyvest.evaluation.engines.base import ScoringEngine

_ENGINES: dict[str, ScoringEngine] = {}
_ALIASES: dict[str, str] = {}


def register_engine(engine: ScoringEngine, *, aliases: tuple[str, ...] = ()) -> ScoringEngine:
    if engine.engine_id in _ENGINES:
        raise ValueError(f"Engine id already registered: {engine.engine_id!r}")
    _ENGINES[engine.engine_id] = engine
    for alias in aliases:
        _ALIASES[alias] = engine.engine_id
    return engine


def resolve_engine_alias(name: str) -> str:
    """Turn an alias or an id into a concrete, versioned engine id."""
    if name in _ENGINES:
        return name
    resolved = _ALIASES.get(name)
    if resolved is None:
        known = ", ".join(sorted([*_ENGINES, *_ALIASES])) or "none"
        raise KeyError(f"Unknown scoring engine {name!r}. Known engines and aliases: {known}")
    return resolved


def get_engine(name: str) -> ScoringEngine:
    return _ENGINES[resolve_engine_alias(name)]


def available_engines() -> dict[str, ScoringEngine]:
    return dict(_ENGINES)


def available_aliases() -> dict[str, str]:
    return dict(_ALIASES)


__all__ = [
    "available_aliases",
    "available_engines",
    "get_engine",
    "register_engine",
    "resolve_engine_alias",
]
