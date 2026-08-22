"""Pluggable scoring engines. Only ``basic-v1`` ships in v7."""

from __future__ import annotations

from cyvest.evaluation.engines.base import ScoringEngine
from cyvest.evaluation.engines.basic import BasicEngine
from cyvest.evaluation.engines.registry import (
    available_aliases,
    available_engines,
    get_engine,
    register_engine,
    resolve_engine_alias,
)

register_engine(BasicEngine(), aliases=("basic",))

DEFAULT_ENGINE_ID = BasicEngine.engine_id

__all__ = [
    "DEFAULT_ENGINE_ID",
    "BasicEngine",
    "ScoringEngine",
    "available_aliases",
    "available_engines",
    "get_engine",
    "register_engine",
    "resolve_engine_alias",
]
