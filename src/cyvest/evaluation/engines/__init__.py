"""Versioned scoring engines, with ``basic-v2`` as the default."""

from __future__ import annotations

from cyvest.evaluation.engines.base import ScoringEngine
from cyvest.evaluation.engines.basic import BasicEngine
from cyvest.evaluation.engines.basic_v2 import BasicV2Engine
from cyvest.evaluation.engines.registry import (
    available_aliases,
    available_engines,
    get_engine,
    register_engine,
    resolve_engine_alias,
)

register_engine(BasicEngine(), aliases=("cyvest:sum-findings",))
register_engine(BasicV2Engine(), aliases=("basic", "cyvest:unique-origins"))

DEFAULT_ENGINE_ID = BasicV2Engine.engine_id

__all__ = [
    "DEFAULT_ENGINE_ID",
    "BasicEngine",
    "BasicV2Engine",
    "ScoringEngine",
    "available_aliases",
    "available_engines",
    "get_engine",
    "register_engine",
    "resolve_engine_alias",
]
