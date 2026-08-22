"""Combination primitives shared by engines."""

from __future__ import annotations

from collections.abc import Iterable

from cyvest.enums import Aggregation

# Neutral element of a max over an empty set. Must NOT be 0.0: v6 produces negative scores
# (anything below zero was TRUSTED), so a zero neutral would silently clamp every exculpatory
# result up to zero.
NEG_INF = float("-inf")


def combine(own_signals: Iterable[float], child_values: Iterable[float], mode: Aggregation) -> float:
    """
    Fold an observable's own signals and its children's contributions.

    Mirrors v6 exactly: ``MAX`` takes the maximum across both groups, ``SUM`` takes the strongest
    signal and adds the children on top.
    """
    signals = list(own_signals)
    children = list(child_values)
    if mode is Aggregation.SUM:
        best_signal = max(signals, default=0.0)
        return best_signal + sum(children)
    return max([*signals, *children], default=0.0)


def bounded_max(values: Iterable[float]) -> float:
    """Max with the ``-inf`` neutral, so an empty set stays distinguishable from a zero result."""
    return max(values, default=NEG_INF)


__all__ = ["NEG_INF", "bounded_max", "combine"]
