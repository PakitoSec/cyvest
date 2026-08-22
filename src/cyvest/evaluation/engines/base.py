"""
The scoring engine protocol.

The combination law is an explicit point of variation, distinct from the parameters that live in
the policy. An engine must never require a new field on a fact — if it needs one, it is asking
the model to bend around it, which is how v6 ended up storing derived values.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from cyvest.evaluation.report import Report
from cyvest.facts.store import FactStore
from cyvest.policy import Policy


@runtime_checkable
class ScoringEngine(Protocol):
    """
    A combination law.

    ``engine_id`` is versioned and frozen for life once stable: ``basic-v2`` would ship alongside
    ``basic-v1``, never replace it, so an archived investigation replays identically.
    ``experimental`` engines are exempt until they stabilize.
    """

    engine_id: str
    experimental: bool

    def evaluate(self, store: FactStore, policy: Policy) -> Report:
        """
        Produce a report from facts and parameters.

        Must be **pure**: no clock, no I/O, no global state. The same store evaluated twice at
        different instants must produce identical reports, or ``engine_id`` and ``policy_version``
        would mean nothing.
        """
        ...


__all__ = ["ScoringEngine"]
