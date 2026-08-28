"""
Shared investigation context: several workers, one store.

v6 guarded a mutable model with a global lock and deep-copied everything on every read, because
concurrent mutation of shared objects had to be prevented. None of that is needed once facts are
immutable and merging is a union: a worker builds its own fragment, and reconciling is
``store.union()`` — idempotent, commutative and associative, so the order of arrivals is
irrelevant and a double reconcile is harmless.

The lock that remains protects one dict insertion, not an object graph.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Literal

from logurich import get_logger

from cyvest import keys
from cyvest.cyvest import Cyvest
from cyvest.enums import ObservableType, Verdict
from cyvest.evaluation import Report, evaluate
from cyvest.facts import Evidence, Finding, Observable
from cyvest.facts.store import FactStore, InvestigationHeader
from cyvest.investigation import Investigation
from cyvest.policy import DEFAULT_POLICY, Policy
from cyvest.ulid import generate_ulid

logger = get_logger(__name__)


class SharedInvestigationContext:
    """
    A store several tasks contribute to.

    Each ``create_cyvest`` hands out its own fragment id; reconciling folds that fragment back in.
    Reads see the current union without taking a global lock on the object graph.
    """

    def __init__(
        self,
        root_data: Any = None,
        root_type: ObservableType | Literal["file", "artifact"] = ObservableType.FILE,
        *,
        policy: Policy | None = None,
        engine: str | None = None,
        investigation_name: str | None = None,
        investigation_id: str | None = None,
    ) -> None:
        self.policy = policy or DEFAULT_POLICY
        self._root_data = root_data
        self._root_type = root_type
        self._main = Investigation(
            root_data,
            root_type=root_type,
            policy=self.policy,
            engine=engine,
            investigation_name=investigation_name,
            investigation_id=investigation_id,
        )
        self._append_lock = threading.Lock()

    @classmethod
    def from_investigation(cls, investigation: Investigation) -> SharedInvestigationContext:
        """Wrap an existing investigation so workers can contribute fragments to it."""
        context = cls.__new__(cls)
        context.policy = investigation.policy
        root = investigation.get_root()
        context._root_data = root.extra
        context._root_type = root.obs_type
        context._main = investigation
        context._append_lock = threading.Lock()
        return context

    # ------------------------------------------------------------------ fragments

    def create_cyvest(
        self,
        *,
        fragment_id: str | None = None,
        investigation_id: str | None = None,
        investigation_name: str | None = None,
    ) -> Cyvest:
        """
        Hand out a worker-local investigation sharing this context's root.

        The fragment id is what keeps a worker's facts attributable after reconciliation: every
        fact it appends carries it, so the report can still say who established what.

        Usable directly or as a context manager, in which case exiting reconciles the fragment.
        """
        worker = Cyvest(
            self._root_data,
            root_type=self._root_type,
            policy=self.policy,
            engine=self._main.store.header.engine_id,
            investigation_id=fragment_id or investigation_id or generate_ulid(),
            investigation_name=investigation_name,
        )
        worker._shared_context = self
        return worker

    async def acreate_cyvest(self, *, fragment_id: str | None = None) -> Cyvest:
        return await asyncio.to_thread(self.create_cyvest, fragment_id=fragment_id)

    @contextmanager
    def task(self, *, fragment_id: str | None = None) -> Iterator[Cyvest]:
        """Scope a worker and reconcile it on exit, including when the body raises."""
        worker = self.create_cyvest(fragment_id=fragment_id)
        try:
            yield worker
        finally:
            self.reconcile(worker)

    # ------------------------------------------------------------------ reconcile

    @staticmethod
    def _investigation_of(source: Cyvest | Investigation) -> Investigation:
        return source._investigation if isinstance(source, Cyvest) else source

    def reconcile(self, source: Cyvest | Investigation) -> None:
        """Fold a worker's fragment into the shared store. Safe to call twice."""
        incoming = self._investigation_of(source)
        with self._append_lock:
            self._main.store = self._main.store.union(incoming.store)
            self._main.invalidate()

    async def areconcile(self, source: Cyvest | Investigation) -> None:
        await asyncio.to_thread(self.reconcile, source)

    # ------------------------------------------------------------------ reads

    @property
    def store(self) -> FactStore:
        return self._main.store

    @property
    def header(self) -> InvestigationHeader:
        return self._main.store.header

    @property
    def report(self) -> Report:
        return self._main.report

    def evaluate(self, *, policy: Policy | None = None, engine: str | None = None) -> Report:
        return evaluate(self._main.store, policy or self.policy, engine or self.header.engine_id)

    def get_global_score(self) -> float:
        return self._main.get_global_score()

    async def aget_global_score(self) -> float:
        return await asyncio.to_thread(self.get_global_score)

    def get_global_verdict(self) -> Verdict:
        return self._main.get_global_verdict()

    async def aget_global_verdict(self) -> Verdict:
        return await asyncio.to_thread(self.get_global_verdict)

    def observable_get(self, *args: Any, **kwargs: Any) -> Observable | None:
        """Accepts a key, or the identity components — same call as on the facade it hands out."""
        return self._main.get_observable(keys.resolve_observable_key(*args, **kwargs))

    async def observable_aget(self, *args: Any, **kwargs: Any) -> Observable | None:
        return await asyncio.to_thread(self.observable_get, *args, **kwargs)

    def observables_list_by_type(self, obs_type: ObservableType | str) -> list[Observable]:
        wanted = obs_type.value if isinstance(obs_type, ObservableType) else str(obs_type).lower()
        return [
            observable
            for observable in self._main.get_all_observables().values()
            if (observable.obs_type.value if hasattr(observable.obs_type, "value") else observable.obs_type) == wanted
        ]

    def finding_get(self, key: str) -> Finding | None:
        return self._main.get_finding(key)

    async def finding_aget(self, key: str) -> Finding | None:
        return await asyncio.to_thread(self.finding_get, key)

    def evidence_get(self, key: str) -> Evidence | None:
        return self._main.get_evidence(key)

    async def evidence_aget(self, key: str) -> Evidence | None:
        return await asyncio.to_thread(self.evidence_get, key)

    def finalize_relationships(self) -> None:
        self._main.finalize_relationships()

    def as_cyvest(self) -> Cyvest:
        """Expose the reconciled whole through the ordinary facade."""
        return Cyvest._wrap(self._main)


__all__ = ["SharedInvestigationContext"]
