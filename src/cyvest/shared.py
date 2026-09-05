"""
Shared investigation context: several workers, one store.

v6 guarded a mutable model with a global lock and deep-copied everything on every read, because
concurrent mutation of shared objects had to be prevented. None of that is needed once facts are
immutable and merging is a union: a worker builds its own fragment, and reconciling folds it in —
idempotent, commutative and associative, so the order of arrivals is irrelevant and a double
reconcile is harmless.

Reads go through :meth:`SharedInvestigationContext.snapshot`, a frozen view of the union. That is
the whole read API: what it hands out is the ordinary ``Cyvest`` facade.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Literal

from logurich import get_logger

from cyvest.autolink import AutoLink
from cyvest.cyvest import Cyvest, InvestigationSpec
from cyvest.enums import ObservableType
from cyvest.investigation import Investigation
from cyvest.policy import DEFAULT_POLICY, Policy
from cyvest.ulid import generate_ulid

logger = get_logger(__name__)


class SharedInvestigationContext:
    """
    A store several tasks contribute to.

    Each worker gets its own fragment id; reconciling folds that fragment back in. Reading is
    taking a snapshot, which every read of a given task then shares.
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
        auto_link: AutoLink | None = None,
    ) -> None:
        self.policy = policy or DEFAULT_POLICY
        self._main = Investigation(
            root_data,
            root_type=root_type,
            policy=self.policy,
            engine=engine,
            investigation_name=investigation_name,
            investigation_id=investigation_id,
        )
        # Every worker is built from this spec, so the derived edges are the same whichever task
        # first saw an observable, and a worker shares the main's root, policy and engine.
        self.spec = InvestigationSpec(
            root_data,
            root_type=root_type,
            policy=self.policy,
            engine=self._main.store.header.engine_id,
            auto_link=auto_link,
        )
        self._lock = threading.Lock()
        self._snapshot: Cyvest | None = None

    @property
    def auto_link(self) -> AutoLink | None:
        return self.spec.auto_link

    @classmethod
    def from_investigation(cls, investigation: Investigation) -> SharedInvestigationContext:
        """Wrap an existing investigation so workers can contribute fragments to it."""
        root = investigation.get_root()
        context = cls(
            root.extra,
            root_type=root.obs_type,
            policy=investigation.policy,
            engine=investigation.store.header.engine_id,
        )
        # The investigation __init__ just built is a placeholder; one initialisation path is worth
        # one throwaway root.
        context._main = investigation
        return context

    # ------------------------------------------------------------------ fragments

    def create_cyvest(
        self,
        *,
        fragment_id: str | None = None,
        investigation_name: str | None = None,
    ) -> Cyvest:
        """
        Hand out a worker-local investigation sharing this context's root.

        The fragment id is what keeps a worker's facts attributable after reconciliation: every
        fact it appends carries it, so the report can still say who established what.

        Usable directly or as a context manager, in which case exiting reconciles the fragment.
        """
        worker = self.spec.new(investigation_id=fragment_id or generate_ulid(), investigation_name=investigation_name)
        worker._shared_context = self
        return worker

    @contextmanager
    def task(self, *, fragment_id: str | None = None, reconcile_on_error: bool = True) -> Iterator[Cyvest]:
        """
        Scope a worker and reconcile it on exit.

        A worker that raises still contributes what it managed to establish, which is usually what
        an analyst wants. Pass ``reconcile_on_error=False`` when a half-finished fragment is worse
        than no fragment at all.
        """
        worker = self.create_cyvest(fragment_id=fragment_id)
        try:
            yield worker
        except BaseException:
            if reconcile_on_error:
                self.reconcile(worker)
            raise
        else:
            self.reconcile(worker)

    @asynccontextmanager
    async def atask(self, *, fragment_id: str | None = None, reconcile_on_error: bool = True) -> AsyncIterator[Cyvest]:
        """Async twin of :meth:`task`; reconciling runs off the event loop."""
        worker = self.create_cyvest(fragment_id=fragment_id)
        try:
            yield worker
        except BaseException:
            if reconcile_on_error:
                await self.areconcile(worker)
            raise
        else:
            await self.areconcile(worker)

    # ------------------------------------------------------------------ reconcile

    @staticmethod
    def _investigation_of(source: Cyvest | Investigation) -> Investigation:
        return source._investigation if isinstance(source, Cyvest) else source

    def reconcile(self, source: Cyvest | Investigation) -> None:
        """
        Fold a worker's fragment into the shared store. Safe to call twice.

        Folding in place costs the size of the fragment; ``union`` would rebuild the whole store on
        every arrival, which is quadratic over a run. Same merge law either way.
        """
        incoming = self._investigation_of(source)
        with self._lock:
            store = self._main.store
            # The same header law as ``union`` — the fold in place is only an optimisation of it.
            store.header = store.header.merge(incoming.store.header)
            store.extend(incoming.store.all_facts())
            self._main.investigation_id = store.header.investigation_id
            self._main.invalidate()
            self._snapshot = None

    async def areconcile(self, source: Cyvest | Investigation) -> None:
        await asyncio.to_thread(self.reconcile, source)

    # ------------------------------------------------------------------ reads

    def snapshot(self) -> Cyvest:
        """
        A frozen view of the union at this instant.

        Every read through it sees one state. A task that consults a finding, then an observable,
        then the report would otherwise be handed three different versions of the store, and score
        something that never existed. Writing to a snapshot raises instead of being discarded.

        The copy is paid once per reconciliation, and only if somebody reads.
        """
        with self._lock:
            if self._snapshot is None:
                frozen, self._main.store = self._main.store, self._main.store.copy()
                self._snapshot = Cyvest._wrap(Investigation.from_store(frozen, policy=self.policy, frozen=True))
            return self._snapshot

    async def asnapshot(self) -> Cyvest:
        return await asyncio.to_thread(self.snapshot)

    def finalize_relationships(self) -> None:
        """Attach orphaned components to the root."""
        with self._lock:
            self._main.finalize_relationships()
            self._snapshot = None


__all__ = ["SharedInvestigationContext"]
