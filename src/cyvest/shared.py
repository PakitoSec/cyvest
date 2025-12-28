"""
Shared investigation context for concurrent execution.

This module provides a single implementation that supports both:
- synchronous usage (threads / thread pools)
- asynchronous usage (asyncio)

Key design goals:
- All state mutation and reads go through a single shared implementation.
- Async APIs never block the event loop: they run the critical section in a worker thread.
- Returned objects are deep-copied snapshots (read-only-by-convention) to avoid shared mutable state.
"""

from __future__ import annotations

import asyncio
import threading
from copy import deepcopy
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from logurich import logger

from cyvest import keys
from cyvest.cyvest import Cyvest
from cyvest.io_serialization import (
    generate_markdown_report,
    save_investigation_json,
    save_investigation_markdown,
    serialize_investigation,
)
from cyvest.levels import Level
from cyvest.model import Check, Enrichment, Observable, ObservableType

if TYPE_CHECKING:
    from cyvest.investigation import Investigation
    from cyvest.model_schema import InvestigationSchema


class _SharedLock:
    """
    Dual-mode lock adapter with a single canonical lock.

    - Sync path: acquires a single `threading.RLock` around the critical section.
    - Async path: runs the entire critical section in a worker thread via `asyncio.to_thread(...)`
      so the event loop is never blocked.

    Notes:
    - Optionally limits concurrent async callers via a single `asyncio.Semaphore(max_async_workers)`.
    """

    def __init__(
        self,
        thread_lock: threading.RLock | None = None,
        *,
        max_async_workers: int | None = None,
    ) -> None:
        self._thread_lock = thread_lock or threading.RLock()
        self._max_async_workers = max_async_workers
        self._async_semaphores: dict[int, asyncio.Semaphore] = {}

    def run(self, fn, /, *args, **kwargs):
        with self._thread_lock:
            return fn(*args, **kwargs)

    async def arun(self, fn, /, *args, **kwargs):
        max_workers = self._max_async_workers
        if max_workers is None:
            return await asyncio.to_thread(self.run, fn, *args, **kwargs)

        loop = asyncio.get_running_loop()
        loop_id = id(loop)
        semaphore = self._async_semaphores.get(loop_id)
        if semaphore is None:
            semaphore = asyncio.Semaphore(max_workers)
            self._async_semaphores[loop_id] = semaphore

        async with semaphore:
            return await asyncio.to_thread(self.run, fn, *args, **kwargs)


class SharedInvestigationContext:
    """
    Shared context for cross-task observable/check/enrichment sharing.

    Initialize with a Cyvest instance; the canonical state is its investigation.

    Invariants:
    - The canonical state lives in `_main_investigation`.
    - All merges are atomic: merge + registry refresh happen in a single critical section.
    - Registries only contain deep-copied snapshots; callers never get live references.
    - Async APIs never block the event loop: all critical sections run in a worker thread.
    """

    def __init__(
        self,
        root_cyvest: Cyvest,
        *,
        lock: threading.RLock | None = None,
        max_async_workers: int | None = None,
    ) -> None:
        if not isinstance(root_cyvest, Cyvest):
            raise TypeError("SharedInvestigationContext expects a Cyvest instance. Use Cyvest.shared_context().")
        self._lock = _SharedLock(lock, max_async_workers=max_async_workers)
        self._main_cyvest = root_cyvest
        self._main_investigation = root_cyvest._investigation

        self._root_type = (
            ObservableType.ARTIFACT
            if self._main_investigation._root_observable.obs_type == ObservableType.ARTIFACT
            else ObservableType.FILE
        )
        self._score_mode_obs = self._main_investigation._score_engine._score_mode_obs

        self._observable_registry: dict[str, Observable] = {}
        self._check_registry: dict[str, Check] = {}
        self._enrichment_registry: dict[str, Enrichment] = {}

        # Initialize registries from the provided canonical investigation so lookups
        # work immediately (even before the first reconcile).
        self._lock.run(self._refresh_registries_unlocked)

    # ---------------------------------------------------------------------
    # Task creation (local fragment builder)
    # ---------------------------------------------------------------------

    def create_cyvest(self, root_data: Any | None = None):
        """
        Return a context manager for a task-local Cyvest instance.

        - `with shared.create_cyvest() as cy:` auto-reconciles on successful exit.
        - `async with shared.create_cyvest() as cy:` also works (reconciles via `areconcile()`).

        If `root_data` is None, task data is a deep copy of the canonical root observable extra.
        """
        return self._CyvestContextManager(shared_context=self, root_data=root_data)

    def acreate_cyvest(self, root_data: Any | None = None):
        """Async-friendly alias for `create_cyvest` (supports `async with`)."""
        return self.create_cyvest(root_data=root_data)

    class _CyvestContextManager:
        def __init__(self, *, shared_context: SharedInvestigationContext, root_data: Any | None) -> None:
            self._shared_context = shared_context
            self._root_data = root_data
            self._cyvest: Cyvest | None = None

        def __enter__(self):
            self._cyvest = self._shared_context._create_task_cyvest_sync(self._root_data)
            return self._cyvest

        def __exit__(self, exc_type, exc_val, exc_tb) -> Literal[False]:
            if exc_type is None and self._cyvest is not None:
                self._shared_context.reconcile(self._cyvest)
            return False

        async def __aenter__(self):
            self._cyvest = await self._shared_context._create_task_cyvest_async(self._root_data)
            return self._cyvest

        async def __aexit__(self, exc_type, exc_val, exc_tb) -> Literal[False]:
            if exc_type is None and self._cyvest is not None:
                await self._shared_context.areconcile(self._cyvest)
            return False

    def _create_task_cyvest_sync(self, root_data: Any | None):
        if root_data is None:
            root_data = self._lock.run(self._get_root_data_copy_unlocked)
        else:
            root_data = deepcopy(root_data)
        return Cyvest(root_data, root_type=self._root_type, score_mode_obs=self._score_mode_obs)

    async def _create_task_cyvest_async(self, root_data: Any | None):
        if root_data is None:
            root_data = await self._lock.arun(self._get_root_data_copy_unlocked)
        else:
            root_data = deepcopy(root_data)
        return Cyvest(root_data, root_type=self._root_type, score_mode_obs=self._score_mode_obs)

    def _get_root_data_copy_unlocked(self) -> Any:
        return deepcopy(self._main_investigation._root_observable.extra)

    # ---------------------------------------------------------------------
    # Reconciliation (atomic merge into canonical)
    # ---------------------------------------------------------------------

    def reconcile(self, source: Cyvest | Investigation) -> None:
        task_investigation = self._extract_investigation(source)
        self._lock.run(self._reconcile_unlocked, task_investigation)

    async def areconcile(self, source: Cyvest | Investigation) -> None:
        task_investigation = self._extract_investigation(source)
        await self._lock.arun(self._reconcile_unlocked, task_investigation)

    def _extract_investigation(self, source: Cyvest | Investigation) -> Investigation:
        if isinstance(source, Cyvest):
            return source._investigation
        return source

    def _reconcile_unlocked(self, task_investigation: Investigation) -> None:
        logger.debug("Reconciling task investigation into shared context")
        self._main_investigation.merge_investigation(task_investigation)
        self._refresh_registries_unlocked()
        logger.debug(
            "Reconciliation complete. Registry: %d observables, %d checks, %d enrichments",
            len(self._observable_registry),
            len(self._check_registry),
            len(self._enrichment_registry),
        )

    def _refresh_registries_unlocked(self) -> None:
        observable_registry: dict[str, Observable] = {}
        for obs in self._main_investigation.get_all_observables().values():
            copy = obs.model_copy(deep=True)
            copy._from_shared_context = True
            observable_registry[obs.key] = copy
        check_registry = {
            check.key: check.model_copy(deep=True) for check in self._main_investigation.get_all_checks().values()
        }
        enrichment_registry = {
            enrichment.key: enrichment.model_copy(deep=True)
            for enrichment in self._main_investigation.get_all_enrichments().values()
        }
        self._observable_registry = observable_registry
        self._check_registry = check_registry
        self._enrichment_registry = enrichment_registry

    # ---------------------------------------------------------------------
    # Lookups (deep-copied snapshots only)
    # ---------------------------------------------------------------------

    def observable_get(self, obs_type: ObservableType, value: str) -> Observable | None:
        key = self._observable_key(obs_type, value)
        return self._lock.run(self._get_observable_by_key_unlocked, key)

    async def observable_aget(self, obs_type: ObservableType, value: str) -> Observable | None:
        key = self._observable_key(obs_type, value)
        return await self._lock.arun(self._get_observable_by_key_unlocked, key)

    def _get_observable_by_key_unlocked(self, key: str) -> Observable | None:
        obs = self._observable_registry.get(key)
        if obs is None:
            return None
        copy = obs.model_copy(deep=True)
        copy._from_shared_context = True
        return copy

    def _observable_key(self, obs_type: ObservableType, value: str) -> str:
        try:
            return keys.generate_observable_key(obs_type.value, value)
        except Exception as e:
            raise ValueError(f"Failed to generate observable key for type='{obs_type}', value='{value}': {e}") from e

    def check_get(self, check_id: str, scope: str) -> Check | None:
        key = self._check_key(check_id, scope)
        return self._lock.run(self._get_check_by_key_unlocked, key)

    async def check_aget(self, check_id: str, scope: str) -> Check | None:
        key = self._check_key(check_id, scope)
        return await self._lock.arun(self._get_check_by_key_unlocked, key)

    def _get_check_by_key_unlocked(self, key: str) -> Check | None:
        check = self._check_registry.get(key)
        return check.model_copy(deep=True) if check else None

    def _check_key(self, check_id: str, scope: str) -> str:
        try:
            return keys.generate_check_key(check_id, scope)
        except Exception as e:
            raise ValueError(f"Failed to generate check key for check_id='{check_id}', scope='{scope}': {e}") from e

    def enrichment_get(self, name: str, context: str = "") -> Enrichment | None:
        key = self._enrichment_key(name, context)
        return self._lock.run(self._get_enrichment_by_key_unlocked, key)

    async def enrichment_aget(self, name: str, context: str = "") -> Enrichment | None:
        key = self._enrichment_key(name, context)
        return await self._lock.arun(self._get_enrichment_by_key_unlocked, key)

    def _get_enrichment_by_key_unlocked(self, key: str) -> Enrichment | None:
        enrichment = self._enrichment_registry.get(key)
        return enrichment.model_copy(deep=True) if enrichment else None

    def _enrichment_key(self, name: str, context: str = "") -> str:
        try:
            return keys.generate_enrichment_key(name, context)
        except Exception as e:
            raise ValueError(f"Failed to generate enrichment key for name='{name}', context='{context}': {e}") from e

    # ---------------------------------------------------------------------
    # Lightweight state reads
    # ---------------------------------------------------------------------

    def get_global_score(self) -> Decimal:
        return self._lock.run(self._main_investigation.get_global_score)

    async def aget_global_score(self) -> Decimal:
        return await self._lock.arun(self._main_investigation.get_global_score)

    def is_whitelisted(self) -> bool:
        return self._lock.run(self._main_investigation.is_whitelisted)

    async def ais_whitelisted(self) -> bool:
        return await self._lock.arun(self._main_investigation.is_whitelisted)

    def get_global_level(self) -> Level:
        return self._lock.run(self._main_investigation.get_global_level)

    async def aget_global_level(self) -> Level:
        return await self._lock.arun(self._main_investigation.get_global_level)

    def observables_list_by_type(self, obs_type: ObservableType) -> list[Observable]:
        return self._lock.run(self._observables_list_by_type_unlocked, obs_type)

    async def observables_alist_by_type(self, obs_type: ObservableType) -> list[Observable]:
        return await self._lock.arun(self._observables_list_by_type_unlocked, obs_type)

    def _observables_list_by_type_unlocked(self, obs_type: ObservableType) -> list[Observable]:
        matches = [obs for obs in self._observable_registry.values() if obs.obs_type == obs_type]

        results: list[Observable] = []
        for obs in matches:
            copy = obs.model_copy(deep=True)
            copy._from_shared_context = True
            results.append(copy)
        return results

    # Intentionally minimal: prefer `observable_get()` / `check_get()` and user-side filtering.

    # ---------------------------------------------------------------------
    # Serialization helpers (sync + async wrappers)
    # ---------------------------------------------------------------------

    def io_to_markdown(
        self,
        include_containers: bool = False,
        include_enrichments: bool = False,
        include_observables: bool = True,
    ) -> str:
        return self._lock.run(
            self._io_to_markdown_unlocked,
            include_containers,
            include_enrichments,
            include_observables,
        )

    async def aio_to_markdown(
        self,
        include_containers: bool = False,
        include_enrichments: bool = False,
        include_observables: bool = True,
    ) -> str:
        return await self._lock.arun(
            self._io_to_markdown_unlocked,
            include_containers,
            include_enrichments,
            include_observables,
        )

    def _io_to_markdown_unlocked(
        self,
        include_containers: bool,
        include_enrichments: bool,
        include_observables: bool,
    ) -> str:
        return generate_markdown_report(
            self._main_investigation,
            include_containers,
            include_enrichments,
            include_observables,
        )

    def io_save_markdown(
        self,
        filepath: str | Path,
        include_containers: bool = False,
        include_enrichments: bool = False,
        include_observables: bool = True,
    ) -> str:
        return self._lock.run(
            self._io_save_markdown_unlocked,
            filepath,
            include_containers,
            include_enrichments,
            include_observables,
        )

    async def aio_save_markdown(
        self,
        filepath: str | Path,
        include_containers: bool = False,
        include_enrichments: bool = False,
        include_observables: bool = True,
    ) -> str:
        return await self._lock.arun(
            self._io_save_markdown_unlocked,
            filepath,
            include_containers,
            include_enrichments,
            include_observables,
        )

    def _io_save_markdown_unlocked(
        self,
        filepath: str | Path,
        include_containers: bool,
        include_enrichments: bool,
        include_observables: bool,
    ) -> str:
        save_investigation_markdown(
            self._main_investigation,
            filepath,
            include_containers,
            include_enrichments,
            include_observables,
        )
        return str(Path(filepath).resolve())

    def io_to_invest(self) -> InvestigationSchema:
        return self._lock.run(self._io_to_invest_unlocked)

    async def aio_to_invest(self) -> InvestigationSchema:
        return await self._lock.arun(self._io_to_invest_unlocked)

    def _io_to_invest_unlocked(self) -> InvestigationSchema:
        return serialize_investigation(self._main_investigation)

    def io_save_json(self, filepath: str | Path) -> str:
        return self._lock.run(self._io_save_json_unlocked, filepath)

    async def aio_save_json(self, filepath: str | Path) -> str:
        return await self._lock.arun(self._io_save_json_unlocked, filepath)

    def _io_save_json_unlocked(self, filepath: str | Path) -> str:
        save_investigation_json(self._main_investigation, filepath)
        return str(Path(filepath).resolve())
