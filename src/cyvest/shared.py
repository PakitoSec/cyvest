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
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, overload

from logurich import logger

from cyvest import keys
from cyvest.levels import Level
from cyvest.model import Check, Enrichment, Observable, ObservableType

if TYPE_CHECKING:
    from cyvest import Cyvest
    from cyvest.investigation import Investigation
    from cyvest.model_schema import InvestigationSchema


class _SharedLock:
    """
    Dual-mode lock adapter.

    - Sync path: uses a threading lock directly.
    - Async path: serializes callers via an asyncio.Lock gate, then runs the critical section in a thread.

    Notes:
    - The async path does not rely on holding the threading lock in the event-loop thread; the entire
      critical section (including lock acquire/release) runs in a worker thread.
    - `async with _SharedLock` is provided for completeness, but internal code should prefer `arun()`
      to ensure the critical section itself does not execute on the event loop.
    """

    def __init__(
        self,
        thread_lock: threading.RLock | None = None,
        *,
        async_gate: asyncio.Lock | None = None,
    ) -> None:
        self._thread_lock = thread_lock or threading.RLock()
        self._async_gate: asyncio.Lock | None = async_gate
        self._cm_executor: ThreadPoolExecutor | None = None  # used only for async context-manager methods

    def __enter__(self) -> _SharedLock:
        self._thread_lock.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> Literal[False]:
        self._thread_lock.release()
        return False

    async def __aenter__(self) -> _SharedLock:
        gate = await self._ensure_async_gate()
        await gate.acquire()
        try:
            # Acquire/release for the async CM must happen on a consistent worker thread for RLock.
            loop = asyncio.get_running_loop()
            executor = self._cm_executor
            if executor is None:
                executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cyvest-shared-lock")
                self._cm_executor = executor
            await loop.run_in_executor(executor, self._thread_lock.acquire)
            return self
        except BaseException:
            gate.release()
            raise

    async def __aexit__(self, exc_type, exc, tb) -> Literal[False]:
        try:
            loop = asyncio.get_running_loop()
            executor = self._cm_executor
            if executor is None:
                # Should not happen, but keep behavior predictable.
                self._thread_lock.release()
            else:
                await loop.run_in_executor(executor, self._thread_lock.release)
        finally:
            # Gate is always acquired in __aenter__.
            if self._async_gate is not None and self._async_gate.locked():
                self._async_gate.release()
        return False

    def run(self, fn, /, *args, **kwargs):
        with self._thread_lock:
            return fn(*args, **kwargs)

    async def arun(self, fn, /, *args, **kwargs):
        gate = await self._ensure_async_gate()
        async with gate:
            return await asyncio.to_thread(self.run, fn, *args, **kwargs)

    async def _ensure_async_gate(self) -> asyncio.Lock:
        gate = self._async_gate
        if gate is None:
            gate = asyncio.Lock()
            self._async_gate = gate
        return gate


class SharedInvestigationContext:
    """
    Shared context for cross-task observable/check/enrichment sharing.

    Invariants:
    - The canonical state lives in `_main_investigation`.
    - All merges are atomic: merge + registry refresh happen in a single critical section.
    - Registries only contain deep-copied snapshots; callers never get live references.
    - Async APIs never block the event loop: all critical sections run in a worker thread.
    """

    def __init__(
        self,
        root_investigation: Investigation,
        *,
        lock: threading.RLock | asyncio.Lock | None = None,
        async_gate: asyncio.Lock | None = None,
    ) -> None:
        if isinstance(lock, asyncio.Lock):
            async_gate = lock
            lock = None
        self._lock = _SharedLock(lock, async_gate=async_gate)
        self._main_investigation = root_investigation

        self._root_type = (
            "artifact" if root_investigation._root_observable.obs_type == ObservableType.ARTIFACT else "file"
        )
        self._score_mode = root_investigation._score_engine._score_mode

        self._observable_registry: dict[str, Observable] = {}
        self._check_registry: dict[str, Check] = {}
        self._enrichment_registry: dict[str, Enrichment] = {}

    # ---------------------------------------------------------------------
    # Task creation (local fragment builder)
    # ---------------------------------------------------------------------

    def create_cyvest(self, data: Any | None = None):
        """
        Return a context manager for a task-local Cyvest instance.

        - `with shared.create_cyvest() as cy:` auto-reconciles on successful exit.
        - `async with shared.create_cyvest() as cy:` also works (reconciles via `areconcile()`).

        If `data` is None, task data is a deep copy of the canonical root observable extra.
        """
        return self._CyvestContextManager(shared_context=self, data=data)

    def acreate_cyvest(self, data: Any | None = None):
        """Async-friendly alias for `create_cyvest` (supports `async with`)."""
        return self.create_cyvest(data=data)

    class _CyvestContextManager:
        def __init__(self, *, shared_context: SharedInvestigationContext, data: Any | None) -> None:
            self._shared_context = shared_context
            self._data = data
            self._cyvest: Cyvest | None = None

        def __enter__(self):
            self._cyvest = self._shared_context._create_task_cyvest_sync(self._data)
            return self._cyvest

        def __exit__(self, exc_type, exc_val, exc_tb) -> Literal[False]:
            if exc_type is None and self._cyvest is not None:
                self._shared_context.reconcile(self._cyvest)
            return False

        async def __aenter__(self):
            self._cyvest = await self._shared_context._create_task_cyvest_async(self._data)
            return self._cyvest

        async def __aexit__(self, exc_type, exc_val, exc_tb) -> Literal[False]:
            if exc_type is None and self._cyvest is not None:
                await self._shared_context.areconcile(self._cyvest)
            return False

    def _create_task_cyvest_sync(self, data: Any | None):
        from cyvest import Cyvest

        if data is None:
            data = self._lock.run(self._get_root_data_copy_unlocked)
        else:
            data = deepcopy(data)
        return Cyvest(data, root_type=self._root_type, score_mode=self._score_mode)

    async def _create_task_cyvest_async(self, data: Any | None):
        from cyvest import Cyvest

        if data is None:
            data = await self._lock.arun(self._get_root_data_copy_unlocked)
        else:
            data = deepcopy(data)
        return Cyvest(data, root_type=self._root_type, score_mode=self._score_mode)

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
        from cyvest import Cyvest

        if isinstance(source, Cyvest):
            return source._investigation
        return source

    def _reconcile_unlocked(self, task_investigation: Investigation) -> None:
        logger.info("Reconciling task investigation into shared context")
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

    @overload
    def get_observable(self, key: str) -> Observable | None: ...

    @overload
    def get_observable(self, obs_type: str | ObservableType, value: str) -> Observable | None: ...

    def get_observable(self, *args, **kwargs) -> Observable | None:
        key = self._parse_observable_lookup_args(*args, **kwargs, _caller="get_observable")
        return self._lock.run(self._get_observable_by_key_unlocked, key)

    async def aget_observable(self, *args, **kwargs) -> Observable | None:
        key = self._parse_observable_lookup_args(*args, **kwargs, _caller="get_observable")
        return await self._lock.arun(self._get_observable_by_key_unlocked, key)

    def _get_observable_by_key_unlocked(self, key: str) -> Observable | None:
        obs = self._observable_registry.get(key)
        if obs is None:
            return None
        copy = obs.model_copy(deep=True)
        copy._from_shared_context = True
        return copy

    def _parse_observable_lookup_args(self, *args, _caller: str, **kwargs) -> str:
        if len(args) == 1 and not kwargs:
            return args[0]
        if len(args) == 2 and not kwargs:
            obs_type, value = args
            if isinstance(obs_type, ObservableType):
                obs_type = obs_type.value
            try:
                return keys.generate_observable_key(obs_type, value)
            except Exception as e:
                raise ValueError(
                    f"Failed to generate observable key for type='{obs_type}', value='{value}': {e}"
                ) from e
        raise ValueError(f"{_caller}() accepts either (key: str) or (obs_type: str | ObservableType, value: str)")

    @overload
    def get_check(self, key: str) -> Check | None: ...

    @overload
    def get_check(self, check_id: str, scope: str) -> Check | None: ...

    def get_check(self, *args, **kwargs) -> Check | None:
        key = self._parse_check_lookup_args(*args, **kwargs, _caller="get_check")
        return self._lock.run(self._get_check_by_key_unlocked, key)

    async def aget_check(self, *args, **kwargs) -> Check | None:
        key = self._parse_check_lookup_args(*args, **kwargs, _caller="get_check")
        return await self._lock.arun(self._get_check_by_key_unlocked, key)

    def _get_check_by_key_unlocked(self, key: str) -> Check | None:
        check = self._check_registry.get(key)
        return check.model_copy(deep=True) if check else None

    def _parse_check_lookup_args(self, *args, _caller: str, **kwargs) -> str:
        if len(args) == 1 and not kwargs:
            return args[0]
        if len(args) == 2 and not kwargs:
            check_id, scope = args
            try:
                return keys.generate_check_key(check_id, scope)
            except Exception as e:
                raise ValueError(f"Failed to generate check key for check_id='{check_id}', scope='{scope}': {e}") from e
        raise ValueError(f"{_caller}() accepts either (key: str) or (check_id: str, scope: str)")

    @overload
    def get_enrichment(self, key: str) -> Enrichment | None: ...

    @overload
    def get_enrichment(self, name: str, context: str = "") -> Enrichment | None: ...

    def get_enrichment(self, *args, **kwargs) -> Enrichment | None:
        key = self._parse_enrichment_lookup_args(*args, **kwargs, _caller="get_enrichment")
        return self._lock.run(self._get_enrichment_by_key_unlocked, key)

    async def aget_enrichment(self, *args, **kwargs) -> Enrichment | None:
        key = self._parse_enrichment_lookup_args(*args, **kwargs, _caller="get_enrichment")
        return await self._lock.arun(self._get_enrichment_by_key_unlocked, key)

    def _get_enrichment_by_key_unlocked(self, key: str) -> Enrichment | None:
        enrichment = self._enrichment_registry.get(key)
        return enrichment.model_copy(deep=True) if enrichment else None

    def _parse_enrichment_lookup_args(self, *args, _caller: str, **kwargs) -> str:
        if len(args) == 1 and not kwargs:
            arg = args[0]
            if arg.startswith("enr:"):
                return arg
            try:
                return keys.generate_enrichment_key(arg)
            except Exception as e:
                raise ValueError(f"Failed to generate enrichment key for name='{arg}': {e}") from e
        if len(args) == 2 and not kwargs:
            name, context = args
            try:
                return keys.generate_enrichment_key(name, context)
            except Exception as e:
                raise ValueError(
                    f"Failed to generate enrichment key for name='{name}', context='{context}': {e}"
                ) from e
        raise ValueError(f"{_caller}() accepts either (key: str) or (name: str, context: str = '')")

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

    def list_observables(self) -> list[str]:
        return self._lock.run(lambda: list(self._observable_registry.keys()))

    async def alist_observables(self) -> list[str]:
        return await self._lock.arun(lambda: list(self._observable_registry.keys()))

    def list_checks(self) -> list[str]:
        return self._lock.run(lambda: list(self._check_registry.keys()))

    async def alist_checks(self) -> list[str]:
        return await self._lock.arun(lambda: list(self._check_registry.keys()))

    def list_enrichments(self) -> list[str]:
        return self._lock.run(lambda: list(self._enrichment_registry.keys()))

    async def alist_enrichments(self) -> list[str]:
        return await self._lock.arun(lambda: list(self._enrichment_registry.keys()))

    def find_observables_by_type(self, obs_type: ObservableType) -> list[Observable]:
        return self._lock.run(self._find_observables_by_type_unlocked, obs_type)

    async def afind_observables_by_type(self, obs_type: ObservableType) -> list[Observable]:
        return await self._lock.arun(self._find_observables_by_type_unlocked, obs_type)

    def _find_observables_by_type_unlocked(self, obs_type: ObservableType) -> list[Observable]:
        return [obs.model_copy(deep=True) for obs in self._observable_registry.values() if obs.obs_type == obs_type]

    def find_observables_by_value(self, value: str) -> list[Observable]:
        return self._lock.run(self._find_observables_by_value_unlocked, value)

    async def afind_observables_by_value(self, value: str) -> list[Observable]:
        return await self._lock.arun(self._find_observables_by_value_unlocked, value)

    def _find_observables_by_value_unlocked(self, value: str) -> list[Observable]:
        return [obs.model_copy(deep=True) for obs in self._observable_registry.values() if obs.value == value]

    @overload
    def has_observable(self, key: str) -> bool: ...

    @overload
    def has_observable(self, obs_type: str | ObservableType, value: str) -> bool: ...

    def has_observable(self, *args, **kwargs) -> bool:
        key = self._parse_observable_lookup_args(*args, **kwargs, _caller="has_observable")
        return self._lock.run(lambda: key in self._observable_registry)

    async def ahas_observable(self, *args, **kwargs) -> bool:
        key = self._parse_observable_lookup_args(*args, **kwargs, _caller="has_observable")
        return await self._lock.arun(lambda: key in self._observable_registry)

    @overload
    def has_check(self, key: str) -> bool: ...

    @overload
    def has_check(self, check_id: str, scope: str) -> bool: ...

    def has_check(self, *args, **kwargs) -> bool:
        key = self._parse_check_lookup_args(*args, **kwargs, _caller="has_check")
        return self._lock.run(lambda: key in self._check_registry)

    async def ahas_check(self, *args, **kwargs) -> bool:
        key = self._parse_check_lookup_args(*args, **kwargs, _caller="has_check")
        return await self._lock.arun(lambda: key in self._check_registry)

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
        from cyvest import Cyvest
        from cyvest.io_serialization import generate_markdown_report

        temp_cy = Cyvest.__new__(Cyvest)
        temp_cy._investigation = self._main_investigation
        return generate_markdown_report(temp_cy, include_containers, include_enrichments, include_observables)

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
        from cyvest import Cyvest
        from cyvest.io_serialization import save_investigation_markdown

        temp_cy = Cyvest.__new__(Cyvest)
        temp_cy._investigation = self._main_investigation
        save_investigation_markdown(temp_cy, filepath, include_containers, include_enrichments, include_observables)
        return str(Path(filepath).resolve())

    def io_to_dict(self) -> InvestigationSchema:
        return self._lock.run(self._io_to_dict_unlocked)

    async def aio_to_dict(self) -> InvestigationSchema:
        return await self._lock.arun(self._io_to_dict_unlocked)

    def _io_to_dict_unlocked(self) -> InvestigationSchema:
        from cyvest import Cyvest
        from cyvest.io_serialization import serialize_investigation

        temp_cy = Cyvest.__new__(Cyvest)
        temp_cy._investigation = self._main_investigation
        return serialize_investigation(temp_cy)

    def io_save_json(self, filepath: str | Path) -> str:
        return self._lock.run(self._io_save_json_unlocked, filepath)

    async def aio_save_json(self, filepath: str | Path) -> str:
        return await self._lock.arun(self._io_save_json_unlocked, filepath)

    def _io_save_json_unlocked(self, filepath: str | Path) -> str:
        from cyvest import Cyvest
        from cyvest.io_serialization import save_investigation_json

        temp_cy = Cyvest.__new__(Cyvest)
        temp_cy._investigation = self._main_investigation
        save_investigation_json(temp_cy, filepath)
        return str(Path(filepath).resolve())
