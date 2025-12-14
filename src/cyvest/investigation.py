"""
Investigation core - central state management for cybersecurity investigations.

Handles all object storage, merging, scoring, and statistics in a unified way.
Provides automatic merge-on-create for all object types.
"""

from __future__ import annotations

import threading
from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, overload

from logurich import logger

from cyvest import keys
from cyvest.level_score_rules import recalculate_level_for_score
from cyvest.levels import Level, normalize_level
from cyvest.model import (
    Check,
    CheckScorePolicy,
    Container,
    Enrichment,
    InvestigationWhitelist,
    Observable,
    ObservableType,
    ThreatIntel,
)
from cyvest.score import ScoreEngine, ScoreMode
from cyvest.stats import InvestigationStats

if TYPE_CHECKING:
    from cyvest import Cyvest
    from cyvest.model_schema import InvestigationSchema, StatisticsSchema


class SharedInvestigationContext:
    """
    Thread-safe shared context for cross-task observable and check sharing.

    Allows multiple investigation tasks running in parallel to:
    - Register observables/checks they create for others to reference
    - Look up observables/checks created by previously-completed tasks
    - Incrementally merge task results into a central investigation

    Thread-safety is achieved using a reentrant lock (RLock) for all operations.

    Example (manual reconcile):
        >>> shared = SharedInvestigationContext(main_inv)
        >>> cy = shared.create_cyvest()
        >>> # ... do work ...
        >>> shared.reconcile(cy)

    Example (auto-reconcile):
        >>> shared = SharedInvestigationContext(main_inv)
        >>> with shared.create_cyvest() as cy:
        >>>     # ... do work ...
        >>>     # Auto-reconciles on exit!
    """

    def __init__(self, root_investigation: Investigation):
        """
        Initialize shared context with a root investigation.

        Args:
            root_investigation: The main investigation that will receive merged results
        """
        self._lock = threading.RLock()  # Reentrant lock for nested calls
        self._main_investigation = root_investigation

        # Store main investigation configuration for task creation
        self._root_type = (
            "artifact" if root_investigation._root_observable.obs_type == ObservableType.ARTIFACT else "file"
        )
        self._score_mode = root_investigation._score_engine._score_mode

        # Thread-safe registries (copies of objects for lookup)
        self._observable_registry: dict[str, Observable] = {}
        self._check_registry: dict[str, Check] = {}
        self._enrichment_registry: dict[str, Enrichment] = {}

    def create_cyvest(self, data: Any | None = None):
        """
        Create a new Cyvest instance with the same configuration as the main investigation.

        Returns a context manager that auto-reconciles on exit for clean usage in tasks.

        Args:
            data: Task-specific data. If None, reuses the main investigation's data.

        Returns:
            A Cyvest context manager that auto-reconciles on exit

        Example:
            >>> # Auto-reconcile pattern (recommended)
            >>> with shared.create_cyvest() as cy:
            >>>     cy.observable(...)
            >>>     # Automatically reconciles on exit
            >>>
            >>> # Manual pattern (if you need the instance outside the context)
            >>> cy = shared.create_cyvest().__enter__()
            >>> # ... work ...
            >>> shared.reconcile(cy)
        """
        from cyvest import Cyvest

        # Use main investigation's data if not provided
        if data is None:
            with self._lock:
                data = deepcopy(self._main_investigation._root_observable.extra)

        cy = Cyvest(data, root_type=self._root_type, score_mode=self._score_mode)

        # Return context manager wrapper
        return self._CyvestContextManager(cy, self)

    class _CyvestContextManager:
        """Context manager wrapper for auto-reconcile on exit."""

        def __init__(self, cyvest, shared_context):
            self._cyvest = cyvest
            self._shared_context = shared_context

        def __enter__(self):
            return self._cyvest

        def __exit__(self, exc_type, exc_val, exc_tb):
            if exc_type is None:  # Only reconcile on success
                self._shared_context.reconcile(self._cyvest)
            return False

    def reconcile(self, source: Cyvest | Investigation) -> None:
        """
        Reconcile (merge) a completed task's investigation into the shared context.

        Thread-safe: Uses lock to ensure atomic merge operation.
        Also registers all observables and checks for future task lookups.

        Args:
            source: Either a Cyvest instance or Investigation instance to reconcile

        Example:
            >>> cy = shared.create_cyvest().__enter__()
            >>> # ... do work ...
            >>> shared.reconcile(cy)  # Accepts Cyvest
            >>>
            >>> # Or directly with Investigation
            >>> shared.reconcile(investigation)
        """
        # Extract Investigation from Cyvest if needed
        from cyvest import Cyvest

        if isinstance(source, Cyvest):
            task_investigation = source._investigation
        else:
            task_investigation = source

        with self._lock:
            logger.info("Reconciling task investigation into shared context")

            # Merge into main investigation
            self._main_investigation.merge_investigation(task_investigation)

            # Refresh registries from canonical, post-merge investigation state
            self._observable_registry = {}
            for obs in self._main_investigation.get_all_observables().values():
                copy = obs.model_copy(deep=True)
                copy._from_shared_context = True
                self._observable_registry[obs.key] = copy

            self._check_registry = {
                check.key: check.model_copy(deep=True) for check in self._main_investigation.get_all_checks().values()
            }
            self._enrichment_registry = {
                enrichment.key: enrichment.model_copy(deep=True)
                for enrichment in self._main_investigation.get_all_enrichments().values()
            }

            logger.debug(
                f"Reconciliation complete. Registry: {len(self._observable_registry)} observables, "
                f"{len(self._check_registry)} checks, {len(self._enrichment_registry)} enrichments"
            )

    @overload
    def get_observable(self, key: str) -> Observable | None:
        """Look up observable by full key string."""
        ...

    @overload
    def get_observable(self, obs_type: str | ObservableType, value: str) -> Observable | None:
        """Look up observable by type and value."""
        ...

    def get_observable(self, *args, **kwargs) -> Observable | None:
        """
        Look up a shared observable by key or by type and value.

        Thread-safe: Returns a deep copy to prevent concurrent modification.

        **IMPORTANT: Returns a READ-ONLY COPY for inspection only.**

        DO NOT use the returned observable directly in relationships!
        The copy is not registered in your local investigation and will cause errors.

        WRONG:
            >>> malicious_domain = shared_context.get_observable(ObservableType.DOMAIN_NAME, "evil.com")
            >>> url_obs.relate_to(malicious_domain, RelationshipType.RELATED_TO)  # ERROR!

        CORRECT:
            >>> # Inspect the shared observable's properties
            >>> domain_info = shared_context.get_observable(ObservableType.DOMAIN_NAME, "evil.com")
            >>> if domain_info and domain_info.score > 7:
            >>>     # Create a NEW observable in your local investigation
            >>>     url_obs.relate_to(
            >>>         cy.observable(ObservableType.DOMAIN_NAME, "evil.com"),
            >>>         RelationshipType.RELATED_TO
            >>>     )

        Args:
            key: Observable key to look up (single argument)
            obs_type: Observable type (when using two arguments)
            value: Observable value (when using two arguments)

        Returns:
            Copy of the observable if found, None otherwise

        Raises:
            ValueError: If arguments are invalid or key generation fails

        Examples:
            >>> # Key-based lookup
            >>> obs = shared_context.get_observable("obs:email-addr:user@domain.com")
            >>>
            >>> # Parameter-based lookup (recommended)
            >>> obs = shared_context.get_observable(ObservableType.EMAIL_ADDR, "user@domain.com")
            >>> obs = shared_context.get_observable("email-addr", "user@domain.com")
        """
        # Parse arguments
        if len(args) == 1 and not kwargs:
            # Key-based lookup
            key = args[0]
        elif len(args) == 2 and not kwargs:
            # Parameter-based lookup
            obs_type, value = args
            # Convert ObservableType enum to string if needed
            if isinstance(obs_type, ObservableType):
                obs_type = obs_type.value
            # Generate key using keys module
            try:
                key = keys.generate_observable_key(obs_type, value)
            except Exception as e:
                raise ValueError(
                    f"Failed to generate observable key for type='{obs_type}', value='{value}': {e}"
                ) from e
        else:
            raise ValueError(
                "get_observable() accepts either (key: str) or (obs_type: str | ObservableType, value: str)"
            )

        with self._lock:
            obs = self._observable_registry.get(key)
            if obs:
                copy = obs.model_copy(deep=True)
                # Mark this as a copy from shared context to prevent misuse in relationships
                copy._from_shared_context = True
                return copy
            return None

    @overload
    def get_check(self, key: str) -> Check | None:
        """Look up check by full key string."""
        ...

    @overload
    def get_check(self, check_id: str, scope: str) -> Check | None:
        """Look up check by ID and scope."""
        ...

    def get_check(self, *args, **kwargs) -> Check | None:
        """
        Look up a shared check by key or by check ID and scope.

        Thread-safe: Returns a deep copy to prevent concurrent modification.

        Args:
            key: Check key to look up (single argument)
            check_id: Check identifier (when using two arguments)
            scope: Check scope (when using two arguments)

        Returns:
            Copy of the check if found, None otherwise

        Raises:
            ValueError: If arguments are invalid or key generation fails

        Examples:
            >>> # Key-based lookup
            >>> check = shared_context.get_check("chk:from:header")
            >>>
            >>> # Parameter-based lookup (recommended)
            >>> check = shared_context.get_check("from", "header")
        """
        # Parse arguments
        if len(args) == 1 and not kwargs:
            # Key-based lookup
            key = args[0]
        elif len(args) == 2 and not kwargs:
            # Parameter-based lookup
            check_id, scope = args
            # Generate key using keys module
            try:
                key = keys.generate_check_key(check_id, scope)
            except Exception as e:
                raise ValueError(f"Failed to generate check key for check_id='{check_id}', scope='{scope}': {e}") from e
        else:
            raise ValueError("get_check() accepts either (key: str) or (check_id: str, scope: str)")

        with self._lock:
            check = self._check_registry.get(key)
            if check:
                return check.model_copy(deep=True)
            return None

    @overload
    def get_enrichment(self, key: str) -> Enrichment | None:
        """Look up enrichment by full key string."""
        ...

    @overload
    def get_enrichment(self, name: str, context: str = "") -> Enrichment | None:
        """Look up enrichment by name and optional context."""
        ...

    def get_enrichment(self, *args, **kwargs) -> Enrichment | None:
        """
        Look up a shared enrichment by key or by name and context.

        Thread-safe: Returns a deep copy to prevent concurrent modification.

        Args:
            key: Enrichment key to look up (single argument)
            name: Enrichment name (when using one or two arguments)
            context: Optional enrichment context (when using two arguments)

        Returns:
            Copy of the enrichment if found, None otherwise

        Raises:
            ValueError: If arguments are invalid or key generation fails

        Examples:
            >>> # Key-based lookup
            >>> enr = shared_context.get_enrichment("enr:whois")
            >>>
            >>> # Parameter-based lookup (recommended)
            >>> enr = shared_context.get_enrichment("whois")
            >>> enr = shared_context.get_enrichment("dns", "specific-context")
        """
        # Parse arguments
        if len(args) == 1 and not kwargs:
            # Could be key-based or name-only lookup
            arg = args[0]
            if arg.startswith("enr:"):
                # Key-based lookup
                key = arg
            else:
                # Name-only lookup
                try:
                    key = keys.generate_enrichment_key(arg)
                except Exception as e:
                    raise ValueError(f"Failed to generate enrichment key for name='{arg}': {e}") from e
        elif len(args) == 2 and not kwargs:
            # Parameter-based lookup with context
            name, context = args
            try:
                key = keys.generate_enrichment_key(name, context)
            except Exception as e:
                raise ValueError(
                    f"Failed to generate enrichment key for name='{name}', context='{context}': {e}"
                ) from e
        else:
            raise ValueError("get_enrichment() accepts either (key: str) or (name: str, context: str = '')")

        with self._lock:
            enrichment = self._enrichment_registry.get(key)
            if enrichment:
                return enrichment.model_copy(deep=True)
            return None

    def get_global_score(self) -> Decimal:
        """
        Get the global score from the main investigation.

        Thread-safe: Uses lock to ensure consistent read.

        Returns:
            The global investigation score

        Example:
            >>> shared = SharedInvestigationContext(main_inv)
            >>> score = shared.get_global_score()
            >>> print(f"Investigation score: {score}")
        """
        with self._lock:
            return self._main_investigation.get_global_score()

    def is_whitelisted(self) -> bool:
        """
        Return whether the shared investigation is whitelisted.

        Thread-safe: Uses lock to ensure consistent read.
        """
        with self._lock:
            return self._main_investigation.is_whitelisted()

    def get_global_level(self) -> Level:
        """
        Get the global level from the main investigation.

        Thread-safe: Uses lock to ensure consistent read.
        """
        with self._lock:
            return self._main_investigation.get_global_level()

    def list_observables(self) -> list[str]:
        """
        List all observable keys available for cross-task reference.

        Returns:
            List of observable keys
        """
        with self._lock:
            return list(self._observable_registry.keys())

    def list_checks(self) -> list[str]:
        """
        List all check keys available for cross-task reference.

        Returns:
            List of check keys
        """
        with self._lock:
            return list(self._check_registry.keys())

    def list_enrichments(self) -> list[str]:
        """
        List all enrichment keys available for cross-task reference.

        Returns:
            List of enrichment keys
        """
        with self._lock:
            return list(self._enrichment_registry.keys())

    def find_observables_by_type(self, obs_type: ObservableType) -> list[Observable]:
        """
        Find all observables of a specific type.

        Useful for tasks that need to reference observables by type
        (e.g., all EMAIL_ADDR observables).

        Args:
            obs_type: Observable type to filter by

        Returns:
            List of matching observables (deep copies)
        """
        with self._lock:
            matches = []
            for obs in self._observable_registry.values():
                if obs.obs_type == obs_type:
                    matches.append(obs.model_copy(deep=True))
            return matches

    def find_observables_by_value(self, value: str) -> list[Observable]:
        """
        Find observables by exact value match.

        Args:
            value: Observable value to search for

        Returns:
            List of matching observables (deep copies)
        """
        with self._lock:
            matches = []
            for obs in self._observable_registry.values():
                if obs.value == value:
                    matches.append(obs.model_copy(deep=True))
            return matches

    @overload
    def has_observable(self, key: str) -> bool:
        """Check if observable exists by full key string."""
        ...

    @overload
    def has_observable(self, obs_type: str | ObservableType, value: str) -> bool:
        """Check if observable exists by type and value."""
        ...

    def has_observable(self, *args, **kwargs) -> bool:
        """
        Check if an observable exists in the shared context.

        Args:
            key: Observable key to check (single argument)
            obs_type: Observable type (when using two arguments)
            value: Observable value (when using two arguments)

        Returns:
            True if observable exists, False otherwise

        Raises:
            ValueError: If arguments are invalid or key generation fails
        """
        # Parse arguments
        if len(args) == 1 and not kwargs:
            key = args[0]
        elif len(args) == 2 and not kwargs:
            obs_type, value = args
            if isinstance(obs_type, ObservableType):
                obs_type = obs_type.value
            try:
                key = keys.generate_observable_key(obs_type, value)
            except Exception as e:
                raise ValueError(
                    f"Failed to generate observable key for type='{obs_type}', value='{value}': {e}"
                ) from e
        else:
            raise ValueError(
                "has_observable() accepts either (key: str) or (obs_type: str | ObservableType, value: str)"
            )

        with self._lock:
            return key in self._observable_registry

    @overload
    def has_check(self, key: str) -> bool:
        """Check if check exists by full key string."""
        ...

    @overload
    def has_check(self, check_id: str, scope: str) -> bool:
        """Check if check exists by ID and scope."""
        ...

    def has_check(self, *args, **kwargs) -> bool:
        """
        Check if a check exists in the shared context.

        Args:
            key: Check key to check (single argument)
            check_id: Check identifier (when using two arguments)
            scope: Check scope (when using two arguments)

        Returns:
            True if check exists, False otherwise

        Raises:
            ValueError: If arguments are invalid or key generation fails
        """
        # Parse arguments
        if len(args) == 1 and not kwargs:
            key = args[0]
        elif len(args) == 2 and not kwargs:
            check_id, scope = args
            try:
                key = keys.generate_check_key(check_id, scope)
            except Exception as e:
                raise ValueError(f"Failed to generate check key for check_id='{check_id}', scope='{scope}': {e}") from e
        else:
            raise ValueError("has_check() accepts either (key: str) or (check_id: str, scope: str)")

        with self._lock:
            return key in self._check_registry

    def io_to_markdown(
        self,
        include_containers: bool = False,
        include_enrichments: bool = False,
        include_observables: bool = True,
    ) -> str:
        """
        Generate a Markdown report of the shared investigation.

        Thread-safe: Uses lock to ensure consistent read of investigation state.

        Args:
            include_containers: Include containers section in the report (default: False)
            include_enrichments: Include enrichments section in the report (default: False)
            include_observables: Include observables section in the report (default: True)

        Returns:
            Markdown formatted report as a string

        Example:
            >>> shared = SharedInvestigationContext(main_inv)
            >>> markdown = shared.io_to_markdown()
            >>> print(markdown)
            # Cybersecurity Investigation Report
            ...
        """
        from cyvest import Cyvest
        from cyvest.io_serialization import generate_markdown_report

        with self._lock:
            # Create temporary Cyvest wrapper for compatibility with generate_markdown_report
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
        """
        Save the shared investigation as a Markdown report.

        Thread-safe: Uses lock to ensure consistent read of investigation state.
        Relative paths are converted to absolute paths before saving.

        Args:
            filepath: Path to save the Markdown file (relative or absolute)
            include_containers: Include containers section in the report (default: False)
            include_enrichments: Include enrichments section in the report (default: False)
            include_observables: Include observables section in the report (default: True)

        Returns:
            Absolute path to the saved file as a string

        Raises:
            PermissionError: If the file cannot be written
            OSError: If there are file system issues

        Example:
            >>> shared = SharedInvestigationContext(main_inv)
            >>> path = shared.io_save_markdown("report.md")
            >>> print(path)  # /absolute/path/to/report.md
        """
        from pathlib import Path

        from cyvest import Cyvest
        from cyvest.io_serialization import save_investigation_markdown

        with self._lock:
            # Create temporary Cyvest wrapper for compatibility with save_investigation_markdown
            temp_cy = Cyvest.__new__(Cyvest)
            temp_cy._investigation = self._main_investigation
            save_investigation_markdown(temp_cy, filepath, include_containers, include_enrichments, include_observables)
            return str(Path(filepath).resolve())

    def io_to_dict(self) -> InvestigationSchema:
        """
        Serialize the shared investigation to an InvestigationSchema.

        Thread-safe: Uses lock to ensure consistent read of investigation state.

        Returns:
            InvestigationSchema instance (use .model_dump() for dict)

        Example:
            >>> shared = SharedInvestigationContext(main_inv)
            >>> schema = shared.io_to_dict()
            >>> dict_data = schema.model_dump(by_alias=True)
        """
        from cyvest import Cyvest
        from cyvest.io_serialization import serialize_investigation

        with self._lock:
            # Create temporary Cyvest wrapper for compatibility with serialize_investigation
            temp_cy = Cyvest.__new__(Cyvest)
            temp_cy._investigation = self._main_investigation
            return serialize_investigation(temp_cy)

    def io_save_json(self, filepath: str | Path) -> str:
        """
        Save the shared investigation to a JSON file.

        Thread-safe: Uses lock to ensure consistent read of investigation state.
        Relative paths are converted to absolute paths before saving.

        Args:
            filepath: Path to save the JSON file (relative or absolute)

        Returns:
            Absolute path to the saved file as a string

        Raises:
            PermissionError: If the file cannot be written
            OSError: If there are file system issues

        Example:
            >>> shared = SharedInvestigationContext(main_inv)
            >>> path = shared.io_save_json("investigation.json")
            >>> print(path)  # /absolute/path/to/investigation.json
        """
        from pathlib import Path

        from cyvest import Cyvest
        from cyvest.io_serialization import save_investigation_json

        with self._lock:
            # Create temporary Cyvest wrapper for compatibility with save_investigation_json
            temp_cy = Cyvest.__new__(Cyvest)
            temp_cy._investigation = self._main_investigation
            save_investigation_json(temp_cy, filepath)
            return str(Path(filepath).resolve())


class Investigation:
    """
    Core investigation state and operations.

    Manages all investigation objects (observables, checks, threat intel, etc.),
    handles automatic merging on creation, score propagation, and statistics tracking.
    """

    _MODEL_METADATA_RULES: dict[str, dict[str, set[str]]] = {
        "observable": {
            "fields": {"comment", "extra", "internal", "whitelisted"},
            "dict_fields": {"extra"},
        },
        "check": {
            "fields": {"comment", "extra", "description", "score_policy"},
            "dict_fields": {"extra"},
        },
        "threat_intel": {
            "fields": {"comment", "extra", "level"},
            "dict_fields": {"extra"},
        },
        "enrichment": {
            "fields": {"context", "data"},
            "dict_fields": {"data"},
        },
        "container": {
            "fields": {"description"},
            "dict_fields": set(),
        },
    }

    def __init__(
        self, data: Any, root_type: str = "file", score_mode: ScoreMode | Literal["max", "sum"] = ScoreMode.MAX
    ) -> None:
        """
        Initialize a new investigation.

        Args:
            root_type: Type of root observable ("file" or "artifact")
            score_mode: Score calculation mode (MAX or SUM)
        """
        self._started_at = datetime.now(timezone.utc)

        # Object collections
        self._observables: dict[str, Observable] = {}
        self._checks: dict[str, Check] = {}
        self._threat_intels: dict[str, ThreatIntel] = {}
        self._enrichments: dict[str, Enrichment] = {}
        self._containers: dict[str, Container] = {}

        # Internal components
        normalized_score_mode = ScoreMode.normalize(score_mode)
        self._score_engine = ScoreEngine(score_mode=normalized_score_mode)
        self._stats = InvestigationStats()
        self._whitelists: dict[str, InvestigationWhitelist] = {}

        # Create root observable
        obj_type = ObservableType.FILE
        if root_type == "artifact":
            obj_type = ObservableType.ARTIFACT
        elif root_type != "file":
            raise ValueError(f"root_type {root_type} is not allowed")

        self._root_observable = Observable(
            obs_type=obj_type,
            value="root",
            internal=False,
            whitelisted=False,
            comment="Root observable for investigation",
            extra=data,
            score=Decimal("0"),
            level=Level.INFO,
        )
        self._observables[self._root_observable.key] = self._root_observable
        self._score_engine.register_observable(self._root_observable)
        self._stats.register_observable(self._root_observable)

    # Private merge methods

    def _merge_observable(self, existing: Observable, incoming: Observable) -> tuple[Observable, list]:
        """
        Merge an incoming observable into an existing observable.

        Strategy:
        - Update score (take maximum)
        - Update level (take maximum)
        - Update extra (merge dicts)
        - Concatenate comments
        - Merge threat intels
        - Merge relationships (defer if target missing)
        - Merge generated_by_checks

        Args:
            existing: The existing observable
            incoming: The incoming observable to merge

        Returns:
            Tuple of (merged observable, deferred relationships)
        """
        # Normal merge logic for scores and levels (SAFE level protection in Observable.update_score)
        # Take the higher score
        if incoming.score > existing.score:
            existing.update_score(incoming.score, reason=f"Merged from {incoming.key}")

        # Take the higher level
        if incoming.level > existing.level:
            existing.set_level(incoming.level)

        # Update extra (merge dictionaries)
        if existing.extra:
            existing.extra.update(incoming.extra)
        elif incoming.extra:
            existing.extra = dict(incoming.extra)

        # Concatenate comments
        if incoming.comment:
            if existing.comment:
                existing.comment += "\n\n" + incoming.comment
            else:
                existing.comment = incoming.comment

        # Merge whitelisted status (if either is whitelisted, result is whitelisted)
        existing.whitelisted = existing.whitelisted or incoming.whitelisted

        # Merge internal status (if either is external, result is external)
        existing.internal = existing.internal and incoming.internal

        # Merge threat intels (avoid duplicates by key)
        existing_ti_keys = {ti.key for ti in existing.threat_intels}
        for ti in incoming.threat_intels:
            if ti.key not in existing_ti_keys:
                existing.add_threat_intel(ti)

        # Merge relationships (defer if target not yet available)
        deferred_relationships = []
        for rel in incoming.relationships:
            if rel.target_key in self._observables:
                # Target exists - add relationship immediately
                existing._add_relationship_internal(rel.target_key, rel.relationship_type, rel.direction)
            else:
                # Target doesn't exist yet - defer for Pass 2 of merge_investigation()
                deferred_relationships.append((existing.key, rel))

        # Merge generated_by_checks
        for check_key in incoming._generated_by_checks:
            if check_key not in existing._generated_by_checks:
                existing.mark_generated_by_check(check_key)

        return existing, deferred_relationships

    def _merge_check(self, existing: Check, incoming: Check) -> Check:
        """
        Merge an incoming check into an existing check.

        Strategy:
        - Update score (take maximum)
        - Update level (take maximum)
        - Update extra (merge dicts)
        - Replace comment with incoming
        - Merge observables (key-based deduplication)

        Args:
            existing: The existing check
            incoming: The incoming check to merge

        Returns:
            The merged check (existing is modified in place)
        """
        # Take the higher score
        if incoming.score > existing.score:
            existing.update_score(incoming.score, reason=f"Merged from {incoming.key}")

        # Take the higher level
        if incoming.level > existing.level:
            existing.set_level(incoming.level)

        # Preserve the stricter score policy (MANUAL wins)
        if incoming.score_policy == CheckScorePolicy.MANUAL or existing.score_policy == CheckScorePolicy.MANUAL:
            if existing.score_policy != CheckScorePolicy.MANUAL:
                existing.set_score_policy(CheckScorePolicy.MANUAL)

        # Update extra (merge dictionaries)
        existing.extra.update(incoming.extra)

        # Concatenate comments
        if incoming.comment:
            if existing.comment:
                existing.comment += "\n\n" + incoming.comment
            else:
                existing.comment = incoming.comment

        # Merge observables (use key-based deduplication, not identity)
        existing_obs_keys = {obs.key for obs in existing.observables}
        for obs in incoming.observables:
            if obs.key not in existing_obs_keys:
                target_obs = self._observables.get(obs.key)
                if target_obs is None:
                    target_obs, _ = self.add_observable(obs)
                existing.add_observable(target_obs)
                existing_obs_keys.add(target_obs.key)

        # Ensure final observable references are canonical
        self._reattach_check_observables(existing)

        return existing

    def _reattach_check_observables(self, check: Check) -> None:
        """
        Rebind a check's observables to the canonical investigation objects.

        When merging investigations, check.observables may reference Observable instances
        that belong to the temporary task investigation, which breaks identity-based
        score propagation. This helper replaces them with the instances stored in this
        investigation and refreshes generated-by metadata.
        """
        if not check.observables:
            return

        canonical: list[Observable] = []
        for obs in check.observables:
            target = self._observables.get(obs.key)
            if target is None:
                target, _ = self.add_observable(obs)
            if target not in canonical:
                canonical.append(target)

        check.observables = []
        for obs in canonical:
            check.add_observable(obs)
            obs.mark_generated_by_check(check.key)

    def _merge_threat_intel(self, existing: ThreatIntel, incoming: ThreatIntel) -> ThreatIntel:
        """
        Merge an incoming threat intel into an existing threat intel.

        Strategy:
        - Update score (take maximum)
        - Update level (take maximum)
        - Update extra (merge dicts)
        - Concatenate comments
        - Merge taxonomies

        Args:
            existing: The existing threat intel
            incoming: The incoming threat intel to merge

        Returns:
            The merged threat intel (existing is modified in place)
        """
        # Take the higher score
        if incoming.score > existing.score:
            existing.score = incoming.score
            # Recalculate level from new score (SAFE remains sticky against downgrades)
            existing.level = recalculate_level_for_score(existing.level, existing.score)

        # Take the higher level
        if incoming.level > existing.level:
            existing.set_level(incoming.level)

        # Update extra (merge dictionaries)
        existing.extra.update(incoming.extra)

        # Concatenate comments
        if incoming.comment:
            if existing.comment:
                existing.comment += "\n\n" + incoming.comment
            else:
                existing.comment = incoming.comment

        # Merge taxonomies (avoid duplicates)
        for taxonomy in incoming.taxonomies:
            if taxonomy not in existing.taxonomies:
                existing.taxonomies.append(taxonomy)

        return existing

    def _merge_enrichment(self, existing: Enrichment, incoming: Enrichment) -> Enrichment:
        """
        Merge an incoming enrichment into an existing enrichment.

        Strategy:
        - Deep merge data structure (merge dictionaries recursively)

        Args:
            existing: The existing enrichment
            incoming: The incoming enrichment to merge

        Returns:
            The merged enrichment (existing is modified in place)
        """

        def deep_merge(base: dict, update: dict) -> dict:
            """Recursively merge dictionaries."""
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    deep_merge(base[key], value)
                else:
                    base[key] = value
            return base

        # Deep merge data structures
        if isinstance(existing.data, dict) and isinstance(incoming.data, dict):
            deep_merge(existing.data, incoming.data)
        else:
            existing.data = incoming.data.copy() if hasattr(incoming.data, "copy") else incoming.data

        # Update context if incoming has one
        if incoming.context:
            existing.context = incoming.context

        return existing

    def _merge_container(self, existing: Container, incoming: Container) -> Container:
        """
        Merge an incoming container into an existing container.

        Strategy:
        - Merge checks (dict-based lookup for efficiency)
        - Merge sub-containers recursively

        Args:
            existing: The existing container
            incoming: The incoming container to merge

        Returns:
            The merged container (existing is modified in place)
        """
        # Update description if incoming has one
        if incoming.description:
            existing.description = incoming.description

        # Merge checks using dict-based lookup (more efficient)
        existing_checks_dict = {check.key: check for check in existing.checks}

        for incoming_check in incoming.checks:
            if incoming_check.key in existing_checks_dict:
                # Merge existing check
                self._merge_check(existing_checks_dict[incoming_check.key], incoming_check)
            else:
                # Add new check
                existing.add_check(incoming_check)

        # Merge sub-containers recursively
        for sub_key, incoming_sub in incoming.sub_containers.items():
            if sub_key in existing.sub_containers:
                # Merge existing sub-container
                self._merge_container(existing.sub_containers[sub_key], incoming_sub)
            else:
                # Add new sub-container
                existing.add_sub_container(incoming_sub)

        return existing

    # Public add methods with merge-on-create

    def add_observable(self, obs: Observable) -> tuple[Observable, list]:
        """
        Add or merge an observable.

        Args:
            obs: Observable to add or merge

        Returns:
            Tuple of (resulting observable, deferred relationships)
        """
        if obs.key in self._observables:
            r = self._merge_observable(self._observables[obs.key], obs)
            self._score_engine.recalculate_all()
            return r

        # Register new observable
        self._observables[obs.key] = obs
        self._score_engine.register_observable(obs)
        self._stats.register_observable(obs)
        return obs, []

    def add_check(self, check: Check) -> Check:
        """
        Add or merge a check.

        Args:
            check: Check to add or merge

        Returns:
            The resulting check (either new or merged)
        """
        if check.key in self._checks:
            r = self._merge_check(self._checks[check.key], check)
            self._score_engine.recalculate_all()
            return r

        # Ensure observables linked to the check reference canonical instances
        self._reattach_check_observables(check)

        # Register new check
        self._checks[check.key] = check
        self._score_engine.register_check(check)
        self._stats.register_check(check)
        return check

    def add_threat_intel(self, ti: ThreatIntel, observable: Observable) -> ThreatIntel:
        """
        Add or merge threat intel and link to observable.

        Args:
            ti: Threat intel to add or merge
            observable: Observable to link to

        Returns:
            The resulting threat intel (either new or merged)
        """
        if ti.key in self._threat_intels:
            merged_ti = self._merge_threat_intel(self._threat_intels[ti.key], ti)
            # Propagate score to observable
            self._score_engine.propagate_threat_intel_to_observable(merged_ti, observable)
            return merged_ti

        # Register new threat intel
        self._threat_intels[ti.key] = ti
        self._stats.register_threat_intel(ti)

        # Add to observable
        observable.add_threat_intel(ti)

        # Propagate score
        self._score_engine.propagate_threat_intel_to_observable(ti, observable)

        return ti

    def add_enrichment(self, enrichment: Enrichment) -> Enrichment:
        """
        Add or merge enrichment.

        Args:
            enrichment: Enrichment to add or merge

        Returns:
            The resulting enrichment (either new or merged)
        """
        if enrichment.key in self._enrichments:
            return self._merge_enrichment(self._enrichments[enrichment.key], enrichment)

        # Register new enrichment
        self._enrichments[enrichment.key] = enrichment
        return enrichment

    def add_container(self, container: Container) -> Container:
        """
        Add or merge container.

        Args:
            container: Container to add or merge

        Returns:
            The resulting container (either new or merged)
        """
        if container.key in self._containers:
            r = self._merge_container(self._containers[container.key], container)
            self._score_engine.recalculate_all()
            return r

        # Register new container
        self._containers[container.key] = container
        self._stats.register_container(container)
        return container

    # Relationship and linking methods

    def add_relationship(
        self,
        source: Observable | str,
        target: Observable | str,
        relationship_type: str,
        direction: str | None = None,
    ) -> Observable | None:
        """
        Add a relationship between observables.

        Args:
            source: Source observable or its key
            target: Target observable or its key
            relationship_type: Type of relationship
            direction: Direction of the relationship (None = use semantic default)

        Returns:
            The source observable if both source and target exist, None otherwise
        """

        # Extract keys from Observable objects if needed
        source_key = source.key if isinstance(source, Observable) else source
        target_key = target.key if isinstance(target, Observable) else target

        # Check if target is a copy from shared context (anti-pattern)
        if isinstance(target, Observable) and getattr(target, "_from_shared_context", False):
            obs_type_name = (
                target.obs_type.name
                if hasattr(target.obs_type, "name")
                else str(target.obs_type).upper().replace("-", "_")
            )
            raise ValueError(
                f"Cannot use observable from shared_context.get_observable() directly in relationships.\n"
                f"Observable '{target_key}' is a read-only copy not registered in this investigation.\n\n"
                f"Incorrect pattern:\n"
                f"  source.relate_to(shared_context.get_observable(...), RelationshipType.{relationship_type})\n\n"
                f"Correct pattern (and use reconcile or merge):\n"
                f"  # Use cy.observable() to create/get observable in local investigation\n"
                f"  source.relate_to(\n"
                f"      cy.observable(ObservableType.{obs_type_name}, '{target.value}'),\n"
                f"      RelationshipType.{relationship_type}\n"
                f"  )"
            )

        # Validate both source and target exist
        source_obs = self._observables.get(source_key)
        target_obs = self._observables.get(target_key)

        if not source_obs:
            logger.critical(f"Cannot add relationship: source observable '{source_key}' does not exist")
            return None

        if not target_obs:
            logger.critical(
                f"Cannot add relationship: target observable '{target_key}' does not exist. "
                f"Relationship from '{source_key}' to '{target_key}' was not created."
            )
            return None

        # Add relationship using internal method
        source_obs._add_relationship_internal(target_key, relationship_type, direction)

        # Recalculate scores after adding relationship
        self._score_engine.recalculate_all()

        return source_obs

    def link_check_observable(self, check_key: str, observable_key: str) -> Check | None:
        """
        Link an observable to a check.

        Args:
            check_key: Key of the check
            observable_key: Key of the observable

        Returns:
            The check if found, None otherwise
        """
        check = self._checks.get(check_key)
        observable = self._observables.get(observable_key)

        if check and observable:
            check.add_observable(observable)
            observable.mark_generated_by_check(check_key)
            self._score_engine._propagate_observable_to_checks(observable)

        return check

    def add_check_to_container(self, container_key: str, check_key: str) -> Container | None:
        """
        Add a check to a container.

        Args:
            container_key: Key of the container
            check_key: Key of the check

        Returns:
            The container if found, None otherwise
        """
        container = self._containers.get(container_key)
        check = self._checks.get(check_key)

        if container and check:
            container.add_check(check)

        return container

    def add_sub_container(self, parent_key: str, child_key: str) -> Container | None:
        """
        Add a sub-container to a container.

        Args:
            parent_key: Key of the parent container
            child_key: Key of the child container

        Returns:
            The parent container if found, None otherwise
        """
        parent = self._containers.get(parent_key)
        child = self._containers.get(child_key)

        if parent and child:
            parent.add_sub_container(child)

        return parent

    # Query methods

    @overload
    def get_observable(self, key: str) -> Observable | None:
        """Get observable by full key string."""
        ...

    @overload
    def get_observable(self, obs_type: str | ObservableType, value: str) -> Observable | None:
        """Get observable by type and value."""
        ...

    def get_observable(self, *args, **kwargs) -> Observable | None:
        """
        Get an observable by key or by type and value.

        Args:
            key: Observable key (single argument)
            obs_type: Observable type (when using two arguments)
            value: Observable value (when using two arguments)

        Returns:
            Observable if found, None otherwise

        Raises:
            ValueError: If arguments are invalid or key generation fails

        Examples:
            >>> obs = investigation.get_observable("obs:email-addr:user@domain.com")
            >>> obs = investigation.get_observable(ObservableType.EMAIL_ADDR, "user@domain.com")
        """
        if len(args) == 1 and not kwargs:
            key = args[0]
        elif len(args) == 2 and not kwargs:
            obs_type, value = args
            if isinstance(obs_type, ObservableType):
                obs_type = obs_type.value
            try:
                key = keys.generate_observable_key(obs_type, value)
            except Exception as e:
                raise ValueError(
                    f"Failed to generate observable key for type='{obs_type}', value='{value}': {e}"
                ) from e
        else:
            raise ValueError(
                "get_observable() accepts either (key: str) or (obs_type: str | ObservableType, value: str)"
            )
        return self._observables.get(key)

    @overload
    def get_check(self, key: str) -> Check | None:
        """Get check by full key string."""
        ...

    @overload
    def get_check(self, check_id: str, scope: str) -> Check | None:
        """Get check by ID and scope."""
        ...

    def get_check(self, *args, **kwargs) -> Check | None:
        """
        Get a check by key or by check ID and scope.

        Args:
            key: Check key (single argument)
            check_id: Check identifier (when using two arguments)
            scope: Check scope (when using two arguments)

        Returns:
            Check if found, None otherwise

        Raises:
            ValueError: If arguments are invalid or key generation fails

        Examples:
            >>> check = investigation.get_check("chk:from:header")
            >>> check = investigation.get_check("from", "header")
        """
        if len(args) == 1 and not kwargs:
            key = args[0]
        elif len(args) == 2 and not kwargs:
            check_id, scope = args
            try:
                key = keys.generate_check_key(check_id, scope)
            except Exception as e:
                raise ValueError(f"Failed to generate check key for check_id='{check_id}', scope='{scope}': {e}") from e
        else:
            raise ValueError("get_check() accepts either (key: str) or (check_id: str, scope: str)")
        return self._checks.get(key)

    def get_container(self, key: str) -> Container | None:
        """Get a container by key."""
        return self._containers.get(key)

    def get_enrichment(self, key: str) -> Enrichment | None:
        """Get an enrichment by key."""
        return self._enrichments.get(key)

    def get_threat_intel(self, key: str) -> ThreatIntel | None:
        """Get a threat intel by key."""
        return self._threat_intels.get(key)

    def get_root(self) -> Observable:
        """Get the root observable."""
        return self._root_observable

    def update_model_metadata(
        self,
        model_type: Literal["observable", "check", "threat_intel", "enrichment", "container"],
        key: str,
        updates: dict[str, Any],
        *,
        dict_merge: dict[str, bool] | None = None,
    ):
        """
        Update mutable metadata fields for a stored model instance.

        Args:
            model_type: Model family to update.
            key: Key of the target object.
            updates: Mapping of field names to new values. ``None`` values are ignored.
            dict_merge: Optional overrides for dict fields (True=merge, False=replace).

        Returns:
            The updated model instance.

        Raises:
            KeyError: If the key cannot be found.
            ValueError: If an unsupported field is requested.
            TypeError: If a dict field receives a non-dict value.
        """
        store_lookup: dict[str, dict[str, Any]] = {
            "observable": self._observables,
            "check": self._checks,
            "threat_intel": self._threat_intels,
            "enrichment": self._enrichments,
            "container": self._containers,
        }
        store = store_lookup[model_type]
        target = store.get(key)
        if target is None:
            raise KeyError(f"{model_type} '{key}' not found in investigation.")

        if not updates:
            return target

        rules = self._MODEL_METADATA_RULES[model_type]
        allowed_fields = rules["fields"]
        dict_fields = rules["dict_fields"]

        for field, value in updates.items():
            if field not in allowed_fields:
                raise ValueError(f"Field '{field}' is not mutable on {model_type}.")
            if value is None:
                continue
            if field == "level":
                value = normalize_level(value)
            if field == "score_policy":
                value = CheckScorePolicy(value)
            if field in dict_fields:
                if not isinstance(value, dict):
                    raise TypeError(f"Field '{field}' on {model_type} expects a dict value.")
                merge = dict_merge.get(field, True) if dict_merge else True
                if merge:
                    current_value = getattr(target, field, None)
                    if current_value is None:
                        setattr(target, field, deepcopy(value))
                    else:
                        current_value.update(value)
                else:
                    setattr(target, field, deepcopy(value))
            else:
                setattr(target, field, value)

        return target

    def get_all_observables(self) -> dict[str, Observable]:
        """Get all observables."""
        return self._observables.copy()

    def get_all_checks(self) -> dict[str, Check]:
        """Get all checks."""
        return self._checks.copy()

    def get_all_threat_intels(self) -> dict[str, ThreatIntel]:
        """Get all threat intels."""
        return self._threat_intels.copy()

    def get_all_enrichments(self) -> dict[str, Enrichment]:
        """Get all enrichments."""
        return self._enrichments.copy()

    def get_all_containers(self) -> dict[str, Container]:
        """Get all containers."""
        return self._containers.copy()

    # Scoring and statistics

    def get_global_score(self) -> Decimal:
        """Get the global investigation score."""
        return self._score_engine.get_global_score()

    def get_global_level(self) -> Level:
        """Get the global investigation level."""
        return self._score_engine.get_global_level()

    def is_whitelisted(self) -> bool:
        """Return whether the investigation has any whitelist entries."""
        return bool(self._whitelists)

    def add_whitelist(self, identifier: str, name: str, justification: str | None = None) -> InvestigationWhitelist:
        """
        Add or update a whitelist entry.

        Args:
            identifier: Unique identifier for this whitelist entry.
            name: Human-readable name for the whitelist entry.
            justification: Optional markdown justification.

        Returns:
            The stored whitelist entry.
        """
        identifier = str(identifier).strip()
        name = str(name).strip()
        if not identifier:
            raise ValueError("Whitelist identifier must be provided.")
        if not name:
            raise ValueError("Whitelist name must be provided.")
        if justification is not None:
            justification = str(justification)

        entry = InvestigationWhitelist(identifier=identifier, name=name, justification=justification)
        self._whitelists[identifier] = entry
        return entry

    def remove_whitelist(self, identifier: str) -> bool:
        """
        Remove a whitelist entry by identifier.

        Returns:
            True if removed, False if it did not exist.
        """
        return self._whitelists.pop(identifier, None) is not None

    def clear_whitelists(self) -> None:
        """Remove all whitelist entries."""
        self._whitelists.clear()

    def get_whitelists(self) -> list[InvestigationWhitelist]:
        """Return a copy of all whitelist entries."""
        return [w.model_copy(deep=True) for w in self._whitelists.values()]

    def get_statistics(self) -> StatisticsSchema:
        """Get comprehensive investigation statistics."""
        return self._stats.get_summary()

    def finalize_relationships(self) -> None:
        """
        Finalize observable relationships by linking orphans to root.

        Detects orphan sub-graphs (connected components not linked to root) and links
        the most appropriate starting node of each sub-graph to root.
        """
        from cyvest.model import RelationshipType

        root_key = self._root_observable.key

        # Build adjacency lists for graph traversal
        graph = {key: set() for key in self._observables.keys()}
        incoming = {key: set() for key in self._observables.keys()}

        for obs_key, obs in self._observables.items():
            for rel in obs.relationships:
                if rel.target_key in self._observables:
                    graph[obs_key].add(rel.target_key)
                    incoming[rel.target_key].add(obs_key)

        # Find all connected components using BFS
        visited = set()
        components = []

        def bfs(start_key: str) -> set[str]:
            """Breadth-first search to find connected component."""
            component = set()
            queue = [start_key]
            component.add(start_key)

            while queue:
                current = queue.pop(0)
                # Check both outgoing and incoming edges for connectivity
                neighbors = graph[current] | incoming[current]
                for neighbor in neighbors:
                    if neighbor not in component:
                        component.add(neighbor)
                        queue.append(neighbor)

            return component

        # Find all connected components
        for obs_key in self._observables.keys():
            if obs_key not in visited:
                component = bfs(obs_key)
                visited.update(component)
                components.append(component)

        # Process each component that doesn't include root
        for component in components:
            if root_key in component:
                continue  # This component is already connected to root

            # Find the best starting node in this orphan sub-graph
            # Prioritize nodes with:
            # 1. No incoming edges (true source nodes)
            # 2. Most outgoing edges (central nodes)
            best_node = None
            best_score = (-1, -1)  # (negative incoming count, outgoing count)

            for node_key in component:
                incoming_count = len(incoming[node_key] & component)
                outgoing_count = len(graph[node_key] & component)
                score = (-incoming_count, outgoing_count)

                if score > best_score:
                    best_score = score
                    best_node = node_key

            # Link the best starting node to root
            if best_node:
                self._root_observable._add_relationship_internal(best_node, RelationshipType.RELATED_TO)
        self._score_engine.recalculate_all()

    # Investigation merging

    def merge_investigation(self, other: Investigation) -> None:
        """
        Merge another investigation into this one.

        Uses a two-pass approach to handle relationship dependencies:
        - Pass 1: Merge all observables, collecting deferred relationships
        - Pass 2: Add deferred relationships now that all observables exist

        Args:
            other: The investigation to merge
        """
        # PASS 1: Merge observables and collect deferred relationships
        all_deferred_relationships = []
        for obs in other._observables.values():
            _, deferred = self.add_observable(obs)
            all_deferred_relationships.extend(deferred)

        # PASS 2: Process deferred relationships now that all observables exist
        for source_key, rel in all_deferred_relationships:
            source_obs = self._observables.get(source_key)
            if source_obs and rel.target_key in self._observables:
                # Both source and target exist - add relationship
                source_obs._add_relationship_internal(rel.target_key, rel.relationship_type, rel.direction)
            else:
                # Genuine error - target still doesn't exist after Pass 2
                logger.critical(
                    "Relationship target '{}' not found after merge completion for observable '{}'. "
                    "This indicates corrupted data or a bug in the merge logic.",
                    rel.target_key,
                    source_key,
                )

        # Merge threat intels (need to link to observables)
        for ti in other._threat_intels.values():
            # Find the observable this TI belongs to
            observable = self._observables.get(ti.observable_key)
            if observable:
                self.add_threat_intel(ti, observable)

        # Merge checks
        for check in other._checks.values():
            self.add_check(check)

        # Merge enrichments
        for enrichment in other._enrichments.values():
            self.add_enrichment(enrichment)

        # Merge containers
        for container in other._containers.values():
            self.add_container(container)

        # Merge whitelists (other investigation overrides on identifier conflicts)
        for entry in other.get_whitelists():
            self.add_whitelist(entry.identifier, entry.name, entry.justification)

        # Final score recalculation
        self._score_engine.recalculate_all()
