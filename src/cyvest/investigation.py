"""
Investigation core - central state management for cybersecurity investigations.

Handles all object storage, merging, scoring, and statistics in a unified way.
Provides automatic merge-on-create for all object types.
"""

from __future__ import annotations

import threading
from copy import deepcopy
from decimal import Decimal
from typing import TYPE_CHECKING, Any, overload

from logurich import logger

from cyvest import keys
from cyvest.levels import Level, get_level_from_score
from cyvest.model import Check, Container, Enrichment, Observable, ObservableType, ThreatIntel
from cyvest.score import ScoreEngine, ScoreMode
from cyvest.stats import InvestigationStats

if TYPE_CHECKING:
    from cyvest import Cyvest


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
                data = self._main_investigation._root_observable.extra

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

            # Register all observables and checks for cross-task sharing
            for obs in task_investigation.get_all_observables().values():
                # Update registry (latest version wins)
                self._observable_registry[obs.key] = deepcopy(obs)

            for check in task_investigation.get_all_checks().values():
                self._check_registry[check.key] = deepcopy(check)

            # Merge into main investigation
            self._main_investigation.merge_investigation(task_investigation)

            logger.debug(
                f"Reconciliation complete. Registry: {len(self._observable_registry)} observables, "
                f"{len(self._check_registry)} checks"
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
            >>> url_obs.relate_to(malicious_domain, RelationshipType.RESOLVES_TO)  # ERROR!

        CORRECT:
            >>> # Inspect the shared observable's properties
            >>> domain_info = shared_context.get_observable(ObservableType.DOMAIN_NAME, "evil.com")
            >>> if domain_info and domain_info.score > 7:
            >>>     # Create a NEW observable in your local investigation
            >>>     url_obs.relate_to(
            >>>         cy.observable(ObservableType.DOMAIN_NAME, "evil.com"),
            >>>         RelationshipType.RESOLVES_TO
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
                copy = deepcopy(obs)
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
                raise ValueError(
                    f"Failed to generate check key for check_id='{check_id}', scope='{scope}': {e}"
                ) from e
        else:
            raise ValueError(
                "get_check() accepts either (key: str) or (check_id: str, scope: str)"
            )

        with self._lock:
            check = self._check_registry.get(key)
            if check:
                return deepcopy(check)
            return None

    def get_investigation(self) -> Investigation:
        """
        Get the main investigation (thread-safe read-only access).

        Returns:
            The main investigation instance
        """
        with self._lock:
            return self._main_investigation

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
                    matches.append(deepcopy(obs))
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
                    matches.append(deepcopy(obs))
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
                raise ValueError(
                    f"Failed to generate check key for check_id='{check_id}', scope='{scope}': {e}"
                ) from e
        else:
            raise ValueError(
                "has_check() accepts either (key: str) or (check_id: str, scope: str)"
            )

        with self._lock:
            return key in self._check_registry


class Investigation:
    """
    Core investigation state and operations.

    Manages all investigation objects (observables, checks, threat intel, etc.),
    handles automatic merging on creation, score propagation, and statistics tracking.
    """

    def __init__(self, data: Any, root_type: str = "file", score_mode: ScoreMode = ScoreMode.MAX) -> None:
        """
        Initialize a new investigation.

        Args:
            root_type: Type of root observable ("file" or "artifact")
            score_mode: Score calculation mode (MAX or SUM)
        """
        # Object collections
        self._observables: dict[str, Observable] = {}
        self._checks: dict[str, Check] = {}
        self._threat_intels: dict[str, ThreatIntel] = {}
        self._enrichments: dict[str, Enrichment] = {}
        self._containers: dict[str, Container] = {}

        # Internal components
        self._score_engine = ScoreEngine(score_mode=score_mode)
        self._stats = InvestigationStats()

        # Create root observable
        obj_type = ObservableType.FILE
        if root_type == "artifact":
            obj_type = ObservableType.ARTIFACT
        elif root_type != "file":
            raise ValueError(f"root_type {root_type} is not allowed")

        self._root_observable = Observable(
            obs_type=obj_type,
            value="input-data",
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
            existing.extra = dict().update(incoming.extra)

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

        # Recalculate scores after merge
        self._score_engine.recalculate_all()

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
                existing.add_observable(obs)

        # Recalculate scores after merge
        self._score_engine.recalculate_all()

        return existing

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
            # Recalculate level
            if not existing._explicit_level:
                calculated_level = get_level_from_score(existing.score)
                if calculated_level > existing.level:
                    existing.level = calculated_level

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
            return self._merge_observable(self._observables[obs.key], obs)

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
            return self._merge_check(self._checks[check.key], check)

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
            return self._merge_container(self._containers[container.key], container)

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
            relationship_type: Type of relationship (STIX2 convention)
            direction: Direction of the relationship (None = use semantic default)

        Returns:
            The source observable if both source and target exist, None otherwise
        """

        # Extract keys from Observable objects if needed
        source_key = source.key if isinstance(source, Observable) else source
        target_key = target.key if isinstance(target, Observable) else target

        # Check if target is a copy from shared context (anti-pattern)
        if isinstance(target, Observable) and getattr(target, '_from_shared_context', False):
            obs_type_name = (
                target.obs_type.name
                if hasattr(target.obs_type, 'name')
                else str(target.obs_type).upper().replace('-', '_')
            )
            raise ValueError(
                f"Cannot use observable from shared_context.get_observable() directly in relationships.\n"
                f"Observable '{target_key}' is a read-only copy not registered in this investigation.\n\n"
                f"Incorrect pattern:\n"
                f"  source.relate_to(shared_context.get_observable(...), RelationshipType.{relationship_type})\n\n"
                f"Correct pattern:\n"
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
                raise ValueError(
                    f"Failed to generate check key for check_id='{check_id}', scope='{scope}': {e}"
                ) from e
        else:
            raise ValueError(
                "get_check() accepts either (key: str) or (check_id: str, scope: str)"
            )
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

    def get_statistics(self) -> dict[str, Any]:
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

        # Final score recalculation
        self._score_engine.recalculate_all()
