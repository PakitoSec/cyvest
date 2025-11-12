"""
Cyvest facade - high-level API for building cybersecurity investigations.

Provides a simplified interface for creating and managing investigation objects,
handling score propagation, and generating reports.
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal

from cyvest.levels import Level
from cyvest.merge import InvestigationMerger
from cyvest.model import Check, Container, Enrichment, Observable, ThreatIntel
from cyvest.score import ScoreEngine
from cyvest.stats import InvestigationStats

if TYPE_CHECKING:
    from cyvest.dsl import CheckHandler, ContainerHandler, ObservableHandler


class Cyvest:
    """
    High-level facade for building and managing cybersecurity investigations.

    Provides methods for creating observables, checks, threat intel, enrichments,
    and containers, with automatic score propagation and statistics tracking.
    """

    def __init__(self, data: Any = None, root_type: Literal["file", "artifact"] = "file") -> None:
        """
        Initialize a new investigation.

        Args:
            data: The data being investigated (optional)
            root_type: Type of root observable ("file" or "artifact")
        """
        self.data = data
        self._score_engine = ScoreEngine()
        self._stats = InvestigationStats()
        self._merger = InvestigationMerger()

        # Storage
        self._observables: dict[str, Observable] = {}
        self._checks: dict[str, Check] = {}
        self._threat_intels: dict[str, ThreatIntel] = {}
        self._enrichments: dict[str, Enrichment] = {}
        self._containers: dict[str, Container] = {}

        # Create root observable
        self._root_observable = self.observable_create(
            root_type, f"root_{root_type}", internal=False, comment="Root observable for investigation"
        )

    def __enter__(self) -> Cyvest:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        pass

    # Observable methods

    def observable_create(
        self,
        obs_type: str,
        value: str,
        internal: bool = True,
        whitelisted: bool = False,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> Observable:
        """
        Create a new observable or return existing one.

        Args:
            obs_type: Type of observable (ip, url, domain, hash, etc.)
            value: Value of the observable
            internal: Whether this is an internal asset
            whitelisted: Whether this is whitelisted
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level

        Returns:
            The created or existing observable
        """
        obs = Observable(
            obs_type=obs_type,
            value=value,
            internal=internal,
            whitelisted=whitelisted,
            comment=comment,
            extra=extra or {},
            score=Decimal(str(score)) if score is not None else Decimal("0"),
            level=level or Level.INFO,
        )

        # Check if already exists
        if obs.key in self._observables:
            return self._observables[obs.key]

        # Register
        self._observables[obs.key] = obs
        self._score_engine.register_observable(obs)
        self._stats.register_observable(obs)

        # Auto-link to root if no relationships (will be added later if needed)
        # This is handled in observable_finalize

        return obs

    def observable_get(self, key: str) -> Observable | None:
        """
        Get an observable by key.

        Args:
            key: Observable key

        Returns:
            Observable if found, None otherwise
        """
        return self._observables.get(key)

    def observable_get_root(self) -> Observable:
        """
        Get the root observable.

        Returns:
            Root observable
        """
        return self._root_observable

    def observable_add_relationship(
        self, source_key: str, target_key: str, relationship_type: str, direction: str | None = None
    ) -> Observable | None:
        """
        Add a relationship between observables.

        Args:
            source_key: Key of source observable
            target_key: Key of target observable
            relationship_type: Type of relationship (STIX2 convention)
            direction: Direction of the relationship (None = use semantic default for relationship type)

        Returns:
            The source observable if found, None otherwise
        """
        source = self._observables.get(source_key)
        if source:
            source.add_relationship(target_key, relationship_type, direction)
            # Recalculate scores after adding relationship
            self._score_engine.recalculate_all()
        return source

    def observable_add_threat_intel(
        self,
        observable_key: str,
        source: str,
        score: Decimal | float,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        level: Level | None = None,
        taxonomies: list[dict[str, Any]] | None = None,
    ) -> ThreatIntel | None:
        """
        Add threat intelligence to an observable.

        Args:
            observable_key: Key of the observable
            source: Threat intel source name
            score: Score from threat intel
            comment: Optional comment
            extra: Optional extra data
            level: Optional explicit level
            taxonomies: Optional taxonomies

        Returns:
            The created threat intel if observable found, None otherwise
        """
        observable = self._observables.get(observable_key)
        if not observable:
            return None

        ti = ThreatIntel(
            source=source,
            observable_key=observable_key,
            comment=comment,
            extra=extra or {},
            score=Decimal(str(score)),
            level=level or Level.INFO,
            taxonomies=taxonomies or [],
        )

        # Register
        self._threat_intels[ti.key] = ti
        self._stats.register_threat_intel(ti)

        # Add to observable
        observable.add_threat_intel(ti)

        # Propagate score
        self._score_engine.propagate_threat_intel_to_observable(ti, observable)

        return ti

    def observable_finalize_relationships(self) -> None:
        """
        Finalize observable relationships by linking orphans to root.

        Any observable without parent relationships is automatically linked to root.
        """
        root_key = self._root_observable.key

        # Find all observables that are targets of relationships
        targets = set()
        for obs in self._observables.values():
            for rel in obs.relationships:
                targets.add(rel.target_key)

        # Link orphans to root
        for obs in self._observables.values():
            if obs.key == root_key:
                continue

            # Check if this observable is referenced by others
            is_referenced = obs.key in targets

            # If not referenced and has no relationships, link to root
            if not is_referenced and not obs.relationships:
                self._root_observable.add_relationship(obs.key, "related-to")

    # Check methods

    def check_create(
        self,
        check_id: str,
        scope: str,
        description: str,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> Check:
        """
        Create a new check.

        Args:
            check_id: Check identifier
            scope: Check scope
            description: Check description
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level

        Returns:
            The created check
        """
        check = Check(
            check_id=check_id,
            scope=scope,
            description=description,
            comment=comment,
            extra=extra or {},
            score=Decimal(str(score)) if score is not None else Decimal("0"),
            level=level or Level.NONE,
        )

        # Register
        self._checks[check.key] = check
        self._score_engine.register_check(check)
        self._stats.register_check(check)

        return check

    def check_get(self, key: str) -> Check | None:
        """
        Get a check by key.

        Args:
            key: Check key

        Returns:
            Check if found, None otherwise
        """
        return self._checks.get(key)

    def check_link_observable(self, check_key: str, observable_key: str) -> Check | None:
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
            # Propagate if observable is malicious
            if observable.level == Level.MALICIOUS:
                self._score_engine._propagate_observable_to_checks(observable)

        return check

    def check_update_score(self, check_key: str, score: Decimal | float, reason: str = "") -> Check | None:
        """
        Update a check's score.

        Args:
            check_key: Key of the check
            score: New score
            reason: Reason for update

        Returns:
            The check if found, None otherwise
        """
        check = self._checks.get(check_key)
        if check:
            check.update_score(Decimal(str(score)), reason)
        return check

    # Container methods

    def container_create(self, path: str, description: str = "") -> Container:
        """
        Create a new container.

        Args:
            path: Container path
            description: Container description

        Returns:
            The created container
        """
        container = Container(path=path, description=description)

        # Register
        self._containers[container.key] = container
        self._stats.register_container(container)

        return container

    def container_get(self, key: str) -> Container | None:
        """
        Get a container by key.

        Args:
            key: Container key

        Returns:
            Container if found, None otherwise
        """
        return self._containers.get(key)

    def container_add_check(self, container_key: str, check_key: str) -> Container | None:
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

    def container_add_sub_container(self, parent_key: str, child_key: str) -> Container | None:
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

    # Enrichment methods

    def enrichment_create(self, name: str, data: dict[str, Any], context: str = "") -> Enrichment:
        """
        Create a new enrichment.

        Args:
            name: Enrichment name
            data: Enrichment data
            context: Optional context

        Returns:
            The created enrichment
        """
        enrichment = Enrichment(name=name, data=data, context=context)

        # Register
        self._enrichments[enrichment.key] = enrichment

        return enrichment

    def enrichment_get(self, key: str) -> Enrichment | None:
        """
        Get an enrichment by key.

        Args:
            key: Enrichment key

        Returns:
            Enrichment if found, None otherwise
        """
        return self._enrichments.get(key)

    # Score and statistics methods

    def get_global_score(self) -> Decimal:
        """
        Get the global investigation score.

        Returns:
            Global score
        """
        return self._score_engine.get_global_score()

    def get_global_level(self) -> Level:
        """
        Get the global investigation level.

        Returns:
            Global level
        """
        return self._score_engine.get_global_level()

    def get_statistics(self) -> dict[str, Any]:
        """
        Get comprehensive investigation statistics.

        Returns:
            Statistics dictionary
        """
        return self._stats.get_summary()

    # Merge methods

    def merge_investigation(self, other: Cyvest) -> None:
        """
        Merge another investigation into this one.

        Args:
            other: The investigation to merge
        """
        # Merge observables
        for obs in other._observables.values():
            merged_obs = self._merger.add_observable(obs)
            self._observables[merged_obs.key] = merged_obs
            self._score_engine.register_observable(merged_obs)
            self._stats.register_observable(merged_obs)

        # Merge threat intels
        for ti in other._threat_intels.values():
            merged_ti = self._merger.add_threat_intel(ti)
            self._threat_intels[merged_ti.key] = merged_ti
            self._stats.register_threat_intel(merged_ti)

        # Merge checks
        for check in other._checks.values():
            merged_check = self._merger.add_check(check)
            self._checks[merged_check.key] = merged_check
            self._score_engine.register_check(merged_check)
            self._stats.register_check(merged_check)

        # Merge enrichments
        for enrichment in other._enrichments.values():
            merged_enrichment = self._merger.add_enrichment(enrichment)
            self._enrichments[merged_enrichment.key] = merged_enrichment

        # Merge containers
        for container in other._containers.values():
            merged_container = self._merger.add_container(container)
            self._containers[merged_container.key] = merged_container
            self._stats.register_container(merged_container)

        # Recalculate all scores
        self._score_engine.recalculate_all()

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

    # DSL methods for fluent interface

    def observable(
        self,
        obs_type: str,
        value: str,
        internal: bool = True,
        whitelisted: bool = False,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> ObservableHandler:
        """
        Create an observable with fluent interface.

        Args:
            obs_type: Type of observable
            value: Value of the observable
            internal: Whether this is an internal asset
            whitelisted: Whether this is whitelisted
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level

        Returns:
            Observable handler for chaining
        """
        from cyvest.dsl import ObservableHandler

        obs = self.observable_create(obs_type, value, internal, whitelisted, comment, extra, score, level)
        return ObservableHandler(self, obs)

    def check(
        self,
        check_id: str,
        scope: str,
        description: str,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> CheckHandler:
        """
        Create a check with fluent interface.

        Args:
            check_id: Check identifier
            scope: Check scope
            description: Check description
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level

        Returns:
            Check handler for chaining
        """
        from cyvest.dsl import CheckHandler

        chk = self.check_create(check_id, scope, description, comment, extra, score, level)
        return CheckHandler(self, chk)

    def container(self, path: str, description: str = "") -> ContainerHandler:
        """
        Create a container with fluent interface.

        Args:
            path: Container path
            description: Container description

        Returns:
            Container handler for chaining
        """
        from cyvest.dsl import ContainerHandler

        ctr = self.container_create(path, description)
        return ContainerHandler(self, ctr)

    def root(self) -> Observable:
        """
        Get the root observable.

        Returns:
            Root observable
        """
        return self.observable_get_root()
