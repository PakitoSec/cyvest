"""
Cyvest facade - high-level API for building cybersecurity investigations.

Provides a simplified interface for creating and managing investigation objects,
handling score propagation, and generating reports.
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal

from logurich import logger

from cyvest.investigation import Investigation
from cyvest.io_rich import display_statistics, display_summary
from cyvest.levels import Level
from cyvest.model import Check, Container, Enrichment, Observable, ThreatIntel
from cyvest.score import ScoreMode

if TYPE_CHECKING:
    from cyvest.dsl import CheckHandler, ContainerHandler, ObservableHandler


class Cyvest:
    """
    High-level facade for building and managing cybersecurity investigations.

    Provides methods for creating observables, checks, threat intel, enrichments,
    and containers, with automatic score propagation and statistics tracking.
    """

    def __init__(
        self,
        data: Any = None,
        root_type: Literal["file", "artifact"] = "file",
        score_mode: ScoreMode = ScoreMode.MAX,
    ) -> None:
        """
        Initialize a new investigation.

        Args:
            data: The data being investigated (optional)
            root_type: Type of root observable ("file" or "artifact")
            score_mode: Score calculation mode (MAX or SUM)
        """
        self.data = data
        self._investigation = Investigation(data, root_type=root_type, score_mode=score_mode)

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
        internal: bool = False,
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
        return self._investigation.add_observable(obs)

    def observable_get(self, key: str) -> Observable | None:
        """
        Get an observable by key.

        Args:
            key: Observable key

        Returns:
            Observable if found, None otherwise
        """
        return self._investigation.get_observable(key)

    def observable_get_root(self) -> Observable:
        """
        Get the root observable.

        Returns:
            Root observable
        """
        return self._investigation.get_root()

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
        return self._investigation.add_relationship(source_key, target_key, relationship_type, direction)

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
        observable = self._investigation.get_observable(observable_key)
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
        return self._investigation.add_threat_intel(ti, observable)

    def observable_finalize_relationships(self) -> None:
        """
        Finalize observable relationships by linking orphans to root.

        Any observable without parent relationships is automatically linked to root.
        """
        self._investigation.finalize_relationships()

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
        return self._investigation.add_check(check)

    def check_get(self, key: str) -> Check | None:
        """
        Get a check by key.

        Args:
            key: Check key

        Returns:
            Check if found, None otherwise
        """
        return self._investigation.get_check(key)

    def check_link_observable(self, check_key: str, observable_key: str) -> Check | None:
        """
        Link an observable to a check.

        Args:
            check_key: Key of the check
            observable_key: Key of the observable

        Returns:
            The check if found, None otherwise
        """
        return self._investigation.link_check_observable(check_key, observable_key)

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
        check = self._investigation.get_check(check_key)
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
        return self._investigation.add_container(container)

    def container_get(self, key: str) -> Container | None:
        """
        Get a container by key.

        Args:
            key: Container key

        Returns:
            Container if found, None otherwise
        """
        return self._investigation.get_container(key)

    def container_add_check(self, container_key: str, check_key: str) -> Container | None:
        """
        Add a check to a container.

        Args:
            container_key: Key of the container
            check_key: Key of the check

        Returns:
            The container if found, None otherwise
        """
        return self._investigation.add_check_to_container(container_key, check_key)

    def container_add_sub_container(self, parent_key: str, child_key: str) -> Container | None:
        """
        Add a sub-container to a container.

        Args:
            parent_key: Key of the parent container
            child_key: Key of the child container

        Returns:
            The parent container if found, None otherwise
        """
        return self._investigation.add_sub_container(parent_key, child_key)

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
        return self._investigation.add_enrichment(enrichment)

    def enrichment_get(self, key: str) -> Enrichment | None:
        """
        Get an enrichment by key.

        Args:
            key: Enrichment key

        Returns:
            Enrichment if found, None otherwise
        """
        return self._investigation.get_enrichment(key)

    # Score and statistics methods

    def get_global_score(self) -> Decimal:
        """
        Get the global investigation score.

        Returns:
            Global score
        """
        return self._investigation.get_global_score()

    def get_global_level(self) -> Level:
        """
        Get the global investigation level.

        Returns:
            Global level
        """
        return self._investigation.get_global_level()

    def get_statistics(self) -> dict[str, Any]:
        """
        Get comprehensive investigation statistics.

        Returns:
            Statistics dictionary
        """
        return self._investigation.get_statistics()

    # Merge methods

    def merge_investigation(self, other: Cyvest) -> None:
        """
        Merge another investigation into this one.

        Args:
            other: The investigation to merge
        """
        self._investigation.merge_investigation(other._investigation)

    def finalize_relationships(self) -> None:
        """
        Finalize observable relationships by linking orphan sub-graphs to root.

        Any observable or sub-graph not connected to the root will be automatically
        linked by finding the best starting node of each disconnected component.
        """
        self._investigation.finalize_relationships()

    def get_all_observables(self) -> dict[str, Observable]:
        """Get all observables."""
        return self._investigation.get_all_observables()

    def get_all_checks(self) -> dict[str, Check]:
        """Get all checks."""
        return self._investigation.get_all_checks()

    def get_all_threat_intels(self) -> dict[str, ThreatIntel]:
        """Get all threat intels."""
        return self._investigation.get_all_threat_intels()

    def get_all_enrichments(self) -> dict[str, Enrichment]:
        """Get all enrichments."""
        return self._investigation.get_all_enrichments()

    def get_all_containers(self) -> dict[str, Container]:
        """Get all containers."""
        return self._investigation.get_all_containers()

    def display_summary(self, show_graph: bool = True) -> None:
        display_summary(self, lambda renderables: logger.rich("INFO", renderables), show_graph=show_graph)

    def display_statistics(self, show_graph: bool = True) -> None:
        display_statistics(self, lambda renderables: logger.rich("INFO", renderables))

    def display_network(
        self,
        output_dir: str | None = None,
        open_browser: bool = True,
        min_level: Level | None = None,
        observable_types: list[str] | None = None,
        physics: bool = False,
        group_by_type: bool = False,
    ) -> str:
        """
        Generate and display an interactive network graph visualization.

        Creates an HTML file with a pyvis network graph showing observables as nodes
        (colored by level, sized by score, shaped by type) and relationships as edges
        (colored by direction, labeled by type).

        Args:
            output_dir: Directory to save HTML file (defaults to temp directory)
            open_browser: Whether to automatically open the HTML file in a browser
            min_level: Minimum security level to include (filters out lower levels)
            observable_types: List of observable types to include (filters out others)
            physics: Enable physics simulation for organic layout (default: False for static layout)
            group_by_type: Group observables by type using hierarchical layout (default: False)

        Returns:
            Path to the generated HTML file

        Examples:
            >>> with Cyvest() as cv:
            ...     # Create investigation with observables
            ...     cv.display_network()
            '/tmp/cyvest_12345/cyvest_network.html'
        """
        from cyvest.io_visualization import generate_network_graph
        from cyvest.model import ObservableType

        # Convert string types to ObservableType enums if provided
        obs_types_enum = None
        if observable_types is not None:
            obs_types_enum = [ObservableType(t) for t in observable_types]

        return generate_network_graph(
            self,
            output_dir=output_dir,
            open_browser=open_browser,
            min_level=min_level,
            observable_types=obs_types_enum,
            physics=physics,
            group_by_type=group_by_type,
        )

    # DSL methods for fluent interface

    def observable(
        self,
        obs_type: str,
        value: str,
        internal: bool = False,
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
        return ObservableHandler(self._investigation, obs)

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
        return CheckHandler(self._investigation, chk)

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
        return ContainerHandler(self._investigation, ctr)

    def root(self) -> Observable:
        """
        Get the root observable.

        Returns:
            Root observable
        """
        return self.observable_get_root()
