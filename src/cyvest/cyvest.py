"""
Cyvest facade - high-level API for building cybersecurity investigations.

Provides a simplified interface for creating and managing investigation objects,
handling score propagation, and generating reports.

Includes JSON/Markdown export (io_save_json, io_save_markdown), import (io_load_json),
and dictionary export (io_to_dict, io_to_markdown) methods.
"""

from __future__ import annotations

from collections.abc import Iterable
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal

from logurich import logger

from cyvest.investigation import Investigation, InvestigationWhitelist
from cyvest.io_rich import display_statistics, display_summary
from cyvest.io_serialization import (
    generate_markdown_report,
    load_investigation_json,
    save_investigation_json,
    save_investigation_markdown,
    serialize_investigation,
)
from cyvest.levels import Level
from cyvest.model import Check, CheckScorePolicy, Container, Enrichment, Observable, ThreatIntel
from cyvest.model_schema import InvestigationSchema, StatisticsSchema
from cyvest.proxies import CheckProxy, ContainerProxy, EnrichmentProxy, ObservableProxy, ThreatIntelProxy
from cyvest.score import ScoreMode


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
        score_mode: ScoreMode | Literal["max", "sum"] = ScoreMode.MAX,
    ) -> None:
        """
        Initialize a new investigation.

        Args:
            data: The data being investigated (optional)
            root_type: Type of root observable ("file" or "artifact")
            score_mode: Score calculation mode (MAX or SUM)
        """
        normalized_score_mode = ScoreMode.normalize(score_mode)
        self._investigation = Investigation(data, root_type=root_type, score_mode=normalized_score_mode)

    def __enter__(self) -> Cyvest:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        pass

    @staticmethod
    def io_load_json(filepath: str | Path) -> Cyvest:
        """
        Load an investigation from a JSON file.

        Args:
            filepath: Path to the JSON file (relative or absolute)

        Returns:
            Reconstructed Cyvest investigation

        Raises:
            FileNotFoundError: If the file does not exist
            json.JSONDecodeError: If the file contains invalid JSON
            Exception: For other file-related errors

        Example:
            >>> cv = Cyvest.io_load_json("investigation.json")
            >>> cv = Cyvest.io_load_json("/absolute/path/to/investigation.json")
        """
        return load_investigation_json(filepath)

    # Internal helpers -------------------------------------------------

    def _observable_proxy(self, observable: Observable | None) -> ObservableProxy | None:
        if observable is None:
            return None
        return ObservableProxy(self._investigation, observable.key)

    def _check_proxy(self, check: Check | None) -> CheckProxy | None:
        if check is None:
            return None
        return CheckProxy(self._investigation, check.key)

    def _container_proxy(self, container: Container | None) -> ContainerProxy | None:
        if container is None:
            return None
        return ContainerProxy(self._investigation, container.key)

    def _threat_intel_proxy(self, ti: ThreatIntel | None) -> ThreatIntelProxy | None:
        if ti is None:
            return None
        return ThreatIntelProxy(self._investigation, ti.key)

    def _enrichment_proxy(self, enrichment: Enrichment | None) -> EnrichmentProxy | None:
        if enrichment is None:
            return None
        return EnrichmentProxy(self._investigation, enrichment.key)

    @staticmethod
    def _resolve_key(value: Observable | ObservableProxy | str) -> str:
        if isinstance(value, str):
            return value
        if hasattr(value, "key"):
            return value.key  # type: ignore[return-value]
        raise TypeError("Expected an observable key, ObservableProxy, or Observable instance.")

    # Investigation-level helpers

    def investigation_is_whitelisted(self) -> bool:
        """
        Return whether the investigation is whitelisted/marked safe.

        Examples:
            >>> cv = Cyvest()
            >>> cv.investigation_add_whitelist("id-1", "False positive", "Sandboxed sample")
            >>> cv.investigation_is_whitelisted()
            True
        """
        return self._investigation.is_whitelisted()

    def investigation_add_whitelist(
        self, identifier: str, name: str, justification: str | None = None
    ) -> InvestigationWhitelist:
        """
        Add or update a whitelist entry for the investigation.

        Args:
            identifier: Unique identifier for the whitelist entry.
            name: Human-readable name.
            justification: Optional markdown justification.
        """
        return self._investigation.add_whitelist(identifier, name, justification)

    def investigation_remove_whitelist(self, identifier: str) -> bool:
        """
        Remove a whitelist entry by identifier.

        Returns:
            True if removed, False if the identifier was not present.
        """
        return self._investigation.remove_whitelist(identifier)

    def investigation_clear_whitelists(self) -> None:
        """Remove all whitelist entries."""
        self._investigation.clear_whitelists()

    def investigation_get_whitelists(self) -> tuple[InvestigationWhitelist, ...]:
        """
        Get all whitelist entries.

        Returns:
            Tuple of whitelist entries.
        """
        return tuple(self._investigation.get_whitelists())

    def investigation_set_whitelisted(self, whitelisted: bool = True, reason: str | None = None) -> bool:
        """
        Compatibility helper: clears all whitelists when False; adds/updates a default entry when True.

        Args:
            whitelisted: Whether to mark whitelisted.
            reason: Optional justification used for the default entry.
        """
        if not whitelisted:
            self.investigation_clear_whitelists()
            return False
        self.investigation_add_whitelist("default", "Whitelisted", reason)
        return True

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
        level: Level | str | None = None,
    ) -> ObservableProxy:
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
        obs_kwargs: dict[str, Any] = {
            "obs_type": obs_type,
            "value": value,
            "internal": internal,
            "whitelisted": whitelisted,
            "comment": comment,
            "extra": extra or {},
        }
        if score is not None:
            obs_kwargs["score"] = Decimal(str(score))
        if level is not None:
            obs_kwargs["level"] = level
        obs = Observable(**obs_kwargs)
        # Unwrap tuple - facade returns only Observable, discards deferred relationships
        obs_result, _ = self._investigation.add_observable(obs)
        return self._observable_proxy(obs_result)

    def observable_get(self, key: str) -> ObservableProxy | None:
        """
        Get an observable by key.

        Args:
            key: Observable key

        Returns:
            Observable if found, None otherwise
        """
        return self._observable_proxy(self._investigation.get_observable(key))

    def observable_get_root(self) -> ObservableProxy:
        """
        Get the root observable.

        Returns:
            Root observable
        """
        return self._observable_proxy(self._investigation.get_root())

    def observable_add_relationship(
        self,
        source: Observable | ObservableProxy | str,
        target: Observable | ObservableProxy | str,
        relationship_type: str,
        direction: str | None = None,
    ) -> ObservableProxy | None:
        """
        Add a relationship between observables.

        Args:
            source: Source observable or its key
            target: Target observable or its key
            relationship_type: Type of relationship
            direction: Direction of the relationship (None = use semantic default for relationship type)

        Returns:
            The source observable if both source and target exist, None otherwise
        """
        source_key = self._resolve_key(source)
        target_key = self._resolve_key(target)
        result = self._investigation.add_relationship(source_key, target_key, relationship_type, direction)
        return self._observable_proxy(result)

    def observable_add_threat_intel(
        self,
        observable_key: str,
        source: str,
        score: Decimal | float,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        level: Level | str | None = None,
        taxonomies: list[dict[str, Any]] | None = None,
    ) -> ThreatIntelProxy | None:
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

        ti_kwargs: dict[str, Any] = {
            "source": source,
            "observable_key": observable_key,
            "comment": comment,
            "extra": extra or {},
            "score": Decimal(str(score)),
            "taxonomies": taxonomies or [],
        }
        if level is not None:
            ti_kwargs["level"] = level
        ti = ThreatIntel(**ti_kwargs)
        result = self._investigation.add_threat_intel(ti, observable)
        return self._threat_intel_proxy(result)

    def observable_set_level(self, observable_key: str, level: Level | str) -> ObservableProxy | None:
        """
        Explicitly set an observable's level via the service layer.

        Args:
            observable_key: Key of the observable to update
            level: Level to apply

        Returns:
            Updated observable proxy if found, None otherwise
        """
        observable = self._investigation.get_observable(observable_key)
        if not observable:
            return None
        observable.set_level(level)
        return self._observable_proxy(observable)

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
        level: Level | str | None = None,
        score_policy: CheckScorePolicy | Literal["auto", "manual"] | None = None,
    ) -> CheckProxy:
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
            score_policy: Whether observables can update the check (AUTO|MANUAL)

        Returns:
            The created check
        """
        check_kwargs: dict[str, Any] = {
            "check_id": check_id,
            "scope": scope,
            "description": description,
            "comment": comment,
            "extra": extra or {},
        }
        if score is not None:
            check_kwargs["score"] = Decimal(str(score))
        if level is not None:
            check_kwargs["level"] = level
        if score_policy is not None:
            check_kwargs["score_policy"] = score_policy
        check = Check(**check_kwargs)
        return self._check_proxy(self._investigation.add_check(check))

    def check_get(self, key: str) -> CheckProxy | None:
        """
        Get a check by key.

        Args:
            key: Check key

        Returns:
            Check if found, None otherwise
        """
        return self._check_proxy(self._investigation.get_check(key))

    def check_link_observable(self, check_key: str, observable_key: str) -> CheckProxy | None:
        """
        Link an observable to a check.

        Args:
            check_key: Key of the check
            observable_key: Key of the observable

        Returns:
            The check if found, None otherwise
        """
        return self._check_proxy(self._investigation.link_check_observable(check_key, observable_key))

    def check_update_score(self, check_key: str, score: Decimal | float, reason: str = "") -> CheckProxy | None:
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
        return self._check_proxy(check)

    # Container methods

    def container_create(self, path: str, description: str = "") -> ContainerProxy:
        """
        Create a new container.

        Args:
            path: Container path
            description: Container description

        Returns:
            The created container
        """
        container = Container(path=path, description=description)
        return self._container_proxy(self._investigation.add_container(container))

    def container_get(self, key: str) -> ContainerProxy | None:
        """
        Get a container by key.

        Args:
            key: Container key

        Returns:
            Container if found, None otherwise
        """
        return self._container_proxy(self._investigation.get_container(key))

    def container_add_check(self, container_key: str, check_key: str) -> ContainerProxy | None:
        """
        Add a check to a container.

        Args:
            container_key: Key of the container
            check_key: Key of the check

        Returns:
            The container if found, None otherwise
        """
        return self._container_proxy(self._investigation.add_check_to_container(container_key, check_key))

    def container_add_sub_container(self, parent_key: str, child_key: str) -> ContainerProxy | None:
        """
        Add a sub-container to a container.

        Args:
            parent_key: Key of the parent container
            child_key: Key of the child container

        Returns:
            The parent container if found, None otherwise
        """
        return self._container_proxy(self._investigation.add_sub_container(parent_key, child_key))

    # Enrichment methods

    def enrichment_create(self, name: str, data: dict[str, Any], context: str = "") -> EnrichmentProxy:
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
        return self._enrichment_proxy(self._investigation.add_enrichment(enrichment))

    def enrichment_get(self, key: str) -> EnrichmentProxy | None:
        """
        Get an enrichment by key.

        Args:
            key: Enrichment key

        Returns:
            Enrichment if found, None otherwise
        """
        return self._enrichment_proxy(self._investigation.get_enrichment(key))

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

    def get_statistics(self) -> StatisticsSchema:
        """
        Get comprehensive investigation statistics.

        Returns:
            Statistics schema with typed fields
        """
        return self._investigation.get_statistics()

    # Serialization and I/O methods

    def io_save_json(self, filepath: str | Path) -> str:
        """
        Save the investigation to a JSON file.

        Relative paths are converted to absolute paths before saving.

        Args:
            filepath: Path to save the JSON file (relative or absolute)

        Returns:
            Absolute path to the saved file as a string

        Raises:
            PermissionError: If the file cannot be written
            OSError: If there are file system issues

        Examples:
            >>> cv = Cyvest()
            >>> path = cv.io_save_json("investigation.json")
            >>> print(path)  # /absolute/path/to/investigation.json
        """
        save_investigation_json(self, filepath)
        return str(Path(filepath).resolve())

    def io_save_markdown(
        self,
        filepath: str | Path,
        include_containers: bool = False,
        include_enrichments: bool = False,
        include_observables: bool = True,
    ) -> str:
        """
        Save the investigation as a Markdown report.

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

        Examples:
            >>> cv = Cyvest()
            >>> path = cv.io_save_markdown("report.md")
            >>> print(path)  # /absolute/path/to/report.md
        """
        save_investigation_markdown(self, filepath, include_containers, include_enrichments, include_observables)
        return str(Path(filepath).resolve())

    def io_to_markdown(
        self,
        include_containers: bool = False,
        include_enrichments: bool = False,
        include_observables: bool = True,
    ) -> str:
        """
        Generate a Markdown report of the investigation.

        Args:
            include_containers: Include containers section in the report (default: False)
            include_enrichments: Include enrichments section in the report (default: False)
            include_observables: Include observables section in the report (default: True)

        Returns:
            Markdown formatted report as a string

        Examples:
            >>> cv = Cyvest()
            >>> markdown = cv.io_to_markdown()
            >>> print(markdown)
            # Cybersecurity Investigation Report
            ...
        """
        return generate_markdown_report(self, include_containers, include_enrichments, include_observables)

    def io_to_dict(self) -> InvestigationSchema:
        """
        Serialize the investigation to an InvestigationSchema.

        Returns:
            InvestigationSchema instance (use .model_dump() for dict)

        Examples:
            >>> cv = Cyvest()
            >>> schema = cv.io_to_dict()
            >>> print(schema.score, schema.level)
            >>> dict_data = schema.model_dump(by_alias=True)
        """
        return serialize_investigation(self)

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

    def get_all_observables(self) -> dict[str, ObservableProxy]:
        """Get read-only proxies for all observables."""
        return {
            key: ObservableProxy(self._investigation, key) for key in self._investigation.get_all_observables().keys()
        }

    def get_all_checks(self) -> dict[str, CheckProxy]:
        """Get read-only proxies for all checks."""
        return {key: CheckProxy(self._investigation, key) for key in self._investigation.get_all_checks().keys()}

    def get_all_threat_intels(self) -> dict[str, ThreatIntelProxy]:
        """Get read-only proxies for all threat intel entries."""
        return {
            key: ThreatIntelProxy(self._investigation, key)
            for key in self._investigation.get_all_threat_intels().keys()
        }

    def get_all_enrichments(self) -> dict[str, EnrichmentProxy]:
        """Get read-only proxies for all enrichments."""
        return {
            key: EnrichmentProxy(self._investigation, key) for key in self._investigation.get_all_enrichments().keys()
        }

    def get_all_containers(self) -> dict[str, ContainerProxy]:
        """Get read-only proxies for all containers."""
        return {
            key: ContainerProxy(self._investigation, key) for key in self._investigation.get_all_containers().keys()
        }

    def display_summary(
        self,
        show_graph: bool = True,
        exclude_levels: Level | str | Iterable[Level | str] = Level.NONE,
        show_score_history: bool = False,
    ) -> None:
        display_summary(
            self,
            lambda renderables: logger.rich("INFO", renderables),
            show_graph=show_graph,
            exclude_levels=exclude_levels,
            show_score_history=show_score_history,
        )

    def display_statistics(self) -> None:
        display_statistics(self, lambda renderables: logger.rich("INFO", renderables))

    def display_network(
        self,
        output_dir: str | None = None,
        open_browser: bool = True,
        min_level: Level | str | None = None,
        observable_types: list[str] | None = None,
        physics: bool = True,
        group_by_type: bool = False,
        max_label_length: int = 60,
        title: str = "Cyvest Investigation Network",
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
            max_label_length: Maximum length for node labels before truncation (default: 60)
            title: Title displayed in the generated HTML visualization

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
            max_label_length=max_label_length,
            title=title,
        )

    # Fluent helper entrypoints

    def observable(
        self,
        obs_type: str,
        value: str,
        internal: bool = False,
        whitelisted: bool = False,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | str | None = None,
    ) -> ObservableProxy:
        """
        Create (or fetch) an observable with fluent helper methods.

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
            Observable proxy exposing mutation helpers for chaining
        """
        return self.observable_create(obs_type, value, internal, whitelisted, comment, extra, score, level)

    def check(
        self,
        check_id: str,
        scope: str,
        description: str,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | str | None = None,
        score_policy: CheckScorePolicy | Literal["auto", "manual"] | None = None,
    ) -> CheckProxy:
        """
        Create a check with fluent helper methods.

        Args:
            check_id: Check identifier
            scope: Check scope
            description: Check description
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level
            score_policy: Whether observables can update the check (AUTO|MANUAL)

        Returns:
            Check proxy exposing mutation helpers for chaining
        """
        return self.check_create(check_id, scope, description, comment, extra, score, level, score_policy)

    def container(self, path: str, description: str = "") -> ContainerProxy:
        """
        Create a container with fluent helper methods.

        Args:
            path: Container path
            description: Container description

        Returns:
            Container proxy exposing mutation helpers for chaining
        """
        return self.container_create(path, description)

    def root(self) -> ObservableProxy:
        """
        Get the root observable.

        Returns:
            Root observable
        """
        return self.observable_get_root()
