"""
Internal DSL for fluent chaining in Cyvest.

Provides a convenient fluent API for building investigations with method chaining.
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Any

from cyvest.levels import Level

if TYPE_CHECKING:
    from cyvest.investigation import Investigation
    from cyvest.model import Check, Container, Observable


class ObservableHandler:
    """Fluent interface for observable operations."""

    def __init__(self, investigation: Investigation, observable: Observable) -> None:
        """
        Initialize the observable handler.

        Args:
            investigation: The Investigation instance
            observable: The observable being handled
        """
        self._investigation = investigation
        self._observable = observable

    def with_ti(
        self,
        source: str,
        score: Decimal | float = 0,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        level: Level | None = None,
        taxonomies: list[dict[str, Any]] | None = None,
    ) -> ObservableHandler:
        """
        Add threat intelligence to this observable.

        Args:
            source: Threat intel source name
            score: Score from threat intel
            comment: Optional comment
            extra: Optional extra data
            level: Optional explicit level
            taxonomies: Optional taxonomies

        Returns:
            Self for chaining
        """
        from decimal import Decimal

        from cyvest.model import ThreatIntel

        ti = ThreatIntel(
            source=source,
            observable_key=self._observable.key,
            comment=comment,
            extra=extra or {},
            score=Decimal(str(score)),
            level=level or Level.INFO,
            taxonomies=taxonomies or [],
        )
        self._investigation.add_threat_intel(ti, self._observable)
        return self

    def add_ti(
        self,
        source: str,
        score: Decimal | float = 0,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        level: Level | None = None,
        taxonomies: list[dict[str, Any]] | None = None,
    ) -> ObservableHandler:
        """
        Alias for with_ti.

        Args:
            source: Threat intel source name
            score: Score from threat intel
            comment: Optional comment
            extra: Optional extra data
            level: Optional explicit level
            taxonomies: Optional taxonomies

        Returns:
            Self for chaining
        """
        return self.with_ti(source, score, comment, extra, level, taxonomies)

    def relate_to(
        self,
        target: Observable | ObservableHandler | str,
        relationship_type: str,
        direction: str | None = None,
    ) -> ObservableHandler:
        """
        Create a relationship to another observable.

        Args:
            target: Target observable, handler, or observable key
            relationship_type: Type of relationship (STIX2 convention)
            direction: Direction of the relationship (None = use semantic default for relationship type)

        Returns:
            Self for chaining
        """
        # Extract Observable from ObservableHandler if needed
        if isinstance(target, ObservableHandler):
            target = target._observable

        # Pass to Investigation - it handles Observable | str
        self._investigation.add_relationship(self._observable, target, relationship_type, direction)
        return self

    def link_check(self, check: Check | CheckHandler) -> ObservableHandler:
        """
        Link this observable to a check.

        Args:
            check: Check or check handler to link

        Returns:
            Self for chaining
        """
        check_obj = check._check if isinstance(check, CheckHandler) else check
        self._investigation.link_check_observable(check_obj.key, self._observable.key)
        return self

    def get(self) -> Observable:
        """
        Get the underlying observable.

        Returns:
            The observable
        """
        return self._observable


class CheckHandler:
    """Fluent interface for check operations."""

    def __init__(self, investigation: Investigation, check: Check) -> None:
        """
        Initialize the check handler.

        Args:
            investigation: The Investigation instance
            check: The check being handled
        """
        self._investigation = investigation
        self._check = check

    def in_container(self, container: Container | ContainerHandler) -> CheckHandler:
        """
        Add this check to a container.

        Args:
            container: Container or container handler

        Returns:
            Self for chaining
        """
        container_obj = container._container if isinstance(container, ContainerHandler) else container
        self._investigation.add_check_to_container(container_obj.key, self._check.key)
        return self

    def link_observable(self, observable: Observable | ObservableHandler) -> CheckHandler:
        """
        Link an observable to this check.

        Args:
            observable: Observable or observable handler

        Returns:
            Self for chaining
        """
        obs_obj = observable._observable if isinstance(observable, ObservableHandler) else observable
        self._investigation.link_check_observable(self._check.key, obs_obj.key)
        return self

    def with_score(self, score: Decimal | float, reason: str = "") -> CheckHandler:
        """
        Update the check's score.

        Args:
            score: New score
            reason: Reason for update

        Returns:
            Self for chaining
        """
        from decimal import Decimal

        check = self._investigation.get_check(self._check.key)
        if check:
            check.update_score(Decimal(str(score)), reason)
        return self

    def get(self) -> Check:
        """
        Get the underlying check.

        Returns:
            The check
        """
        return self._check


class ContainerHandler:
    """Fluent interface for container operations."""

    def __init__(self, investigation: Investigation, container: Container) -> None:
        """
        Initialize the container handler.

        Args:
            investigation: The Investigation instance
            container: The container being handled
        """
        self._investigation = investigation
        self._container = container

    def add_check(self, check: Check | CheckHandler) -> ContainerHandler:
        """
        Add a check to this container.

        Args:
            check: Check or check handler

        Returns:
            Self for chaining
        """
        check_obj = check._check if isinstance(check, CheckHandler) else check
        self._investigation.add_check_to_container(self._container.key, check_obj.key)
        return self

    def sub_container(self, path: str, description: str = "") -> ContainerHandler:
        """
        Create and add a sub-container.

        Args:
            path: Sub-container path
            description: Sub-container description

        Returns:
            Handler for the sub-container
        """
        from cyvest.model import Container

        # Create sub-container with full path
        full_path = f"{self._container.path}/{path}"
        sub = Container(path=full_path, description=description)
        sub = self._investigation.add_container(sub)
        self._investigation.add_sub_container(self._container.key, sub.key)
        return ContainerHandler(self._investigation, sub)

    def __enter__(self) -> ContainerHandler:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        pass

    def get(self) -> Container:
        """
        Get the underlying container.

        Returns:
            The container
        """
        return self._container
