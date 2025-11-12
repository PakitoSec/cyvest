"""
Internal DSL for fluent chaining in Cyvest.

Provides a convenient fluent API for building investigations with method chaining.
"""

from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING, Any

from cyvest.levels import Level

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest
    from cyvest.model import Check, Container, Observable


class ObservableHandler:
    """Fluent interface for observable operations."""

    def __init__(self, cv: Cyvest, observable: Observable) -> None:
        """
        Initialize the observable handler.

        Args:
            cv: The Cyvest instance
            observable: The observable being handled
        """
        self._cv = cv
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
        self._cv.observable_add_threat_intel(
            self._observable.key,
            source=source,
            score=score,
            comment=comment,
            extra=extra,
            level=level,
            taxonomies=taxonomies,
        )
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
        self, target: Observable | ObservableHandler, relationship_type: str, direction: str = "outbound"
    ) -> ObservableHandler:
        """
        Create a relationship to another observable.

        Args:
            target: Target observable or handler
            relationship_type: Type of relationship (STIX2 convention)
            direction: Direction of the relationship (outbound, inbound, or bidirectional)

        Returns:
            Self for chaining
        """
        target_obs = target._observable if isinstance(target, ObservableHandler) else target
        self._cv.observable_add_relationship(self._observable.key, target_obs.key, relationship_type, direction)
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
        self._cv.check_link_observable(check_obj.key, self._observable.key)
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

    def __init__(self, cv: Cyvest, check: Check) -> None:
        """
        Initialize the check handler.

        Args:
            cv: The Cyvest instance
            check: The check being handled
        """
        self._cv = cv
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
        self._cv.container_add_check(container_obj.key, self._check.key)
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
        self._cv.check_link_observable(self._check.key, obs_obj.key)
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
        self._cv.check_update_score(self._check.key, score, reason)
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

    def __init__(self, cv: Cyvest, container: Container) -> None:
        """
        Initialize the container handler.

        Args:
            cv: The Cyvest instance
            container: The container being handled
        """
        self._cv = cv
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
        self._cv.container_add_check(self._container.key, check_obj.key)
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
        # Create sub-container with full path
        full_path = f"{self._container.path}/{path}"
        sub = self._cv.container_create(full_path, description)
        self._cv.container_add_sub_container(self._container.key, sub.key)
        return ContainerHandler(self._cv, sub)

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
