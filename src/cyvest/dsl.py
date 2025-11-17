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
    from cyvest.views import CheckView, ContainerView, ObservableView


class ObservableHandler:
    """Fluent interface for observable operations."""

    def __init__(self, investigation: Investigation, observable_key: str) -> None:
        """
        Initialize the observable handler.

        Args:
            investigation: The Investigation instance
            observable_key: Key of the observable being handled
        """
        self._investigation = investigation
        self._observable_key = observable_key

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

        observable = self._investigation.get_observable(self._observable_key)
        if observable is None:
            raise ValueError(f"Observable '{self._observable_key}' no longer exists.")

        ti = ThreatIntel(
            source=source,
            observable_key=self._observable_key,
            comment=comment,
            extra=extra or {},
            score=Decimal(str(score)),
            level=level or Level.INFO,
            taxonomies=taxonomies or [],
        )
        self._investigation.add_threat_intel(ti, observable)
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
        from cyvest.model import Observable

        if isinstance(target, ObservableHandler):
            resolved_target: Observable | str = target._observable_key
        elif isinstance(target, Observable):
            # Pass Observable instances directly so shared-context guardrails work
            resolved_target = target
        elif hasattr(target, "key"):
            resolved_target = target.key  # ObservableView or CheckView exposing key
        elif isinstance(target, str):
            resolved_target = target
        else:
            raise TypeError("Target must be an observable key, handler, view, or Observable instance.")

        self._investigation.add_relationship(self._observable_key, resolved_target, relationship_type, direction)
        return self

    def link_check(self, check: Check | CheckHandler | CheckView) -> ObservableHandler:
        """
        Link this observable to a check.

        Args:
            check: Check or check handler to link

        Returns:
            Self for chaining
        """
        if isinstance(check, CheckHandler):
            check_key = check._check_key
        elif hasattr(check, "key"):
            check_key = check.key
        else:
            raise TypeError("Check must provide a key attribute.")

        self._investigation.link_check_observable(check_key, self._observable_key)
        return self

    def get(self) -> ObservableView:
        """
        Get the underlying observable.

        Returns:
            The observable
        """
        from cyvest.views import ObservableView

        return ObservableView(self._investigation, self._observable_key)


class CheckHandler:
    """Fluent interface for check operations."""

    def __init__(self, investigation: Investigation, check_key: str) -> None:
        """
        Initialize the check handler.

        Args:
            investigation: The Investigation instance
            check: The check being handled
        """
        self._investigation = investigation
        self._check_key = check_key

    def in_container(self, container: Container | ContainerHandler) -> CheckHandler:
        """
        Add this check to a container.

        Args:
            container: Container or container handler

        Returns:
            Self for chaining
        """
        if isinstance(container, ContainerHandler):
            container_key = container._container_key
        elif hasattr(container, "key"):
            container_key = container.key
        else:
            raise TypeError("Container must provide a key attribute.")
        self._investigation.add_check_to_container(container_key, self._check_key)
        return self

    def link_observable(self, observable: Observable | ObservableHandler | ObservableView) -> CheckHandler:
        """
        Link an observable to this check.

        Args:
            observable: Observable or observable handler

        Returns:
            Self for chaining
        """
        if isinstance(observable, ObservableHandler):
            observable_key = observable._observable_key
        elif hasattr(observable, "key"):
            observable_key = observable.key
        else:
            raise TypeError("Observable must provide a key attribute.")
        self._investigation.link_check_observable(self._check_key, observable_key)
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

        check = self._investigation.get_check(self._check_key)
        if check:
            check.update_score(Decimal(str(score)), reason)
        return self

    def get(self) -> CheckView:
        """
        Get the underlying check.

        Returns:
            The check
        """
        from cyvest.views import CheckView

        return CheckView(self._investigation, self._check_key)


class ContainerHandler:
    """Fluent interface for container operations."""

    def __init__(self, investigation: Investigation, container_key: str) -> None:
        """
        Initialize the container handler.

        Args:
            investigation: The Investigation instance
            container: The container being handled
        """
        self._investigation = investigation
        self._container_key = container_key

    def add_check(self, check: Check | CheckHandler) -> ContainerHandler:
        """
        Add a check to this container.

        Args:
            check: Check or check handler

        Returns:
            Self for chaining
        """
        if isinstance(check, CheckHandler):
            check_key = check._check_key
        elif hasattr(check, "key"):
            check_key = check.key
        else:
            raise TypeError("Check must provide a key attribute.")

        self._investigation.add_check_to_container(self._container_key, check_key)
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
        self._investigation.add_sub_container(self._container_key, sub.key)
        return ContainerHandler(self._investigation, sub.key)

    def __enter__(self) -> ContainerHandler:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        pass

    def get(self) -> ContainerView:
        """
        Get the underlying container.

        Returns:
            The container
        """
        from cyvest.views import ContainerView

        return ContainerView(self._investigation, self._container_key)
