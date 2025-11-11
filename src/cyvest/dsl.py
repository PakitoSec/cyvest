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

    def relate_to(self, target: Observable | ObservableHandler, relationship_type: str) -> ObservableHandler:
        """
        Create a relationship to another observable.

        Args:
            target: Target observable or handler
            relationship_type: Type of relationship (STIX2 convention)

        Returns:
            Self for chaining
        """
        target_obs = target._observable if isinstance(target, ObservableHandler) else target
        self._cv.observable_add_relationship(self._observable.key, target_obs.key, relationship_type)
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


class CyvestDSL:
    """
    DSL extension for Cyvest with fluent chaining methods.

    This class extends the base Cyvest functionality with convenient
    fluent API methods.
    """

    def __init__(self, cv: Cyvest) -> None:
        """
        Initialize the DSL.

        Args:
            cv: The Cyvest instance to wrap
        """
        self._cv = cv

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
        obs = self._cv.observable_create(obs_type, value, internal, whitelisted, comment, extra, score, level)
        return ObservableHandler(self._cv, obs)

    def create_observable(
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
        Create an observable (returns the object, not handler).

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
            The created observable
        """
        return self._cv.observable_create(obs_type, value, internal, whitelisted, comment, extra, score, level)

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
        chk = self._cv.check_create(check_id, scope, description, comment, extra, score, level)
        return CheckHandler(self._cv, chk)

    def create_check(
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
        Create a check (returns the object, not handler).

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
        return self._cv.check_create(check_id, scope, description, comment, extra, score, level)

    def container(self, path: str, description: str = "") -> ContainerHandler:
        """
        Create a container with fluent interface.

        Args:
            path: Container path
            description: Container description

        Returns:
            Container handler for chaining
        """
        ctr = self._cv.container_create(path, description)
        return ContainerHandler(self._cv, ctr)

    def root(self) -> Observable:
        """
        Get the root observable.

        Returns:
            Root observable
        """
        return self._cv.observable_get_root()


# Monkey-patch Cyvest to add DSL methods
def _extend_cyvest() -> None:
    """Extend Cyvest class with DSL methods."""
    from cyvest.cyvest import Cyvest

    # Add DSL methods to Cyvest
    def observable(
        self: Cyvest,
        obs_type: str,
        value: str,
        internal: bool = True,
        whitelisted: bool = False,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> ObservableHandler:
        obs = self.observable_create(obs_type, value, internal, whitelisted, comment, extra, score, level)
        return ObservableHandler(self, obs)

    def create_observable(
        self: Cyvest,
        obs_type: str,
        value: str,
        internal: bool = True,
        whitelisted: bool = False,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> Observable:
        return self.observable_create(obs_type, value, internal, whitelisted, comment, extra, score, level)

    def check(
        self: Cyvest,
        check_id: str,
        scope: str,
        description: str,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> CheckHandler:
        chk = self.check_create(check_id, scope, description, comment, extra, score, level)
        return CheckHandler(self, chk)

    def create_check(
        self: Cyvest,
        check_id: str,
        scope: str,
        description: str,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> Check:
        return self.check_create(check_id, scope, description, comment, extra, score, level)

    def container(self: Cyvest, path: str, description: str = "") -> ContainerHandler:
        ctr = self.container_create(path, description)
        return ContainerHandler(self, ctr)

    def root(self: Cyvest) -> Observable:
        return self.observable_get_root()

    # Apply monkey patches
    Cyvest.observable = observable  # type: ignore
    Cyvest.create_observable = create_observable  # type: ignore
    Cyvest.check = check  # type: ignore
    Cyvest.create_check = create_check  # type: ignore
    Cyvest.container = container  # type: ignore
    Cyvest.root = root  # type: ignore


# Auto-extend on import
_extend_cyvest()
