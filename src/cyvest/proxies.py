"""
Read-only proxy wrappers for Cyvest model objects.

These lightweight proxies expose investigation state to callers without allowing
them to mutate the underlying dataclasses directly. Each proxy stores only the
object key and looks up the live model instance inside the investigation on
every attribute access, ensuring that the latest score engine computations are
visible while keeping mutations confined to Cyvest services.
"""

from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from cyvest.levels import Level
from cyvest.model import Check, Container, Enrichment, Observable, ThreatIntel

if TYPE_CHECKING:
    from cyvest.investigation import Investigation

_T = TypeVar("_T")


class ModelNotFoundError(RuntimeError):
    """Raised when a proxy points to an object that no longer exists."""


class _ReadOnlyProxy(Generic[_T]):
    """Base helper for wrapping model objects."""

    __slots__ = ("__investigation", "__key")

    def __init__(self, investigation: Investigation, key: str) -> None:
        object.__setattr__(self, "_ReadOnlyProxy__investigation", investigation)
        object.__setattr__(self, "_ReadOnlyProxy__key", key)

    @property
    def key(self) -> str:
        """Return the stable object key."""
        return object.__getattribute__(self, "_ReadOnlyProxy__key")

    def _get_investigation(self) -> Investigation:
        return object.__getattribute__(self, "_ReadOnlyProxy__investigation")

    def _resolve(self) -> _T:  # pragma: no cover - overridden in subclasses
        raise NotImplementedError

    def __setattr__(self, name: str, value) -> None:  # noqa: ANN001
        """Prevent attribute mutation."""
        raise AttributeError(f"{self.__class__.__name__} is read-only. Use Cyvest APIs to modify investigation data.")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{self.__class__.__name__} is read-only. Use Cyvest APIs to modify investigation data.")

    def __getattr__(self, item: str):
        """
        Provide attribute access for simple data fields.

        Methods on the underlying dataclasses (like ``update_score``) are
        intentionally blocked to ensure all mutations flow through the façade.
        """
        model = self._resolve()
        if not hasattr(model, item):
            raise AttributeError(f"{self.__class__.__name__} has no attribute '{item}'")

        value = getattr(model, item)
        if callable(value):
            raise AttributeError(
                f"Method '{item}' is not available on read-only proxies. Use Cyvest services for mutations."
            )
        return deepcopy(value)

    def _call_readonly(self, method: str, *args, **kwargs):
        """Invoke a model method in read-only mode and deepcopy the result."""
        model = self._resolve()
        attr = getattr(model, method, None)
        if attr is None or not callable(attr):
            raise AttributeError(f"{self.__class__.__name__} exposes no method '{method}'")
        return deepcopy(attr(*args, **kwargs))

    def __repr__(self) -> str:
        model = self._resolve()
        return f"{self.__class__.__name__}(key={self.key!r}, type={model.__class__.__name__})"


class ObservableProxy(_ReadOnlyProxy[Observable]):
    """Read-only proxy over an observable."""

    def _resolve(self):
        observable = self._get_investigation().get_observable(self.key)
        if observable is None:
            raise ModelNotFoundError(f"Observable '{self.key}' no longer exists in this investigation.")
        return observable

    def get_score_history(self) -> tuple:
        """Return a copy of the score change history."""
        history = self._call_readonly("get_score_history")
        return tuple(history)

    def with_ti(
        self,
        source: str,
        score: Decimal | float = 0,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        level: Level | None = None,
        taxonomies: list[dict[str, Any]] | None = None,
    ) -> ObservableProxy:
        """
        Attach threat intelligence to this observable.

        Mirrors the previous DSL handler convenience method but keeps mutations
        under the proxy wrapper.
        """
        observable = self._resolve()
        ti = ThreatIntel(
            source=source,
            observable_key=self.key,
            comment=comment,
            extra=extra or {},
            score=Decimal(str(score)),
            level=level or Level.INFO,
            taxonomies=taxonomies or [],
        )
        self._get_investigation().add_threat_intel(ti, observable)
        return self

    def add_ti(
        self,
        source: str,
        score: Decimal | float = 0,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        level: Level | None = None,
        taxonomies: list[dict[str, Any]] | None = None,
    ) -> ObservableProxy:
        """Alias for :meth:`with_ti`."""
        return self.with_ti(source, score, comment, extra, level, taxonomies)

    def relate_to(
        self,
        target: Observable | ObservableProxy | str,
        relationship_type: str,
        direction: str | None = None,
    ) -> ObservableProxy:
        """Create a relationship to another observable."""
        if isinstance(target, ObservableProxy):
            resolved_target: Observable | str = target.key
        elif isinstance(target, Observable):
            resolved_target = target
        elif isinstance(target, str):
            resolved_target = target
        else:
            raise TypeError("Target must be an observable key, ObservableProxy, or Observable instance.")

        self._get_investigation().add_relationship(self.key, resolved_target, relationship_type, direction)
        return self

    def link_check(self, check: Check | CheckProxy | str) -> ObservableProxy:
        """Link this observable to a check."""
        if isinstance(check, CheckProxy):
            check_key = check.key
        elif isinstance(check, Check):
            check_key = check.key
        elif isinstance(check, str):
            check_key = check
        else:
            raise TypeError("Check must provide a key.")

        self._get_investigation().link_check_observable(check_key, self.key)
        return self


class CheckProxy(_ReadOnlyProxy[Check]):
    """Read-only proxy over a check."""

    def _resolve(self):
        check = self._get_investigation().get_check(self.key)
        if check is None:
            raise ModelNotFoundError(f"Check '{self.key}' no longer exists in this investigation.")
        return check

    def get_score_history(self) -> tuple:
        """Return a copy of the score change history."""
        history = self._call_readonly("get_score_history")
        return tuple(history)

    def in_container(self, container: Container | ContainerProxy | str) -> CheckProxy:
        """Add this check to a container."""
        if isinstance(container, ContainerProxy):
            container_key = container.key
        elif isinstance(container, Container):
            container_key = container.key
        elif isinstance(container, str):
            container_key = container
        else:
            raise TypeError("Container must provide a key.")

        self._get_investigation().add_check_to_container(container_key, self.key)
        return self

    def link_observable(self, observable: Observable | ObservableProxy | str) -> CheckProxy:
        """Link an observable to this check."""
        if isinstance(observable, ObservableProxy):
            observable_key = observable.key
        elif isinstance(observable, Observable):
            observable_key = observable.key
        elif isinstance(observable, str):
            observable_key = observable
        else:
            raise TypeError("Observable must provide a key.")

        self._get_investigation().link_check_observable(self.key, observable_key)
        return self

    def with_score(self, score: Decimal | float, reason: str = "") -> CheckProxy:
        """Update the check's score."""
        check = self._resolve()
        check.update_score(Decimal(str(score)), reason)
        return self


class ContainerProxy(_ReadOnlyProxy[Container]):
    """Read-only proxy over a container."""

    def _resolve(self):
        container = self._get_investigation().get_container(self.key)
        if container is None:
            raise ModelNotFoundError(f"Container '{self.key}' no longer exists in this investigation.")
        return container

    def get_aggregated_score(self):
        """Return the aggregated score copy."""
        return self._call_readonly("get_aggregated_score")

    def get_aggregated_level(self):
        """Return the aggregated level copy."""
        return self._call_readonly("get_aggregated_level")

    def add_check(self, check: Check | CheckProxy | str) -> ContainerProxy:
        """Add a check to this container."""
        if isinstance(check, CheckProxy):
            check_key = check.key
        elif isinstance(check, Check):
            check_key = check.key
        elif isinstance(check, str):
            check_key = check
        else:
            raise TypeError("Check must provide a key.")

        self._get_investigation().add_check_to_container(self.key, check_key)
        return self

    def sub_container(self, path: str, description: str = "") -> ContainerProxy:
        """Create a sub-container nested beneath this container."""
        parent = self._resolve()
        full_path = f"{parent.path}/{path}"
        sub = Container(path=full_path, description=description)
        sub = self._get_investigation().add_container(sub)
        self._get_investigation().add_sub_container(self.key, sub.key)
        return ContainerProxy(self._get_investigation(), sub.key)

    def __enter__(self) -> ContainerProxy:
        """Context manager entry returning self."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit (no-op)."""
        return None


class ThreatIntelProxy(_ReadOnlyProxy[ThreatIntel]):
    """Read-only proxy over a threat intel entry."""

    def _resolve(self):
        ti = self._get_investigation().get_threat_intel(self.key)
        if ti is None:
            raise ModelNotFoundError(f"Threat intel '{self.key}' no longer exists in this investigation.")
        return ti


class EnrichmentProxy(_ReadOnlyProxy[Enrichment]):
    """Read-only proxy over an enrichment."""

    def _resolve(self):
        enrichment = self._get_investigation().get_enrichment(self.key)
        if enrichment is None:
            raise ModelNotFoundError(f"Enrichment '{self.key}' no longer exists in this investigation.")
        return enrichment
