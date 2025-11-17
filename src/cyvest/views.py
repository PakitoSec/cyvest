"""
Read-only view wrappers for Cyvest model objects.

These lightweight proxies expose investigation state to callers without allowing
them to mutate the underlying dataclasses directly. Each view stores only the
object key and looks up the live model instance inside the investigation on
every attribute access, ensuring that the latest score engine computations are
visible while keeping mutations confined to Cyvest services.
"""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING, Generic, TypeVar

from cyvest.model import Check, Container, Enrichment, Observable, ThreatIntel

if TYPE_CHECKING:
    from cyvest.investigation import Investigation

_T = TypeVar("_T")


class ModelNotFoundError(RuntimeError):
    """Raised when a view points to an object that no longer exists."""


class _ReadOnlyView(Generic[_T]):
    """Base helper for wrapping model objects."""

    __slots__ = ("__investigation", "__key")

    def __init__(self, investigation: Investigation, key: str) -> None:
        object.__setattr__(self, "_ReadOnlyView__investigation", investigation)
        object.__setattr__(self, "_ReadOnlyView__key", key)

    @property
    def key(self) -> str:
        """Return the stable object key."""
        return object.__getattribute__(self, "_ReadOnlyView__key")

    def _get_investigation(self) -> Investigation:
        return object.__getattribute__(self, "_ReadOnlyView__investigation")

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
                f"Method '{item}' is not available on read-only views. Use Cyvest services for mutations."
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


class ObservableView(_ReadOnlyView[Observable]):
    """Read-only view over an observable."""

    def _resolve(self):
        observable = self._get_investigation().get_observable(self.key)
        if observable is None:
            raise ModelNotFoundError(f"Observable '{self.key}' no longer exists in this investigation.")
        return observable

    def get_score_history(self) -> tuple:
        """Return a copy of the score change history."""
        history = self._call_readonly("get_score_history")
        return tuple(history)


class CheckView(_ReadOnlyView[Check]):
    """Read-only view over a check."""

    def _resolve(self):
        check = self._get_investigation().get_check(self.key)
        if check is None:
            raise ModelNotFoundError(f"Check '{self.key}' no longer exists in this investigation.")
        return check

    def get_score_history(self) -> tuple:
        """Return a copy of the score change history."""
        history = self._call_readonly("get_score_history")
        return tuple(history)


class ContainerView(_ReadOnlyView[Container]):
    """Read-only view over a container."""

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


class ThreatIntelView(_ReadOnlyView[ThreatIntel]):
    """Read-only view over a threat intel entry."""

    def _resolve(self):
        ti = self._get_investigation().get_threat_intel(self.key)
        if ti is None:
            raise ModelNotFoundError(f"Threat intel '{self.key}' no longer exists in this investigation.")
        return ti


class EnrichmentView(_ReadOnlyView[Enrichment]):
    """Read-only view over an enrichment."""

    def _resolve(self):
        enrichment = self._get_investigation().get_enrichment(self.key)
        if enrichment is None:
            raise ModelNotFoundError(f"Enrichment '{self.key}' no longer exists in this investigation.")
        return enrichment
