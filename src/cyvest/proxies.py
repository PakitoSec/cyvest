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

from cyvest import keys
from cyvest.levels import Level
from cyvest.model import (
    Check,
    Container,
    Enrichment,
    Observable,
    ObservableLink,
    ObservableType,
    Relationship,
    Taxonomy,
    ThreatIntel,
)
from cyvest.model_enums import PropagationMode, RelationshipDirection, RelationshipType

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

    def _read_attr(self, name: str):
        """Resolve and deep-copy a public attribute from the model."""
        model = self._resolve()
        value = getattr(model, name)
        if callable(value):
            raise AttributeError(
                f"Method '{name}' is not available on read-only proxies. Use Cyvest services for mutations."
            )
        return deepcopy(value)

    def __setattr__(self, name: str, value) -> None:  # noqa: ANN001
        """Prevent attribute mutation."""
        raise AttributeError(f"{self.__class__.__name__} is read-only. Use Cyvest APIs to modify investigation data.")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{self.__class__.__name__} is read-only. Use Cyvest APIs to modify investigation data.")

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

    @property
    def obs_type(self) -> ObservableType | str:
        return self._read_attr("obs_type")

    @property
    def value(self) -> str:
        return self._read_attr("value")

    @property
    def internal(self) -> bool:
        return self._read_attr("internal")

    @property
    def whitelisted(self) -> bool:
        return self._read_attr("whitelisted")

    @property
    def comment(self) -> str:
        return self._read_attr("comment")

    @property
    def extra(self) -> dict[str, Any]:
        return self._read_attr("extra")

    @property
    def score(self) -> Decimal:
        return self._read_attr("score")

    @property
    def score_display(self) -> str:
        return self._read_attr("score_display")

    @property
    def level(self) -> Level:
        return self._read_attr("level")

    @property
    def threat_intels(self) -> list[ThreatIntel]:
        return self._read_attr("threat_intels")

    @property
    def relationships(self) -> list[Relationship]:
        return self._read_attr("relationships")

    @property
    def check_links(self) -> list[str]:
        """Checks that currently link to this observable."""
        return self._read_attr("check_links")

    def get_audit_events(self) -> tuple:
        """Return audit events for this observable."""
        events = self._get_investigation().get_audit_events(object_type="observable", object_key=self.key)
        return tuple(events)

    def update_metadata(
        self,
        *,
        comment: str | None = None,
        extra: dict[str, Any] | None = None,
        internal: bool | None = None,
        whitelisted: bool | None = None,
        merge_extra: bool = True,
    ) -> ObservableProxy:
        """
        Update mutable metadata fields on the observable.

        Args:
            comment: Optional comment override.
            extra: Dictionary to merge into (or replace) ``extra``.
            internal: Whether the observable is an internal asset.
            whitelisted: Whether the observable is whitelisted.
            merge_extra: When False, replaces ``extra`` entirely.
        """
        updates: dict[str, Any] = {}
        if comment is not None:
            updates["comment"] = comment
        if extra is not None:
            updates["extra"] = extra
        if internal is not None:
            updates["internal"] = internal
        if whitelisted is not None:
            updates["whitelisted"] = whitelisted

        if not updates:
            return self

        dict_merge = {"extra": merge_extra} if extra is not None else None
        self._get_investigation().update_model_metadata("observable", self.key, updates, dict_merge=dict_merge)
        return self

    def with_ti(
        self,
        source: str,
        score: Decimal | float,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        level: Level | None = None,
        taxonomies: list[Taxonomy | dict[str, Any]] | None = None,
    ) -> ObservableProxy:
        """
        Attach threat intelligence to this observable.
        """
        observable = self._resolve()
        ti_kwargs: dict[str, Any] = {
            "source": source,
            "observable_key": self.key,
            "comment": comment,
            "extra": extra or {},
            "score": Decimal(str(score)),
            "taxonomies": taxonomies or [],
        }
        if level is not None:
            ti_kwargs["level"] = level
        ti = ThreatIntel(**ti_kwargs)
        self._get_investigation().add_threat_intel(ti, observable)
        return self

    def with_ti_draft(self, draft: ThreatIntel) -> ThreatIntelProxy:
        """
        Attach a threat intel draft to this observable.
        """
        if not isinstance(draft, ThreatIntel):
            raise TypeError("Threat intel draft must be a ThreatIntel instance.")
        if draft.observable_key and draft.observable_key != self.key:
            raise ValueError("Threat intel is already bound to a different observable.")

        observable = self._resolve()
        draft.observable_key = self.key
        expected_key = keys.generate_threat_intel_key(draft.source, self.key)
        if not draft.key or draft.key != expected_key:
            draft.key = expected_key

        result = self._get_investigation().add_threat_intel(draft, observable)
        return ThreatIntelProxy(self._get_investigation(), result.key)

    def relate_to(
        self,
        target: Observable | ObservableProxy | str,
        relationship_type: RelationshipType,
        direction: RelationshipDirection | None = None,
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

    def link_check(
        self,
        check: Check | CheckProxy | str,
        *,
        propagation_mode: PropagationMode = PropagationMode.LOCAL_ONLY,
    ) -> ObservableProxy:
        """Link this observable to a check."""
        if isinstance(check, CheckProxy):
            check_key = check.key
        elif isinstance(check, Check):
            check_key = check.key
        elif isinstance(check, str):
            check_key = check
        else:
            raise TypeError("Check must provide a key.")

        self._get_investigation().link_check_observable(check_key, self.key, propagation_mode=propagation_mode)
        return self


class CheckProxy(_ReadOnlyProxy[Check]):
    """Read-only proxy over a check."""

    def _resolve(self):
        check = self._get_investigation().get_check(self.key)
        if check is None:
            raise ModelNotFoundError(f"Check '{self.key}' no longer exists in this investigation.")
        return check

    @property
    def check_id(self) -> str:
        return self._read_attr("check_id")

    @property
    def scope(self) -> str:
        return self._read_attr("scope")

    @property
    def description(self) -> str:
        return self._read_attr("description")

    @property
    def comment(self) -> str:
        return self._read_attr("comment")

    @property
    def extra(self) -> dict[str, Any]:
        return self._read_attr("extra")

    @property
    def score(self) -> Decimal:
        return self._read_attr("score")

    @property
    def score_display(self) -> str:
        return self._read_attr("score_display")

    @property
    def level(self) -> Level:
        return self._read_attr("level")

    @property
    def origin_investigation_id(self) -> str:
        return self._read_attr("origin_investigation_id")

    @property
    def observable_links(self) -> list[ObservableLink]:
        return self._read_attr("observable_links")

    def get_audit_events(self) -> tuple:
        """Return audit events for this check."""
        events = self._get_investigation().get_audit_events(object_type="check", object_key=self.key)
        return tuple(events)

    def update_metadata(
        self,
        *,
        comment: str | None = None,
        description: str | None = None,
        extra: dict[str, Any] | None = None,
        merge_extra: bool = True,
    ) -> CheckProxy:
        """Update mutable metadata on the check."""
        updates: dict[str, Any] = {}
        if comment is not None:
            updates["comment"] = comment
        if description is not None:
            updates["description"] = description
        if extra is not None:
            updates["extra"] = extra

        if not updates:
            return self

        dict_merge = {"extra": merge_extra} if extra is not None else None
        self._get_investigation().update_model_metadata("check", self.key, updates, dict_merge=dict_merge)
        return self

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

    def link_observable(
        self,
        observable: Observable | ObservableProxy | str,
        *,
        propagation_mode: PropagationMode = PropagationMode.LOCAL_ONLY,
    ) -> CheckProxy:
        """Link an observable to this check."""
        if isinstance(observable, ObservableProxy):
            observable_key = observable.key
        elif isinstance(observable, Observable):
            observable_key = observable.key
        elif isinstance(observable, str):
            observable_key = observable
        else:
            raise TypeError("Observable must provide a key.")

        self._get_investigation().link_check_observable(self.key, observable_key, propagation_mode=propagation_mode)
        return self

    def with_score(self, score: Decimal | float, reason: str = "") -> CheckProxy:
        """Update the check's score."""
        check = self._resolve()
        self._get_investigation().apply_score_change(check, Decimal(str(score)), reason=reason)
        return self


class ContainerProxy(_ReadOnlyProxy[Container]):
    """Read-only proxy over a container."""

    def _resolve(self):
        container = self._get_investigation().get_container(self.key)
        if container is None:
            raise ModelNotFoundError(f"Container '{self.key}' no longer exists in this investigation.")
        return container

    @property
    def path(self) -> str:
        return self._read_attr("path")

    @property
    def description(self) -> str:
        return self._read_attr("description")

    @property
    def checks(self) -> list[Check]:
        return self._read_attr("checks")

    @property
    def sub_containers(self) -> dict[str, Container]:
        return self._read_attr("sub_containers")

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

    def update_metadata(self, *, description: str | None = None) -> ContainerProxy:
        """Update mutable metadata on the container."""
        if description is None:
            return self
        self._get_investigation().update_model_metadata("container", self.key, {"description": description})
        return self


class ThreatIntelProxy(_ReadOnlyProxy[ThreatIntel]):
    """Read-only proxy over a threat intel entry."""

    def _resolve(self):
        ti = self._get_investigation().get_threat_intel(self.key)
        if ti is None:
            raise ModelNotFoundError(f"Threat intel '{self.key}' no longer exists in this investigation.")
        return ti

    @property
    def source(self) -> str:
        return self._read_attr("source")

    @property
    def observable_key(self) -> str:
        return self._read_attr("observable_key")

    @property
    def comment(self) -> str:
        return self._read_attr("comment")

    @property
    def extra(self) -> dict[str, Any]:
        return self._read_attr("extra")

    @property
    def score(self) -> Decimal:
        return self._read_attr("score")

    @property
    def score_display(self) -> str:
        return self._read_attr("score_display")

    @property
    def level(self) -> Level:
        return self._read_attr("level")

    @property
    def taxonomies(self) -> list[Taxonomy]:
        return self._read_attr("taxonomies")

    def add_taxonomy(self, *, level: Level, name: str, value: str) -> ThreatIntelProxy:
        """Add or replace a taxonomy by name."""
        taxonomy = Taxonomy(level=level, name=name, value=value)
        self._get_investigation().add_threat_intel_taxonomy(self.key, taxonomy)
        return self

    def remove_taxonomy(self, name: str) -> ThreatIntelProxy:
        """Remove a taxonomy by name."""
        self._get_investigation().remove_threat_intel_taxonomy(self.key, name)
        return self

    def update_metadata(
        self,
        *,
        comment: str | None = None,
        extra: dict[str, Any] | None = None,
        level: Level | None = None,
        merge_extra: bool = True,
    ) -> ThreatIntelProxy:
        """Update mutable metadata on the threat intel entry."""
        updates: dict[str, Any] = {}
        if comment is not None:
            updates["comment"] = comment
        if extra is not None:
            updates["extra"] = extra
        if level is not None:
            updates["level"] = level

        if not updates:
            return self

        dict_merge = {"extra": merge_extra} if extra is not None else None
        self._get_investigation().update_model_metadata("threat_intel", self.key, updates, dict_merge=dict_merge)
        return self


class EnrichmentProxy(_ReadOnlyProxy[Enrichment]):
    """Read-only proxy over an enrichment."""

    def _resolve(self):
        enrichment = self._get_investigation().get_enrichment(self.key)
        if enrichment is None:
            raise ModelNotFoundError(f"Enrichment '{self.key}' no longer exists in this investigation.")
        return enrichment

    @property
    def name(self) -> str:
        return self._read_attr("name")

    @property
    def data(self) -> dict[str, Any]:
        return self._read_attr("data")

    @property
    def context(self) -> str:
        return self._read_attr("context")

    def update_metadata(
        self,
        *,
        context: str | None = None,
        data: dict[str, Any] | None = None,
        merge_data: bool = True,
    ) -> EnrichmentProxy:
        """Update mutable metadata on the enrichment."""
        updates: dict[str, Any] = {}
        if context is not None:
            updates["context"] = context
        if data is not None:
            updates["data"] = data

        if not updates:
            return self

        dict_merge = {"data": merge_data} if data is not None else None
        self._get_investigation().update_model_metadata("enrichment", self.key, updates, dict_merge=dict_merge)
        return self
