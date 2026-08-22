"""
Observables: the entities an investigation reasons about.

They carry no score and no level in v7 — those are results, and results live in the report.
What stays is identity, provenance and the ``internal`` flag.
"""

from __future__ import annotations

from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator

from cyvest import keys
from cyvest.enums import ObservableSubtype, ObservableType
from cyvest.facts.base import Fact

_SUBTYPES_BY_TYPE: dict[str, set[str]] = {
    ObservableType.USER.value: {"email", "sid", "upn", "okta_id", "username", "uid"},
    ObservableType.HOST.value: {"hostname", "fqdn", "netbios", "device_id"},
    ObservableType.PROCESS.value: {"pid", "process_guid"},
    ObservableType.FILE.value: {"path"},
    ObservableType.CLOUD_RESOURCE.value: {"aws_arn", "azure_resource_id", "gcp_resource_name"},
}

_SUBTYPE_REQUIRED = {
    ObservableType.USER.value,
    ObservableType.HOST.value,
    ObservableType.PROCESS.value,
    ObservableType.CLOUD_RESOURCE.value,
}

_NAMESPACE_REQUIRED = {
    (ObservableType.USER.value, "okta_id"),
    (ObservableType.USER.value, "username"),
    (ObservableType.USER.value, "uid"),
    (ObservableType.HOST.value, "hostname"),
    (ObservableType.HOST.value, "netbios"),
    (ObservableType.HOST.value, "device_id"),
    (ObservableType.PROCESS.value, "pid"),
    (ObservableType.FILE.value, "path"),
}


class _ObservableIdentityBase(BaseModel):
    """The quadruplet that identifies an observable."""

    model_config = ConfigDict(frozen=True, populate_by_name=True)

    obs_type: ObservableType | str = Field(..., alias="type")
    subtype: ObservableSubtype | str | None = Field(default=None)
    namespace: str | None = Field(default=None)
    value: str = Field(..., min_length=1)

    @field_validator("obs_type", mode="before")
    @classmethod
    def _coerce_type(cls, value: Any) -> Any:
        if isinstance(value, str):
            try:
                return ObservableType(value.lower())
            except ValueError:
                return value
        return value

    @field_validator("subtype", mode="before")
    @classmethod
    def _coerce_subtype(cls, value: Any) -> Any:
        if isinstance(value, str):
            normalized = value.strip().lower()
            try:
                return ObservableSubtype(normalized)
            except ValueError:
                return normalized
        return value

    @field_validator("namespace", mode="before")
    @classmethod
    def _coerce_namespace(cls, value: Any) -> str | None:
        if value is None:
            return None
        return str(value).strip() or None

    @property
    def identity_tuple(self) -> tuple[ObservableType | str, ObservableSubtype | str | None, str | None, str]:
        return (self.obs_type, self.subtype, self.namespace, self.value)

    @field_serializer("obs_type")
    def _serialize_type(self, value: ObservableType | str) -> str:
        return value.value if isinstance(value, ObservableType) else value

    @field_serializer("subtype")
    def _serialize_subtype(self, value: ObservableSubtype | str | None) -> str | None:
        return value.value if isinstance(value, ObservableSubtype) else value


class ObservableIdentity(_ObservableIdentityBase):
    """Canonical observable identity returned by resolvers."""


class ObservableAlias(_ObservableIdentityBase):
    """A source identity that resolved to a canonical observable."""

    counts: dict[str, int] = Field(default_factory=dict)

    @property
    def count(self) -> int:
        """Total occurrences across fragments — a CRDT sum, so merging stays commutative."""
        return sum(self.counts.values())


class Observable(Fact):
    """A cyber observable. Identity is ``(type, subtype, namespace, value)``, nothing else."""

    obs_type: ObservableType | str = Field(..., alias="type")
    subtype: ObservableSubtype | str | None = Field(default=None)
    namespace: str | None = Field(default=None)
    value: str = Field(..., min_length=1)
    internal: bool = Field(default=True)
    comment: str = Field(default="")
    extra: dict[str, Any] = Field(default_factory=dict)
    aliases: tuple[ObservableAlias, ...] = Field(default=())
    occurrences: dict[str, int] = Field(default_factory=dict)

    @field_validator("obs_type", mode="before")
    @classmethod
    def _coerce_type(cls, value: Any) -> Any:
        if isinstance(value, str):
            try:
                return ObservableType(value.lower())
            except ValueError:
                return value
        return value

    @field_validator("subtype", mode="before")
    @classmethod
    def _coerce_subtype(cls, value: Any) -> Any:
        if isinstance(value, str):
            normalized = value.strip().lower()
            try:
                return ObservableSubtype(normalized)
            except ValueError:
                return normalized
        return value

    @field_validator("namespace", mode="before")
    @classmethod
    def _coerce_namespace(cls, value: Any) -> str | None:
        if value is None:
            return None
        return str(value).strip() or None

    @model_validator(mode="before")
    @classmethod
    def _derive_key(cls, values: Any) -> Any:
        if not isinstance(values, dict) or values.get("key"):
            return values
        obs_type = values.get("obs_type") or values.get("type")
        obs_type = obs_type.value if isinstance(obs_type, ObservableType) else str(obs_type or "").lower()
        subtype = values.get("subtype")
        subtype = subtype.value if isinstance(subtype, ObservableSubtype) else subtype
        values["key"] = keys.generate_observable_key(
            obs_type,
            str(values.get("value", "")),
            subtype=subtype,
            namespace=values.get("namespace"),
        )
        return values

    @model_validator(mode="after")
    def _validate_identity(self) -> Self:
        obs_type = self.obs_type.value if isinstance(self.obs_type, ObservableType) else str(self.obs_type).lower()
        subtype = self.subtype.value if isinstance(self.subtype, ObservableSubtype) else self.subtype

        if obs_type in _SUBTYPE_REQUIRED and not subtype:
            raise ValueError(f"Observable type '{obs_type}' requires a subtype")
        if obs_type == ObservableType.COMMAND_LINE.value and subtype is not None:
            raise ValueError("COMMAND_LINE observables do not accept a subtype")
        if isinstance(self.subtype, ObservableSubtype) and subtype not in _SUBTYPES_BY_TYPE.get(obs_type, set()):
            raise ValueError(f"Subtype '{subtype}' is not valid for observable type '{obs_type}'")
        if (obs_type, subtype) in _NAMESPACE_REQUIRED and not self.namespace:
            raise ValueError(f"Observable {obs_type}/{subtype} requires a namespace")
        return self

    @property
    def identity_tuple(self) -> tuple[ObservableType | str, ObservableSubtype | str | None, str | None, str]:
        return (self.obs_type, self.subtype, self.namespace, self.value)

    @property
    def occurrence_count(self) -> int:
        return sum(self.occurrences.values()) or 1

    @field_serializer("obs_type")
    def _serialize_type(self, value: ObservableType | str) -> str:
        return value.value if isinstance(value, ObservableType) else value

    @field_serializer("subtype")
    def _serialize_subtype(self, value: ObservableSubtype | str | None) -> str | None:
        return value.value if isinstance(value, ObservableSubtype) else value


__all__ = ["Observable", "ObservableAlias", "ObservableIdentity"]
