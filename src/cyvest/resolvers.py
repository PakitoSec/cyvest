"""Observable identity resolver types."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cyvest.enums import ObservableSubtype, ObservableType
from cyvest.facts import ObservableAlias, ObservableIdentity
from cyvest.facts.observable import NAMESPACE_REQUIRED, SUBTYPE_REQUIRED

ObservableSourceType = tuple[ObservableType | str, ObservableSubtype | str | None]


class ObservableResolution(BaseModel):
    """Canonical observable identity and metadata returned by a resolver."""

    model_config = ConfigDict(extra="forbid")

    identity: ObservableIdentity
    metadata: dict[str, Any] = Field(default_factory=dict)


ObservableResolverResult = ObservableIdentity | ObservableResolution | None


@dataclass(frozen=True)
class ObservableResolver:
    """Resolve source observable identities to canonical observable identities."""

    name: str
    source_types: set[ObservableSourceType]
    resolve: Callable[[ObservableAlias], ObservableResolverResult] | None = None
    aresolve: Callable[[ObservableAlias], Awaitable[ObservableResolverResult]] | None = None

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("ObservableResolver name must not be empty.")
        if not self.source_types:
            raise ValueError("ObservableResolver source_types must not be empty.")
        if self.resolve is None and self.aresolve is None:
            raise ValueError("ObservableResolver requires resolve or aresolve.")
        object.__setattr__(self, "name", name)


# --------------------------------------------------------------------------- inference

_SID_RE = re.compile(r"^S-\d+(?:-\d+)+$", re.IGNORECASE)
_GUID_RE = re.compile(r"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")

DEFAULT_NAMESPACE = "default"


def infer_observable_identity(
    obs_type: ObservableType | str,
    value: str,
    *,
    default_namespace: str = DEFAULT_NAMESPACE,
) -> tuple[ObservableType | str, ObservableSubtype | None, str | None]:
    """
    Guess the subtype and namespace an observable needs from its type and value alone.

    For material that arrives without them — an alert field, a model's answer — where the type
    is known but the identity rules of :class:`Observable` would refuse a bare value. The guess is
    conservative: a ``process`` that is neither a pid nor a GUID gets no subtype, and the caller
    decides whether to drop it (see :func:`identity_is_complete`). Returns
    ``(type, subtype, namespace)``; the namespace is ``default_namespace`` exactly where the
    identity rules require one.
    """
    kind = obs_type.value if isinstance(obs_type, ObservableType) else str(obs_type).strip().lower()
    text = value.strip()
    subtype: ObservableSubtype | None = None

    if kind == ObservableType.HOST.value:
        subtype = ObservableSubtype.HOST_FQDN if "." in text else ObservableSubtype.HOST_HOSTNAME
    elif kind == ObservableType.USER.value:
        if "@" in text:
            subtype = ObservableSubtype.USER_EMAIL
        elif _SID_RE.fullmatch(text):
            subtype = ObservableSubtype.USER_SID
        else:
            subtype = ObservableSubtype.USER_USERNAME
    elif kind == ObservableType.PROCESS.value:
        if text.isdecimal():
            subtype = ObservableSubtype.PROCESS_PID
        elif _GUID_RE.fullmatch(text):
            subtype = ObservableSubtype.PROCESS_GUID
    elif kind == ObservableType.FILE.value:
        subtype = ObservableSubtype.FILE_PATH
    elif kind == ObservableType.CLOUD_RESOURCE.value:
        if text.startswith("arn:"):
            subtype = ObservableSubtype.CLOUD_AWS_ARN
        elif text.startswith("/subscriptions/"):
            subtype = ObservableSubtype.CLOUD_AZURE_RESOURCE_ID
        elif text.startswith("//"):
            subtype = ObservableSubtype.CLOUD_GCP_RESOURCE_NAME

    namespace = default_namespace if subtype is not None and (kind, subtype.value) in NAMESPACE_REQUIRED else None
    return obs_type, subtype, namespace


def identity_is_complete(obs_type: ObservableType | str, subtype: ObservableSubtype | str | None) -> bool:
    """Whether :class:`Observable` would accept this type with this subtype."""
    kind = obs_type.value if isinstance(obs_type, ObservableType) else str(obs_type).strip().lower()
    return subtype is not None or kind not in SUBTYPE_REQUIRED
