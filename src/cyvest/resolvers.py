"""Observable identity resolver types."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from cyvest.model import ObservableAlias, ObservableIdentity
from cyvest.model_enums import ObservableSubtype, ObservableType

ObservableSourceType = tuple[ObservableType | str, ObservableSubtype | str | None]


@dataclass(frozen=True)
class ObservableResolver:
    """Resolve source observable identities to canonical observable identities."""

    name: str
    source_types: set[ObservableSourceType]
    resolve: Callable[[ObservableAlias], ObservableIdentity | None] | None = None
    aresolve: Callable[[ObservableAlias], Awaitable[ObservableIdentity | None]] | None = None

    def __post_init__(self) -> None:
        name = self.name.strip()
        if not name:
            raise ValueError("ObservableResolver name must not be empty.")
        if not self.source_types:
            raise ValueError("ObservableResolver source_types must not be empty.")
        if self.resolve is None and self.aresolve is None:
            raise ValueError("ObservableResolver requires resolve or aresolve.")
        object.__setattr__(self, "name", name)
