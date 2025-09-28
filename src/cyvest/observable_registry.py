from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import Level, Observable


class ObservableRegistry:
    """Central store for observables shared across result checks."""

    def __init__(self) -> None:
        self._observables: dict[str, Observable] = {}

    def get(self, full_key: str) -> Observable | None:
        return self._observables.get(full_key)

    def values(self) -> Iterable[Observable]:
        return self._observables.values()

    def upsert(self, observable: Observable) -> Observable:
        stored = self._observables.get(observable.full_key)
        if stored:
            stored.update(observable)
            target = stored
        else:
            self._observables[observable.full_key] = observable
            target = observable
        self._propagate_whitelist(target)
        return target

    def mark_whitelisted(self, observable: Observable) -> None:
        observable.whitelisted = True
        self._propagate_whitelist(observable)

    def _propagate_whitelist(self, observable: Observable) -> None:
        if not observable.whitelisted:
            for intel in observable.threat_intels.values():
                extra = intel.extra or {}
                if extra.get("whitelisted") is True:
                    observable.whitelisted = True
                    break
                if extra.get("warning_lists"):
                    observable.whitelisted = True
                    break
                tags = extra.get("tags") or extra.get("labels")
                if isinstance(tags, str):
                    tags_iterable: Iterable[Any] = [tags]
                elif isinstance(tags, Iterable):
                    tags_iterable = tags
                else:
                    tags_iterable = []
                if any(str(tag).lower() in {"allow", "trusted", "whitelist"} for tag in tags_iterable):
                    observable.whitelisted = True
                    break
                if intel.level == Level.TRUSTED:
                    observable.whitelisted = True
                    break
        if observable.whitelisted:
            for parent in observable.observables_parents.values():
                parent.whitelisted = True

    def root_observables(self) -> list[Observable]:
        return [obs for obs in self._observables.values() if not obs.observables_parents]

    def whitelisted(self, obs_type: str, obs_value: str) -> bool:
        key = f"{obs_type}.{obs_value}"
        observable = self._observables.get(key)
        return bool(observable and observable.whitelisted)
