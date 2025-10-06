from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .models import Level, Observable, ThreatIntel, update_all_parents_score


class ObservableGraph:
    """Maintain a canonical observable graph with reconciliation helpers."""

    def __init__(self) -> None:
        self._observables: dict[str, Observable] = {}

    # ------------------------------------------------------------------
    # Public API
    def integrate(self, root: Observable) -> tuple[Observable, list[Observable], list[ThreatIntel]]:
        """Merge ``root`` (and its linked neighbors) into the graph.

        Returns the canonical observable, along with the set of observables and
        threat-intel objects that were touched during the reconciliation. The
        caller can use those collections to update statistics or run visitor
        hooks without re-walking the original structure.
        """

        seen: dict[str, Observable] = {}
        visited_nodes: list[Observable] = []
        visited_intels: list[ThreatIntel] = []
        canonical = self._integrate(root, seen, visited_nodes, visited_intels)
        for node in visited_nodes:
            self._propagate_whitelist(node)
        return canonical, visited_nodes, visited_intels

    def get(self, full_key: str) -> Observable | None:
        return self._observables.get(full_key)

    def values(self) -> Iterable[Observable]:
        return self._observables.values()

    def root_observables(self) -> list[Observable]:
        return [obs for obs in self._observables.values() if not obs.observables_parents]

    def is_whitelisted(self, obs_type: str, obs_value: str) -> bool:
        key = f"{obs_type}.{obs_value}"
        observable = self._observables.get(key)
        return bool(observable and observable.whitelisted)

    # ------------------------------------------------------------------
    # Internal helpers
    def _integrate(
        self,
        node: Observable,
        seen: dict[str, Observable],
        visited_nodes: list[Observable],
        visited_intels: list[ThreatIntel],
    ) -> Observable:
        key = node.full_key
        cached = seen.get(key)
        if cached:
            return cached

        target = self._observables.get(key)
        if target is None:
            self._observables[key] = node
            target = node
        else:
            self._merge_observable(target, node)

        seen[key] = target
        if target not in visited_nodes:
            visited_nodes.append(target)

        for threat_intel in list(node.threat_intels.values()):
            merged_intel = self._merge_threat_intel(target, threat_intel)
            if merged_intel not in visited_intels:
                visited_intels.append(merged_intel)

        for child in list(node.observables_children.values()):
            merged_child = self._integrate(child, seen, visited_nodes, visited_intels)
            self._link(parent=target, child=merged_child)

        for parent in list(node.observables_parents.values()):
            merged_parent = self._integrate(parent, seen, visited_nodes, visited_intels)
            self._link(parent=merged_parent, child=target)

        return target

    def _merge_observable(self, target: Observable, incoming: Observable) -> None:
        if target is incoming:
            return
        target.generated_by.update(incoming.generated_by)
        target.details.update(incoming.details)
        if incoming.whitelisted:
            target.whitelisted = True
        target.update_score(incoming)

    def _merge_threat_intel(self, observable: Observable, threat_intel: ThreatIntel) -> ThreatIntel:
        existing = observable.threat_intels.get(threat_intel.name)
        if existing:
            existing.update(threat_intel)
            merged = existing
        else:
            observable.threat_intels[threat_intel.name] = threat_intel
            merged = threat_intel
        observable.update_score(merged)
        update_all_parents_score(observable, merged, {id(observable)})
        if merged.extra:
            if merged.extra.get("whitelisted") is True or merged.extra.get("warning_lists"):
                observable.whitelisted = True
        if merged.level == Level.TRUSTED:
            observable.whitelisted = True
        return merged

    def _link(self, *, parent: Observable, child: Observable) -> None:
        if child.full_key in parent.observables_children:
            existing = parent.observables_children[child.full_key]
            if existing is not child:
                self._merge_observable(existing, child)
                child = existing
        parent.observables_children[child.full_key] = child
        child.observables_parents[parent.full_key] = parent
        parent.update_score(child)
        update_all_parents_score(parent, child, {id(parent)})

    def _propagate_whitelist(self, observable: Observable) -> None:
        if not observable.whitelisted:
            for intel in observable.threat_intels.values():
                extra = intel.extra or {}
                if extra.get("whitelisted") is True or extra.get("warning_lists"):
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
