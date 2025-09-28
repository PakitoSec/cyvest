from __future__ import annotations

from collections import OrderedDict, defaultdict
from collections.abc import Iterable

from .models import ContainableSLM, Container, Level, ResultCheck


class CheckTree:
    """Canonical structure that stores containers/result checks and keeps their scores in sync."""

    def __init__(self) -> None:
        self._nodes: dict[str, ContainableSLM] = {}
        self._roots: dict[str, OrderedDict[str, ContainableSLM]] = defaultdict(OrderedDict)

    def integrate_container(self, container: Container) -> Container:
        return self._integrate_container(container, seen=set())

    def integrate_result_check(self, result_check: ResultCheck) -> ResultCheck:
        return self._integrate_result_check(result_check, seen=set())

    def _integrate_container(self, container: Container, seen: set[int]) -> Container:
        if id(container) in seen:
            existing = self._nodes.get(container.full_key)
            if isinstance(existing, Container):
                return existing
        seen.add(id(container))
        parent = container.parent
        if parent is not None:
            parent = self._integrate_container(parent, seen)
            container.set_parent(parent)
        key = container.full_key
        existing = self._nodes.get(key)
        if isinstance(existing, Container):
            existing.merge_from(container)
            target = existing
        else:
            target = container
            self._nodes[key] = target
            if target.parent is not None:
                target.parent.attach_child(target)
            else:
                root_scope = target.scope.name if target.scope else "GLOBAL"
                self._roots[root_scope][key] = target
        # integrate children
        for child in list(container.children):
            if isinstance(child, Container):
                child.set_parent(target)
                self._integrate_container(child, seen)
            else:
                child.set_parent(target)
                self._integrate_result_check(child, seen)
        target.recompute()
        self._recompute_upwards(target.parent)
        return target

    def _integrate_result_check(self, result_check: ResultCheck, seen: set[int]) -> ResultCheck:
        if id(result_check) in seen:
            existing = self._nodes.get(result_check.full_key)
            if isinstance(existing, ResultCheck):
                return existing
        seen.add(id(result_check))
        parent = result_check.parent
        if parent is not None:
            parent = self._integrate_container(parent, seen)
            result_check.set_parent(parent)
        key = result_check.full_key
        existing = self._nodes.get(key)
        if isinstance(existing, ResultCheck):
            existing.merge_from(result_check)
            target = existing
        else:
            target = result_check
            self._nodes[key] = target
            if target.parent is not None:
                target.parent.attach_child(target)
            else:
                scope_name = target.scope.name if target.scope else "GLOBAL"
                self._roots[scope_name][key] = target
        self._recompute_upwards(target.parent)
        return target

    def _recompute_upwards(self, node: Container | None) -> None:
        current = node
        while current is not None:
            current.recompute()
            current = current.parent

    def get(self, full_key: str) -> ContainableSLM | None:
        return self._nodes.get(full_key)

    def total_score(self) -> float:
        return sum(node.score for node in self._nodes.values() if isinstance(node, ResultCheck))

    def highest_level(self) -> Level:
        highest = Level.INFO
        for node in self._nodes.values():
            if node.level > highest:
                highest = node.level
        return highest

    def result_checks(self) -> Iterable[ResultCheck]:
        for node in self._nodes.values():
            if isinstance(node, ResultCheck):
                yield node

    def containers(self) -> Iterable[Container]:
        for node in self._nodes.values():
            if isinstance(node, Container):
                yield node

    def roots_for_scope(self, scope_name: str) -> list[ContainableSLM]:
        return list(self._roots.get(scope_name, {}).values())

    def iter_roots(self) -> Iterable[tuple[str, list[ContainableSLM]]]:
        for scope_name, nodes in self._roots.items():
            yield scope_name, list(nodes.values())
