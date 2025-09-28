from __future__ import annotations

import threading
from collections.abc import Iterable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any

from .models import ContainableSLM, Container, Level, ResultCheck, Scope
from .visitors import Report


@dataclass
class _ContainerNode:
    container: Container


class _ContainerContext(AbstractContextManager["BuilderContainerProxy"]):
    def __init__(self, builder: ReportBuilder, node: _ContainerNode) -> None:
        self._builder = builder
        self._node = node

    def __enter__(self) -> BuilderContainerProxy:
        self._builder._enter_container(self._node)
        return BuilderContainerProxy(self._builder, self._node)

    def __exit__(self, exc_type, exc, exc_tb) -> None:
        self._builder._exit_container(self._node)


class BuilderContainerProxy:
    def __init__(self, builder: ReportBuilder, node: _ContainerNode) -> None:
        self._builder = builder
        self._node = node

    def add_check(
        self,
        path: str,
        *,
        identifier: str | None = None,
        description: str | None = None,
        level: Level = Level.INFO,
        score: float = 0.0,
        details: dict | None = None,
        observable_chain: Sequence[dict[str, Any]] | None = None,
    ) -> ResultCheck:
        return self._builder.add_check(
            path,
            scope=self._node.container.scope,
            identifier=identifier,
            description=description,
            level=level,
            score=score,
            details=details,
            observable_chain=observable_chain,
        )

    def add_existing(self, node: ContainableSLM) -> ContainableSLM:
        return self._builder.add_existing(node)

    def container(
        self,
        path: str,
        *,
        scope: Scope | None = None,
        description: str | None = None,
        identifier: str | None = None,
        level: Level = Level.INFO,
        details: dict | None = None,
    ) -> _ContainerContext:
        container_scope = scope or self._node.container.scope
        return self._builder.container(
            path,
            scope=container_scope,
            description=description,
            identifier=identifier,
            level=level,
            details=details,
        )


class ReportBuilder:
    """Helper for constructing reports with nested containers and checks."""

    def __init__(self, report: Report | None = None, *, graph: bool = False) -> None:
        self.report: Report = report or Report(graph=graph)
        self._stack: list[_ContainerNode] = []
        self._roots: list[ContainableSLM] = []
        self._lock = threading.RLock()

    def container(
        self,
        path: str,
        *,
        scope: Scope,
        description: str | None = None,
        identifier: str | None = None,
        level: Level = Level.INFO,
        details: dict | None = None,
    ) -> _ContainerContext:
        container = Container(
            path,
            scope=scope,
            identifier=identifier,
            description=description,
            score=0.0,
            level=level,
            details=details,
        )
        node = _ContainerNode(container)
        return _ContainerContext(self, node)

    def add_check(
        self,
        path: str,
        *,
        scope: Scope | None = None,
        identifier: str | None = None,
        description: str | None = None,
        level: Level = Level.INFO,
        score: float = 0.0,
        details: dict | None = None,
        observable_chain: Sequence[dict[str, Any]] | None = None,
    ) -> ResultCheck:
        with self._lock:
            check_scope = scope
            if check_scope is None:
                if not self._stack:
                    raise ValueError("Scope must be provided when adding a check outside a container context")
                check_scope = self._stack[-1].container.scope
            result_check = ResultCheck.create(
                path,
                scope=check_scope,
                identifier=identifier,
                description=description,
                level=level,
                score=score,
                details=details,
            )
            if self._stack:
                self._stack[-1].container.contain(result_check)
            else:
                self._roots.append(result_check)
        if observable_chain:
            result_check.add_observable_chain(observable_chain)
        return result_check

    def build(self) -> Report:
        with self._lock:
            roots = list(self._roots)
            self._roots.clear()
        for root in roots:
            root.accept(self.report)
        return self.report

    def add_existing(self, node: ContainableSLM) -> ContainableSLM:
        with self._lock:
            if self._stack:
                self._stack[-1].container.contain(node)
            else:
                self._roots.append(node)
        return node

    def extend_existing(self, nodes: Iterable[ContainableSLM]) -> None:
        for node in nodes:
            self.add_existing(node)

    # Internal helpers -------------------------------------------------
    def _enter_container(self, node: _ContainerNode) -> None:
        with self._lock:
            if self._stack:
                parent = self._stack[-1].container
                parent.contain(node.container)
            else:
                self._roots.append(node.container)
            self._stack.append(node)

    def _exit_container(self, node: _ContainerNode) -> None:
        with self._lock:
            if not self._stack or self._stack[-1] is not node:
                raise RuntimeError("Container context stack is inconsistent")
            self._stack.pop()
