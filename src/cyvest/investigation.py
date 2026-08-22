"""
Investigation: a thin orchestrator over a fact store, a policy and an engine.

v6 kept mutable models and mutated their scores in place; this class now only appends facts and
hands them to a pure evaluator. Scores are never stored — they are recomputed and cached, and the
cache is dropped the moment a fact lands.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from datetime import datetime
from typing import Any, Literal

from cyvest import keys
from cyvest.enums import (
    DecisionKind,
    ObservableType,
    RelationKind,
    Scope,
    SourceClass,
    Verdict,
)
from cyvest.evaluation import Report, ResolvedScope, evaluate, resolve_engine_alias
from cyvest.evaluation.timeline import TimelineEntry, build_timeline
from cyvest.facts import (
    Decision,
    Evidence,
    Fact,
    Finding,
    Observable,
    ObservableLink,
    Relation,
    SourceRef,
    Tag,
    ThreatIntel,
    utc_now,
)
from cyvest.facts.store import FactStore, InvestigationHeader
from cyvest.policy import DEFAULT_POLICY, Policy
from cyvest.ulid import generate_ulid

# The root is a presentation anchor, not evidence. v6 spotted it with ``value == "root"``, which
# collided with a genuine observable named root; the header now carries its key instead.
ROOT_SENTINEL = "__cyvest_root__"

DEFAULT_SOURCE = SourceRef(name="cyvest", source_class=SourceClass.INTERNAL_TOOL)


class Investigation:
    """Owns the facts, the parameters and the cached report — nothing else."""

    def __init__(
        self,
        root_data: Any = None,
        root_type: ObservableType | Literal["file", "artifact"] = ObservableType.FILE,
        *,
        policy: Policy | None = None,
        engine: str | None = None,
        investigation_id: str | None = None,
        investigation_name: str | None = None,
    ) -> None:
        self.policy = policy or DEFAULT_POLICY
        engine_id = resolve_engine_alias(engine or self.policy.engine_id)

        self.investigation_id = investigation_id or generate_ulid()
        self.fragment_id = self.investigation_id
        self.started_at = utc_now()

        resolved_root_type = ObservableType.normalize_root_type(root_type)
        root = Observable(
            type=resolved_root_type,
            value=ROOT_SENTINEL,
            internal=False,
            comment="Root observable for investigation",
            extra=root_data if isinstance(root_data, dict) else ({} if root_data is None else {"data": root_data}),
            source=DEFAULT_SOURCE,
            fragment_id=self.fragment_id,
        )

        self.store = FactStore(
            InvestigationHeader(
                investigation_id=self.investigation_id,
                name=investigation_name or "",
                root_key=root.key,
                opened_at=self.started_at,
                policy_version=self.policy.version,
                engine_id=engine_id,
                fragment_ids=(self.fragment_id,),
            )
        )
        self.store.append(root)
        self._report: Report | None = None

    # ---------------------------------------------------------------- report

    @property
    def report(self) -> Report:
        """Evaluate lazily, cache until a fact changes. Pure, so caching is always safe."""
        if self._report is None:
            self._report = evaluate(self.store, self.policy, self.store.header.engine_id)
        return self._report

    def invalidate(self) -> None:
        self._report = None

    def reevaluate(self, *, policy: Policy | None = None, engine: str | None = None) -> Report:
        """
        Replay the same facts under different parameters, and keep the result.

        The chosen engine is written to the header, so it survives the next fact append — a
        report that reverted to the previous engine as soon as anything changed would make the
        override a decoration. Saving afterwards therefore records the engine that actually ran.

        The policy is in-memory only: v7 is mono-policy and does not persist a custom policy body.
        """
        if policy is not None:
            self.policy = policy
        if engine is not None:
            resolved = resolve_engine_alias(engine)
            self.store.header = self.store.header.model_copy(update={"engine_id": resolved})
        self._report = evaluate(self.store, self.policy, self.store.header.engine_id)
        return self._report

    def get_global_score(self) -> float:
        return self.report.investigation.score or 0.0

    def get_global_verdict(self) -> Verdict:
        return self.report.investigation.verdict

    def explain(self, key: str) -> tuple:
        """
        Named contributions behind a result, including the ones that were overridden.

        An unknown key raises: an empty tuple means "this key contributed nothing", which is a
        different statement from "this key does not exist", and a typo deserves to be told so.
        """
        finding = self.report.finding(key)
        if finding is not None:
            return finding.contributions
        observable = self.report.observable(key)
        if observable is not None:
            return observable.contributions
        raise KeyError(key)

    def timeline(self, **kwargs: Any) -> list[TimelineEntry]:
        kwargs.setdefault("policy", self.policy)
        if kwargs.get("track_verdict_changes"):
            kwargs.setdefault("evaluator", lambda store, policy: evaluate(store, policy, self.store.header.engine_id))
        return build_timeline(self.store, self.report, **kwargs)

    # ---------------------------------------------------------------- facts

    def append(self, fact: Fact) -> Fact:
        stored = self.store.append(fact)
        self.invalidate()
        return stored

    def supersede(self, fact: Fact, **updates: Any) -> Fact:
        """
        Re-assert a fact with new content.

        Facts are immutable, so an edit is a fresh assertion carrying a newer ``seq``; the merge
        law then keeps it over the previous version.

        The replacement is rebuilt through the model rather than copied: ``model_copy`` skips
        validation, so an edit could otherwise reach a state construction refuses. Every
        invariant then holds on one path instead of being restated by each caller.
        """
        now = utc_now()
        updates.setdefault("asserted_at", now)
        updates.setdefault("seq", generate_ulid(timestamp_ms=int(now.timestamp() * 1000)))
        return self.append(type(fact)(**{**dict(fact), **updates}))

    # --- observables

    @property
    def root_key(self) -> str:
        """
        The key of the root observable.

        It is derived from the root type and a constant sentinel, so it is the same in every
        investigation. That is deliberate: a finding stated about the case rather than about a
        specific observable must survive a merge, which an investigation-scoped ULID would prevent.
        """
        return self.store.header.root_key or ""

    def get_root(self) -> Observable:
        return self.store.observables[self.store.header.root_key]

    def add_observable(self, observable: Observable) -> Observable:
        return self.append(observable)

    def get_observable(self, key: str) -> Observable | None:
        return self.store.observables.get(key)

    def get_all_observables(self) -> dict[str, Observable]:
        return dict(self.store.observables)

    # --- relations

    def add_relation(
        self,
        source: Observable | str,
        target: Observable | str,
        kind: RelationKind | str = RelationKind.RELATED_TO,
        *,
        confidence: float = 1.0,
        comment: str = "",
        observed_at: datetime | None = None,
    ) -> Relation:
        """
        Link two observables. ``source`` is the parent, ``target`` the child.

        There is no ``direction`` argument: the pivot kind implies it, so v6's contradictory
        ``EXTRACTION`` + ``BIDIRECTIONAL`` is no longer expressible.
        """
        source_key = source.key if isinstance(source, Observable) else source
        target_key = target.key if isinstance(target, Observable) else target
        relation = Relation(
            source_key=source_key,
            target_key=target_key,
            kind=RelationKind(kind) if isinstance(kind, str) else kind,
            confidence=confidence,
            comment=comment,
            observed_at=observed_at,
            source=DEFAULT_SOURCE,
            fragment_id=self.fragment_id,
        )
        return self.append(relation)  # type: ignore[return-value]

    def get_all_relations(self) -> dict[str, Relation]:
        return dict(self.store.relations)

    # --- signals

    def add_threat_intel(self, threat_intel: ThreatIntel) -> ThreatIntel:
        return self.append(threat_intel)  # type: ignore[return-value]

    def get_threat_intel(self, key: str) -> ThreatIntel | None:
        signal = self.store.signals.get(key)
        return signal if isinstance(signal, ThreatIntel) else None

    def get_all_threat_intels(self) -> dict[str, ThreatIntel]:
        return {key: signal for key, signal in self.store.signals.items() if isinstance(signal, ThreatIntel)}

    # --- evidence

    def add_evidence(self, evidence: Evidence) -> Evidence:
        return self.append(evidence)  # type: ignore[return-value]

    def get_evidence(self, key: str) -> Evidence | None:
        return self.store.evidences.get(key)

    def get_all_evidences(self) -> dict[str, Evidence]:
        return dict(self.store.evidences)

    # --- findings

    def add_finding(self, finding: Finding) -> Finding:
        return self.append(finding)  # type: ignore[return-value]

    def get_finding(self, key: str) -> Finding | None:
        return self.store.findings.get(key)

    def get_all_findings(self) -> dict[str, Finding]:
        return dict(self.store.findings)

    def link_finding_observable(
        self,
        finding_key: str,
        observable_key: str,
        scope: Scope | str = Scope.OWN_FRAGMENT,
    ) -> Finding:
        finding = self.store.findings.get(finding_key)
        if finding is None:
            raise KeyError(f"Unknown finding: {finding_key}")
        if observable_key not in self.store.observables:
            raise KeyError(f"Unknown observable: {observable_key}")
        link = ObservableLink(observable_key=observable_key, scope=Scope(scope) if isinstance(scope, str) else scope)
        if link in finding.observable_links:
            return finding
        return self.supersede(finding, observable_links=(*finding.observable_links, link))  # type: ignore[return-value]

    def link_finding_evidence(self, finding_key: str, evidence_key: str) -> Finding:
        finding = self.store.findings.get(finding_key)
        if finding is None:
            raise KeyError(f"Unknown finding: {finding_key}")
        if evidence_key in finding.evidence_keys:
            return finding
        return self.supersede(finding, evidence_keys=(*finding.evidence_keys, evidence_key))  # type: ignore[return-value]

    # --- decisions

    def add_decision(
        self,
        target_key: str,
        kind: DecisionKind | str,
        *,
        justification: str | None = None,
        source: SourceRef | None = None,
        occurred_at: datetime | None = None,
    ) -> Decision:
        decision = Decision(
            target_key=target_key,
            kind=DecisionKind(kind) if isinstance(kind, str) else kind,
            justification=justification,
            occurred_at=occurred_at,
            source=source or DEFAULT_SOURCE,
            fragment_id=self.fragment_id,
        )
        return self.append(decision)  # type: ignore[return-value]

    def get_decisions(self, target_key: str) -> list[Decision]:
        return self.store.decisions_for(target_key)

    def get_all_decisions(self) -> dict[str, Decision]:
        return dict(self.store.decisions)

    # --- tags

    def add_tag(self, tag: Tag) -> Tag:
        """Adding ``a:b:c`` materializes ``a`` and ``a:b`` too, so the hierarchy is always whole."""
        for ancestor in tag.ancestors:
            ancestor_key = keys.generate_tag_key(ancestor)
            if ancestor_key not in self.store.tags:
                self.append(Tag(name=ancestor, source=DEFAULT_SOURCE, fragment_id=self.fragment_id))
        return self.append(tag)  # type: ignore[return-value]

    def get_tag(self, key: str) -> Tag | None:
        return self.store.tags.get(key)

    def get_all_tags(self) -> dict[str, Tag]:
        return dict(self.store.tags)

    def get_tag_children(self, tag_name: str) -> list[Tag]:
        return [tag for tag in self.store.tags.values() if keys.is_tag_child_of(tag.name, tag_name)]

    def get_tag_descendants(self, tag_name: str) -> list[Tag]:
        return [tag for tag in self.store.tags.values() if keys.is_tag_descendant_of(tag.name, tag_name)]

    def get_tag_ancestors(self, tag_name: str) -> list[Tag]:
        found = [self.store.tags.get(keys.generate_tag_key(name)) for name in keys.get_tag_ancestors(tag_name)]
        return [tag for tag in found if tag is not None]

    def add_finding_to_tag(self, tag_key: str, finding_key: str) -> Tag:
        tag = self.store.tags.get(tag_key)
        if tag is None:
            raise KeyError(f"Unknown tag: {tag_key}")
        if finding_key in tag.finding_keys:
            return tag
        return self.supersede(tag, finding_keys=(*tag.finding_keys, finding_key))  # type: ignore[return-value]

    def get_tag_direct_score(self, tag_name: str) -> float:
        tag = self.store.tags.get(keys.generate_tag_key(tag_name))
        return self._sum_findings(tag.finding_keys) if tag is not None else 0.0

    def get_tag_aggregated_score(self, tag_name: str) -> float:
        """A tag's own findings plus every descendant's, read from the report."""
        tag_keys: list[str] = []
        tag = self.store.tags.get(keys.generate_tag_key(tag_name))
        if tag is not None:
            tag_keys.extend(tag.finding_keys)
        for descendant in self.get_tag_descendants(tag_name):
            tag_keys.extend(descendant.finding_keys)
        return self._sum_findings(tag_keys)

    def get_tag_aggregated_verdict(self, tag_name: str) -> Verdict:
        from cyvest.evaluation.projection import verdict_from_score

        return verdict_from_score(self.get_tag_aggregated_score(tag_name))

    def _sum_findings(self, finding_keys: Iterable[str]) -> float:
        report = self.report
        total = 0.0
        for key in dict.fromkeys(finding_keys):
            result = report.finding(key)
            if result is not None and result.counted and result.score is not None:
                total += result.score
        return total

    # ---------------------------------------------------------------- graph

    def finalize_relationships(self) -> None:
        """
        Attach orphan components to the root.

        Same heuristic as v6 — prefer a node with no inbound edge inside its component, then the
        one with the most outbound edges — but the root is now identified by ``header.root_key``
        instead of a magic string.
        """
        root_key = self.store.header.root_key
        if root_key is None:
            return

        adjacency: dict[str, set[str]] = {key: set() for key in self.store.observables}
        incoming: dict[str, set[str]] = {key: set() for key in self.store.observables}
        for relation in self.store.relations.values():
            if relation.source_key in adjacency and relation.target_key in adjacency:
                adjacency[relation.source_key].add(relation.target_key)
                incoming[relation.target_key].add(relation.source_key)

        visited: set[str] = set()
        for start in list(self.store.observables):
            if start in visited:
                continue
            component = self._component(start, adjacency, incoming)
            visited |= component
            if root_key in component:
                continue
            best = max(
                component,
                key=lambda node: (-len(incoming[node] & component), len(adjacency[node] & component)),
            )
            self.add_relation(root_key, best, RelationKind.RELATED_TO)

    @staticmethod
    def _component(start: str, adjacency: dict[str, set[str]], incoming: dict[str, set[str]]) -> set[str]:
        component = {start}
        queue = deque([start])
        while queue:
            current = queue.popleft()
            for neighbour in adjacency[current] | incoming[current]:
                if neighbour not in component:
                    component.add(neighbour)
                    queue.append(neighbour)
        return component

    # ---------------------------------------------------------------- merge

    def merge_investigation(self, other: Investigation) -> None:
        """
        Merge another investigation in place.

        No dedicated merge logic left: the whole operation is ``store.union``, which is idempotent,
        commutative and associative by construction.
        """
        self.store = self.store.union(other.store)
        self.invalidate()

    # ---------------------------------------------------------------- misc

    @property
    def investigation_name(self) -> str:
        return self.store.header.name

    def set_investigation_name(self, name: str | None) -> None:
        self.store.header = self.store.header.model_copy(update={"name": name or ""})

    def observable_result(self, observable_key: str, scope: ResolvedScope | None = None):
        return self.report.observable(observable_key, scope)


__all__ = ["ROOT_SENTINEL", "Investigation"]
