"""
Investigation: a thin orchestrator over a fact store, a policy and an engine.

v6 kept mutable models and mutated their scores in place; this class now only appends facts and
hands them to a pure evaluator. Scores are never stored — they are recomputed and cached, and the
cache is dropped the moment a fact lands.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from typing import Any, Literal

from cyvest import keys
from cyvest.enums import (
    DecisionKind,
    LinkBasis,
    ObservableType,
    RelationKind,
    Salience,
    SourceClass,
    Verdict,
)
from cyvest.evaluation import Report, evaluate, resolve_engine_alias
from cyvest.evaluation.timeline import TimeBasis, TimelineEntry, build_timeline
from cyvest.facts import (
    Decision,
    Evidence,
    Fact,
    Finding,
    Observable,
    ObservableLink,
    ObservableSignal,
    Relation,
    SourceRef,
    Tag,
    Taxonomy,
    ThreatIntel,
    utc_now,
)
from cyvest.facts.store import FactStore, InvestigationHeader, MergeReport
from cyvest.policy import DEFAULT_POLICY, Policy
from cyvest.ulid import generate_ulid

# The root is a presentation anchor, not evidence. v6 spotted it with ``value == "root"``, which
# collided with a genuine observable named root; the header now carries its key instead.
ROOT_SENTINEL = "__cyvest_root__"

DEFAULT_SOURCE = SourceRef(name="cyvest", source_class=SourceClass.INTERNAL_TOOL)


class FrozenInvestigationError(RuntimeError):
    """Raised when a snapshot is written to; the fact would be discarded on the next read."""


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
        self.frozen = False
        self._report: Report | None = None

    @classmethod
    def from_store(
        cls,
        store: FactStore,
        *,
        policy: Policy | None = None,
        frozen: bool = False,
        fragment_id: str | None = None,
    ) -> Investigation:
        """
        Rebuild an investigation around facts that already exist.

        ``__init__`` mints a root observable and a fresh header, which is wrong for anything
        rehydrated — a loaded file, a wrapped fragment, a snapshot. The header already carries the
        identity, so it is read back rather than invented.

        ``fragment_id`` defaults to the investigation id. A scratch copy taken to apply a batch
        atomically passes the live fragment instead, so the facts it appends stay attributed to
        the worker that produced them rather than to the document they were folded into.
        """
        investigation = cls.__new__(cls)
        investigation.policy = policy or DEFAULT_POLICY
        investigation.investigation_id = store.header.investigation_id
        investigation.fragment_id = fragment_id or store.header.investigation_id
        investigation.started_at = store.header.opened_at
        investigation.store = store
        investigation.frozen = frozen
        investigation._report = None
        return investigation

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

    def timeline(
        self,
        *,
        time: TimeBasis = "occurred",
        since: datetime | None = None,
        until: datetime | None = None,
        entity_key: str | None = None,
        min_salience: Salience = Salience.NOTABLE,
        policy: Policy | None = None,
        track_verdict_changes: bool = False,
        evaluator: Callable[[FactStore, Policy], Report] | None = None,
    ) -> list[TimelineEntry]:
        if track_verdict_changes and evaluator is None:
            # Replaying verdict changes must use the engine this investigation was built with.
            def evaluator(store: FactStore, policy: Policy) -> Report:
                return evaluate(store, policy, self.store.header.engine_id)

        return build_timeline(
            self.store,
            self.report,
            time=time,
            since=since,
            until=until,
            entity_key=entity_key,
            min_salience=min_salience,
            policy=policy or self.policy,
            track_verdict_changes=track_verdict_changes,
            evaluator=evaluator,
        )

    # ---------------------------------------------------------------- facts

    def append(self, fact: Fact) -> Fact:
        if self.frozen:
            raise FrozenInvestigationError(
                "This investigation is a snapshot and cannot be written to. "
                "Contribute through a worker obtained from the shared context instead."
            )
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
        asserted_by: SourceRef | None = None,
    ) -> Relation:
        """
        Link two observables. ``source`` is the parent, ``target`` the child.

        There is no ``direction`` argument: the pivot kind implies it, so v6's contradictory
        ``EXTRACTION`` + ``BIDIRECTIONAL`` is no longer expressible.

        ``asserted_by`` names who established the edge — an auto-link rule, an agent's plan — so
        a derived relation stays distinguishable from one an analyst drew. It is not called
        ``source`` because that word already means the parent observable here.
        """
        source_key = source.key if isinstance(source, Observable) else source
        target_key = target.key if isinstance(target, Observable) else target
        for key in (source_key, target_key):
            if key not in self.store.observables:
                raise KeyError(f"Unknown observable: {key}")
        relation = Relation(
            source_key=source_key,
            target_key=target_key,
            kind=RelationKind(kind) if isinstance(kind, str) else kind,
            confidence=confidence,
            comment=comment,
            observed_at=observed_at,
            source=asserted_by or DEFAULT_SOURCE,
            fragment_id=self.fragment_id,
        )
        return self.append(relation)  # type: ignore[return-value]

    def get_all_relations(self) -> dict[str, Relation]:
        return dict(self.store.relations)

    # --- signals

    def add_threat_intel(self, threat_intel: ThreatIntel) -> ThreatIntel:
        """A signal judges an observable that exists; one about nothing would score nothing, silently."""
        if threat_intel.subject_key not in self.store.observables:
            raise KeyError(f"Unknown observable: {threat_intel.subject_key}")
        return self.append(threat_intel)  # type: ignore[return-value]

    def get_threat_intel(self, key: str) -> ThreatIntel | None:
        signal = self.store.signals.get(key)
        return signal if isinstance(signal, ThreatIntel) else None

    def get_all_threat_intels(self) -> dict[str, ThreatIntel]:
        return {key: signal for key, signal in self.store.signals.items() if isinstance(signal, ThreatIntel)}

    def add_threat_intel_taxonomy(self, key: str, taxonomy: Taxonomy | str) -> ThreatIntel:
        """Upsert descriptive metadata by name, preserving the signal's judgment."""
        signal = self.get_threat_intel(key)
        if signal is None:
            raise KeyError(f"Unknown threat intel: {key}")
        entry = Taxonomy.model_validate(taxonomy)
        entries = list(signal.taxonomies)
        for index, existing in enumerate(entries):
            if existing.name == entry.name:
                if existing == entry:
                    return signal
                entries[index] = entry
                break
        else:
            entries.append(entry)
        return self.supersede(signal, taxonomies=tuple(entries))  # type: ignore[return-value]

    def remove_threat_intel_taxonomy(self, key: str, name: str) -> ThreatIntel:
        """Remove a descriptive entry by name; absent names are a no-op."""
        signal = self.get_threat_intel(key)
        if signal is None:
            raise KeyError(f"Unknown threat intel: {key}")
        entries = tuple(entry for entry in signal.taxonomies if entry.name != name)
        if entries == signal.taxonomies:
            return signal
        return self.supersede(signal, taxonomies=entries)  # type: ignore[return-value]

    # --- evidence

    def add_evidence(self, evidence: Evidence) -> Evidence:
        return self.append(evidence)  # type: ignore[return-value]

    def get_evidence(self, key: str) -> Evidence | None:
        return self.store.evidences.get(key)

    def get_all_evidences(self) -> dict[str, Evidence]:
        return dict(self.store.evidences)

    # --- findings

    def add_finding(self, finding: Finding) -> Finding:
        """
        Add a finding; reusing its key updates the finding rather than adding one.

        An update that says nothing about *when* or *which tactic* keeps what the previous version
        said. Without this, a re-assertion without ``occurred_at`` would rank at its own
        ``asserted_at`` — later than any past ``occurred_at`` — win the merge, and erase the date.
        """
        existing = self.store.findings.get(finding.key)
        if existing is not None:
            carried: dict[str, Any] = {}
            if finding.occurred_at is None and existing.occurred_at is not None:
                carried["occurred_at"] = existing.occurred_at
            if finding.tactic is None and existing.tactic is not None:
                carried["tactic"] = existing.tactic
            if carried:
                finding = Finding(**{**dict(finding), **carried})
        return self.append(finding)  # type: ignore[return-value]

    def get_finding(self, key: str) -> Finding | None:
        return self.store.findings.get(key)

    def get_all_findings(self) -> dict[str, Finding]:
        return dict(self.store.findings)

    def link_finding_observable(
        self,
        finding_key: str,
        observable_key: str,
        basis: LinkBasis | str = LinkBasis.OBSERVABLE,
        signal_keys: Sequence[str] = (),
    ) -> Finding:
        finding = self.store.findings.get(finding_key)
        if finding is None:
            raise KeyError(f"Unknown finding: {finding_key}")
        if observable_key not in self.store.observables:
            raise KeyError(f"Unknown observable: {observable_key}")
        resolved = LinkBasis(basis) if isinstance(basis, str) else basis
        for signal_key in signal_keys:
            signal = self.store.signals.get(signal_key)
            if signal is None:
                raise KeyError(f"Unknown signal: {signal_key}")
            if signal.subject_key != observable_key:
                raise ValueError(
                    f"signal {signal_key} judges {signal.subject_key}, not {observable_key}; "
                    "a pinned link may only name signals about the observable it links"
                )
        link = ObservableLink(observable_key=observable_key, basis=resolved, signal_keys=tuple(signal_keys))
        if link in finding.observable_links:
            return finding
        return self.supersede(finding, observable_links=(*finding.observable_links, link))  # type: ignore[return-value]

    def pin_finding_signals(self, finding_key: str, *signals: ObservableSignal | str) -> Finding:
        """
        Pin a finding to the signals it fetched, so later intel on the same observable cannot
        move it.

        The observable is *derived* from the signals: a signal's identity already carries its
        subject, so restating it could only introduce a disagreement. All signals must share that
        subject — one pin is one link.
        """
        if not signals:
            raise ValueError("pinning takes at least one signal")
        keys_ = [s if isinstance(s, str) else s.key for s in signals]
        subjects = {self._pinned_subject(key) for key in keys_}
        if len(subjects) > 1:
            raise ValueError(
                f"cannot pin one link to signals about different observables: {sorted(subjects)}; "
                "pin once per observable"
            )
        return self.link_finding_observable(finding_key, subjects.pop(), basis=LinkBasis.SIGNALS, signal_keys=keys_)

    def _pinned_subject(self, signal_key: str) -> str:
        signal = self.store.signals.get(signal_key)
        if signal is None:
            raise KeyError(f"Unknown signal: {signal_key}")
        return signal.subject_key

    def link_finding_evidence(self, finding_key: str, evidence_key: str) -> Finding:
        finding = self.store.findings.get(finding_key)
        if finding is None:
            raise KeyError(f"Unknown finding: {finding_key}")
        if evidence_key not in self.store.evidences:
            raise KeyError(f"Unknown evidence: {evidence_key}")
        if evidence_key in finding.evidence_keys:
            return finding
        return self.supersede(finding, evidence_keys=(*finding.evidence_keys, evidence_key))  # type: ignore[return-value]

    # --- decisions

    def add_decision(
        self,
        target_key: str,
        kind: DecisionKind | str,
        justification: str,
        *,
        source: SourceRef | None = None,
        occurred_at: datetime | None = None,
    ) -> Decision:
        """A decision bounds an observable or a finding that exists — the key says which family."""
        if target_key not in self.store.observables and target_key not in self.store.findings:
            raise KeyError(f"Unknown observable or finding: {target_key}")
        decision = Decision(
            target_key=target_key,
            kind=DecisionKind(kind) if isinstance(kind, str) else kind,
            justification=justification,
            occurred_at=occurred_at,
            source=source or DEFAULT_SOURCE,
            fragment_id=self.fragment_id,
        )
        return self.append(decision)  # type: ignore[return-value]

    def get_decision(self, target_key: str) -> Decision | None:
        """The stance standing on a target — at most one, the merge law having settled it."""
        return self.store.decision_for(target_key)

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
                sorted(component),
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

    def merge_investigation(
        self,
        other: Investigation,
        *,
        on_engine_mismatch: Literal["raise", "reevaluate"] = "raise",
    ) -> MergeReport:
        """
        Merge another investigation in place and say what changed.

        The whole operation is ``store.union`` — idempotent, commutative and associative, header
        included — so the investigation may come out carrying the other side's identity and name
        when that side was opened first. What never changes is this object's ``fragment_id``: the
        facts it appends afterwards stay attributed to it.

        Two engines are refused by default: their scores are not on one scale, and a merge that
        quietly re-scored one side's facts under the other side's engine would hide that. Passing
        ``on_engine_mismatch="reevaluate"`` states the decision — the other side's facts are
        adopted and everything is evaluated under this investigation's engine.
        """
        incoming = other.store
        if on_engine_mismatch == "reevaluate" and incoming.header.engine_id != self.store.header.engine_id:
            incoming = incoming.copy()
            incoming.header = incoming.header.model_copy(update={"engine_id": self.store.header.engine_id})
        merged = self.store.union(incoming)
        report = self.store.report_merge(incoming, merged)
        self.store = merged
        self.investigation_id = merged.header.investigation_id
        self.invalidate()
        return report

    # ---------------------------------------------------------------- misc

    @property
    def investigation_name(self) -> str:
        return self.store.header.name

    def set_investigation_name(self, name: str | None) -> None:
        self.store.header = self.store.header.model_copy(update={"name": name or ""})

    def observable_result(self, observable_key: str):
        return self.report.observable(observable_key)


__all__ = ["ROOT_SENTINEL", "FrozenInvestigationError", "Investigation"]
