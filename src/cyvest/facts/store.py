"""
The fact store: append-only, indexed, with a single merge law.

Union is by semantic key; when two facts share a key the **freshest wins in block**, settled on
``(observed_at or asserted_at, seq)``. That makes ``union`` idempotent, commutative and
associative *by construction* rather than by convention — one law, one set of tests.

Two counters deliberately escape freshest-wins and merge as CRDTs instead, because they are
per-fragment tallies rather than competing assertions: observable occurrences/aliases, and a
tag's finding keys.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Iterator
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cyvest.facts.base import Fact, utc_now
from cyvest.facts.decision import Decision
from cyvest.facts.evidence import Evidence
from cyvest.facts.finding import Finding
from cyvest.facts.observable import Observable, ObservableAlias
from cyvest.facts.relation import Relation
from cyvest.facts.signal import ObservableSignal
from cyvest.facts.tag import Tag


class InvestigationHeader(BaseModel):
    """
    What used to be a ``Case`` fact: metadata about the store rather than a fact inside it.

    ``engine_id`` is denormalized here so an investigation stays replayable identically years
    later, even after a newer stable engine ships.
    """

    model_config = ConfigDict(frozen=True)

    investigation_id: str = Field(...)
    name: str = Field(default="")
    root_key: str | None = Field(default=None)
    opened_at: datetime = Field(default_factory=utc_now)
    policy_version: str = Field(default="default-v1")
    engine_id: str = Field(default="basic-v1")
    fragment_ids: tuple[str, ...] = Field(default=())

    def with_fragments(self, fragment_ids: Iterable[str]) -> InvestigationHeader:
        merged = dict.fromkeys((*self.fragment_ids, *fragment_ids))
        return self.model_copy(update={"fragment_ids": tuple(merged)})


def _merge_counters(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    """Per-fragment tallies: each fragment is authoritative for its own count, so take the max."""
    merged = dict(left)
    for fragment_id, count in right.items():
        merged[fragment_id] = max(merged.get(fragment_id, 0), count)
    return merged


def _merge_aliases(
    left: tuple[ObservableAlias, ...],
    right: tuple[ObservableAlias, ...],
) -> tuple[ObservableAlias, ...]:
    by_identity: dict[Any, ObservableAlias] = {}
    for alias in (*left, *right):
        existing = by_identity.get(alias.identity_tuple)
        if existing is None:
            by_identity[alias.identity_tuple] = alias
        else:
            by_identity[alias.identity_tuple] = existing.model_copy(
                update={"counts": _merge_counters(existing.counts, alias.counts)}
            )
    return tuple(by_identity.values())


def resolve_conflict(existing: Fact, incoming: Fact) -> Fact:
    """
    Pick the winner between two facts sharing a key.

    Freshest wins in block. Observation time outranks assertion time, so a slow worker asserting
    stale data late does not overwrite fresher data.

    Note this differs from v6, which took the ``max``: a score could never come back down there.
    In v7 it can — if VirusTotal reclassifies a URL as clean, the clean verdict wins.
    """
    winner, loser = (incoming, existing) if incoming.merge_rank() > existing.merge_rank() else (existing, incoming)

    if isinstance(winner, Observable) and isinstance(loser, Observable):
        return winner.model_copy(
            update={
                "occurrences": _merge_counters(loser.occurrences, winner.occurrences),
                "aliases": _merge_aliases(loser.aliases, winner.aliases),
            }
        )
    if isinstance(winner, Tag) and isinstance(loser, Tag):
        union = tuple(dict.fromkeys((*loser.finding_keys, *winner.finding_keys)))
        return winner.model_copy(update={"finding_keys": union})
    return winner


class FactStore:
    """Append-only collection of facts, indexed for evaluation."""

    def __init__(self, header: InvestigationHeader) -> None:
        self.header = header
        self.observables: dict[str, Observable] = {}
        self.relations: dict[str, Relation] = {}
        self.signals: dict[str, ObservableSignal] = {}
        self.evidences: dict[str, Evidence] = {}
        self.findings: dict[str, Finding] = {}
        self.decisions: dict[str, Decision] = {}
        self.tags: dict[str, Tag] = {}

        # Bidirectional adjacency, maintained on append — this is what removes v6's O(n²) scan.
        self._children: dict[str, set[str]] = defaultdict(set)
        self._parents: dict[str, set[str]] = defaultdict(set)
        self._signals_by_subject: dict[str, set[str]] = defaultdict(set)
        self._findings_by_subject: dict[str, set[str]] = defaultdict(set)
        self._decisions_by_target: dict[str, set[str]] = defaultdict(set)

    def _collection_for(self, fact: Fact) -> dict[str, Any]:
        if isinstance(fact, Observable):
            return self.observables
        if isinstance(fact, Relation):
            return self.relations
        if isinstance(fact, ObservableSignal):
            return self.signals
        if isinstance(fact, Evidence):
            return self.evidences
        if isinstance(fact, Finding):
            return self.findings
        if isinstance(fact, Decision):
            return self.decisions
        if isinstance(fact, Tag):
            return self.tags
        raise TypeError(f"Unsupported fact type: {type(fact).__name__}")

    def append(self, fact: Fact) -> Fact:
        """Add a fact, resolving any conflict on its key. Returns the fact now in the store."""
        collection = self._collection_for(fact)
        existing = collection.get(fact.key)
        resolved = resolve_conflict(existing, fact) if existing is not None else fact
        collection[fact.key] = resolved
        self._index(resolved)
        return resolved

    def extend(self, facts: Iterable[Fact]) -> None:
        for fact in facts:
            self.append(fact)

    def _index(self, fact: Fact) -> None:
        if isinstance(fact, Relation):
            self._children[fact.source_key].add(fact.key)
            self._parents[fact.target_key].add(fact.key)
        elif isinstance(fact, ObservableSignal):
            self._signals_by_subject[fact.subject_key].add(fact.key)
        elif isinstance(fact, Finding):
            self._findings_by_subject[fact.subject_key].add(fact.key)
        elif isinstance(fact, Decision):
            self._decisions_by_target[fact.target_key].add(fact.key)

    def union(self, other: FactStore) -> FactStore:
        """
        Merge another store into a new one.

        Idempotent, commutative and associative: ``union`` is a fold of ``resolve_conflict`` over
        a key-indexed registry, and that resolver is itself a deterministic total order.
        """
        merged = FactStore(self.header.with_fragments(other.header.fragment_ids))
        merged.extend(self.all_facts())
        merged.extend(other.all_facts())
        return merged

    def all_facts(self) -> Iterator[Fact]:
        yield from self.observables.values()
        yield from self.relations.values()
        yield from self.signals.values()
        yield from self.evidences.values()
        yield from self.findings.values()
        yield from self.decisions.values()
        yield from self.tags.values()

    def get(self, key: str) -> Fact | None:
        for collection in (
            self.observables,
            self.relations,
            self.signals,
            self.evidences,
            self.findings,
            self.decisions,
            self.tags,
        ):
            found = collection.get(key)
            if found is not None:
                return found
        return None

    def signals_for(self, observable_key: str) -> list[ObservableSignal]:
        return [self.signals[key] for key in self._signals_by_subject.get(observable_key, ())]

    def child_relations(self, observable_key: str) -> list[Relation]:
        """Outgoing relations, i.e. the observables this one is the parent of."""
        return [self.relations[key] for key in self._children.get(observable_key, ())]

    def parent_relations(self, observable_key: str) -> list[Relation]:
        return [self.relations[key] for key in self._parents.get(observable_key, ())]

    def decisions_for(self, target_key: str) -> list[Decision]:
        return [self.decisions[key] for key in self._decisions_by_target.get(target_key, ())]

    def findings_for(self, subject_key: str) -> list[Finding]:
        return [self.findings[key] for key in self._findings_by_subject.get(subject_key, ())]

    def __len__(self) -> int:
        return sum(
            len(collection)
            for collection in (
                self.observables,
                self.relations,
                self.signals,
                self.evidences,
                self.findings,
                self.decisions,
                self.tags,
            )
        )


__all__ = ["FactStore", "InvestigationHeader", "resolve_conflict"]
