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
from typing import Any, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from cyvest.errors import EngineMismatchError, PolicyMismatchError, RootMismatchError
from cyvest.facts.base import Fact, utc_now
from cyvest.facts.decision import Decision
from cyvest.facts.evidence import Evidence
from cyvest.facts.finding import Finding
from cyvest.facts.observable import Observable, ObservableAlias
from cyvest.facts.relation import Relation
from cyvest.facts.signal import ObservableSignal
from cyvest.facts.tag import Tag
from cyvest.keys import generate_decision_key

_F = TypeVar("_F", bound=Fact)


def _ordered(facts: Iterable[_F]) -> list[_F]:
    """
    Sort facts into a stable chronological order.

    The adjacency indexes are sets, whose iteration order varies between interpreter runs. An
    engine folding them would then produce a different report for the same facts, so every
    accessor sorts before returning. ``key`` breaks ties, keeping the order total even when two
    facts share a ``seq``.
    """
    return sorted(facts, key=lambda fact: (fact.seq, fact.key))


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

    @property
    def sort_key(self) -> tuple[datetime, str]:
        """The canonical order of two headers: the one opened first comes first, the id breaks ties."""
        return (self.opened_at, self.investigation_id)

    def with_fragments(self, fragment_ids: Iterable[str]) -> InvestigationHeader:
        merged = sorted(dict.fromkeys((*self.fragment_ids, *fragment_ids)))
        return self.model_copy(update={"fragment_ids": tuple(merged)})

    def merge(self, other: InvestigationHeader) -> InvestigationHeader:
        """
        The header of the union of two stores — the one law, symmetric and deterministic.

        Facts have always merged by a total order; the header used to come from whichever side
        was ``self``, which made a merge commutative on its facts and not on its name. Now both
        headers are put in canonical order first (:attr:`sort_key`), so ``a.merge(b)`` and
        ``b.merge(a)`` are the same header: the identity and the name of the investigation opened
        first, the earliest opening time, the sorted union of the fragments.

        Three fields must agree, and refuse rather than pick a side: facts collected under two
        engines or two policies are not on one scale, and two roots are two cases. Re-evaluating
        under one engine is a decision the caller states — see
        :meth:`Investigation.merge_investigation`.
        """
        if self.engine_id != other.engine_id:
            raise EngineMismatchError(
                f"Cannot merge a {self.engine_id} investigation with a {other.engine_id} one; "
                "scores from different engines are not on the same scale. "
                "Re-evaluate both under one engine first."
            )
        if self.policy_version != other.policy_version:
            raise PolicyMismatchError(
                f"Cannot merge a {self.policy_version} investigation with a {other.policy_version} one; "
                "the two were scored under different policies."
            )
        if self.root_key and other.root_key and self.root_key != other.root_key:
            raise RootMismatchError(
                f"Cannot merge investigations anchored on different roots ({self.root_key} vs {other.root_key})."
            )
        first, second = sorted((self, other), key=lambda header: header.sort_key)
        return InvestigationHeader(
            investigation_id=first.investigation_id,
            name=first.name or second.name,
            root_key=first.root_key or second.root_key,
            opened_at=first.opened_at,
            policy_version=first.policy_version,
            engine_id=first.engine_id,
            fragment_ids=first.with_fragments(second.fragment_ids).fragment_ids,
        )


class MergeReport(BaseModel):
    """
    What a merge did to the receiving store, key by key.

    ``added`` are facts the receiver did not have; ``superseded`` are facts it had and that the
    incoming, fresher assertion replaced; ``kept`` are facts it had and kept, the incoming one
    being older or identical. ``fragments`` lists the fragments joined by the merge.
    """

    model_config = ConfigDict(frozen=True)

    added: tuple[str, ...] = Field(default=())
    superseded: tuple[str, ...] = Field(default=())
    kept: tuple[str, ...] = Field(default=())
    fragments: tuple[str, ...] = Field(default=())

    @property
    def changed(self) -> bool:
        return bool(self.added or self.superseded)


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

    def union(self, other: FactStore) -> FactStore:
        """
        Merge another store into a new one.

        Idempotent, commutative and associative — header included: ``union`` is a fold of
        ``resolve_conflict`` over a key-indexed registry, that resolver is a deterministic total
        order, and the two sides are put in canonical order (:attr:`InvestigationHeader.sort_key`)
        before folding, so the order the arguments came in cannot leak into the result.

        Raises the mismatch errors of :meth:`InvestigationHeader.merge` when the two stores were
        scored on different scales or anchor on different roots.
        """
        header = self.header.merge(other.header)
        # Two branches of one investigation share a header, so the tie is broken on the stores'
        # own content; the fold order then never depends on which side was ``self``.
        first, second = sorted((self, other), key=lambda store: (store.header.sort_key, sorted(store.keys())))
        merged = FactStore(header)
        merged.extend(first.all_facts())
        merged.extend(second.all_facts())
        return merged

    def report_merge(self, incoming: FactStore, merged: FactStore) -> MergeReport:
        """Describe ``merged`` from this store's point of view: what ``incoming`` added, replaced or lost."""
        added: list[str] = []
        superseded: list[str] = []
        kept: list[str] = []
        roots = {self.header.root_key, incoming.header.root_key}
        for fact in incoming.all_facts():
            # The root is an anchor every side re-mints; it would be "superseded" by every merge.
            if fact.key in roots:
                continue
            before = self.get(fact.key)
            if before is None:
                added.append(fact.key)
                continue
            after = merged.get(fact.key)
            (kept if after is None or after.seq == before.seq else superseded).append(fact.key)
        return MergeReport(
            added=tuple(sorted(added)),
            superseded=tuple(sorted(superseded)),
            kept=tuple(sorted(kept)),
            fragments=tuple(sorted(set(incoming.header.fragment_ids) - set(self.header.fragment_ids))),
        )

    def copy(self) -> FactStore:
        """
        A store holding the same facts, with containers of its own.

        Facts are immutable, so only the registries and indexes need duplicating. That is what
        lets a snapshot detach from a live store without paying for a deep copy.
        """
        clone = FactStore(self.header)
        clone.observables = dict(self.observables)
        clone.relations = dict(self.relations)
        clone.signals = dict(self.signals)
        clone.evidences = dict(self.evidences)
        clone.findings = dict(self.findings)
        clone.decisions = dict(self.decisions)
        clone.tags = dict(self.tags)
        clone._children = defaultdict(set, {key: set(value) for key, value in self._children.items()})
        clone._parents = defaultdict(set, {key: set(value) for key, value in self._parents.items()})
        clone._signals_by_subject = defaultdict(
            set, {key: set(value) for key, value in self._signals_by_subject.items()}
        )
        return clone

    def keys(self) -> Iterator[str]:
        yield from (fact.key for fact in self.all_facts())

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
        return _ordered(self.signals[key] for key in self._signals_by_subject.get(observable_key, ()))

    def child_relations(self, observable_key: str) -> list[Relation]:
        """Outgoing relations, i.e. the observables this one is the parent of."""
        return _ordered(self.relations[key] for key in self._children.get(observable_key, ()))

    def parent_relations(self, observable_key: str) -> list[Relation]:
        return _ordered(self.relations[key] for key in self._parents.get(observable_key, ()))

    def decision_for(self, target_key: str) -> Decision | None:
        """
        The single decision standing on a target, if any.

        Keys carry the target alone, so the store holds at most one decision per target and the
        merge law has already settled which stance is current. No arbitration is left to callers,
        and no secondary index is needed — the primary key already answers the question.
        """
        return self.decisions.get(generate_decision_key(target_key))

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


__all__ = ["FactStore", "InvestigationHeader", "MergeReport", "resolve_conflict"]
