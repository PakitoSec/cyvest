"""
Read-only views over facts, with the derived values pulled from the report.

A proxy holds a key, not an object: facts are immutable and superseded rather than edited, so
resolving on every access is what keeps a proxy from going stale. Fluent methods append new facts
and return a proxy on the result.

``.level`` is gone — the ``Verdict`` *is* the level, and keeping two names for one value would
reintroduce the confusion v7 exists to remove.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from cyvest.enums import DecisionKind, Effect, LinkBasis, RelationKind, SourceClass, Status, Tactic, Verdict
from cyvest.evaluation.projection import verdict_from_score
from cyvest.evaluation.report import CONCLUSION_BOUND_LABELS, Contribution, FindingResult, ObservableResult
from cyvest.facts import (
    Decision,
    Evidence,
    Fact,
    Finding,
    Label,
    Observable,
    ObservableAlias,
    ObservableSignal,
    SourceRef,
    Tag,
    Taxonomy,
    ThreatIntel,
)

if TYPE_CHECKING:
    from cyvest.investigation import Investigation

_T = TypeVar("_T", bound=Fact)
# Annotates the fluent return of the shared decision methods: each concrete proxy gets itself
# back, not the mixin.
_D = TypeVar("_D", bound="_DecidableProxy[Any]")


class ModelNotFoundError(RuntimeError):
    """Raised when a proxy points at a key the store no longer holds."""


class _ReadOnlyProxy(Generic[_T]):
    """Base view. Attribute assignment is refused so a caller cannot fake an edit."""

    __slots__ = ("_investigation", "_key")

    def __init__(self, investigation: Investigation, key: str) -> None:
        object.__setattr__(self, "_investigation", investigation)
        object.__setattr__(self, "_key", key)

    @property
    def key(self) -> str:
        return self._key

    @property
    def investigation(self) -> Investigation:
        return self._investigation

    def _resolve(self) -> _T:  # pragma: no cover - overridden
        raise NotImplementedError

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError(f"{type(self).__name__} is read-only; facts are superseded, not edited")

    def __delattr__(self, name: str) -> None:
        raise AttributeError(f"{type(self).__name__} is read-only")

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and other.key == self.key

    def __hash__(self) -> int:
        return hash((type(self).__name__, self._key))

    def __repr__(self) -> str:
        return f"{type(self).__name__}(key={self._key!r})"


class _JudgedProxy(_ReadOnlyProxy[_T]):
    """Shared read side for facts that carry a judgment."""

    __slots__ = ()

    @property
    def verdict(self) -> Verdict:
        """The **asserted** verdict. The computed one lives on the result."""
        return self._resolve().verdict

    @property
    def confidence(self) -> float:
        return self._resolve().confidence

    @property
    def weight(self) -> float | None:
        return self._resolve().weight


class _DecidableProxy(_ReadOnlyProxy[_T]):
    """
    The decision surface shared by the two families a stance can be taken on.

    The named verbs (``allowlist``, ``dismiss``, …) live on the concrete proxies, because the
    word an analyst uses depends on what is being decided. What they all reduce to is here.
    """

    __slots__ = ()

    @property
    def decision(self) -> Decision | None:
        """The stance standing on this fact, if any — a single lookup, not a scan."""
        return self._investigation.get_decision(self._key)

    def _is(self, kind: DecisionKind) -> bool:
        decision = self.decision
        return decision is not None and decision.kind is kind

    @property
    def decided(self) -> bool:
        """Whether a stance currently constrains this fact. A vacated one does not."""
        decision = self.decision
        return decision is not None and decision.kind.bounds

    @property
    def vacated(self) -> bool:
        return self._is(DecisionKind.VACATED)

    def decide(
        self: _D,
        kind: DecisionKind | str,
        justification: str,
        *,
        decided_by: str | None = None,
        source: SourceRef | None = None,
        occurred_at: datetime | None = None,
    ) -> _D:
        """
        Take a stance, with the kind carried as data.

        The named verbs read better when the kind is known as you write; this is the path for
        code that replays a feed or imports a corporate list, where it is a variable.
        """
        if source is None and decided_by is not None:
            source = SourceRef(name=decided_by, source_class=SourceClass.ORG_ANALYST)
        self._investigation.add_decision(
            self._key,
            kind,
            justification,
            source=source,
            occurred_at=occurred_at,
        )
        return self

    def vacate(
        self: _D,
        justification: str,
        *,
        decided_by: str | None = None,
        source: SourceRef | None = None,
        occurred_at: datetime | None = None,
    ) -> _D:
        """
        Withdraw the stance and let the computation speak again.

        Not the same as deciding the opposite: asserting ``blocklist`` to undo an ``allowlist``
        would claim the target is malicious, which is a different statement — and usually a lie.
        """
        return self.decide(
            DecisionKind.VACATED,
            justification,
            decided_by=decided_by,
            source=source,
            occurred_at=occurred_at,
        )


class ObservableProxy(_DecidableProxy[Observable]):
    """An observable, plus its result in a chosen scope."""

    __slots__ = ()

    def _resolve(self) -> Observable:
        found = self._investigation.get_observable(self._key)
        if found is None:
            raise ModelNotFoundError(f"Observable no longer in the store: {self._key}")
        return found

    @property
    def obs_type(self):  # noqa: ANN201 - mirrors the fact's own union type
        return self._resolve().obs_type

    @property
    def value(self) -> str:
        return self._resolve().value

    @property
    def subtype(self):  # noqa: ANN201
        return self._resolve().subtype

    @property
    def namespace(self) -> str | None:
        return self._resolve().namespace

    @property
    def internal(self) -> bool:
        return self._resolve().internal

    @property
    def comment(self) -> str:
        return self._resolve().comment

    @property
    def extra(self) -> dict[str, Any]:
        return self._resolve().extra

    @property
    def aliases(self) -> tuple[ObservableAlias, ...]:
        return self._resolve().aliases

    @property
    def occurrence_count(self) -> int:
        return self._resolve().occurrence_count

    def result(self) -> ObservableResult | None:
        return self._investigation.report.observable(self._key)

    @property
    def score(self) -> float:
        result = self.result()
        return result.score if result is not None and result.score is not None else 0.0

    @property
    def verdict(self) -> Verdict:
        """Computed, not asserted: an observable states nothing by itself."""
        result = self.result()
        return result.verdict if result is not None else Verdict.INFO

    @property
    def contributions(self) -> tuple[Contribution, ...]:
        result = self.result()
        return result.contributions if result is not None else ()

    @property
    def allowlisted(self) -> bool:
        return self._is(DecisionKind.REFUTE)

    @property
    def blocklisted(self) -> bool:
        return self._is(DecisionKind.UPHOLD)

    @property
    def suppressed_by_decision(self) -> bool:
        """Whether a decision actually changed this observable's score."""
        result = self.result()
        return result.suppressed_by_decision if result is not None else False

    @property
    def threat_intels(self) -> list[ThreatIntel]:
        return [s for s in self._investigation.store.signals_for(self._key) if isinstance(s, ThreatIntel)]

    def with_ti(
        self,
        threat_intel: ThreatIntel | dict[str, Any] | str,
        weight: float | None = None,
        comment: str = "",
        *,
        verdict: Verdict | str | None = None,
        confidence: float = 1.0,
        source_class: SourceClass = SourceClass.VENDOR_FEED,
        **kwargs: Any,
    ) -> ObservableProxy:
        """
        Attach a signal and return the observable, so calls chain.

        Accepts a built ``ThreatIntel``, a draft dict, or the short form ``with_ti("VT", 6.0)``.
        In the short form the verdict is **derived from the weight's own band** — the two are the
        same scale since v7 merged ``Level`` into ``Verdict``, so stating both would be redundant.
        """
        if isinstance(threat_intel, str):
            resolved_weight = 0.0 if weight is None else float(weight)
            threat_intel = ThreatIntel(
                subject_key=self._key,
                verdict=Verdict(verdict)
                if isinstance(verdict, str)
                else (verdict or verdict_from_score(resolved_weight)),
                weight=abs(resolved_weight),
                confidence=confidence,
                comment=comment,
                source=SourceRef(name=threat_intel, source_class=source_class),
                fragment_id=self._investigation.fragment_id,
                **kwargs,
            )
        elif isinstance(threat_intel, dict):
            draft = dict(threat_intel)
            source_name = draft.pop("source")
            draft_class = draft.pop("source_class", source_class)
            threat_intel = ThreatIntel(
                subject_key=self._key,
                source=SourceRef(name=source_name, source_class=draft_class),
                fragment_id=self._investigation.fragment_id,
                **draft,
            )
        self._investigation.add_threat_intel(threat_intel)
        return self

    def signal(self, source: str) -> ThreatIntelProxy | None:
        """The signal this observable holds from a given source, if any."""
        for candidate in self.threat_intels:
            if candidate.source.name == source:
                return ThreatIntelProxy(self._investigation, candidate.key)
        return None

    def relate_to(
        self,
        target: ObservableProxy | Observable | str,
        kind: RelationKind | str = RelationKind.RELATED_TO,
        **kwargs: Any,
    ) -> ObservableProxy:
        target_key = target.key if isinstance(target, (ObservableProxy, Observable)) else target
        self._investigation.add_relation(self._key, target_key, kind, **kwargs)
        return self

    def allowlist(
        self,
        justification: str,
        *,
        decided_by: str | None = None,
        source: SourceRef | None = None,
        occurred_at: datetime | None = None,
    ) -> ObservableProxy:
        """Cap this observable's score, whatever the signals say."""
        return self.decide(
            DecisionKind.REFUTE,
            justification,
            decided_by=decided_by,
            source=source,
            occurred_at=occurred_at,
        )

    def blocklist(
        self,
        justification: str,
        *,
        decided_by: str | None = None,
        source: SourceRef | None = None,
        occurred_at: datetime | None = None,
    ) -> ObservableProxy:
        """Raise this observable's score to the policy floor, whatever the signals say."""
        return self.decide(
            DecisionKind.UPHOLD,
            justification,
            decided_by=decided_by,
            source=source,
            occurred_at=occurred_at,
        )


class FindingProxy(_DecidableProxy[Finding], _JudgedProxy[Finding]):
    """A finding, plus its result."""

    __slots__ = ()

    def _resolve(self) -> Finding:
        found = self._investigation.get_finding(self._key)
        if found is None:
            raise ModelNotFoundError(f"Finding no longer in the store: {self._key}")
        return found

    @property
    def rule_id(self) -> str:
        return self._resolve().rule_id

    @property
    def name(self) -> str:
        finding = self._resolve()
        return finding.name or finding.rule_id

    @property
    def comment(self) -> str:
        return self._resolve().comment

    @property
    def extra(self) -> dict[str, Any]:
        return self._resolve().extra

    @property
    def status(self) -> Status:
        return self._resolve().status

    @property
    def effect(self) -> Effect:
        return self._resolve().effect

    @property
    def is_conclusion(self) -> bool:
        return self._resolve().effect.concludes

    @property
    def observable_links(self) -> tuple:
        return self._resolve().observable_links

    @property
    def evidence_keys(self) -> tuple[str, ...]:
        return self._resolve().evidence_keys

    @property
    def labels(self) -> tuple[Label, ...]:
        return self._resolve().labels

    @property
    def tactic(self) -> Tactic | None:
        """The ATT&CK tactic the finding demonstrates, if it states one."""
        return self._resolve().tactic

    @property
    def occurred_at(self) -> datetime | None:
        """When the activity the finding describes happened; ``None`` when the finding is undated."""
        return self._resolve().occurred_at

    def with_tactic(self, tactic: Tactic | str | None) -> FindingProxy:
        resolved = Tactic(tactic) if isinstance(tactic, str) else tactic
        self._investigation.supersede(self._resolve(), tactic=resolved)
        return self

    def dated(self, occurred_at: datetime) -> FindingProxy:
        """Re-assert the finding with the time the activity it describes happened."""
        self._investigation.supersede(self._resolve(), occurred_at=occurred_at)
        return self

    def result(self) -> FindingResult | None:
        return self._investigation.report.finding(self._key)

    @property
    def score(self) -> float:
        """The finding's own magnitude — always ``0.0`` for a conclusion, see :attr:`applied_bound`."""
        result = self.result()
        return result.score if result is not None and result.score is not None else 0.0

    @property
    def applied_bound(self) -> float:
        """How much this conclusion moved the total: positive for a floor, negative for a ceiling."""
        if not self.is_conclusion:
            return 0.0
        for contribution in self._investigation.report.investigation.contributions:
            if contribution.source_key == self._key and contribution.label.startswith(CONCLUSION_BOUND_LABELS):
                return contribution.value
        return 0.0

    @property
    def computed_verdict(self) -> Verdict:
        """What the engine concluded, as opposed to :attr:`verdict`, which is what the rule claims."""
        result = self.result()
        return result.verdict if result is not None else Verdict.INFO

    @property
    def contributions(self) -> tuple[Contribution, ...]:
        result = self.result()
        return result.contributions if result is not None else ()

    @property
    def own_term_suppressed(self) -> bool:
        """True when the rule's own claim was outweighed by one of its observables."""
        result = self.result()
        return result.own_term_suppressed if result is not None else False

    def link_observable(
        self,
        observable: ObservableProxy | Observable | str,
        basis: LinkBasis | str = LinkBasis.OBSERVABLE,
        signal_keys: Sequence[str] = (),
    ) -> FindingProxy:
        key = observable.key if isinstance(observable, (ObservableProxy, Observable)) else observable
        self._investigation.link_finding_observable(self._key, key, basis, signal_keys)
        return self

    def pin(self, *signals: ThreatIntelProxy | ObservableSignal | str) -> FindingProxy:
        """
        Score this finding on the signals it fetched, and on nothing else.

        The observable is derived from the signals, so it is never restated. Later intel on that
        observable — and anything its children pick up — leaves this finding where it stands.
        """
        resolved = [s.key if isinstance(s, (ThreatIntelProxy, ObservableSignal)) else s for s in signals]
        self._investigation.pin_finding_signals(self._key, *resolved)
        return self

    def link_evidence(self, evidence: EvidenceProxy | Evidence | str) -> FindingProxy:
        key = evidence.key if isinstance(evidence, (EvidenceProxy, Evidence)) else evidence
        self._investigation.link_finding_evidence(self._key, key)
        return self

    def tagged(self, *tags: TagProxy | Tag | str) -> FindingProxy:
        """Tag by name or key; an unknown name is created, ancestors included."""
        from cyvest import keys as key_utils
        from cyvest.facts import Tag as TagFact

        for tag in tags:
            if isinstance(tag, (TagProxy, Tag)):
                key = tag.key
            else:
                key = tag if tag.startswith("tag:") else key_utils.generate_tag_key(tag)
                if self._investigation.get_tag(key) is None:
                    name = key.removeprefix("tag:")
                    self._investigation.add_tag(
                        TagFact(
                            name=name,
                            source=self._resolve().source,
                            fragment_id=self._investigation.fragment_id,
                        )
                    )
            self._investigation.add_finding_to_tag(key, self._key)
        return self

    def with_weight(self, weight: float) -> FindingProxy:
        """
        Set the weight, and let it name the verdict when none was stated.

        Without this, ``finding("x").with_weight(8.5)`` would keep the default ``INFO`` — a
        verdict that claims nothing, so the finding would score ``0`` despite carrying a weight of
        8.5. An explicit verdict is left alone: changing a magnitude must not flip a conclusion.

        A negative weight names an exculpatory verdict; the magnitude stored stays unsigned, the
        sign living in the verdict alone. Weighting a conclusion is refused by the model.
        """
        current = self._resolve()
        updates: dict[str, Any] = {"weight": abs(float(weight))}
        if current.verdict is Verdict.INFO:
            updates["verdict"] = verdict_from_score(float(weight))
        self._investigation.supersede(current, **updates)
        return self

    def describe(
        self,
        *,
        name: str | None = None,
        comment: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> FindingProxy:
        """
        Re-assert what this finding says about itself, leaving its judgment untouched.

        A rule usually creates its finding before it knows the answer, then fills in the story it
        tells. Each argument replaces its field outright; omitted ones are left alone. ``extra``
        is not merged — a rule that means to merge already holds the previous value.
        """
        updates: dict[str, Any] = {}
        if name is not None:
            updates["name"] = name
        if comment is not None:
            updates["comment"] = comment
        if extra is not None:
            updates["extra"] = extra
        if updates:
            self._investigation.supersede(self._resolve(), **updates)
        return self

    def set_verdict(self, verdict: Verdict | str, confidence: float | None = None) -> FindingProxy:
        updates: dict[str, Any] = {"verdict": Verdict(verdict) if isinstance(verdict, str) else verdict}
        if confidence is not None:
            updates["confidence"] = float(confidence)
        self._investigation.supersede(self._resolve(), **updates)
        return self

    def confirm(
        self,
        justification: str,
        *,
        decided_by: str | None = None,
        source: SourceRef | None = None,
        occurred_at: datetime | None = None,
    ) -> FindingProxy:
        """Hold this claim as established, and score it at the policy floor."""
        return self.decide(
            DecisionKind.UPHOLD,
            justification,
            decided_by=decided_by,
            source=source,
            occurred_at=occurred_at,
        )

    def dismiss(
        self,
        justification: str,
        *,
        decided_by: str | None = None,
        source: SourceRef | None = None,
        occurred_at: datetime | None = None,
    ) -> FindingProxy:
        """Take this claim out of the evaluation. It stays in the report, uncounted."""
        return self.decide(
            DecisionKind.REFUTE,
            justification,
            decided_by=decided_by,
            source=source,
            occurred_at=occurred_at,
        )

    @property
    def confirmed(self) -> bool:
        return self._is(DecisionKind.UPHOLD)

    @property
    def dismissed(self) -> bool:
        return self._is(DecisionKind.REFUTE)

    @property
    def suppressed_by_decision(self) -> bool:
        """Whether a decision actually changed this finding's outcome."""
        result = self.result()
        return result.suppressed_by_decision if result is not None else False


class ThreatIntelProxy(_JudgedProxy[ThreatIntel]):
    """A threat-intel signal."""

    __slots__ = ()

    def _resolve(self) -> ThreatIntel:
        found = self._investigation.get_threat_intel(self._key)
        if found is None:
            raise ModelNotFoundError(f"Threat intel no longer in the store: {self._key}")
        return found

    @property
    def source(self) -> str:
        return self._resolve().source.name

    @property
    def subject_key(self) -> str:
        return self._resolve().subject_key

    @property
    def source_class(self):  # noqa: ANN201
        return self._resolve().source_class

    @property
    def taxonomies(self) -> tuple[Taxonomy, ...]:
        return self._resolve().taxonomies

    def add_taxonomy(
        self,
        taxonomy: Taxonomy | str | None = None,
        *,
        name: str | None = None,
        value: str = "",
        verdict: Verdict | str = Verdict.INFO,
    ) -> ThreatIntelProxy:
        """Add an object or named fields. An existing name is updated, not duplicated."""
        if taxonomy is not None:
            if name is not None or value != "" or verdict != Verdict.INFO:
                raise ValueError("Pass a taxonomy or its fields, not both")
        elif name is not None:
            taxonomy = Taxonomy(name=name, value=value, verdict=Verdict(verdict))
        else:
            raise ValueError("Pass a taxonomy or its name")
        self._investigation.add_threat_intel_taxonomy(self._key, taxonomy)
        return self

    def remove_taxonomy(self, name: str) -> ThreatIntelProxy:
        self._investigation.remove_threat_intel_taxonomy(self._key, name)
        return self

    @property
    def comment(self) -> str:
        return self._resolve().comment

    @property
    def payload(self) -> dict[str, Any]:
        return self._resolve().payload

    @property
    def observed_at(self):  # noqa: ANN201
        return self._resolve().observed_at


class EvidenceProxy(_ReadOnlyProxy[Evidence]):
    """A captured artefact."""

    __slots__ = ()

    def _resolve(self) -> Evidence:
        found = self._investigation.get_evidence(self._key)
        if found is None:
            raise ModelNotFoundError(f"Evidence no longer in the store: {self._key}")
        return found

    @property
    def evidence_type(self) -> str:
        return self._resolve().evidence_type

    @property
    def title(self) -> str:
        return self._resolve().title

    @property
    def content(self) -> Any:
        return self._resolve().content

    @property
    def uri(self) -> str | None:
        return self._resolve().uri

    @property
    def source(self) -> str:
        return self._resolve().source.name

    @property
    def external_id(self) -> str | None:
        return self._resolve().external_id

    @property
    def captured_at(self):  # noqa: ANN201
        return self._resolve().captured_at


class TagProxy(_ReadOnlyProxy[Tag]):
    """A tag, with its scores read from the report."""

    __slots__ = ()

    def _resolve(self) -> Tag:
        found = self._investigation.get_tag(self._key)
        if found is None:
            raise ModelNotFoundError(f"Tag no longer in the store: {self._key}")
        return found

    @property
    def name(self) -> str:
        return self._resolve().name

    @property
    def description(self) -> str:
        return self._resolve().description

    @property
    def finding_keys(self) -> tuple[str, ...]:
        """Keys, not objects: a tag references findings, it does not own copies of them."""
        return self._resolve().finding_keys

    @property
    def direct_score(self) -> float:
        return self._investigation.get_tag_direct_score(self.name)

    @property
    def aggregated_score(self) -> float:
        return self._investigation.get_tag_aggregated_score(self.name)

    @property
    def aggregated_verdict(self) -> Verdict:
        return self._investigation.get_tag_aggregated_verdict(self.name)

    def children(self) -> list[TagProxy]:
        return [TagProxy(self._investigation, tag.key) for tag in self._investigation.get_tag_children(self.name)]

    def descendants(self) -> list[TagProxy]:
        return [TagProxy(self._investigation, tag.key) for tag in self._investigation.get_tag_descendants(self.name)]

    def ancestors(self) -> list[TagProxy]:
        return [TagProxy(self._investigation, tag.key) for tag in self._investigation.get_tag_ancestors(self.name)]


class DecisionProxy(_ReadOnlyProxy[Decision]):
    """A named override, kept visible so the report can explain what was overridden."""

    __slots__ = ()

    def _resolve(self) -> Decision:
        found = self._investigation.store.decisions.get(self._key)
        if found is None:
            raise ModelNotFoundError(f"Decision no longer in the store: {self._key}")
        return found

    @property
    def target_key(self) -> str:
        return self._resolve().target_key

    @property
    def kind(self) -> DecisionKind:
        return self._resolve().kind

    @property
    def justification(self) -> str | None:
        return self._resolve().justification

    @property
    def decided_by(self) -> str:
        """Who decided, read from the fact envelope rather than a duplicated field."""
        return self._resolve().source.name

    @property
    def decided_at(self):  # noqa: ANN201
        fact = self._resolve()
        return fact.occurred_at or fact.asserted_at


__all__ = [
    "DecisionProxy",
    "EvidenceProxy",
    "FindingProxy",
    "ModelNotFoundError",
    "ObservableProxy",
    "TagProxy",
    "ThreatIntelProxy",
]
