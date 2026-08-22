"""
Read-only views over facts, with the derived values pulled from the report.

A proxy holds a key, not an object: facts are immutable and superseded rather than edited, so
resolving on every access is what keeps a proxy from going stale. Fluent methods append new facts
and return a proxy on the result.

``.level`` is gone — the ``Verdict`` *is* the level, and keeping two names for one value would
reintroduce the confusion v7 exists to remove.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generic, TypeVar

from cyvest.enums import DecisionKind, Effect, RelationKind, Scope, SourceClass, Status, Verdict
from cyvest.evaluation import ResolvedScope
from cyvest.evaluation.projection import verdict_from_score
from cyvest.evaluation.report import Contribution, FindingResult, ObservableResult
from cyvest.facts import (
    Decision,
    Evidence,
    Fact,
    Finding,
    Label,
    Observable,
    ObservableAlias,
    SourceRef,
    Tag,
    ThreatIntel,
)

if TYPE_CHECKING:
    from cyvest.investigation import Investigation

_T = TypeVar("_T", bound=Fact)


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

    @property
    def subject_key(self) -> str:
        return self._resolve().subject_key


class ObservableProxy(_ReadOnlyProxy[Observable]):
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

    def result(self, scope: ResolvedScope | None = None) -> ObservableResult | None:
        return self._investigation.report.observable(self._key, scope)

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
        return any(d.kind is DecisionKind.ALLOWLISTED for d in self._investigation.get_decisions(self._key))

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

    def allowlist(self, justification: str | None = None) -> ObservableProxy:
        self._investigation.add_decision(self._key, DecisionKind.ALLOWLISTED, justification=justification)
        return self

    def blocklist(self, justification: str | None = None) -> ObservableProxy:
        self._investigation.add_decision(self._key, DecisionKind.BLOCKLISTED, justification=justification)
        return self


class FindingProxy(_JudgedProxy[Finding]):
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
        return self._resolve().effect is Effect.FLOOR

    @property
    def observable_links(self) -> tuple:
        return self._resolve().observable_links

    @property
    def evidence_keys(self) -> tuple[str, ...]:
        return self._resolve().evidence_keys

    @property
    def labels(self) -> tuple[Label, ...]:
        return self._resolve().labels

    def result(self) -> FindingResult | None:
        return self._investigation.report.finding(self._key)

    @property
    def score(self) -> float:
        """The finding's own magnitude — always ``0.0`` for a conclusion, see :attr:`applied_floor`."""
        result = self.result()
        return result.score if result is not None and result.score is not None else 0.0

    @property
    def applied_floor(self) -> float:
        """How much this conclusion actually lifted the total; ``0.0`` once the verdict was reached."""
        if not self.is_conclusion:
            return 0.0
        for contribution in self._investigation.report.investigation.contributions:
            if contribution.source_key == self._key and contribution.label.startswith("conclusion floor"):
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
        scope: Scope | str = Scope.OWN_FRAGMENT,
    ) -> FindingProxy:
        key = observable.key if isinstance(observable, (ObservableProxy, Observable)) else observable
        self._investigation.link_finding_observable(self._key, key, scope)
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

    def set_verdict(self, verdict: Verdict | str, confidence: float | None = None) -> FindingProxy:
        updates: dict[str, Any] = {"verdict": Verdict(verdict) if isinstance(verdict, str) else verdict}
        if confidence is not None:
            updates["confidence"] = float(confidence)
        self._investigation.supersede(self._resolve(), **updates)
        return self

    def confirm(self, justification: str | None = None) -> FindingProxy:
        self._investigation.add_decision(self._key, DecisionKind.CONFIRMED, justification=justification)
        return self

    def dismiss(self, justification: str | None = None) -> FindingProxy:
        self._investigation.add_decision(self._key, DecisionKind.DISMISSED, justification=justification)
        return self


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
    def source_class(self):  # noqa: ANN201
        return self._resolve().source_class

    @property
    def taxonomies(self) -> tuple[str, ...]:
        return self._resolve().taxonomies

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
