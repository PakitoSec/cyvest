"""
The public facade.

Thin by design: it builds facts, hands them to the investigation, and returns proxies. No
scoring lives here — scores come from the report, which is recomputed rather than stored.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, overload

from logurich import get_logger

from cyvest import keys
from cyvest.enums import (
    Confidence,
    DecisionKind,
    Effect,
    ObservableSubtype,
    ObservableType,
    RelationKind,
    Scope,
    SourceClass,
    Status,
    Verdict,
    Weight,
)
from cyvest.evaluation import Report, ResolvedScope
from cyvest.evaluation.engines import available_aliases, available_engines
from cyvest.evaluation.projection import verdict_from_score
from cyvest.evaluation.timeline import TimelineEntry
from cyvest.facts import (
    Evidence,
    Finding,
    Label,
    Observable,
    ObservableAlias,
    ObservableIdentity,
    SourceRef,
    Tag,
    ThreatIntel,
)
from cyvest.investigation import DEFAULT_SOURCE, Investigation
from cyvest.policy import DEFAULT_POLICY, Policy
from cyvest.proxies import (
    DecisionProxy,
    EvidenceProxy,
    FindingProxy,
    ObservableProxy,
    TagProxy,
    ThreatIntelProxy,
)
from cyvest.resolvers import ObservableResolution, ObservableResolver, ObservableResolverResult
from cyvest.signal_schema import SignalEnvelope
from cyvest.stats import InvestigationStats, StatisticsSchema

if TYPE_CHECKING:
    from cyvest.shared import SharedInvestigationContext

logger = get_logger(__name__)


def _deep_merge_dict(base: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    for key, value in update.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge_dict(base[key], value)
        else:
            base[key] = deepcopy(value)
    return base


class Cyvest:
    """Build an investigation, then read its report."""

    OBS: Final[type[ObservableType]] = ObservableType
    SUB: Final[type[ObservableSubtype]] = ObservableSubtype
    REL: Final[type[RelationKind]] = RelationKind
    SCOPE: Final[type[Scope]] = Scope
    VERDICT: Final[type[Verdict]] = Verdict
    WEIGHT: Final[type[Weight]] = Weight
    CONF: Final[type[Confidence]] = Confidence
    DECISION: Final[type[DecisionKind]] = DecisionKind
    STATUS: Final[type[Status]] = Status
    EFFECT: Final[type[Effect]] = Effect
    SRC: Final[type[SourceClass]] = SourceClass

    def __init__(
        self,
        root_data: Any = None,
        root_type: ObservableType | Literal["file", "artifact"] = ObservableType.FILE,
        *,
        policy: Policy | None = None,
        engine: str | None = None,
        investigation_name: str | None = None,
        investigation_id: str | None = None,
    ) -> None:
        self._investigation = Investigation(
            root_data,
            root_type=root_type,
            policy=policy or DEFAULT_POLICY,
            engine=engine,
            investigation_name=investigation_name,
            investigation_id=investigation_id,
        )
        self._observable_resolvers: list[ObservableResolver] = []

    # ------------------------------------------------------------------ engines

    @staticmethod
    def ENGINES() -> dict[str, str]:
        """Registered engines and the aliases pointing at them."""
        return {**{name: name for name in available_engines()}, **available_aliases()}

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _key_of(value: Any) -> str:
        return value.key if hasattr(value, "key") else str(value)

    @staticmethod
    def _judgment(verdict: Verdict | str | None, weight: float | None) -> tuple[Verdict, float | None]:
        """
        Complete a judgment from whichever half the caller gave.

        Weight and verdict are the same scale since v7 merged ``Level`` into ``Verdict``, so each
        one implies the other and stating both is optional:

        - a verdict alone takes the weight of its band (``policy.weight_by_verdict``);
        - a weight alone takes the verdict of its band, sign included.

        Without this, ``weight=8.5`` with no verdict would score ``0`` — the mirror image of the
        footgun that made ``verdict=MALICIOUS`` with no weight report ``INFO``.
        """
        if verdict is not None:
            return (Verdict(verdict) if isinstance(verdict, str) else verdict), weight
        if weight is None:
            return Verdict.INFO, None
        return verdict_from_score(float(weight)), abs(float(weight))

    def _fragment(self) -> str:
        return self._investigation.fragment_id

    def _source(self, name: str | None = None, source_class: SourceClass | None = None) -> SourceRef:
        if name is None:
            return DEFAULT_SOURCE
        return SourceRef(name=name, source_class=source_class or SourceClass.UNKNOWN)

    # ------------------------------------------------------------------ investigation

    def investigation_get_name(self) -> str:
        return self._investigation.investigation_name

    def investigation_set_name(self, name: str | None) -> None:
        self._investigation.set_investigation_name(name)

    @property
    def investigation_id(self) -> str:
        return self._investigation.investigation_id

    # ------------------------------------------------------------------ resolvers

    @staticmethod
    def _normalized_source_type(
        obs_type: ObservableType | str,
        subtype: ObservableSubtype | str | None,
    ) -> tuple[str, str | None]:
        normalized_type = obs_type.value if isinstance(obs_type, ObservableType) else str(obs_type).strip().lower()
        normalized_subtype = subtype.value if isinstance(subtype, ObservableSubtype) else subtype
        if isinstance(normalized_subtype, str):
            normalized_subtype = normalized_subtype.strip().lower()
        return normalized_type, normalized_subtype

    @classmethod
    def _resolver_applies(cls, resolver: ObservableResolver, alias: ObservableAlias) -> bool:
        alias_source_type = cls._normalized_source_type(alias.obs_type, alias.subtype)
        return any(
            cls._normalized_source_type(obs_type, subtype) == alias_source_type
            for obs_type, subtype in resolver.source_types
        )

    def observable_resolver_register(self, resolver: ObservableResolver, *, replace: bool = False) -> None:
        if not isinstance(resolver, ObservableResolver):
            raise TypeError("resolver must be an ObservableResolver.")
        existing = next((i for i, item in enumerate(self._observable_resolvers) if item.name == resolver.name), None)
        if existing is not None:
            if not replace:
                raise ValueError(f"Observable resolver '{resolver.name}' is already registered.")
            self._observable_resolvers[existing] = resolver
            return
        self._observable_resolvers.append(resolver)

    def observable_resolver_unregister(self, name: str) -> bool:
        normalized = name.strip()
        for index, resolver in enumerate(self._observable_resolvers):
            if resolver.name == normalized:
                del self._observable_resolvers[index]
                return True
        return False

    def observable_resolver_clear(self) -> None:
        self._observable_resolvers.clear()

    def observable_resolver_get_all(self) -> tuple[ObservableResolver, ...]:
        return tuple(self._observable_resolvers)

    @staticmethod
    def _normalize_resolution(resolved: ObservableResolverResult) -> ObservableResolution | None:
        if resolved is None:
            return None
        if isinstance(resolved, ObservableResolution):
            return ObservableResolution.model_validate(resolved)
        return ObservableResolution(identity=ObservableIdentity.model_validate(resolved))

    def _resolve_identity_sync(self, alias: ObservableAlias) -> tuple[str, ObservableResolution] | None:
        for resolver in self._observable_resolvers:
            if self._resolver_applies(resolver, alias) and resolver.aresolve is not None:
                raise RuntimeError(
                    f"Observable resolver '{resolver.name}' is async; use 'await cv.observable_acreate(...)'."
                )
        for resolver in self._observable_resolvers:
            if not self._resolver_applies(resolver, alias) or resolver.resolve is None:
                continue
            resolution = self._normalize_resolution(resolver.resolve(alias))
            if resolution is not None:
                return resolver.name, resolution
        return None

    async def _resolve_identity_async(self, alias: ObservableAlias) -> tuple[str, ObservableResolution] | None:
        for resolver in self._observable_resolvers:
            if not self._resolver_applies(resolver, alias):
                continue
            resolved: ObservableResolverResult = None
            if resolver.resolve is not None:
                resolved = resolver.resolve(alias)
            elif resolver.aresolve is not None:
                resolved = await resolver.aresolve(alias)
            resolution = self._normalize_resolution(resolved)
            if resolution is not None:
                return resolver.name, resolution
        return None

    @staticmethod
    def _extra_with_resolution(
        extra: dict[str, Any] | None,
        resolved: tuple[str, ObservableResolution] | None,
    ) -> dict[str, Any]:
        observable_extra = deepcopy(extra) if extra is not None else {}
        resolver_data = observable_extra.get("resolver_data")
        if resolver_data is not None and not isinstance(resolver_data, dict):
            raise ValueError("Observable extra field 'resolver_data' must be a dictionary.")
        if resolved is None:
            return observable_extra
        resolver_name, resolution = resolved
        if not resolution.metadata:
            return observable_extra
        if resolver_data is None:
            resolver_data = {}
            observable_extra["resolver_data"] = resolver_data
        _deep_merge_dict(resolver_data, {resolver_name: resolution.metadata})
        return observable_extra

    def _create_from_identity(
        self,
        *,
        alias: ObservableAlias,
        resolved: tuple[str, ObservableResolution] | None,
        internal: bool,
        comment: str,
        extra: dict[str, Any] | None,
    ) -> ObservableProxy:
        source_identity = ObservableIdentity(
            type=alias.obs_type,
            subtype=alias.subtype,
            namespace=alias.namespace,
            value=alias.value,
        )
        identity = resolved[1].identity if resolved is not None else source_identity
        fragment = self._fragment()
        # Counters are per fragment and merged by max, so re-merging a fragment cannot inflate the
        # tally. Within a fragment, though, seeing the same artifact twice is a real second
        # occurrence — so we count up from what this fragment has already recorded.
        seen = 0
        alias_seen = 0
        probe = Observable(
            type=identity.obs_type,
            subtype=identity.subtype,
            namespace=identity.namespace,
            value=identity.value,
            source=DEFAULT_SOURCE,
            fragment_id=fragment,
        )
        existing = self._investigation.get_observable(probe.key)
        if existing is not None:
            seen = existing.occurrences.get(fragment, 0)
            previous = next((a for a in existing.aliases if a.identity_tuple == alias.identity_tuple), None)
            if previous is not None:
                alias_seen = previous.counts.get(fragment, 0)
        # An alias keeps its own tally: it answers "how often did we see *this* spelling", which
        # is not the observable's total once several spellings resolve to the same canonical one.
        alias = alias.model_copy(update={"counts": {fragment: alias_seen + 1}})

        observable = Observable(
            type=identity.obs_type,
            subtype=identity.subtype,
            namespace=identity.namespace,
            value=identity.value,
            internal=internal,
            comment=comment,
            extra=self._extra_with_resolution(extra, resolved),
            aliases=(alias,) if resolved is not None else (),
            occurrences={fragment: seen + 1},
            source=DEFAULT_SOURCE,
            fragment_id=fragment,
        )
        stored = self._investigation.add_observable(observable)
        return ObservableProxy(self._investigation, stored.key)

    # ------------------------------------------------------------------ observables

    def observable_create(
        self,
        obs_type: ObservableType | str,
        value: str,
        subtype: ObservableSubtype | str | None = None,
        namespace: str | None = None,
        internal: bool = False,
        comment: str = "",
        extra: dict[str, Any] | None = None,
    ) -> ObservableProxy:
        """Create an observable, or return the existing one — identity is the quadruplet."""
        alias = ObservableAlias(type=obs_type, subtype=subtype, namespace=namespace, value=value)
        return self._create_from_identity(
            alias=alias,
            resolved=self._resolve_identity_sync(alias),
            internal=internal,
            comment=comment,
            extra=extra,
        )

    async def observable_acreate(
        self,
        obs_type: ObservableType | str,
        value: str,
        subtype: ObservableSubtype | str | None = None,
        namespace: str | None = None,
        internal: bool = False,
        comment: str = "",
        extra: dict[str, Any] | None = None,
    ) -> ObservableProxy:
        """Async variant, for resolvers that need to call out."""
        alias = ObservableAlias(type=obs_type, subtype=subtype, namespace=namespace, value=value)
        return self._create_from_identity(
            alias=alias,
            resolved=await self._resolve_identity_async(alias),
            internal=internal,
            comment=comment,
            extra=extra,
        )

    @overload
    def observable_get(self, key: str) -> ObservableProxy | None: ...

    @overload
    def observable_get(
        self,
        obs_type: ObservableType | str,
        value: str,
        subtype: ObservableSubtype | str | None = None,
        namespace: str | None = None,
    ) -> ObservableProxy | None: ...

    def observable_get(self, *args: Any, **kwargs: Any) -> ObservableProxy | None:
        found = self._investigation.get_observable(keys.resolve_observable_key(*args, **kwargs))
        return ObservableProxy(self._investigation, found.key) if found is not None else None

    def observable_get_root(self) -> ObservableProxy:
        return ObservableProxy(self._investigation, self._investigation.get_root().key)

    def observable_get_all(self) -> dict[str, ObservableProxy]:
        return {key: ObservableProxy(self._investigation, key) for key in self._investigation.get_all_observables()}

    def observable_add_relation(
        self,
        source: ObservableProxy | Observable | str,
        target: ObservableProxy | Observable | str,
        kind: RelationKind | str = RelationKind.RELATED_TO,
        *,
        confidence: float = 1.0,
        comment: str = "",
        observed_at: datetime | None = None,
    ) -> ObservableProxy:
        """``source`` is the parent, ``target`` the child; the kind implies the direction."""
        source_key = self._key_of(source)
        self._investigation.add_relation(
            source_key,
            self._key_of(target),
            kind,
            confidence=confidence,
            comment=comment,
            observed_at=observed_at,
        )
        return ObservableProxy(self._investigation, source_key)

    def observable_add_threat_intel(
        self,
        observable: ObservableProxy | Observable | str,
        source: str,
        *,
        verdict: Verdict | str = Verdict.INFO,
        weight: float | None = None,
        confidence: float = Confidence.HIGH.value,
        source_class: SourceClass = SourceClass.VENDOR_FEED,
        taxonomies: tuple[str, ...] = (),
        comment: str = "",
        payload: dict[str, Any] | None = None,
        observed_at: datetime | None = None,
        external_id: str | None = None,
    ) -> ThreatIntelProxy:
        """One signal per source and per observable — pass ``external_id`` to keep history."""
        resolved_verdict, resolved_weight = self._judgment(verdict, weight)
        signal = ThreatIntel(
            subject_key=self._key_of(observable),
            verdict=resolved_verdict,
            weight=resolved_weight,
            confidence=confidence,
            source_class=source_class,
            taxonomies=taxonomies,
            comment=comment,
            payload=payload or {},
            observed_at=observed_at,
            external_id=external_id,
            source=self._source(source, source_class),
            fragment_id=self._fragment(),
        )
        stored = self._investigation.add_threat_intel(signal)
        return ThreatIntelProxy(self._investigation, stored.key)

    def observable_set_verdict(
        self,
        observable: ObservableProxy | Observable | str,
        verdict: Verdict | str,
        *,
        confidence: float = Confidence.HIGH.value,
        weight: float | None = None,
        source: str = "analyst",
    ) -> ThreatIntelProxy:
        """
        Record an analyst's own verdict on an observable.

        An observable holds no verdict of its own in v7 — stating one means adding a signal whose
        source is the analyst, which keeps the claim attributable.
        """
        return self.observable_add_threat_intel(
            observable,
            source,
            verdict=verdict,
            weight=weight,
            confidence=confidence,
            source_class=SourceClass.ORG_ANALYST,
        )

    # ------------------------------------------------------------------ threat intel

    def threat_intel_get(self, key: str) -> ThreatIntelProxy | None:
        found = self._investigation.get_threat_intel(key)
        return ThreatIntelProxy(self._investigation, found.key) if found is not None else None

    def threat_intel_get_all(self) -> dict[str, ThreatIntelProxy]:
        return {key: ThreatIntelProxy(self._investigation, key) for key in self._investigation.get_all_threat_intels()}

    def threat_intel_add_taxonomy(self, threat_intel_key: str, taxonomy: str) -> ThreatIntelProxy:
        signal = self._investigation.get_threat_intel(threat_intel_key)
        if signal is None:
            raise KeyError(f"Unknown threat intel: {threat_intel_key}")
        if taxonomy not in signal.taxonomies:
            self._investigation.supersede(signal, taxonomies=(*signal.taxonomies, taxonomy))
        return ThreatIntelProxy(self._investigation, threat_intel_key)

    def threat_intel_remove_taxonomy(self, threat_intel_key: str, taxonomy: str) -> ThreatIntelProxy:
        signal = self._investigation.get_threat_intel(threat_intel_key)
        if signal is None:
            raise KeyError(f"Unknown threat intel: {threat_intel_key}")
        remaining = tuple(item for item in signal.taxonomies if item != taxonomy)
        if remaining != signal.taxonomies:
            self._investigation.supersede(signal, taxonomies=remaining)
        return ThreatIntelProxy(self._investigation, threat_intel_key)

    # ------------------------------------------------------------------ findings

    def finding_create(
        self,
        rule_id: str,
        name: str = "",
        comment: str = "",
        *,
        verdict: Verdict | str | None = None,
        weight: float | None = None,
        confidence: float = Confidence.HIGH.value,
        subject: ObservableProxy | Observable | str | None = None,
        status: Status = Status.EVALUATED,
        effect: Effect | str = Effect.ADDITIVE,
        labels: tuple[Label, ...] = (),
        extra: dict[str, Any] | None = None,
        external_id: str | None = None,
    ) -> FindingProxy:
        """
        Create a finding.

        Identity is ``(rule_id, subject)``: the same rule on two observables yields two findings,
        and the same rule on the same observable merges — which is why v6 needed
        ``origin_investigation_id`` and v7 does not.

        Stating a ``verdict`` or a ``weight`` alone is enough; each implies the other.
        """
        resolved_verdict, resolved_weight = self._judgment(verdict, weight)
        finding = Finding(
            rule_id=rule_id,
            name=name,
            comment=comment,
            verdict=resolved_verdict,
            weight=resolved_weight,
            confidence=confidence,
            subject_key=self._key_of(subject) if subject is not None else self._investigation.root_key,
            status=status,
            effect=Effect(effect) if isinstance(effect, str) else effect,
            labels=labels,
            extra=extra or {},
            external_id=external_id,
            source=DEFAULT_SOURCE,
            fragment_id=self._fragment(),
        )
        stored = self._investigation.add_finding(finding)
        return FindingProxy(self._investigation, stored.key)

    def conclusion_create(
        self,
        rule_id: str,
        name: str = "",
        comment: str = "",
        *,
        verdict: Verdict | str,
        confidence: float = Confidence.HIGH.value,
        subject: ObservableProxy | Observable | str | None = None,
        labels: tuple[Label, ...] = (),
        extra: dict[str, Any] | None = None,
        external_id: str | None = None,
    ) -> FindingProxy:
        """
        Create a conclusion: a finding that raises the total to the verdict it asserts.

        Meant for an analysis that already read the other findings — an LLM most of the time. It
        adds just enough to reach ``verdict``, and nothing at all when the investigation is
        already there, so several analysers can conclude without inflating each other.

        ``verdict`` is required and no ``weight`` is accepted: a conclusion's magnitude *is* the
        floor of its verdict.
        """
        return self.finding_create(
            rule_id,
            name,
            comment,
            verdict=verdict,
            confidence=confidence,
            subject=subject,
            effect=Effect.FLOOR,
            labels=labels,
            extra=extra or {},
            external_id=external_id,
        )

    def finding_get(self, key: str) -> FindingProxy | None:
        found = self._investigation.get_finding(key)
        return FindingProxy(self._investigation, found.key) if found is not None else None

    def finding_get_all(self) -> dict[str, FindingProxy]:
        return {key: FindingProxy(self._investigation, key) for key in self._investigation.get_all_findings()}

    def finding_link_observable(
        self,
        finding_key: str,
        observable_key: str,
        scope: Scope | str = Scope.OWN_FRAGMENT,
    ) -> FindingProxy:
        self._investigation.link_finding_observable(finding_key, observable_key, scope)
        return FindingProxy(self._investigation, finding_key)

    def finding_link_evidence(self, finding_key: str, evidence_key: str) -> FindingProxy:
        self._investigation.link_finding_evidence(finding_key, evidence_key)
        return FindingProxy(self._investigation, finding_key)

    def finding_set_weight(self, finding_key: str, weight: float) -> FindingProxy:
        if self._investigation.get_finding(finding_key) is None:
            raise KeyError(f"Unknown finding: {finding_key}")
        return FindingProxy(self._investigation, finding_key).with_weight(weight)

    # ------------------------------------------------------------------ evidence

    def evidence_create(
        self,
        evidence_type: str,
        *,
        title: str = "",
        content: Any = None,
        uri: str | None = None,
        source: str = "cyvest",
        captured_at: datetime | None = None,
        external_id: str | None = None,
    ) -> EvidenceProxy:
        """Raw material. The v6 ``Enrichment`` is just ``evidence_type="enrichment"``."""
        evidence = Evidence(
            evidence_type=evidence_type,
            title=title,
            content=content,
            uri=uri,
            captured_at=captured_at,
            external_id=external_id,
            source=self._source(source, SourceClass.INTERNAL_TOOL),
            fragment_id=self._fragment(),
        )
        stored = self._investigation.add_evidence(evidence)
        return EvidenceProxy(self._investigation, stored.key)

    def evidence_get(self, key: str) -> EvidenceProxy | None:
        found = self._investigation.get_evidence(key)
        return EvidenceProxy(self._investigation, found.key) if found is not None else None

    def evidence_get_all(self, evidence_type: str | None = None) -> dict[str, EvidenceProxy]:
        return {
            key: EvidenceProxy(self._investigation, key)
            for key, evidence in self._investigation.get_all_evidences().items()
            if evidence_type is None or evidence.evidence_type == evidence_type
        }

    # ------------------------------------------------------------------ tags

    def tag_create(self, name: str, description: str = "") -> TagProxy:
        tag = Tag(name=name, description=description, source=DEFAULT_SOURCE, fragment_id=self._fragment())
        stored = self._investigation.add_tag(tag)
        return TagProxy(self._investigation, stored.key)

    def tag_get(self, name_or_key: str) -> TagProxy | None:
        key = name_or_key if name_or_key.startswith("tag:") else keys.generate_tag_key(name_or_key)
        found = self._investigation.get_tag(key)
        return TagProxy(self._investigation, found.key) if found is not None else None

    def tag_get_all(self) -> dict[str, TagProxy]:
        return {key: TagProxy(self._investigation, key) for key in self._investigation.get_all_tags()}

    def tag_add_finding(self, tag_key: str, finding_key: str) -> TagProxy:
        self._investigation.add_finding_to_tag(tag_key, finding_key)
        return TagProxy(self._investigation, tag_key)

    def tag_get_children(self, tag_name: str) -> list[TagProxy]:
        return [TagProxy(self._investigation, tag.key) for tag in self._investigation.get_tag_children(tag_name)]

    def tag_get_descendants(self, tag_name: str) -> list[TagProxy]:
        return [TagProxy(self._investigation, tag.key) for tag in self._investigation.get_tag_descendants(tag_name)]

    def tag_get_ancestors(self, tag_name: str) -> list[TagProxy]:
        return [TagProxy(self._investigation, tag.key) for tag in self._investigation.get_tag_ancestors(tag_name)]

    # ------------------------------------------------------------------ decisions

    def decision_create(
        self,
        target: ObservableProxy | FindingProxy | str,
        kind: DecisionKind | str,
        *,
        justification: str | None = None,
        decided_by: str | None = None,
        occurred_at: datetime | None = None,
    ) -> DecisionProxy:
        """
        Override the computation with a declared act.

        ``ALLOWLISTED``/``BLOCKLISTED`` bound an observable; ``CONFIRMED``/``DISMISSED`` force a
        finding. The who and the when come from the fact envelope, not from duplicated fields.
        """
        stored = self._investigation.add_decision(
            self._key_of(target),
            kind,
            justification=justification,
            source=self._source(decided_by, SourceClass.ORG_ANALYST) if decided_by else None,
            occurred_at=occurred_at,
        )
        return DecisionProxy(self._investigation, stored.key)

    def decision_get_all(self) -> dict[str, DecisionProxy]:
        return {key: DecisionProxy(self._investigation, key) for key in self._investigation.get_all_decisions()}

    # ------------------------------------------------------------------ results

    def get_report(self) -> Report:
        return self._investigation.report

    def get_global_score(self) -> float:
        return self._investigation.get_global_score()

    def get_global_verdict(self) -> Verdict:
        return self._investigation.get_global_verdict()

    def explain(self, key: str) -> tuple:
        return self._investigation.explain(key)

    def timeline(self, **kwargs: Any) -> list[TimelineEntry]:
        return self._investigation.timeline(**kwargs)

    def reevaluate(self, *, policy: Policy | None = None, engine: str | None = None) -> Report:
        return self._investigation.reevaluate(policy=policy, engine=engine)

    def observable_result(self, observable_key: str, scope: ResolvedScope | None = None):
        return self._investigation.report.observable(observable_key, scope)

    def statistics(self) -> StatisticsSchema:
        """Counts describing the shape of the investigation, computed on demand from the report."""
        return InvestigationStats(self._investigation.store, self._investigation.report).get_summary()

    # ------------------------------------------------------------------ graph & merge

    def merge_investigation(self, other: Cyvest) -> None:
        self._investigation.merge_investigation(other._investigation)

    def finalize_relationships(self) -> None:
        self._investigation.finalize_relationships()

    def shared_context(self) -> SharedInvestigationContext:
        """Turn this investigation into a context several workers can contribute to."""
        from cyvest.shared import SharedInvestigationContext

        return SharedInvestigationContext.from_investigation(self._investigation)

    def __enter__(self) -> Cyvest:
        return self

    def __exit__(self, *_exc: object) -> Literal[False]:
        """Reconcile into the owning context, if any — including when the body raised."""
        context = getattr(self, "_shared_context", None)
        if context is not None:
            context.reconcile(self)
        return False

    # ------------------------------------------------------------------ io

    def io_to_dict(self) -> dict[str, Any]:
        from cyvest.io_serialization import investigation_to_dict

        return investigation_to_dict(self._investigation)

    def io_save_json(self, filepath: str | Path) -> str:
        from cyvest.io_serialization import save_investigation_json

        save_investigation_json(self._investigation, filepath)
        return str(filepath)

    def io_to_markdown(self, **kwargs: Any) -> str:
        from cyvest.io_serialization import generate_markdown_report

        return generate_markdown_report(self._investigation, **kwargs)

    def io_save_markdown(self, filepath: str | Path, **kwargs: Any) -> str:
        from cyvest.io_serialization import save_investigation_markdown

        return save_investigation_markdown(self._investigation, filepath, **kwargs)

    @classmethod
    def io_load_dict(cls, data: dict[str, Any], *, migrate: bool = False) -> Cyvest:
        from cyvest.io_serialization import load_investigation_dict

        return cls._wrap(load_investigation_dict(data, migrate=migrate))

    @classmethod
    def io_load_json(cls, filepath: str | Path, *, migrate: bool = False) -> Cyvest:
        from cyvest.io_serialization import load_investigation_json

        return cls._wrap(load_investigation_json(filepath, migrate=migrate))

    @classmethod
    def _wrap(cls, investigation: Investigation) -> Cyvest:
        facade = cls.__new__(cls)
        facade._investigation = investigation
        facade._observable_resolvers = []
        return facade

    # ------------------------------------------------------------------ display

    def display_summary(self, *, show_graph: bool = False) -> None:
        from cyvest.io_rich import build_summary, print_renderable

        print_renderable(build_summary(self._investigation, show_graph=show_graph))

    def display_statistics(self) -> None:
        from cyvest.io_rich import build_statistics, print_renderable

        print_renderable(build_statistics(self._investigation))

    def display_explanation(self, key: str) -> None:
        from cyvest.io_rich import build_explanation, print_renderable

        print_renderable(build_explanation(self._investigation, key))

    def display_timeline(self, **kwargs: Any) -> None:
        from cyvest.io_rich import build_timeline, print_renderable

        print_renderable(build_timeline(self._investigation, **kwargs))

    def display_diff(
        self,
        expected: Cyvest | None = None,
        result_expected: list[Any] | None = None,
        *,
        title: str = "Investigation diff",
    ) -> None:
        from cyvest.compare import compare_investigations
        from cyvest.io_rich import build_diff, print_renderable

        diffs = compare_investigations(self, expected, result_expected)
        print_renderable(build_diff(diffs, title=title))

    # ------------------------------------------------------------------ sugar

    def observable(
        self,
        obs_type: ObservableType | str,
        value: str,
        **kwargs: Any,
    ) -> ObservableProxy:
        return self.observable_create(obs_type, value, **kwargs)

    def finding(self, rule_id: str, name: str = "", **kwargs: Any) -> FindingProxy:
        return self.finding_create(rule_id, name, **kwargs)

    def conclusion(self, rule_id: str, name: str = "", **kwargs: Any) -> FindingProxy:
        return self.conclusion_create(rule_id, name, **kwargs)

    def evidence(self, evidence_type: str, **kwargs: Any) -> EvidenceProxy:
        return self.evidence_create(evidence_type, **kwargs)

    def tag(self, name: str, description: str = "") -> TagProxy:
        return self.tag_create(name, description)

    def root(self) -> ObservableProxy:
        return self.observable_get_root()

    @staticmethod
    def threat_intel_draft(
        source: str,
        *,
        verdict: Verdict | str = Verdict.INFO,
        weight: float | None = None,
        confidence: float = Confidence.HIGH.value,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """A signal without its subject yet — completed by ``ObservableProxy.with_ti``."""
        return {"source": source, "verdict": verdict, "weight": weight, "confidence": confidence, **kwargs}

    @staticmethod
    def io_load_signal(payload: dict[str, Any]) -> dict[str, Any]:
        """
        Validate an external system's response against the published signal contract.

        Strict on purpose: a malformed payload raises here rather than becoming a signal that
        quietly scores zero. The returned draft is what ``ObservableProxy.with_ti`` consumes, so
        the caller decides which observable the judgment lands on.

        Re-ingesting the same response is a no-op — identity is ``(source, observable)`` and the
        raw body sits in ``payload``, outside any key. Pass ``external_id`` to keep history.
        """
        envelope = SignalEnvelope.model_validate(payload)
        draft = envelope.as_draft()
        draft["verdict"], draft["weight"] = Cyvest._judgment(envelope.verdict, envelope.weight)
        if draft["weight"] is None:
            draft.pop("weight")
        return draft


__all__ = ["Cyvest"]
