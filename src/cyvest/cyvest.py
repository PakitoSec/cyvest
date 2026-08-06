"""
Cyvest facade - high-level API for building cybersecurity investigations.

Provides a simplified interface for creating and managing investigation objects,
handling score propagation, and generating reports.

Includes JSON/Markdown export (io_save_json, io_save_markdown), import (io_load_json, io_load_dict),
and investigation export (io_to_invest, io_to_dict, io_to_markdown) methods.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from copy import deepcopy
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, overload

from logurich import get_logger

from cyvest import keys
from cyvest.compare import compare_investigations
from cyvest.investigation import Investigation, InvestigationWhitelist, _deep_merge_dict
from cyvest.io_rich import (
    display_diff,
    display_finding_query,
    display_observable_query,
    display_statistics,
    display_summary,
    display_threat_intel_query,
)
from cyvest.io_serialization import (
    generate_markdown_report,
    load_investigation_dict,
    load_investigation_json,
    save_investigation_json,
    save_investigation_markdown,
    serialize_investigation,
)
from cyvest.io_visualization import generate_network_graph
from cyvest.levels import Level
from cyvest.model import (
    Enrichment,
    Evidence,
    Finding,
    Observable,
    ObservableAlias,
    ObservableIdentity,
    Tag,
    Taxonomy,
    ThreatIntel,
    round_score_decimal,
)
from cyvest.model_enums import (
    ObservableSubtype,
    ObservableType,
    PropagationMode,
    RelationshipDirection,
    RelationshipType,
)
from cyvest.model_schema import InvestigationSchema, StatisticsSchema
from cyvest.proxies import EnrichmentProxy, EvidenceProxy, FindingProxy, ObservableProxy, TagProxy, ThreatIntelProxy
from cyvest.resolvers import ObservableResolution, ObservableResolver, ObservableResolverResult
from cyvest.score import ScoreMode

if TYPE_CHECKING:
    from cyvest.shared import SharedInvestigationContext

logger = get_logger(__name__)


class Cyvest:
    """
    High-level facade for building and managing cybersecurity investigations.

    Provides methods for creating observables, findings, threat intel, enrichments,
    and tags, with automatic score propagation and statistics tracking.
    """

    OBS: Final[type[ObservableType]] = ObservableType
    SUB: Final[type[ObservableSubtype]] = ObservableSubtype
    REL: Final[type[RelationshipType]] = RelationshipType
    DIR: Final[type[RelationshipDirection]] = RelationshipDirection
    PROP: Final[type[PropagationMode]] = PropagationMode
    LVL: Final[type[Level]] = Level

    def __init__(
        self,
        root_data: Any = None,
        root_type: ObservableType | Literal["file", "artifact"] = ObservableType.FILE,
        score_mode_obs: ScoreMode = ScoreMode.MAX,
        investigation_name: str | None = None,
        investigation_id: str | None = None,
    ) -> None:
        """
        Initialize a new investigation.

        Args:
            root_data: The data being investigated (optional)
            root_type: Root observable type (ObservableType.FILE or ObservableType.ARTIFACT)
            score_mode_obs: Observable score calculation mode (MAX or SUM)
            investigation_name: Optional human-readable investigation name
            investigation_id: Optional deterministic investigation ID (auto-generated ULID if not provided)
        """
        self._investigation = Investigation(
            root_data,
            root_type=root_type,
            score_mode_obs=score_mode_obs,
            investigation_name=investigation_name,
            investigation_id=investigation_id,
        )
        self._observable_resolvers: list[ObservableResolver] = []

    # Internal helpers

    def _observable_proxy(self, observable: Observable | None) -> ObservableProxy | None:
        if observable is None:
            return None
        return ObservableProxy(self._investigation, observable.key)

    def _finding_proxy(self, finding: Finding | None) -> FindingProxy | None:
        if finding is None:
            return None
        return FindingProxy(self._investigation, finding.key)

    def _evidence_proxy(self, evidence: Evidence | None) -> EvidenceProxy | None:
        if evidence is None:
            return None
        return EvidenceProxy(self._investigation, evidence.key)

    def _tag_proxy(self, tag: Tag | None) -> TagProxy | None:
        if tag is None:
            return None
        return TagProxy(self._investigation, tag.key)

    def _threat_intel_proxy(self, ti: ThreatIntel | None) -> ThreatIntelProxy | None:
        if ti is None:
            return None
        return ThreatIntelProxy(self._investigation, ti.key)

    def _enrichment_proxy(self, enrichment: Enrichment | None) -> EnrichmentProxy | None:
        if enrichment is None:
            return None
        return EnrichmentProxy(self._investigation, enrichment.key)

    @staticmethod
    def _resolve_observable_key(value: Observable | ObservableProxy | str) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (Observable, ObservableProxy)):
            return value.key
        raise TypeError("Expected an observable key, ObservableProxy, or Observable instance.")

    @staticmethod
    def _resolve_threat_intel_key(value: ThreatIntel | ThreatIntelProxy | str) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, (ThreatIntel, ThreatIntelProxy)):
            return value.key
        raise TypeError("Expected a threat intel key, ThreatIntelProxy, or ThreatIntel instance.")

    def _require_observable(self, key: str) -> Observable:
        observable = self._investigation.get_observable(key)
        if observable is None:
            raise KeyError(f"observable '{key}' not found in investigation.")
        return observable

    def _require_finding(self, key: str) -> Finding:
        finding = self._investigation.get_finding(key)
        if finding is None:
            raise KeyError(f"finding '{key}' not found in investigation.")
        return finding

    def _require_evidence(self, key: str) -> Evidence:
        evidence = self._investigation.get_evidence(key)
        if evidence is None:
            raise KeyError(f"evidence '{key}' not found in investigation.")
        return evidence

    # Investigation-level helpers

    def investigation_is_whitelisted(self) -> bool:
        """
        Return whether the investigation is whitelisted/marked safe.

        Examples:
            >>> cv = Cyvest()
            >>> cv.investigation_add_whitelist("id-1", "False positive", "Sandboxed sample")
            >>> cv.investigation_is_whitelisted()
            True
        """
        return self._investigation.is_whitelisted()

    def investigation_get_name(self) -> str | None:
        """Return the human-readable investigation name (if set)."""
        return self._investigation.investigation_name

    def investigation_set_name(self, name: str | None, reason: str | None = None) -> None:
        """Set or clear the human-readable investigation name."""
        self._investigation.set_investigation_name(name, reason=reason)

    def investigation_get_audit_log(self) -> tuple:
        """Return the investigation-level audit log."""
        return tuple(self._investigation.get_audit_log())

    def investigation_add_whitelist(
        self, identifier: str, name: str, justification: str | None = None
    ) -> InvestigationWhitelist:
        """
        Add or update a whitelist entry for the investigation.

        Args:
            identifier: Unique identifier for the whitelist entry.
            name: Human-readable name.
            justification: Optional markdown justification.
        """
        return self._investigation.add_whitelist(identifier, name, justification)

    def investigation_remove_whitelist(self, identifier: str) -> bool:
        """
        Remove a whitelist entry by identifier.

        Returns:
            True if removed, False if the identifier was not present.
        """
        return self._investigation.remove_whitelist(identifier)

    def investigation_clear_whitelists(self) -> None:
        """Remove all whitelist entries."""
        self._investigation.clear_whitelists()

    def investigation_get_whitelists(self) -> tuple[InvestigationWhitelist, ...]:
        """
        Get all whitelist entries.

        Returns:
            Tuple of whitelist entries.
        """
        return tuple(self._investigation.get_whitelists())

    # Observable methods

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

    @staticmethod
    def _observable_kwargs_from_identity(
        identity: ObservableIdentity,
        *,
        internal: bool,
        whitelisted: bool,
        comment: str,
        extra: dict[str, Any],
        score: Decimal | float | None,
        level: Level | None,
        aliases: list[ObservableAlias] | None = None,
    ) -> dict[str, Any]:
        obs_kwargs: dict[str, Any] = {
            "obs_type": identity.obs_type,
            "subtype": identity.subtype,
            "namespace": identity.namespace,
            "value": identity.value,
            "internal": internal,
            "whitelisted": whitelisted,
            "comment": comment,
            "extra": extra,
            "aliases": aliases or [],
        }
        if score is not None:
            obs_kwargs["score"] = Decimal(str(score))
        if level is not None:
            obs_kwargs["level"] = level
        return obs_kwargs

    def observable_resolver_register(self, resolver: ObservableResolver, *, replace: bool = False) -> None:
        """Register an instance-local observable identity resolver."""
        if not isinstance(resolver, ObservableResolver):
            raise TypeError("resolver must be an ObservableResolver.")
        existing_idx = next(
            (idx for idx, item in enumerate(self._observable_resolvers) if item.name == resolver.name),
            None,
        )
        if existing_idx is not None:
            if not replace:
                raise ValueError(f"Observable resolver '{resolver.name}' is already registered.")
            self._observable_resolvers[existing_idx] = resolver
            return
        self._observable_resolvers.append(resolver)

    def observable_resolver_unregister(self, name: str) -> bool:
        """Unregister an observable identity resolver by name."""
        normalized_name = name.strip()
        for idx, resolver in enumerate(self._observable_resolvers):
            if resolver.name == normalized_name:
                del self._observable_resolvers[idx]
                return True
        return False

    def observable_resolver_clear(self) -> None:
        """Remove all instance-local observable identity resolvers."""
        self._observable_resolvers.clear()

    def observable_resolver_get_all(self) -> tuple[ObservableResolver, ...]:
        """Return registered observable identity resolvers in evaluation order."""
        return tuple(self._observable_resolvers)

    @staticmethod
    def _normalize_observable_resolution(resolved: ObservableResolverResult) -> ObservableResolution | None:
        if resolved is None:
            return None
        if isinstance(resolved, ObservableResolution):
            return ObservableResolution.model_validate(resolved)
        return ObservableResolution(identity=ObservableIdentity.model_validate(resolved))

    def _resolve_observable_identity_sync(self, alias: ObservableAlias) -> tuple[str, ObservableResolution] | None:
        for resolver in self._observable_resolvers:
            if self._resolver_applies(resolver, alias) and resolver.aresolve is not None:
                raise RuntimeError(
                    f"Observable resolver '{resolver.name}' is async; use 'await cv.observable_acreate(...)'."
                )
        for resolver in self._observable_resolvers:
            if not self._resolver_applies(resolver, alias):
                continue
            if resolver.resolve is None:
                continue
            resolved = resolver.resolve(alias)
            if resolved is not None:
                resolution = self._normalize_observable_resolution(resolved)
                if resolution is not None:
                    return resolver.name, resolution
        return None

    async def _resolve_observable_identity_async(
        self,
        alias: ObservableAlias,
    ) -> tuple[str, ObservableResolution] | None:
        for resolver in self._observable_resolvers:
            if not self._resolver_applies(resolver, alias):
                continue
            resolved: ObservableResolverResult = None
            if resolver.resolve is not None:
                resolved = resolver.resolve(alias)
            elif resolver.aresolve is not None:
                resolved = await resolver.aresolve(alias)
            if resolved is not None:
                resolution = self._normalize_observable_resolution(resolved)
                if resolution is not None:
                    return resolver.name, resolution
        return None

    @staticmethod
    def _observable_extra_with_resolution(
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

    def _observable_create_from_resolved_identity(
        self,
        *,
        alias: ObservableAlias,
        resolved: tuple[str, ObservableResolution] | None,
        internal: bool,
        whitelisted: bool,
        comment: str,
        extra: dict[str, Any] | None,
        score: Decimal | float | None,
        level: Level | None,
    ) -> ObservableProxy:
        source_identity = ObservableIdentity(
            obs_type=alias.obs_type,
            subtype=alias.subtype,
            namespace=alias.namespace,
            value=alias.value,
        )
        canonical_identity = resolved[1].identity if resolved is not None else source_identity
        aliases = [alias] if resolved is not None else []
        obs = Observable(
            **self._observable_kwargs_from_identity(
                canonical_identity,
                internal=internal,
                whitelisted=whitelisted,
                comment=comment,
                extra=self._observable_extra_with_resolution(extra, resolved),
                score=score,
                level=level,
                aliases=aliases,
            )
        )
        obs_result, _ = self._investigation.add_observable(obs)
        return self._observable_proxy(obs_result)

    def observable_create(
        self,
        obs_type: ObservableType | str,
        value: str,
        subtype: ObservableSubtype | str | None = None,
        namespace: str | None = None,
        internal: bool = False,
        whitelisted: bool = False,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> ObservableProxy:
        """
        Create a new observable or return existing one.

        Args:
            obs_type: Type of observable
            value: Value of the observable
            internal: Whether this is an internal asset
            whitelisted: Whether this is whitelisted
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level

        Returns:
            The created or existing observable
        """
        alias = ObservableAlias(obs_type=obs_type, subtype=subtype, namespace=namespace, value=value)
        resolved = self._resolve_observable_identity_sync(alias)
        return self._observable_create_from_resolved_identity(
            alias=alias,
            resolved=resolved,
            internal=internal,
            whitelisted=whitelisted,
            comment=comment,
            extra=extra,
            score=score,
            level=level,
        )

    async def observable_acreate(
        self,
        obs_type: ObservableType | str,
        value: str,
        subtype: ObservableSubtype | str | None = None,
        namespace: str | None = None,
        internal: bool = False,
        whitelisted: bool = False,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> ObservableProxy:
        """Async variant of observable_create supporting async resolvers."""
        alias = ObservableAlias(obs_type=obs_type, subtype=subtype, namespace=namespace, value=value)
        resolved = await self._resolve_observable_identity_async(alias)
        return self._observable_create_from_resolved_identity(
            alias=alias,
            resolved=resolved,
            internal=internal,
            whitelisted=whitelisted,
            comment=comment,
            extra=extra,
            score=score,
            level=level,
        )

    @overload
    def observable_get(self, key: str) -> ObservableProxy | None:
        """Get an observable by full key string."""
        ...

    @overload
    def observable_get(
        self,
        obs_type: ObservableType | str,
        value: str,
        subtype: ObservableSubtype | str | None = None,
        namespace: str | None = None,
    ) -> ObservableProxy | None:
        """Get an observable by type and value."""
        ...

    def observable_get(self, *args, **kwargs) -> ObservableProxy | None:
        """
        Get an observable by key or by type and value.

        Args:
            key: Observable key (single argument)
            obs_type: Observable type (when using two arguments)
            value: Observable value (when using two arguments)

        Returns:
            Observable if found, None otherwise

        Raises:
            ValueError: If arguments are invalid or key generation fails
        """
        if kwargs:
            if not args and set(kwargs) == {"key"}:
                key = kwargs["key"]
            elif (
                not args
                and {"obs_type", "value"} <= set(kwargs)
                and set(kwargs) <= {"obs_type", "value", "subtype", "namespace"}
            ):
                obs_type = kwargs["obs_type"]
                value = kwargs["value"]
                subtype = kwargs.get("subtype")
                namespace = kwargs.get("namespace")
                try:
                    obs_type_value = obs_type.value if isinstance(obs_type, ObservableType) else str(obs_type)
                    subtype_value = subtype.value if isinstance(subtype, ObservableSubtype) else subtype
                    key = keys.generate_observable_key(
                        obs_type_value,
                        value,
                        subtype=subtype_value,
                        namespace=namespace,
                    )
                except Exception as e:
                    raise ValueError(
                        f"Failed to generate observable key for type='{obs_type}', value='{value}': {e}"
                    ) from e
            else:
                raise ValueError("observable_get() accepts either (key: str) or (obs_type: ObservableType, value: str)")
        elif len(args) == 1:
            key = args[0]
        elif 2 <= len(args) <= 4:
            obs_type, value = args[:2]
            subtype = args[2] if len(args) >= 3 else None
            namespace = args[3] if len(args) == 4 else None
            try:
                obs_type_value = obs_type.value if isinstance(obs_type, ObservableType) else str(obs_type)
                subtype_value = subtype.value if isinstance(subtype, ObservableSubtype) else subtype
                key = keys.generate_observable_key(
                    obs_type_value,
                    value,
                    subtype=subtype_value,
                    namespace=namespace,
                )
            except Exception as e:
                raise ValueError(
                    f"Failed to generate observable key for type='{obs_type}', value='{value}': {e}"
                ) from e
        else:
            raise ValueError("observable_get() accepts either (key: str) or (obs_type: ObservableType, value: str)")
        return self._observable_proxy(self._investigation.get_observable(key))

    def observable_get_root(self) -> ObservableProxy:
        """
        Get the root observable.

        Returns:
            Root observable
        """
        return self._observable_proxy(self._investigation.get_root())

    def observable_get_all(self) -> dict[str, ObservableProxy]:
        """Get read-only proxies for all observables."""
        return {
            key: ObservableProxy(self._investigation, key) for key in self._investigation.get_all_observables().keys()
        }

    def observable_add_relationship(
        self,
        source: Observable | ObservableProxy | str,
        target: Observable | ObservableProxy | str,
        relationship_type: RelationshipType | str,
        direction: RelationshipDirection | None = None,
    ) -> ObservableProxy:
        """
        Add a relationship between observables.

        Args:
            source: Source observable or its key
            target: Target observable or its key
            relationship_type: Type of relationship
            direction: Direction of the relationship (None = use semantic default for relationship type)

        Returns:
            The source observable

        Raises:
            KeyError: If the source or target observable does not exist
        """
        source_key = self._resolve_observable_key(source)
        target_key = self._resolve_observable_key(target)
        result = self._investigation.add_relationship(source_key, target_key, relationship_type, direction)
        return self._observable_proxy(result)

    def observable_add_threat_intel(
        self,
        observable: Observable | ObservableProxy | str,
        source: str,
        score: Decimal | float,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        level: Level | None = None,
        taxonomies: list[Taxonomy | dict[str, Any]] | None = None,
    ) -> ThreatIntelProxy:
        """
        Add threat intelligence to an observable.

        Args:
            observable: Observable, ObservableProxy, or its key
            source: Threat intel source name
            score: Score from threat intel
            comment: Optional comment
            extra: Optional extra data
            level: Optional explicit level
            taxonomies: Optional taxonomies

        Returns:
            The created threat intel

        Raises:
            KeyError: If the observable does not exist
        """
        observable_key = self._resolve_observable_key(observable)
        observable = self._require_observable(observable_key)

        ti_kwargs: dict[str, Any] = {
            "source": source,
            "observable_key": observable_key,
            "comment": comment,
            "extra": extra or {},
            "score": Decimal(str(score)),
            "taxonomies": taxonomies or [],
        }
        if level is not None:
            ti_kwargs["level"] = level
        ti = ThreatIntel(**ti_kwargs)
        result = self._investigation.add_threat_intel(ti, observable)
        return self._threat_intel_proxy(result)

    def observable_with_ti_draft(
        self,
        observable: Observable | ObservableProxy | str,
        threat_intel: ThreatIntel,
    ) -> ThreatIntelProxy:
        """
        Attach a threat intel draft to an observable.

        Args:
            observable: Observable, ObservableProxy, or its key
            threat_intel: Threat intel draft entry (unbound or matching observable)

        Returns:
            The created/merged threat intel

        Raises:
            KeyError: If the observable does not exist
        """
        if not isinstance(threat_intel, ThreatIntel):
            raise TypeError("Threat intel draft must be a ThreatIntel instance.")

        observable_key = self._resolve_observable_key(observable)
        model_observable = self._require_observable(observable_key)

        if threat_intel.observable_key and threat_intel.observable_key != observable_key:
            raise ValueError("Threat intel is already bound to a different observable.")

        threat_intel.observable_key = observable_key
        expected_key = keys.generate_threat_intel_key(threat_intel.source, observable_key)
        if not threat_intel.key or threat_intel.key != expected_key:
            threat_intel.key = expected_key

        result = self._investigation.add_threat_intel(threat_intel, model_observable)
        return self._threat_intel_proxy(result)

    def observable_set_level(
        self,
        observable: Observable | ObservableProxy | str,
        level: Level,
        reason: str | None = None,
    ) -> ObservableProxy:
        """
        Explicitly set an observable's level via the service layer.

        Args:
            observable: Observable, ObservableProxy, or its key
            level: Level to apply

        Returns:
            Updated observable proxy

        Raises:
            KeyError: If the observable does not exist
        """
        observable_key = self._resolve_observable_key(observable)
        model_observable = self._require_observable(observable_key)
        self._investigation.apply_level_change(
            model_observable,
            level,
            reason=reason or "Manual level update",
        )
        return self._observable_proxy(model_observable)

    # Threat intel methods

    def threat_intel_get(self, key: str) -> ThreatIntelProxy | None:
        """
        Get a threat intel entry by key.

        Args:
            key: Threat intel key (format: ti:{source}:{observable_key})

        Returns:
            ThreatIntelProxy if found, None otherwise
        """
        ti = self._investigation.get_threat_intel(key)
        return self._threat_intel_proxy(ti)

    def threat_intel_draft_create(
        self,
        source: str,
        score: Decimal | float,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        level: Level | None = None,
        taxonomies: list[Taxonomy | dict[str, Any]] | None = None,
    ) -> ThreatIntel:
        """
        Create an unbound threat intel draft entry.

        Args:
            source: Threat intel source name
            score: Score from threat intel
            comment: Optional comment
            extra: Optional extra data
            level: Optional explicit level
            taxonomies: Optional taxonomies

        Returns:
            Unbound ThreatIntel instance
        """
        ti_kwargs: dict[str, Any] = {
            "source": source,
            "observable_key": "",
            "comment": comment,
            "extra": extra or {},
            "score": Decimal(str(score)),
            "taxonomies": taxonomies or [],
        }
        if level is not None:
            ti_kwargs["level"] = level
        return ThreatIntel(**ti_kwargs)

    def threat_intel_add_taxonomy(
        self,
        threat_intel: ThreatIntel | ThreatIntelProxy | str,
        *,
        level: Level,
        name: str,
        value: str,
    ) -> ThreatIntelProxy:
        """
        Add or replace a taxonomy entry by name on a threat intel.

        Args:
            threat_intel: ThreatIntel, ThreatIntelProxy, or its key
            level: Taxonomy level
            name: Taxonomy name (unique per threat intel)
            value: Taxonomy value

        Returns:
            Updated threat intel proxy

        Raises:
            KeyError: If the threat intel does not exist
        """
        ti_key = self._resolve_threat_intel_key(threat_intel)
        taxonomy = Taxonomy(level=level, name=name, value=value)
        updated = self._investigation.add_threat_intel_taxonomy(ti_key, taxonomy)
        return self._threat_intel_proxy(updated)

    def threat_intel_remove_taxonomy(
        self,
        threat_intel: ThreatIntel | ThreatIntelProxy | str,
        name: str,
    ) -> ThreatIntelProxy:
        """
        Remove a taxonomy entry by name from a threat intel.

        Args:
            threat_intel: ThreatIntel, ThreatIntelProxy, or its key
            name: Taxonomy name to remove

        Returns:
            Updated threat intel proxy

        Raises:
            KeyError: If the threat intel does not exist
        """
        ti_key = self._resolve_threat_intel_key(threat_intel)
        updated = self._investigation.remove_threat_intel_taxonomy(ti_key, name)
        return self._threat_intel_proxy(updated)

    def threat_intel_get_all(self) -> dict[str, ThreatIntelProxy]:
        """Get read-only proxies for all threat intel entries."""
        return {
            key: ThreatIntelProxy(self._investigation, key)
            for key in self._investigation.get_all_threat_intels().keys()
        }

    # Finding methods

    def finding_create(
        self,
        finding_name: str,
        description: str,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> FindingProxy:
        """
        Create a new finding.

        Args:
            finding_name: Finding name
            description: Finding description
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level

        Returns:
            The created finding
        """
        finding_kwargs: dict[str, Any] = {
            "finding_name": finding_name,
            "description": description,
            "comment": comment,
            "extra": extra or {},
            "origin_investigation_id": self._investigation.investigation_id,
        }
        if score is not None:
            finding_kwargs["score"] = Decimal(str(score))
        if level is not None:
            finding_kwargs["level"] = level
        finding = Finding(**finding_kwargs)
        return self._finding_proxy(self._investigation.add_finding(finding))

    def finding_get(self, key: str) -> FindingProxy | None:
        """
        Get a finding by key.

        Args:
            key: Finding key

        Returns:
            Finding when found, otherwise None
        """
        return self._finding_proxy(self._investigation.get_finding(key))

    def finding_get_all(self) -> dict[str, FindingProxy]:
        """Get read-only proxies for all findings."""
        return {key: FindingProxy(self._investigation, key) for key in self._investigation.get_all_findings().keys()}

    def finding_link_observable(
        self,
        finding_key: str,
        observable: Observable | ObservableProxy | str,
        propagation_mode: PropagationMode = PropagationMode.LOCAL_ONLY,
    ) -> FindingProxy:
        """
        Link an observable to a finding.

        Args:
            finding_key: Key of the finding
            observable: Observable, ObservableProxy, or its key
            propagation_mode: Propagation behavior for this link

        Returns:
            The finding

        Raises:
            KeyError: If the finding or observable does not exist
        """
        observable_key = self._resolve_observable_key(observable)
        result = self._investigation.link_finding_observable(
            finding_key,
            observable_key,
            propagation_mode=propagation_mode,
        )
        return self._finding_proxy(result)

    def finding_update_score(self, finding_key: str, score: Decimal | float, reason: str = "") -> FindingProxy:
        """
        Update a finding's score.

        Args:
            finding_key: Key of the finding
            score: New score
            reason: Reason for update

        Returns:
            The finding

        Raises:
            KeyError: If the finding does not exist
        """
        finding = self._require_finding(finding_key)
        self._investigation.apply_score_change(finding, Decimal(str(score)), reason=reason)
        return self._finding_proxy(finding)

    def evidence_create(
        self,
        evidence_type: str,
        title: str,
        source: str,
        *,
        description: str = "",
        external_id: str | None = None,
        content: Any | None = None,
        uri: str | None = None,
        captured_at: datetime | None = None,
        extra: dict[str, Any] | None = None,
    ) -> EvidenceProxy:
        """Create or merge structured evidence."""
        evidence_kwargs: dict[str, Any] = {
            "evidence_type": evidence_type,
            "title": title,
            "description": description,
            "source": source,
            "external_id": external_id,
            "content": content,
            "uri": uri,
            "extra": extra or {},
        }
        if captured_at is not None:
            evidence_kwargs["captured_at"] = captured_at
        evidence = Evidence(**evidence_kwargs)
        return self._evidence_proxy(self._investigation.add_evidence(evidence))

    def evidence_get(self, key: str) -> EvidenceProxy | None:
        """Get evidence by key."""
        return self._evidence_proxy(self._investigation.get_evidence(key))

    def evidence_get_all(self) -> dict[str, EvidenceProxy]:
        """Get read-only proxies for all evidences."""
        return {key: EvidenceProxy(self._investigation, key) for key in self._investigation.get_all_evidences()}

    def finding_link_evidence(
        self,
        finding: Finding | FindingProxy | str,
        evidence: Evidence | EvidenceProxy | str,
    ) -> FindingProxy:
        """Link an evidence object to a finding."""
        finding_key = finding if isinstance(finding, str) else finding.key
        evidence_key = evidence if isinstance(evidence, str) else evidence.key
        result = self._investigation.link_finding_evidence(finding_key, evidence_key)
        return self._finding_proxy(result)

    # Tag methods

    def tag_create(self, name: str, description: str = "") -> TagProxy:
        """
        Create a new tag, automatically creating ancestor tags.

        When creating a tag with a hierarchical name (using ":" delimiter),
        ancestor tags are automatically created if they don't exist.
        For example, creating "header:auth:dkim" will auto-create
        "header" and "header:auth" tags.

        Args:
            name: Tag name (use ":" as hierarchy delimiter)
            description: Tag description

        Returns:
            The created tag
        """
        tag = Tag(name=name, description=description)
        return self._tag_proxy(self._investigation.add_tag(tag))

    def tag_get(self, *args, **kwargs) -> TagProxy | None:
        """
        Get a tag by key or by name.

        Args:
            key: Tag key (single argument, prefixed with tag:)
            name: Tag name (single argument without prefix)

        Returns:
            Tag if found, None otherwise

        Raises:
            ValueError: If arguments are invalid or key generation fails
        """
        if kwargs:
            if not args and set(kwargs) == {"key"}:
                key = kwargs["key"]
            elif not args and set(kwargs) == {"name"}:
                name = kwargs["name"]
                try:
                    key = keys.generate_tag_key(name)
                except Exception as e:
                    raise ValueError(f"Failed to generate tag key for name='{name}': {e}") from e
            else:
                raise ValueError("tag_get() accepts either (key: str) or (name: str)")
        elif len(args) == 1:
            key_or_name = args[0]
            if isinstance(key_or_name, str) and key_or_name.startswith("tag:"):
                key = key_or_name
            else:
                try:
                    key = keys.generate_tag_key(key_or_name)
                except Exception as e:
                    raise ValueError(f"Failed to generate tag key for name='{key_or_name}': {e}") from e
        else:
            raise ValueError("tag_get() accepts either (key: str) or (name: str)")
        return self._tag_proxy(self._investigation.get_tag(key))

    def tag_get_all(self) -> dict[str, TagProxy]:
        """Get read-only proxies for all tags."""
        return {key: TagProxy(self._investigation, key) for key in self._investigation.get_all_tags().keys()}

    def tag_add_finding(self, tag_key: str, finding_key: str) -> TagProxy:
        """
        Add a finding to a tag.

        Args:
            tag_key: Key of the tag
            finding_key: Key of the finding

        Returns:
            The tag

        Raises:
            KeyError: If the tag or finding does not exist
        """
        tag = self._investigation.add_finding_to_tag(tag_key, finding_key)
        return self._tag_proxy(tag)

    def tag_get_children(self, tag_name: str) -> list[TagProxy]:
        """Get direct child tags of a tag."""
        tags = self._investigation.get_tag_children(tag_name)
        return [TagProxy(self._investigation, t.key) for t in tags]

    def tag_get_descendants(self, tag_name: str) -> list[TagProxy]:
        """Get all descendant tags of a tag."""
        tags = self._investigation.get_tag_descendants(tag_name)
        return [TagProxy(self._investigation, t.key) for t in tags]

    def tag_get_ancestors(self, tag_name: str) -> list[TagProxy]:
        """Get all ancestor tags of a tag."""
        tags = self._investigation.get_tag_ancestors(tag_name)
        return [TagProxy(self._investigation, t.key) for t in tags]

    # Enrichment methods

    def enrichment_create(self, name: str, data: dict[str, Any], context: str = "") -> EnrichmentProxy:
        """
        Create a new enrichment.

        Args:
            name: Enrichment name
            data: Enrichment data
            context: Optional context

        Returns:
            The created enrichment
        """
        enrichment = Enrichment(name=name, data=data, context=context)
        return self._enrichment_proxy(self._investigation.add_enrichment(enrichment))

    @overload
    def enrichment_get(self, key: str) -> EnrichmentProxy | None:
        """Get an enrichment by full key string."""
        ...

    @overload
    def enrichment_get(self, name: str, context: str = "") -> EnrichmentProxy | None:
        """Get an enrichment by name and optional context."""
        ...

    def enrichment_get(self, *args, **kwargs) -> EnrichmentProxy | None:
        """
        Get an enrichment by key or by name and context.

        Args:
            key: Enrichment key (single argument, prefixed with enr:)
            name: Enrichment name (when using one or two arguments)
            context: Optional context (second argument or context= kw)

        Returns:
            Enrichment if found, None otherwise

        Raises:
            ValueError: If arguments are invalid or key generation fails
        """
        if kwargs:
            if not args and set(kwargs) == {"key"}:
                key = kwargs["key"]
            elif not args and set(kwargs) == {"name"}:
                name = kwargs["name"]
                try:
                    key = keys.generate_enrichment_key(name)
                except Exception as e:
                    raise ValueError(f"Failed to generate enrichment key for name='{name}': {e}") from e
            elif not args and set(kwargs) == {"name", "context"}:
                name = kwargs["name"]
                context = kwargs["context"]
                try:
                    key = keys.generate_enrichment_key(name, context)
                except Exception as e:
                    raise ValueError(
                        f"Failed to generate enrichment key for name='{name}', context='{context}': {e}"
                    ) from e
            elif len(args) == 1 and set(kwargs) == {"context"}:
                name = args[0]
                context = kwargs["context"]
                try:
                    key = keys.generate_enrichment_key(name, context)
                except Exception as e:
                    raise ValueError(
                        f"Failed to generate enrichment key for name='{name}', context='{context}': {e}"
                    ) from e
            else:
                raise ValueError('enrichment_get() accepts either (key: str) or (name: str, context: str = "")')
        elif len(args) == 1:
            key_or_name = args[0]
            if isinstance(key_or_name, str) and key_or_name.startswith("enr:"):
                key = key_or_name
            else:
                try:
                    key = keys.generate_enrichment_key(key_or_name)
                except Exception as e:
                    raise ValueError(f"Failed to generate enrichment key for name='{key_or_name}': {e}") from e
        elif len(args) == 2:
            name, context = args
            try:
                key = keys.generate_enrichment_key(name, context)
            except Exception as e:
                raise ValueError(
                    f"Failed to generate enrichment key for name='{name}', context='{context}': {e}"
                ) from e
        else:
            raise ValueError('enrichment_get() accepts either (key: str) or (name: str, context: str = "")')
        return self._enrichment_proxy(self._investigation.get_enrichment(key))

    def enrichment_get_all(self) -> dict[str, EnrichmentProxy]:
        """Get read-only proxies for all enrichments."""
        return {
            key: EnrichmentProxy(self._investigation, key) for key in self._investigation.get_all_enrichments().keys()
        }

    # Score and statistics methods

    def get_global_score(self) -> Decimal:
        """
        Get the global investigation score.

        Returns:
            Global score
        """
        return self._investigation.get_global_score()

    def get_global_level(self) -> Level:
        """
        Get the global investigation level.

        Returns:
            Global level
        """
        return self._investigation.get_global_level()

    def get_statistics(self) -> StatisticsSchema:
        """
        Get comprehensive investigation statistics.

        Returns:
            Statistics schema with typed fields
        """
        return self._investigation.get_statistics()

    # Serialization and I/O methods

    def io_save_json(self, filepath: str | Path, *, include_audit_log: bool = True) -> str:
        """
        Save the investigation to a JSON file.

        Relative paths are converted to absolute paths before saving.

        Args:
            filepath: Path to save the JSON file (relative or absolute)
            include_audit_log: Include audit log in output (default: True).
                When False, audit_log is set to null for compact, deterministic output.

        Returns:
            Absolute path to the saved file as a string

        Raises:
            PermissionError: If the file cannot be written
            OSError: If there are file system issues

        Examples:
            >>> cv = Cyvest()
            >>> path = cv.io_save_json("investigation.json")
            >>> print(path)  # /absolute/path/to/investigation.json
            >>> # For compact, deterministic output:
            >>> path = cv.io_save_json("output.json", include_audit_log=False)
        """
        save_investigation_json(self._investigation, filepath, include_audit_log=include_audit_log)
        return str(Path(filepath).resolve())

    def io_save_markdown(
        self,
        filepath: str | Path,
        include_tags: bool = False,
        include_enrichments: bool = False,
        include_observables: bool = True,
    ) -> str:
        """
        Save the investigation as a Markdown report.

        Relative paths are converted to absolute paths before saving.

        Args:
            filepath: Path to save the Markdown file (relative or absolute)
            include_tags: Include tags section in the report (default: False)
            include_enrichments: Include enrichments section in the report (default: False)
            include_observables: Include observables section in the report (default: True)

        Returns:
            Absolute path to the saved file as a string

        Raises:
            PermissionError: If the file cannot be written
            OSError: If there are file system issues

        Examples:
            >>> cv = Cyvest()
            >>> path = cv.io_save_markdown("report.md")
            >>> print(path)  # /absolute/path/to/report.md
        """
        save_investigation_markdown(
            self._investigation, filepath, include_tags, include_enrichments, include_observables
        )
        return str(Path(filepath).resolve())

    def io_to_markdown(
        self,
        include_tags: bool = False,
        include_enrichments: bool = False,
        include_observables: bool = True,
        exclude_levels: set[Level] | None = None,
    ) -> str:
        """
        Generate a Markdown report of the investigation.

        Args:
            include_tags: Include tags section in the report (default: False)
            include_enrichments: Include enrichments section in the report (default: False)
            include_observables: Include observables section in the report (default: True)
            exclude_levels: Set of levels to exclude from findings section (default: {Level.NONE})

        Returns:
            Markdown formatted report as a string

        Examples:
            >>> cv = Cyvest()
            >>> markdown = cv.io_to_markdown()
            >>> print(markdown)
            # Cybersecurity Investigation Report
            ...
        """
        return generate_markdown_report(
            self._investigation, include_tags, include_enrichments, include_observables, exclude_levels
        )

    def io_to_invest(self, *, include_audit_log: bool = True) -> InvestigationSchema:
        """
        Serialize the investigation to an InvestigationSchema.

        Args:
            include_audit_log: Include audit log in serialization (default: True).
                When False, audit_log is set to None for compact, deterministic output.

        Returns:
            InvestigationSchema instance (use .model_dump() for dict)

        Examples:
            >>> cv = Cyvest()
            >>> schema = cv.io_to_invest()
            >>> print(schema.score, schema.level)
            >>> dict_data = schema.model_dump()  # defaults to by_alias=True
            >>> # For compact, deterministic output:
            >>> schema = cv.io_to_invest(include_audit_log=False)
            >>> assert schema.audit_log is None
        """
        return serialize_investigation(self._investigation, include_audit_log=include_audit_log)

    def io_to_dict(self, *, include_audit_log: bool = True) -> dict[str, Any]:
        """
        Convert the investigation to a Python dictionary.

        Args:
            include_audit_log: Include audit log in output (default: True).
                When False, audit_log is set to None for compact, deterministic output.

        Returns:
            Dictionary representation of the investigation

        Examples:
            >>> cv = Cyvest()
            >>> data = cv.io_to_dict()
            >>> print(data["score"], data["level"])
            >>> # For compact, deterministic output:
            >>> data = cv.io_to_dict(include_audit_log=False)
            >>> assert data["audit_log"] is None
        """
        return self.io_to_invest(include_audit_log=include_audit_log).model_dump(by_alias=True)

    @staticmethod
    def io_load_json(filepath: str | Path) -> Cyvest:
        """
        Load an investigation from a JSON file.

        Args:
            filepath: Path to the JSON file (relative or absolute)

        Returns:
            Reconstructed Cyvest investigation

        Raises:
            FileNotFoundError: If the file does not exist
            json.JSONDecodeError: If the file contains invalid JSON
            Exception: For other file-related errors

        Example:
            >>> cv = Cyvest.io_load_json("investigation.json")
            >>> cv = Cyvest.io_load_json("/absolute/path/to/investigation.json")
        """
        return load_investigation_json(filepath)

    @staticmethod
    def io_load_dict(data: dict[str, Any]) -> Cyvest:
        """
        Load an investigation from a dictionary (parsed JSON).

        Args:
            data: Dictionary containing the serialized investigation data

        Returns:
            Reconstructed Cyvest investigation

        Raises:
            ValueError: If required fields are missing or invalid

        Example:
            >>> import json
            >>> with open("investigation.json") as f:
            ...     data = json.load(f)
            >>> cv = Cyvest.io_load_dict(data)
        """
        return load_investigation_dict(data)

    @staticmethod
    def io_load_threat_intel_draft(
        report: dict[str, Any],
        *,
        preprocessor: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        safe_getter: Callable[[dict[str, Any]], Any] | None = None,
        safe_values: Iterable[str] | None = None,
    ) -> ThreatIntel:
        """
        Load a ThreatIntel draft from an external API report dict.

        Extracts standard threat-intel fields (source, score, level, comment,
        extra, taxonomies) from *report*, rounds the score to two decimal
        places, and returns a validated :class:`ThreatIntel` instance that is
        **not yet bound** to any observable.  Attach it afterwards with
        :meth:`observable_with_ti_draft` or
        :meth:`ObservableProxy.with_ti_draft`.

        Args:
            report: Dictionary with threat-intel fields coming from an
                external service (e.g. a SOAR/TIP API response).
            preprocessor: Optional callback that receives a **shallow copy**
                of *report* and returns a (possibly modified) dict before
                validation.  Runs before the safe-override finding.
            safe_getter: Optional callable that extracts a value from the
                report dict to match against *safe_values*.
            safe_values: Values that, when matched by *safe_getter*, force
                score to ``0.0`` and level to ``SAFE``.  Requires
                *safe_getter* to be set.

        Returns:
            Unbound ThreatIntel instance (observable_key is empty).

        Raises:
            TypeError: If *report* is not a dict.
            ValueError: If *safe_values* is set without *safe_getter*.
            pydantic.ValidationError: If the extracted payload fails
                ThreatIntel model validation.

        Examples:
            Basic usage::

                report = {"source": "virustotal", "score": 4.256, "level": "SUSPICIOUS"}
                ti = Cyvest.io_load_threat_intel_draft(report)
                obs.with_ti_draft(ti)

            Force MISP warning-list reports to SAFE with ``safe_getter``::

                ti = Cyvest.io_load_threat_intel_draft(
                    report,
                    safe_getter=lambda d: d.get("extra", {}).get("task_name", ""),
                    safe_values=["MISP.analyzer.DBWarningList", "MISP.analyzer.SearchWarningList"],
                )
        """
        if not isinstance(report, dict):
            raise TypeError(f"report must be a dict, got {type(report).__name__}")
        if safe_values is not None and safe_getter is None:
            raise ValueError("safe_values requires safe_getter to be set.")

        data: dict[str, Any] = dict(report)  # shallow copy
        if preprocessor is not None:
            data = preprocessor(data)

        # Built-in safe override: if safe_getter(data) matches any safe_values
        # and level is not already INFO or SAFE, force SAFE + score 0.
        if safe_getter is not None and safe_values is not None:
            matched = safe_getter(data)
            safe_set = set(safe_values)
            if matched in safe_set and data.get("level") not in ("INFO", "SAFE"):
                data["level"] = "SAFE"
                data["score"] = 0.0

        raw_score = data.get("score")
        if raw_score is not None:
            rounded = round_score_decimal(Decimal(str(raw_score)))
        else:
            rounded = None  # let ThreatIntel validators decide

        ti_payload: dict[str, Any] = {
            "source": str(data.get("source", "")),
            "observable_key": "",
            "comment": str(data.get("comment", "") or ""),
            "extra": data.get("extra"),
            "score": rounded,
            "level": data.get("level"),
            "taxonomies": data.get("taxonomies", []),
        }

        return ThreatIntel.model_validate(ti_payload)

    # Shared context, investigation merging, finalization, comparison

    def shared_context(
        self,
        *,
        lock: threading.RLock | None = None,
        max_async_workers: int | None = None,
    ) -> SharedInvestigationContext:
        """
        Create a SharedInvestigationContext tied to this Cyvest instance.

        Args:
            lock: Optional shared lock for advanced synchronization scenarios.
            max_async_workers: Optional limit for concurrent async reconciliation workers.
        """
        from cyvest.shared import SharedInvestigationContext

        return SharedInvestigationContext(self, lock=lock, max_async_workers=max_async_workers)

    def merge_investigation(self, other: Cyvest) -> None:
        """
        Merge another investigation into this one.

        Args:
            other: The investigation to merge
        """
        self._investigation.merge_investigation(other._investigation)

    def finalize_relationships(self) -> None:
        """
        Finalize observable relationships by linking orphan sub-graphs to root.

        Any observable or sub-graph not connected to the root will be automatically
        linked by finding the best starting node of each disconnected component.
        """
        self._investigation.finalize_relationships()

    def compare(
        self,
        expected: Cyvest | None = None,
        result_expected: list | None = None,
    ) -> list:
        """
        Compare this investigation against expected results.

        Args:
            expected: The reference investigation (expected results), optional
            result_expected: List of ExpectedResult tolerance rules for specific findings

        Returns:
            List of DiffItem for all differences found
        """
        return compare_investigations(actual=self, expected=expected, result_expected=result_expected)

    # Display helpers

    def display_summary(
        self,
        show_graph: bool = True,
        exclude_levels: Level | Iterable[Level] = Level.NONE,
        show_audit_log: bool = False,
        rich_print: Callable[[Any], None] | None = None,
    ) -> None:
        """
        Display a comprehensive summary of the investigation using Rich.

        Args:
            show_graph: Whether to display the observable graph
            exclude_levels: Level(s) to omit from the report (default: Level.NONE)
            show_audit_log: Whether to display the investigation audit log
            rich_print: Optional callable that takes a renderable and returns None
        """
        if rich_print is None:

            def rich_print(renderables: Any) -> None:
                logger.rich("INFO", renderables)

        display_summary(
            self,
            rich_print,
            show_graph=show_graph,
            exclude_levels=exclude_levels,
            show_audit_log=show_audit_log,
        )

    def display_statistics(
        self,
        rich_print: Callable[[Any], None] | None = None,
    ) -> None:
        """
        Display investigation statistics using Rich.

        Args:
            rich_print: Optional callable that takes a renderable and returns None.
                        If not provided, uses the default logger.
        """
        if rich_print is None:

            def rich_print(renderables: Any) -> None:
                logger.rich("INFO", renderables)

        display_statistics(self, rich_print)

    def display_diff(
        self,
        expected: Cyvest | None = None,
        result_expected: list | None = None,
        title: str = "Diff",
        rich_print: Callable[[Any], None] | None = None,
    ) -> None:
        """
        Compare and display diff against expected results.

        Args:
            expected: The reference investigation (expected results), optional
            result_expected: List of ExpectedResult tolerance rules for specific findings
            title: Title for the diff table
            rich_print: Optional callable that takes a renderable and returns None
        """
        if rich_print is None:

            def rich_print(renderables):
                return logger.rich("INFO", renderables, width=150)

        diffs = compare_investigations(actual=self, expected=expected, result_expected=result_expected)
        display_diff(diffs, rich_print, title=title)

    def display_finding(
        self,
        finding_key: str,
        rich_print: Callable[[Any], None] | None = None,
    ) -> None:
        """
        Display detailed information about a finding.

        Args:
            finding_key: Key of the finding to display (format: fnd:finding-name)
            rich_print: Optional callable that takes a renderable and returns None.
                        If not provided, uses the default logger.

        Raises:
            KeyError: If finding not found
        """
        if rich_print is None:

            def rich_print(renderables: Any) -> None:
                logger.rich("INFO", renderables, width=150, prefix=False)

        display_finding_query(self, finding_key, rich_print)

    def display_observable(
        self,
        observable_key: str,
        depth: int = 1,
        rich_print: Callable[[Any], None] | None = None,
    ) -> None:
        """
        Display detailed information about an observable.

        Shows observable info, score breakdown (how the score was calculated),
        threat intelligence, and relationships up to the specified depth.

        Args:
            observable_key: Key of the observable to display (format: obs:type:value)
            depth: Relationship traversal depth (default 1)
            rich_print: Optional callable that takes a renderable and returns None.
                        If not provided, uses the default logger.

        Raises:
            KeyError: If observable not found
        """
        if rich_print is None:

            def rich_print(renderables: Any) -> None:
                logger.rich("INFO", renderables, width=150, prefix=False)

        display_observable_query(self, observable_key, rich_print, depth=depth)

    def display_threat_intel(
        self,
        ti_key: str,
        rich_print: Callable[[Any], None] | None = None,
    ) -> None:
        """
        Display detailed information about a threat intel entry.

        Args:
            ti_key: Key of the threat intel to display (format: ti:source:obs:type:value)
            rich_print: Optional callable that takes a renderable and returns None.
                        If not provided, uses the default logger.

        Raises:
            KeyError: If threat intel not found
        """
        if rich_print is None:

            def rich_print(renderables: Any) -> None:
                logger.rich("INFO", renderables, width=150, prefix=False)

        display_threat_intel_query(self, ti_key, rich_print)

    def display_network(
        self,
        output_dir: str | None = None,
        open_browser: bool = True,
        min_level: Level | None = None,
        observable_types: list[ObservableType] | None = None,
        physics: bool = True,
        group_by_type: bool = False,
        max_label_length: int = 60,
        title: str = "Cyvest Investigation Network",
    ) -> str:
        """
        Generate and display an interactive network graph visualization.

        Creates an HTML file with a pyvis network graph showing observables as nodes
        (colored by level, sized by score, shaped by type) and relationships as edges
        (colored by direction, labeled by type).

        Args:
            output_dir: Directory to save HTML file (defaults to temp directory)
            open_browser: Whether to automatically open the HTML file in a browser
            min_level: Minimum security level to include (filters out lower levels)
            observable_types: List of observable types to include (filters out others)
            physics: Enable physics simulation for organic layout (default: False for static layout)
            group_by_type: Group observables by type using hierarchical layout (default: False)
            max_label_length: Maximum length for node labels before truncation (default: 60)
            title: Title displayed in the generated HTML visualization

        Returns:
            Path to the generated HTML file

        Examples:
            >>> cv = Cyvest()
            >>> # Create investigation with observables
            >>> cv.display_network()
            '/tmp/cyvest_12345/cyvest_network.html'
        """
        return generate_network_graph(
            self,
            output_dir=output_dir,
            open_browser=open_browser,
            min_level=min_level,
            observable_types=observable_types,
            physics=physics,
            group_by_type=group_by_type,
            max_label_length=max_label_length,
            title=title,
        )

    # Fluent helper entrypoints

    def taxonomy(self, *, level: Level, name: str, value: str) -> Taxonomy:
        """
        Create a taxonomy object for threat intelligence entries.

        Args:
            level: Taxonomy level (Level enum)
            name: Taxonomy name (unique per threat intel)
            value: Taxonomy value

        Returns:
            Taxonomy instance
        """
        return Taxonomy(level=level, name=name, value=value)

    def threat_intel_draft(
        self,
        source: str,
        score: Decimal | float,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        level: Level | None = None,
        taxonomies: list[Taxonomy | dict[str, Any]] | None = None,
    ) -> ThreatIntel:
        """
        Create an unbound threat intel draft entry with fluent helper methods.

        Args:
            source: Threat intel source name
            score: Score from threat intel
            comment: Optional comment
            extra: Optional extra data
            level: Optional explicit level
            taxonomies: Optional taxonomies

        Returns:
            Unbound ThreatIntel instance
        """
        return self.threat_intel_draft_create(source, score, comment, extra, level, taxonomies)

    def observable(
        self,
        obs_type: ObservableType | str,
        value: str,
        subtype: ObservableSubtype | str | None = None,
        namespace: str | None = None,
        internal: bool = False,
        whitelisted: bool = False,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> ObservableProxy:
        """
        Create (or fetch) an observable with fluent helper methods.

        Args:
            obs_type: Type of observable
            value: Value of the observable
            internal: Whether this is an internal asset
            whitelisted: Whether this is whitelisted
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level

        Returns:
            Observable proxy exposing mutation helpers for chaining
        """
        return self.observable_create(
            obs_type,
            value,
            subtype,
            namespace,
            internal,
            whitelisted,
            comment,
            extra,
            score,
            level,
        )

    def finding(
        self,
        finding_name: str,
        description: str,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> FindingProxy:
        """
        Create a finding with fluent helper methods.

        Args:
            finding_name: Finding name
            description: Finding description
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level

        Returns:
            Finding proxy exposing mutation helpers for chaining
        """
        return self.finding_create(finding_name, description, comment, extra, score, level)

    def evidence(
        self,
        evidence_type: str,
        title: str,
        source: str,
        **kwargs: Any,
    ) -> EvidenceProxy:
        """Create or fetch structured evidence with fluent helpers."""
        return self.evidence_create(evidence_type, title, source, **kwargs)

    def tag(self, name: str, description: str = "") -> TagProxy:
        """
        Create a tag with fluent helper methods.

        Args:
            name: Tag name (use ":" as hierarchy delimiter)
            description: Tag description

        Returns:
            Tag proxy exposing mutation helpers for chaining
        """
        return self.tag_create(name, description)

    def root(self) -> ObservableProxy:
        """
        Get the root observable.

        Returns:
            Root observable
        """
        return self.observable_get_root()
