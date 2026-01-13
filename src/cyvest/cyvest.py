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
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Literal, overload

from logurich import logger

from cyvest import keys
from cyvest.compare import compare_investigations
from cyvest.investigation import Investigation, InvestigationWhitelist
from cyvest.io_rich import (
    display_check_query,
    display_diff,
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
from cyvest.model import Check, Enrichment, Observable, Tag, Taxonomy, ThreatIntel
from cyvest.model_enums import ObservableType, PropagationMode, RelationshipDirection, RelationshipType
from cyvest.model_schema import InvestigationSchema, StatisticsSchema
from cyvest.proxies import CheckProxy, EnrichmentProxy, ObservableProxy, TagProxy, ThreatIntelProxy
from cyvest.score import ScoreMode

if TYPE_CHECKING:
    from cyvest.shared import SharedInvestigationContext


class Cyvest:
    """
    High-level facade for building and managing cybersecurity investigations.

    Provides methods for creating observables, checks, threat intel, enrichments,
    and tags, with automatic score propagation and statistics tracking.
    """

    OBS: Final[type[ObservableType]] = ObservableType
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

    # Internal helpers

    def _observable_proxy(self, observable: Observable | None) -> ObservableProxy | None:
        if observable is None:
            return None
        return ObservableProxy(self._investigation, observable.key)

    def _check_proxy(self, check: Check | None) -> CheckProxy | None:
        if check is None:
            return None
        return CheckProxy(self._investigation, check.key)

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

    def _require_check(self, key: str) -> Check:
        check = self._investigation.get_check(key)
        if check is None:
            raise KeyError(f"check '{key}' not found in investigation.")
        return check

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

    def observable_create(
        self,
        obs_type: ObservableType,
        value: str,
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
        obs_kwargs: dict[str, Any] = {
            "obs_type": obs_type,
            "value": value,
            "internal": internal,
            "whitelisted": whitelisted,
            "comment": comment,
            "extra": extra or {},
        }
        if score is not None:
            obs_kwargs["score"] = Decimal(str(score))
        if level is not None:
            obs_kwargs["level"] = level
        obs = Observable(**obs_kwargs)
        # Unwrap tuple - facade returns only Observable, discards deferred relationships
        obs_result, _ = self._investigation.add_observable(obs)
        return self._observable_proxy(obs_result)

    @overload
    def observable_get(self, key: str) -> ObservableProxy | None:
        """Get an observable by full key string."""
        ...

    @overload
    def observable_get(self, obs_type: ObservableType, value: str) -> ObservableProxy | None:
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
            elif not args and set(kwargs) == {"obs_type", "value"}:
                obs_type = kwargs["obs_type"]
                value = kwargs["value"]
                try:
                    key = keys.generate_observable_key(obs_type.value, value)
                except Exception as e:
                    raise ValueError(
                        f"Failed to generate observable key for type='{obs_type}', value='{value}': {e}"
                    ) from e
            else:
                raise ValueError("observable_get() accepts either (key: str) or (obs_type: ObservableType, value: str)")
        elif len(args) == 1:
            key = args[0]
        elif len(args) == 2:
            obs_type, value = args
            try:
                key = keys.generate_observable_key(obs_type.value, value)
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
        relationship_type: RelationshipType,
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

    # Check methods

    def check_create(
        self,
        check_name: str,
        description: str,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> CheckProxy:
        """
        Create a new check.

        Args:
            check_name: Check name
            description: Check description
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level

        Returns:
            The created check
        """
        check_kwargs: dict[str, Any] = {
            "check_name": check_name,
            "description": description,
            "comment": comment,
            "extra": extra or {},
            "origin_investigation_id": self._investigation.investigation_id,
        }
        if score is not None:
            check_kwargs["score"] = Decimal(str(score))
        if level is not None:
            check_kwargs["level"] = level
        check = Check(**check_kwargs)
        return self._check_proxy(self._investigation.add_check(check))

    def check_get(self, key: str) -> CheckProxy | None:
        """
        Get a check by key.

        Args:
            key: Check key

        Returns:
            Check if found, None otherwise
        """
        return self._check_proxy(self._investigation.get_check(key))

    def check_get_all(self) -> dict[str, CheckProxy]:
        """Get read-only proxies for all checks."""
        return {key: CheckProxy(self._investigation, key) for key in self._investigation.get_all_checks().keys()}

    def check_link_observable(
        self,
        check_key: str,
        observable: Observable | ObservableProxy | str,
        propagation_mode: PropagationMode = PropagationMode.LOCAL_ONLY,
    ) -> CheckProxy:
        """
        Link an observable to a check.

        Args:
            check_key: Key of the check
            observable: Observable, ObservableProxy, or its key
            propagation_mode: Propagation behavior for this link

        Returns:
            The check

        Raises:
            KeyError: If the check or observable does not exist
        """
        observable_key = self._resolve_observable_key(observable)
        result = self._investigation.link_check_observable(check_key, observable_key, propagation_mode=propagation_mode)
        return self._check_proxy(result)

    def check_update_score(self, check_key: str, score: Decimal | float, reason: str = "") -> CheckProxy:
        """
        Update a check's score.

        Args:
            check_key: Key of the check
            score: New score
            reason: Reason for update

        Returns:
            The check

        Raises:
            KeyError: If the check does not exist
        """
        check = self._require_check(check_key)
        self._investigation.apply_score_change(check, Decimal(str(score)), reason=reason)
        return self._check_proxy(check)

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

    def tag_add_check(self, tag_key: str, check_key: str) -> TagProxy:
        """
        Add a check to a tag.

        Args:
            tag_key: Key of the tag
            check_key: Key of the check

        Returns:
            The tag

        Raises:
            KeyError: If the tag or check does not exist
        """
        tag = self._investigation.add_check_to_tag(tag_key, check_key)
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
            exclude_levels: Set of levels to exclude from checks section (default: {Level.NONE})

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
            result_expected: List of ExpectedResult tolerance rules for specific checks

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
            result_expected: List of ExpectedResult tolerance rules for specific checks
            title: Title for the diff table
            rich_print: Optional callable that takes a renderable and returns None
        """
        if rich_print is None:

            def rich_print(renderables):
                return logger.rich("INFO", renderables, width=150)

        diffs = compare_investigations(actual=self, expected=expected, result_expected=result_expected)
        display_diff(diffs, rich_print, title=title)

    def display_check(
        self,
        check_key: str,
        rich_print: Callable[[Any], None] | None = None,
    ) -> None:
        """
        Display detailed information about a check.

        Args:
            check_key: Key of the check to display (format: chk:check-name)
            rich_print: Optional callable that takes a renderable and returns None.
                        If not provided, uses the default logger.

        Raises:
            KeyError: If check not found
        """
        if rich_print is None:

            def rich_print(renderables: Any) -> None:
                logger.rich("INFO", renderables, width=150, prefix=False)

        display_check_query(self, check_key, rich_print)

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
        obs_type: ObservableType,
        value: str,
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
        return self.observable_create(obs_type, value, internal, whitelisted, comment, extra, score, level)

    def check(
        self,
        check_name: str,
        description: str,
        comment: str = "",
        extra: dict[str, Any] | None = None,
        score: Decimal | float | None = None,
        level: Level | None = None,
    ) -> CheckProxy:
        """
        Create a check with fluent helper methods.

        Args:
            check_name: Check name
            description: Check description
            comment: Optional comment
            extra: Optional extra data
            score: Optional explicit score
            level: Optional explicit level

        Returns:
            Check proxy exposing mutation helpers for chaining
        """
        return self.check_create(check_name, description, comment, extra, score, level)

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
