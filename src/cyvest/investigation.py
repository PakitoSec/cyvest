"""
Investigation core - central state management for cybersecurity investigations.

Handles all object storage, merging, scoring, and statistics in a unified way.
Provides automatic merge-on-create for all object types.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal

from logurich import logger

from cyvest import keys
from cyvest.level_score_rules import recalculate_level_for_score
from cyvest.levels import Level, normalize_level
from cyvest.model import (
    AuditEvent,
    Check,
    Enrichment,
    InvestigationWhitelist,
    Observable,
    ObservableLink,
    ObservableType,
    Relationship,
    Tag,
    Taxonomy,
    ThreatIntel,
)
from cyvest.model_enums import PropagationMode, RelationshipDirection, RelationshipType
from cyvest.score import ScoreEngine, ScoreMode
from cyvest.stats import InvestigationStats
from cyvest.ulid import generate_ulid

if TYPE_CHECKING:
    from cyvest.model_schema import StatisticsSchema


class Investigation:
    """
    Core investigation state and operations.

    Manages all investigation objects (observables, checks, threat intel, etc.),
    handles automatic merging on creation, score propagation, and statistics tracking.
    """

    _MODEL_METADATA_RULES: dict[str, dict[str, set[str]]] = {
        "observable": {
            "fields": {"comment", "extra", "internal", "whitelisted"},
            "dict_fields": {"extra"},
        },
        "check": {
            "fields": {"comment", "extra", "description"},
            "dict_fields": {"extra"},
        },
        "threat_intel": {
            "fields": {"comment", "extra", "level", "taxonomies"},
            "dict_fields": {"extra"},
        },
        "enrichment": {
            "fields": {"context", "data"},
            "dict_fields": {"data"},
        },
        "tag": {
            "fields": {"description"},
            "dict_fields": set(),
        },
    }

    def __init__(
        self,
        root_data: Any = None,
        root_type: ObservableType | Literal["file", "artifact"] = ObservableType.FILE,
        score_mode_obs: ScoreMode | Literal["max", "sum"] = ScoreMode.MAX,
        *,
        investigation_id: str | None = None,
        investigation_name: str | None = None,
    ) -> None:
        """
        Initialize a new investigation.

        Args:
            root_data: Data stored on the root observable (optional)
            root_type: Root observable type (ObservableType.FILE or ObservableType.ARTIFACT)
            score_mode_obs: Observable score calculation mode (MAX or SUM)
            investigation_name: Optional human-readable investigation name
        """
        self.investigation_id = investigation_id or generate_ulid()
        self.investigation_name = investigation_name
        self._audit_log: list[AuditEvent] = []
        self._audit_enabled = True

        # Record investigation start as the first event
        self._record_event(
            event_type="INVESTIGATION_STARTED",
            object_type="investigation",
            object_key=self.investigation_id,
        )

        # Object collections
        self._observables: dict[str, Observable] = {}
        self._checks: dict[str, Check] = {}
        self._threat_intels: dict[str, ThreatIntel] = {}
        self._enrichments: dict[str, Enrichment] = {}
        self._tags: dict[str, Tag] = {}

        # Internal components
        normalized_score_mode_obs = ScoreMode.normalize(score_mode_obs)
        self._score_engine = ScoreEngine(score_mode_obs=normalized_score_mode_obs, sink=self)
        self._stats = InvestigationStats()
        self._whitelists: dict[str, InvestigationWhitelist] = {}

        # Create root observable
        obj_type = ObservableType.normalize_root_type(root_type)

        self._root_observable = Observable(
            obs_type=obj_type,
            value="root",
            internal=False,
            whitelisted=False,
            comment="Root observable for investigation",
            extra=root_data,
            score=Decimal("0"),
            level=Level.INFO,
        )
        self._observables[self._root_observable.key] = self._root_observable
        self._score_engine.register_observable(self._root_observable)
        self._stats.register_observable(self._root_observable)
        self._record_event(
            event_type="OBSERVABLE_CREATED",
            object_type="observable",
            object_key=self._root_observable.key,
        )

    def _record_event(
        self,
        *,
        event_type: str,
        object_type: str | None = None,
        object_key: str | None = None,
        reason: str | None = None,
        actor: str | None = None,
        tool: str | None = None,
        details: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> AuditEvent | None:
        if not self._audit_enabled:
            return None

        event = AuditEvent(
            event_id=generate_ulid(),
            timestamp=timestamp or datetime.now(timezone.utc),
            event_type=event_type,
            actor=actor,
            reason=reason,
            tool=tool,
            object_type=object_type,
            object_key=object_key,
            details=deepcopy(details) if details else {},
        )
        self._audit_log.append(event)
        return event

    @property
    def started_at(self) -> datetime:
        """Return the investigation start time from the first event in the audit log."""
        for event in self._audit_log:
            if event.event_type == "INVESTIGATION_STARTED":
                return event.timestamp
        # Fallback if no INVESTIGATION_STARTED event (shouldn't happen)
        return datetime.now(timezone.utc)

    def _link_threat_intel_to_observable(self, observable: Observable, ti: ThreatIntel) -> None:
        if any(existing.key == ti.key for existing in observable.threat_intels):
            return
        observable.threat_intels.append(ti)

    def _create_relationship(
        self,
        source_obs: Observable,
        target_key: str,
        relationship_type: RelationshipType | str,
        direction: RelationshipDirection | str | None = None,
    ) -> None:
        rel = Relationship(target_key=target_key, relationship_type=relationship_type, direction=direction)
        rel_tuple = (rel.target_key, rel.relationship_type, rel.direction)
        existing_rels = {(r.target_key, r.relationship_type, r.direction) for r in source_obs.relationships}
        if rel_tuple not in existing_rels:
            source_obs.relationships.append(rel)

    def _link_check_to_observable(self, check: Check, link: ObservableLink) -> bool:
        existing: dict[tuple[str, PropagationMode], int] = {}
        for idx, existing_link in enumerate(check.observable_links):
            existing[(existing_link.observable_key, existing_link.propagation_mode)] = idx
        link_tuple = (link.observable_key, link.propagation_mode)
        if link_tuple in existing:
            return False

        check.observable_links.append(link)
        return True

    def _link_check_to_tag(self, tag: Tag, check: Check) -> None:
        if any(existing.key == check.key for existing in tag.checks):
            return
        tag.checks.append(check)

    def _get_object_type(self, obj: Any) -> str | None:
        if isinstance(obj, Observable):
            return "observable"
        if isinstance(obj, Check):
            return "check"
        if isinstance(obj, ThreatIntel):
            return "threat_intel"
        if isinstance(obj, Enrichment):
            return "enrichment"
        if isinstance(obj, Tag):
            return "tag"
        return None

    @staticmethod
    def _normalize_taxonomies(value: Any) -> list[Taxonomy]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise TypeError("taxonomies must be a list of taxonomy objects.")
        taxonomies = [Taxonomy.model_validate(item) for item in value]
        seen: set[str] = set()
        duplicates: set[str] = set()
        for taxonomy in taxonomies:
            if taxonomy.name in seen:
                duplicates.add(taxonomy.name)
            seen.add(taxonomy.name)
        if duplicates:
            dupes = ", ".join(sorted(duplicates))
            raise ValueError(f"Duplicate taxonomy name(s): {dupes}")
        return taxonomies

    def apply_score_change(
        self,
        obj: Any,
        new_score: Decimal,
        *,
        reason: str = "",
        event_type: str = "SCORE_CHANGED",
        contributing_investigation_ids: set[str] | None = None,
    ) -> bool:
        """Apply a score change and emit an audit event."""
        if not isinstance(new_score, Decimal):
            new_score = Decimal(str(new_score))

        old_score = obj.score
        old_level = obj.level
        new_level = recalculate_level_for_score(old_level, new_score)

        if new_score == old_score and new_level == old_level:
            return False

        obj.score = new_score
        obj.level = new_level

        if event_type == "SCORE_RECALCULATED":
            # Skip audit log entry for recalculated scores.
            return True

        details = {
            "old_score": float(old_score),
            "new_score": float(new_score),
            "old_level": old_level.value,
            "new_level": new_level.value,
        }
        if contributing_investigation_ids:
            details["contributing_investigation_ids"] = sorted(contributing_investigation_ids)

        self._record_event(
            event_type=event_type,
            object_type=self._get_object_type(obj),
            object_key=getattr(obj, "key", None),
            reason=reason,
            details=details,
        )
        return True

    def apply_level_change(
        self,
        obj: Any,
        level: Level | str,
        *,
        reason: str = "",
        event_type: str = "LEVEL_UPDATED",
    ) -> bool:
        """Apply a level change and emit an audit event."""
        new_level = normalize_level(level)
        old_level = obj.level
        if new_level == old_level:
            return False

        obj.level = new_level
        self._record_event(
            event_type=event_type,
            object_type=self._get_object_type(obj),
            object_key=getattr(obj, "key", None),
            reason=reason,
            details={
                "old_level": old_level.value,
                "new_level": new_level.value,
                "score": float(obj.score),
            },
        )
        return True

    def _update_observable_check_links(self, observable_key: str) -> None:
        obs = self._observables.get(observable_key)
        if not obs:
            return
        check_keys = self._score_engine.get_check_links_for_observable(observable_key)
        obs._check_links = check_keys

    def _rebuild_all_check_links(self) -> None:
        for observable_key in self._observables:
            self._update_observable_check_links(observable_key)

    def get_audit_log(self) -> list[AuditEvent]:
        """Return a deep copy of the audit log."""
        return [event.model_copy(deep=True) for event in self._audit_log]

    def get_audit_events(
        self,
        *,
        object_type: str | None = None,
        object_key: str | None = None,
        event_type: str | None = None,
    ) -> list[AuditEvent]:
        """Filter audit events by optional object type/key and event type."""
        events = self._audit_log
        if object_type is not None:
            events = [event for event in events if event.object_type == object_type]
        if object_key is not None:
            events = [event for event in events if event.object_key == object_key]
        if event_type is not None:
            events = [event for event in events if event.event_type == event_type]
        return [event.model_copy(deep=True) for event in events]

    def set_investigation_name(self, name: str | None, *, reason: str | None = None) -> None:
        """Set or clear the human-readable investigation name."""
        name = str(name).strip() if name is not None else None
        if name == self.investigation_name:
            return
        old_name = self.investigation_name
        self.investigation_name = name
        self._record_event(
            event_type="INVESTIGATION_NAME_UPDATED",
            object_type="investigation",
            object_key=self.investigation_id,
            reason=reason,
            details={"old_name": old_name, "new_name": name},
        )

    def _merge_observable(self, existing: Observable, incoming: Observable) -> tuple[Observable, list]:
        """
        Merge an incoming observable into an existing observable.

        Strategy:
        - Update score (take maximum)
        - Update level (take maximum)
        - Update extra (merge dicts)
        - Overwrite comment (if incoming is non-empty)
        - Merge threat intels
        - Merge relationships (defer if target missing)
        - Preserve provenance metadata

        Args:
            existing: The existing observable
            incoming: The incoming observable to merge

        Returns:
            Tuple of (merged observable, deferred relationships)
        """
        # Normal merge logic for scores and levels (SAFE level protection in Observable.update_score)
        # Take the higher score
        if incoming.score > existing.score:
            self.apply_score_change(
                existing,
                incoming.score,
                reason=f"Merged from {incoming.key}",
            )

        # Take the higher level
        if incoming.level > existing.level:
            self.apply_level_change(existing, incoming.level, reason=f"Merged from {incoming.key}")

        # Update extra (merge dictionaries)
        if existing.extra:
            existing.extra.update(incoming.extra)
        elif incoming.extra:
            existing.extra = dict(incoming.extra)

        # Overwrite comment if incoming is non-empty
        if incoming.comment:
            existing.comment = incoming.comment

        # Merge whitelisted status (if either is whitelisted, result is whitelisted)
        existing.whitelisted = existing.whitelisted or incoming.whitelisted

        # Merge internal status (if either is external, result is external)
        existing.internal = existing.internal and incoming.internal

        # Merge threat intels (avoid duplicates by key)
        existing_ti_keys = {ti.key for ti in existing.threat_intels}
        for ti in incoming.threat_intels:
            if ti.key not in existing_ti_keys:
                self._link_threat_intel_to_observable(existing, ti)
                existing_ti_keys.add(ti.key)

        # Merge relationships (defer if target not yet available)
        deferred_relationships = []
        for rel in incoming.relationships:
            if rel.target_key in self._observables:
                # Target exists - add relationship immediately
                self._create_relationship(existing, rel.target_key, rel.relationship_type, rel.direction)
            else:
                # Target doesn't exist yet - defer for Pass 2 of merge_investigation()
                deferred_relationships.append((existing.key, rel))

        return existing, deferred_relationships

    def _merge_check(self, existing: Check, incoming: Check) -> Check:
        """
        Merge an incoming check into an existing check.

        Strategy:
        - Update score (take maximum)
        - Update level (take maximum)
        - Update extra (merge dicts)
        - Overwrite description (if incoming is non-empty)
        - Overwrite comment (if incoming is non-empty)
        - Merge observable links (tuple-based deduplication, provenance-preserving)

        Args:
            existing: The existing check
            incoming: The incoming check to merge

        Returns:
            The merged check (existing is modified in place)
        """
        if not incoming.origin_investigation_id:
            incoming.origin_investigation_id = self.investigation_id
        if not existing.origin_investigation_id:
            existing.origin_investigation_id = incoming.origin_investigation_id

        # Take the higher score
        if incoming.score > existing.score:
            self.apply_score_change(
                existing,
                incoming.score,
                reason=f"Merged from {incoming.key}",
            )

        # Take the higher level
        if incoming.level > existing.level:
            self.apply_level_change(existing, incoming.level, reason=f"Merged from {incoming.key}")

        # Update extra (merge dictionaries)
        existing.extra.update(incoming.extra)

        # Overwrite description if incoming is non-empty
        if incoming.description:
            existing.description = incoming.description

        # Overwrite comment if incoming is non-empty
        if incoming.comment:
            existing.comment = incoming.comment

        existing_by_tuple: dict[tuple[str, PropagationMode], int] = {}
        for idx, existing_link in enumerate(existing.observable_links):
            existing_by_tuple[(existing_link.observable_key, existing_link.propagation_mode)] = idx
        for incoming_link in incoming.observable_links:
            link_tuple = (incoming_link.observable_key, incoming_link.propagation_mode)
            existing_idx = existing_by_tuple.get(link_tuple)
            if existing_idx is None:
                existing.observable_links.append(incoming_link)
                existing_by_tuple[link_tuple] = len(existing.observable_links) - 1
                continue

        return existing

    def _merge_threat_intel(self, existing: ThreatIntel, incoming: ThreatIntel) -> ThreatIntel:
        """
        Merge an incoming threat intel into an existing threat intel.

        Strategy:
        - Update score (take maximum)
        - Update level (take maximum)
        - Update extra (merge dicts)
        - Concatenate comments
        - Merge taxonomies

        Args:
            existing: The existing threat intel
            incoming: The incoming threat intel to merge

        Returns:
            The merged threat intel (existing is modified in place)
        """
        # Take the higher score
        if incoming.score > existing.score:
            self.apply_score_change(
                existing,
                incoming.score,
                reason=f"Merged from {incoming.key}",
            )

        # Take the higher level
        if incoming.level > existing.level:
            self.apply_level_change(existing, incoming.level, reason=f"Merged from {incoming.key}")

        # Update extra (merge dictionaries)
        existing.extra.update(incoming.extra)

        # Concatenate comments
        if incoming.comment:
            if existing.comment:
                existing.comment += "\n\n" + incoming.comment
            else:
                existing.comment = incoming.comment

        # Merge taxonomies (ensure unique names)
        existing_by_name: dict[str, int] = {taxonomy.name: idx for idx, taxonomy in enumerate(existing.taxonomies)}
        for taxonomy in incoming.taxonomies:
            existing_idx = existing_by_name.get(taxonomy.name)
            if existing_idx is None:
                existing.taxonomies.append(taxonomy)
                existing_by_name[taxonomy.name] = len(existing.taxonomies) - 1
            else:
                existing.taxonomies[existing_idx] = taxonomy

        return existing

    def _merge_enrichment(self, existing: Enrichment, incoming: Enrichment) -> Enrichment:
        """
        Merge an incoming enrichment into an existing enrichment.

        Strategy:
        - Deep merge data structure (merge dictionaries recursively)

        Args:
            existing: The existing enrichment
            incoming: The incoming enrichment to merge

        Returns:
            The merged enrichment (existing is modified in place)
        """

        def deep_merge(base: dict, update: dict) -> dict:
            """Recursively merge dictionaries."""
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    deep_merge(base[key], value)
                else:
                    base[key] = value
            return base

        # Deep merge data structures
        if isinstance(existing.data, dict) and isinstance(incoming.data, dict):
            deep_merge(existing.data, incoming.data)
        else:
            existing.data = deepcopy(incoming.data)

        # Update context if incoming has one
        if incoming.context:
            existing.context = incoming.context

        return existing

    def _merge_tag(self, existing: Tag, incoming: Tag) -> Tag:
        """
        Merge an incoming tag into an existing tag.

        Strategy:
        - Merge checks (dict-based lookup for efficiency)

        Args:
            existing: The existing tag
            incoming: The incoming tag to merge

        Returns:
            The merged tag (existing is modified in place)
        """
        # Update description if incoming has one
        if incoming.description:
            existing.description = incoming.description

        # Merge checks using dict-based lookup (more efficient)
        existing_checks_dict = {check.key: check for check in existing.checks}

        for incoming_check in incoming.checks:
            if incoming_check.key in existing_checks_dict:
                # Merge existing check
                self._merge_check(existing_checks_dict[incoming_check.key], incoming_check)
            else:
                # Add new check
                self._link_check_to_tag(existing, incoming_check)

        return existing

    def _clone_for_merge(
        self, other: Investigation
    ) -> tuple[
        dict[str, Observable],
        dict[str, ThreatIntel],
        dict[str, Check],
        dict[str, Enrichment],
        dict[str, Tag],
    ]:
        """Clone incoming models while preserving shared object references."""
        incoming_threat_intels = {key: ti.model_copy(deep=True) for key, ti in other._threat_intels.items()}
        incoming_checks = {key: check.model_copy(deep=True) for key, check in other._checks.items()}
        incoming_enrichments = {key: enrichment.model_copy(deep=True) for key, enrichment in other._enrichments.items()}

        orphan_threat_intels: dict[str, ThreatIntel] = {}

        def _copy_threat_intel(ti: ThreatIntel) -> ThreatIntel:
            if ti.key in incoming_threat_intels:
                return incoming_threat_intels[ti.key]
            existing = orphan_threat_intels.get(ti.key)
            if existing:
                return existing
            copied = ti.model_copy(deep=True)
            orphan_threat_intels[ti.key] = copied
            return copied

        incoming_observables: dict[str, Observable] = {}
        for obs in other._observables.values():
            copied_obs = obs.model_copy(deep=True)
            if obs.threat_intels:
                copied_obs.threat_intels = [_copy_threat_intel(ti) for ti in obs.threat_intels]
            incoming_observables[obs.key] = copied_obs

        orphan_checks: dict[str, Check] = {}

        def _copy_check(check: Check) -> Check:
            if check.key in incoming_checks:
                return incoming_checks[check.key]
            existing = orphan_checks.get(check.key)
            if existing:
                return existing
            copied = check.model_copy(deep=True)
            orphan_checks[check.key] = copied
            return copied

        incoming_tags: dict[str, Tag] = {}

        def _copy_tag(tag: Tag) -> Tag:
            existing = incoming_tags.get(tag.key)
            if existing:
                return existing
            copied = Tag(
                name=tag.name,
                description=tag.description,
                checks=[_copy_check(check) for check in tag.checks],
                key=tag.key,
            )
            incoming_tags[tag.key] = copied
            return copied

        for tag in other._tags.values():
            _copy_tag(tag)

        return (
            incoming_observables,
            incoming_threat_intels,
            incoming_checks,
            incoming_enrichments,
            incoming_tags,
        )

    def add_observable(self, obs: Observable) -> tuple[Observable, list]:
        """
        Add or merge an observable.

        Args:
            obs: Observable to add or merge

        Returns:
            Tuple of (resulting observable, deferred relationships)
        """
        if obs.key in self._observables:
            r = self._merge_observable(self._observables[obs.key], obs)
            self._score_engine.recalculate_all()
            return r

        # Register new observable
        self._observables[obs.key] = obs
        self._score_engine.register_observable(obs)
        self._stats.register_observable(obs)
        self._update_observable_check_links(obs.key)
        self._record_event(
            event_type="OBSERVABLE_CREATED",
            object_type="observable",
            object_key=obs.key,
        )
        return obs, []

    def add_check(self, check: Check) -> Check:
        """
        Add or merge a check.

        Args:
            check: Check to add or merge

        Returns:
            The resulting check (either new or merged)
        """
        if check.key in self._checks:
            r = self._merge_check(self._checks[check.key], check)
            self._score_engine.rebuild_link_index()
            self._score_engine.recalculate_all()
            for link in r.observable_links:
                self._update_observable_check_links(link.observable_key)
            return r

        if not getattr(check, "origin_investigation_id", None):
            check.origin_investigation_id = self.investigation_id

        # Register new check
        self._checks[check.key] = check
        self._score_engine.register_check(check)
        self._stats.register_check(check)
        for link in check.observable_links:
            self._update_observable_check_links(link.observable_key)
        self._record_event(
            event_type="CHECK_CREATED",
            object_type="check",
            object_key=check.key,
        )
        return check

    def add_threat_intel(self, ti: ThreatIntel, observable: Observable) -> ThreatIntel:
        """
        Add or merge threat intel and link to observable.

        Args:
            ti: Threat intel to add or merge
            observable: Observable to link to

        Returns:
            The resulting threat intel (either new or merged)
        """
        if ti.key in self._threat_intels:
            merged_ti = self._merge_threat_intel(self._threat_intels[ti.key], ti)
            # Propagate score to observable
            self._score_engine.propagate_threat_intel_to_observable(merged_ti, observable)
            self._record_event(
                event_type="THREAT_INTEL_ATTACHED",
                object_type="observable",
                object_key=observable.key,
                details={
                    "threat_intel_key": merged_ti.key,
                    "source": merged_ti.source,
                    "score": merged_ti.score,
                    "level": merged_ti.level,
                },
            )
            return merged_ti

        # Register new threat intel
        self._threat_intels[ti.key] = ti
        self._stats.register_threat_intel(ti)

        # Add to observable
        self._link_threat_intel_to_observable(observable, ti)

        # Propagate score
        self._score_engine.propagate_threat_intel_to_observable(ti, observable)

        self._record_event(
            event_type="THREAT_INTEL_ATTACHED",
            object_type="observable",
            object_key=observable.key,
            details={
                "threat_intel_key": ti.key,
                "source": ti.source,
                "score": ti.score,
                "level": ti.level,
            },
        )
        return ti

    def add_threat_intel_taxonomy(self, threat_intel_key: str, taxonomy: Taxonomy) -> ThreatIntel:
        """
        Add or replace a taxonomy entry on a threat intel by name.

        Args:
            threat_intel_key: Threat intel key
            taxonomy: Taxonomy entry to add or replace

        Returns:
            The updated threat intel
        """
        ti = self._threat_intels.get(threat_intel_key)
        if ti is None:
            raise KeyError(f"threat_intel '{threat_intel_key}' not found in investigation.")

        updated_taxonomies = list(ti.taxonomies)
        replaced = False
        for idx, existing in enumerate(updated_taxonomies):
            if existing.name == taxonomy.name:
                updated_taxonomies[idx] = taxonomy
                replaced = True
                break

        if not replaced:
            updated_taxonomies.append(taxonomy)

        return self.update_model_metadata("threat_intel", threat_intel_key, {"taxonomies": updated_taxonomies})

    def remove_threat_intel_taxonomy(self, threat_intel_key: str, name: str) -> ThreatIntel:
        """
        Remove a taxonomy entry from a threat intel by name.

        Args:
            threat_intel_key: Threat intel key
            name: Taxonomy name to remove

        Returns:
            The updated threat intel
        """
        ti = self._threat_intels.get(threat_intel_key)
        if ti is None:
            raise KeyError(f"threat_intel '{threat_intel_key}' not found in investigation.")

        updated_taxonomies = [taxonomy for taxonomy in ti.taxonomies if taxonomy.name != name]
        if len(updated_taxonomies) == len(ti.taxonomies):
            return ti

        return self.update_model_metadata("threat_intel", threat_intel_key, {"taxonomies": updated_taxonomies})

    def add_enrichment(self, enrichment: Enrichment) -> Enrichment:
        """
        Add or merge enrichment.

        Args:
            enrichment: Enrichment to add or merge

        Returns:
            The resulting enrichment (either new or merged)
        """
        if enrichment.key in self._enrichments:
            return self._merge_enrichment(self._enrichments[enrichment.key], enrichment)

        # Register new enrichment
        self._enrichments[enrichment.key] = enrichment
        self._record_event(
            event_type="ENRICHMENT_CREATED",
            object_type="enrichment",
            object_key=enrichment.key,
        )
        return enrichment

    def add_tag(self, tag: Tag) -> Tag:
        """
        Add or merge a tag, automatically creating ancestor tags.

        When adding a tag with a hierarchical name (using ":" delimiter),
        ancestor tags are automatically created if they don't exist.
        For example, adding "header:auth:dkim" will auto-create
        "header" and "header:auth" tags.

        Args:
            tag: Tag to add or merge

        Returns:
            The resulting tag (either new or merged)
        """
        # Auto-create ancestor tags
        ancestor_names = keys.get_tag_ancestors(tag.name)
        for ancestor_name in ancestor_names:
            ancestor_key = keys.generate_tag_key(ancestor_name)
            if ancestor_key not in self._tags:
                ancestor_tag = Tag(name=ancestor_name)
                self._tags[ancestor_key] = ancestor_tag
                self._stats.register_tag(ancestor_tag)
                self._record_event(
                    event_type="TAG_CREATED",
                    object_type="tag",
                    object_key=ancestor_key,
                    details={"auto_created": True, "descendant": tag.name},
                )

        # Add or merge the tag itself
        if tag.key in self._tags:
            r = self._merge_tag(self._tags[tag.key], tag)
            self._score_engine.recalculate_all()
            return r

        # Register new tag
        self._tags[tag.key] = tag
        self._stats.register_tag(tag)
        self._record_event(
            event_type="TAG_CREATED",
            object_type="tag",
            object_key=tag.key,
        )
        return tag

    def add_relationship(
        self,
        source: Observable | str,
        target: Observable | str,
        relationship_type: RelationshipType | str,
        direction: RelationshipDirection | str | None = None,
    ) -> Observable:
        """
        Add a relationship between observables.

        Args:
            source: Source observable or its key
            target: Target observable or its key
            relationship_type: Type of relationship
            direction: Direction of the relationship (None = use semantic default)

        Returns:
            The source observable

        Raises:
            KeyError: If the source or target observable does not exist
        """

        # Extract keys from Observable objects if needed
        source_key = source.key if isinstance(source, Observable) else source
        target_key = target.key if isinstance(target, Observable) else target

        # Check if target is a copy from shared context (anti-pattern)
        if isinstance(target, Observable) and getattr(target, "_from_shared_context", False):
            obs_type_name = target.obs_type.name
            raise ValueError(
                f"Cannot use observable from shared_context.observable_get() directly in relationships.\n"
                f"Observable '{target_key}' is a read-only copy not registered in this investigation.\n\n"
                f"Incorrect pattern:\n"
                f"  source.relate_to(shared_context.observable_get(...), RelationshipType.{relationship_type})\n\n"
                f"Correct pattern (and use reconcile or merge):\n"
                f"  # Use cy.observable() to create/get observable in local investigation\n"
                f"  source.relate_to(\n"
                f"      cy.observable(ObservableType.{obs_type_name}, '{target.value}'),\n"
                f"      RelationshipType.{relationship_type}\n"
                f"  )"
            )

        # Validate both source and target exist
        source_obs = self._observables.get(source_key)
        target_obs = self._observables.get(target_key)

        if not source_obs:
            raise KeyError(f"observable '{source_key}' not found in investigation.")

        if not target_obs:
            raise KeyError(f"observable '{target_key}' not found in investigation.")

        # Add relationship using internal method
        self._create_relationship(source_obs, target_key, relationship_type, direction)

        self._record_event(
            event_type="RELATIONSHIP_CREATED",
            object_type="observable",
            object_key=source_obs.key,
            details={
                "target_key": target_key,
                "relationship_type": relationship_type,
                "direction": direction,
            },
        )

        # Recalculate scores after adding relationship
        self._score_engine.recalculate_all()

        return source_obs

    def link_check_observable(
        self,
        check_key: str,
        observable_key: str,
        propagation_mode: PropagationMode | str = PropagationMode.LOCAL_ONLY,
    ) -> Check:
        """
        Link an observable to a check.

        Args:
            check_key: Key of the check
            observable_key: Key of the observable
            propagation_mode: Propagation behavior for this link

        Returns:
            The check

        Raises:
            KeyError: If the check or observable does not exist
        """
        check = self._checks.get(check_key)
        observable = self._observables.get(observable_key)

        if check is None:
            raise KeyError(f"check '{check_key}' not found in investigation.")
        if observable is None:
            raise KeyError(f"observable '{observable_key}' not found in investigation.")

        if check and observable:
            propagation_mode = PropagationMode(propagation_mode)
            link = ObservableLink(
                observable_key=observable_key,
                propagation_mode=propagation_mode,
            )
            created = self._link_check_to_observable(check, link)
            if created:
                self._score_engine.register_check_observable_link(check_key=check.key, observable_key=observable_key)
                self._update_observable_check_links(observable_key)
                self._record_event(
                    event_type="CHECK_LINKED_TO_OBSERVABLE",
                    object_type="check",
                    object_key=check.key,
                    details={
                        "observable_key": observable_key,
                        "propagation_mode": propagation_mode.value,
                    },
                )
                is_effective = (
                    propagation_mode == PropagationMode.GLOBAL or self.investigation_id == check.origin_investigation_id
                )
                if is_effective and check.level == Level.NONE:
                    self.apply_level_change(check, Level.INFO, reason="Effective link added")

            self._score_engine._propagate_observable_to_checks(observable_key)

        return check

    def add_check_to_tag(self, tag_key: str, check_key: str) -> Tag:
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
        tag = self._tags.get(tag_key)
        check = self._checks.get(check_key)

        if tag is None:
            raise KeyError(f"tag '{tag_key}' not found in investigation.")
        if check is None:
            raise KeyError(f"check '{check_key}' not found in investigation.")

        if tag and check:
            self._link_check_to_tag(tag, check)
            self._record_event(
                event_type="TAG_CHECK_ADDED",
                object_type="tag",
                object_key=tag.key,
                details={"check_key": check.key},
            )

        return tag

    def get_root(self) -> Observable:
        """Get the root observable."""
        return self._root_observable

    def get_observable(self, key: str) -> Observable | None:
        """Get observable by full key string."""
        return self._observables.get(key)

    def get_check(self, key: str) -> Check | None:
        """Get check by full key string."""
        return self._checks.get(key)

    def get_tag(self, key: str) -> Tag | None:
        """Get a tag by key."""
        return self._tags.get(key)

    def get_tag_children(self, tag_name: str) -> list[Tag]:
        """
        Get direct child tags of a tag.

        Args:
            tag_name: Name of the parent tag

        Returns:
            List of direct child Tag objects
        """
        return [t for t in self._tags.values() if keys.is_tag_child_of(t.name, tag_name)]

    def get_tag_descendants(self, tag_name: str) -> list[Tag]:
        """
        Get all descendant tags of a tag.

        Args:
            tag_name: Name of the ancestor tag

        Returns:
            List of all descendant Tag objects
        """
        return [t for t in self._tags.values() if keys.is_tag_descendant_of(t.name, tag_name)]

    def get_tag_ancestors(self, tag_name: str) -> list[Tag]:
        """
        Get all ancestor tags of a tag.

        Args:
            tag_name: Name of the descendant tag

        Returns:
            List of ancestor Tag objects (in order from root to immediate parent)
        """
        ancestor_names = keys.get_tag_ancestors(tag_name)
        result = []
        for name in ancestor_names:
            tag_key = keys.generate_tag_key(name)
            if tag_key in self._tags:
                result.append(self._tags[tag_key])
        return result

    def get_tag_aggregated_score(self, tag_name: str) -> Decimal:
        """
        Get aggregated score for a tag including all descendants.

        Args:
            tag_name: Name of the tag

        Returns:
            Total score from direct checks and all descendant tag checks
        """
        tag_key = keys.generate_tag_key(tag_name)
        tag = self._tags.get(tag_key)
        if not tag:
            return Decimal("0")

        total = tag.get_direct_score()

        # Add scores from direct children only (they will recursively add their children)
        for child in self.get_tag_children(tag_name):
            total += self.get_tag_aggregated_score(child.name)

        return total

    def get_tag_aggregated_level(self, tag_name: str) -> Level:
        """
        Get aggregated level for a tag including all descendants.

        Args:
            tag_name: Name of the tag

        Returns:
            Level based on aggregated score
        """
        from cyvest.levels import get_level_from_score

        return get_level_from_score(self.get_tag_aggregated_score(tag_name))

    def get_enrichment(self, key: str) -> Enrichment | None:
        """Get an enrichment by key."""
        return self._enrichments.get(key)

    def get_threat_intel(self, key: str) -> ThreatIntel | None:
        """Get a threat intel by key."""
        return self._threat_intels.get(key)

    def update_model_metadata(
        self,
        model_type: Literal["observable", "check", "threat_intel", "enrichment", "tag"],
        key: str,
        updates: dict[str, Any],
        *,
        dict_merge: dict[str, bool] | None = None,
    ):
        """
        Update mutable metadata fields for a stored model instance.

        Args:
            model_type: Model family to update.
            key: Key of the target object.
            updates: Mapping of field names to new values. ``None`` values are ignored.
            dict_merge: Optional overrides for dict fields (True=merge, False=replace).

        Returns:
            The updated model instance.

        Raises:
            KeyError: If the key cannot be found.
            ValueError: If an unsupported field is requested.
            TypeError: If a dict field receives a non-dict value.
        """
        store_lookup: dict[str, dict[str, Any]] = {
            "observable": self._observables,
            "check": self._checks,
            "threat_intel": self._threat_intels,
            "enrichment": self._enrichments,
            "tag": self._tags,
        }
        store = store_lookup[model_type]
        target = store.get(key)
        if target is None:
            raise KeyError(f"{model_type} '{key}' not found in investigation.")

        if not updates:
            return target

        rules = self._MODEL_METADATA_RULES[model_type]
        allowed_fields = rules["fields"]
        dict_fields = rules["dict_fields"]

        changes: dict[str, dict[str, Any]] = {}

        for field, value in updates.items():
            if field not in allowed_fields:
                raise ValueError(f"Field '{field}' is not mutable on {model_type}.")
            if value is None:
                continue
            old_value = deepcopy(getattr(target, field, None))
            if field == "level":
                value = normalize_level(value)
            if model_type == "threat_intel" and field == "taxonomies":
                value = self._normalize_taxonomies(value)
            if field in dict_fields:
                if not isinstance(value, dict):
                    raise TypeError(f"Field '{field}' on {model_type} expects a dict value.")
                merge = dict_merge.get(field, True) if dict_merge else True
                if merge:
                    current_value = getattr(target, field, None)
                    if current_value is None:
                        setattr(target, field, deepcopy(value))
                    else:
                        current_value.update(value)
                else:
                    setattr(target, field, deepcopy(value))
            else:
                setattr(target, field, value)
            new_value = deepcopy(getattr(target, field, None))
            if old_value != new_value:
                changes[field] = {"old": old_value, "new": new_value}

        if changes:
            self._record_event(
                event_type="METADATA_UPDATED",
                object_type=model_type,
                object_key=key,
                details={"changes": changes},
            )
        return target

    def get_all_observables(self) -> dict[str, Observable]:
        """Get all observables."""
        return self._observables.copy()

    def get_all_checks(self) -> dict[str, Check]:
        """Get all checks."""
        return self._checks.copy()

    def get_all_threat_intels(self) -> dict[str, ThreatIntel]:
        """Get all threat intels."""
        return self._threat_intels.copy()

    def get_all_enrichments(self) -> dict[str, Enrichment]:
        """Get all enrichments."""
        return self._enrichments.copy()

    def get_all_tags(self) -> dict[str, Tag]:
        """Get all tags."""
        return self._tags.copy()

    def get_global_score(self) -> Decimal:
        """Get the global investigation score."""
        return self._score_engine.get_global_score()

    def get_global_level(self) -> Level:
        """Get the global investigation level."""
        return self._score_engine.get_global_level()

    def is_whitelisted(self) -> bool:
        """Return whether the investigation has any whitelist entries."""
        return bool(self._whitelists)

    def add_whitelist(self, identifier: str, name: str, justification: str | None = None) -> InvestigationWhitelist:
        """
        Add or update a whitelist entry.

        Args:
            identifier: Unique identifier for this whitelist entry.
            name: Human-readable name for the whitelist entry.
            justification: Optional markdown justification.

        Returns:
            The stored whitelist entry.
        """
        identifier = str(identifier).strip()
        name = str(name).strip()
        if not identifier:
            raise ValueError("Whitelist identifier must be provided.")
        if not name:
            raise ValueError("Whitelist name must be provided.")
        if justification is not None:
            justification = str(justification)

        entry = InvestigationWhitelist(identifier=identifier, name=name, justification=justification)
        self._whitelists[identifier] = entry
        self._record_event(
            event_type="WHITELIST_APPLIED",
            object_type="investigation",
            object_key=self.investigation_id,
            details={
                "identifier": identifier,
                "name": name,
                "justification": justification,
            },
        )
        return entry

    def remove_whitelist(self, identifier: str) -> bool:
        """
        Remove a whitelist entry by identifier.

        Returns:
            True if removed, False if it did not exist.
        """
        removed = self._whitelists.pop(identifier, None)
        if removed:
            self._record_event(
                event_type="WHITELIST_REMOVED",
                object_type="investigation",
                object_key=self.investigation_id,
                details={"identifier": identifier},
            )
        return removed is not None

    def clear_whitelists(self) -> None:
        """Remove all whitelist entries."""
        if not self._whitelists:
            return
        removed = list(self._whitelists.keys())
        self._whitelists.clear()
        self._record_event(
            event_type="WHITELIST_CLEARED",
            object_type="investigation",
            object_key=self.investigation_id,
            details={"identifiers": removed},
        )

    def get_whitelists(self) -> list[InvestigationWhitelist]:
        """Return a copy of all whitelist entries."""
        return [w.model_copy(deep=True) for w in self._whitelists.values()]

    def get_statistics(self) -> StatisticsSchema:
        """Get comprehensive investigation statistics."""
        return self._stats.get_summary()

    def finalize_relationships(self) -> None:
        """
        Finalize observable relationships by linking orphans to root.

        Detects orphan sub-graphs (connected components not linked to root) and links
        the most appropriate starting node of each sub-graph to root.
        """
        root_key = self._root_observable.key

        # Build adjacency lists for graph traversal
        graph = {key: set() for key in self._observables.keys()}
        incoming = {key: set() for key in self._observables.keys()}

        for obs_key, obs in self._observables.items():
            for rel in obs.relationships:
                if rel.target_key in self._observables:
                    graph[obs_key].add(rel.target_key)
                    incoming[rel.target_key].add(obs_key)

        # Find all connected components using BFS
        visited = set()
        components = []

        def bfs(start_key: str) -> set[str]:
            """Breadth-first search to find connected component."""
            component = set()
            queue = [start_key]
            component.add(start_key)

            while queue:
                current = queue.pop(0)
                # Check both outgoing and incoming edges for connectivity
                neighbors = graph[current] | incoming[current]
                for neighbor in neighbors:
                    if neighbor not in component:
                        component.add(neighbor)
                        queue.append(neighbor)

            return component

        # Find all connected components
        for obs_key in self._observables.keys():
            if obs_key not in visited:
                component = bfs(obs_key)
                visited.update(component)
                components.append(component)

        # Process each component that doesn't include root
        for component in components:
            if root_key in component:
                continue  # This component is already connected to root

            # Find the best starting node in this orphan sub-graph
            # Prioritize nodes with:
            # 1. No incoming edges (true source nodes)
            # 2. Most outgoing edges (central nodes)
            best_node = None
            best_score = (-1, -1)  # (negative incoming count, outgoing count)

            for node_key in component:
                incoming_count = len(incoming[node_key] & component)
                outgoing_count = len(graph[node_key] & component)
                score = (-incoming_count, outgoing_count)

                if score > best_score:
                    best_score = score
                    best_node = node_key

            # Link the best starting node to root
            if best_node:
                self._create_relationship(self._root_observable, best_node, RelationshipType.RELATED_TO)
                self._record_event(
                    event_type="RELATIONSHIP_CREATED",
                    object_type="observable",
                    object_key=self._root_observable.key,
                    reason="Finalize relationships",
                    details={
                        "target_key": best_node,
                        "relationship_type": RelationshipType.RELATED_TO.value,
                        "direction": RelationshipType.RELATED_TO.get_default_direction().value,
                    },
                )
        self._score_engine.recalculate_all()

    def merge_investigation(self, other: Investigation) -> None:
        """
        Merge another investigation into this one.

        Uses a two-pass approach to handle relationship dependencies:
        - Pass 1: Merge all observables, collecting deferred relationships
        - Pass 2: Add deferred relationships now that all observables exist

        Args:
            other: The investigation to merge
        """

        def _diff_fields(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
            return [field for field, value in before.items() if value != after.get(field)]

        def _snapshot_observable(obs: Observable) -> dict[str, Any]:
            relationships = [
                (
                    rel.target_key,
                    rel.relationship_type_name,
                    rel.direction.value,
                )
                for rel in obs.relationships
            ]
            return {
                "score": obs.score,
                "level": obs.level,
                "comment": obs.comment,
                "extra": deepcopy(obs.extra),
                "internal": obs.internal,
                "whitelisted": obs.whitelisted,
                "threat_intels": sorted(ti.key for ti in obs.threat_intels),
                "relationships": sorted(relationships),
            }

        def _snapshot_check(check: Check) -> dict[str, Any]:
            links = [
                (
                    link.observable_key,
                    link.propagation_mode.value,
                )
                for link in check.observable_links
            ]
            return {
                "score": check.score,
                "level": check.level,
                "comment": check.comment,
                "description": check.description,
                "extra": deepcopy(check.extra),
                "origin_investigation_id": check.origin_investigation_id,
                "observable_links": sorted(links),
            }

        def _snapshot_threat_intel(ti: ThreatIntel) -> dict[str, Any]:
            return {
                "score": ti.score,
                "level": ti.level,
                "comment": ti.comment,
                "extra": deepcopy(ti.extra),
                "taxonomies": deepcopy(ti.taxonomies),
            }

        def _snapshot_enrichment(enrichment: Enrichment) -> dict[str, Any]:
            return {
                "context": enrichment.context,
                "data": deepcopy(enrichment.data),
            }

        def _snapshot_tag(tag: Tag) -> dict[str, Any]:
            return {
                "description": tag.description,
                "checks": sorted(check.key for check in tag.checks),
            }

        merge_summary: list[dict[str, Any]] = []

        (
            incoming_observables,
            incoming_threat_intels,
            incoming_checks,
            incoming_enrichments,
            incoming_tags,
        ) = self._clone_for_merge(other)

        # PASS 1: Merge observables and collect deferred relationships
        all_deferred_relationships = []
        for obs in incoming_observables.values():
            existing = self._observables.get(obs.key)
            before = _snapshot_observable(existing) if existing else None
            _, deferred = self.add_observable(obs)
            all_deferred_relationships.extend(deferred)
            if existing:
                after = _snapshot_observable(existing)
                changed_fields = _diff_fields(before, after) if before else []
                action = "merged" if changed_fields else "skipped"
                merge_summary.append(
                    {
                        "object_type": "observable",
                        "object_key": obs.key,
                        "action": action,
                        "changed_fields": changed_fields,
                    }
                )
            else:
                merge_summary.append(
                    {
                        "object_type": "observable",
                        "object_key": obs.key,
                        "action": "created",
                        "changed_fields": [],
                    }
                )

        # PASS 2: Process deferred relationships now that all observables exist
        for source_key, rel in all_deferred_relationships:
            source_obs = self._observables.get(source_key)
            if source_obs and rel.target_key in self._observables:
                # Both source and target exist - add relationship
                self._create_relationship(source_obs, rel.target_key, rel.relationship_type, rel.direction)
            else:
                # Genuine error - target still doesn't exist after Pass 2
                logger.critical(
                    "Relationship target '{}' not found after merge completion for observable '{}'. "
                    "This indicates corrupted data or a bug in the merge logic.",
                    rel.target_key,
                    source_key,
                )

        # Merge threat intels (need to link to observables)
        for ti in incoming_threat_intels.values():
            existing_ti = self._threat_intels.get(ti.key)
            before = _snapshot_threat_intel(existing_ti) if existing_ti else None
            # Find the observable this TI belongs to
            observable = self._observables.get(ti.observable_key)
            if observable:
                self.add_threat_intel(ti, observable)
            if existing_ti:
                after = _snapshot_threat_intel(existing_ti)
                changed_fields = _diff_fields(before, after) if before else []
                action = "merged" if changed_fields else "skipped"
            else:
                changed_fields = []
                action = "created"
            merge_summary.append(
                {
                    "object_type": "threat_intel",
                    "object_key": ti.key,
                    "action": action,
                    "changed_fields": changed_fields,
                }
            )

        # Merge checks
        for check in incoming_checks.values():
            existing_check = self._checks.get(check.key)
            before = _snapshot_check(existing_check) if existing_check else None
            self.add_check(check)
            if existing_check:
                after = _snapshot_check(existing_check)
                changed_fields = _diff_fields(before, after) if before else []
                action = "merged" if changed_fields else "skipped"
            else:
                changed_fields = []
                action = "created"
            merge_summary.append(
                {
                    "object_type": "check",
                    "object_key": check.key,
                    "action": action,
                    "changed_fields": changed_fields,
                }
            )

        # Merge enrichments
        for enrichment in incoming_enrichments.values():
            existing_enrichment = self._enrichments.get(enrichment.key)
            before = _snapshot_enrichment(existing_enrichment) if existing_enrichment else None
            self.add_enrichment(enrichment)
            if existing_enrichment:
                after = _snapshot_enrichment(existing_enrichment)
                changed_fields = _diff_fields(before, after) if before else []
                action = "merged" if changed_fields else "skipped"
            else:
                changed_fields = []
                action = "created"
            merge_summary.append(
                {
                    "object_type": "enrichment",
                    "object_key": enrichment.key,
                    "action": action,
                    "changed_fields": changed_fields,
                }
            )

        # Merge tags
        for tag in incoming_tags.values():
            existing_tag = self._tags.get(tag.key)
            before = _snapshot_tag(existing_tag) if existing_tag else None
            self.add_tag(tag)
            if existing_tag:
                after = _snapshot_tag(existing_tag)
                changed_fields = _diff_fields(before, after) if before else []
                action = "merged" if changed_fields else "skipped"
            else:
                changed_fields = []
                action = "created"
            merge_summary.append(
                {
                    "object_type": "tag",
                    "object_key": tag.key,
                    "action": action,
                    "changed_fields": changed_fields,
                }
            )

        # Merge whitelists (other investigation overrides on identifier conflicts)
        for entry in other.get_whitelists():
            self.add_whitelist(entry.identifier, entry.name, entry.justification)

        # Rebuild link index after merges
        self._score_engine.rebuild_link_index()
        self._rebuild_all_check_links()

        # Final score recalculation
        self._score_engine.recalculate_all()

        self._record_event(
            event_type="INVESTIGATION_MERGED",
            object_type="investigation",
            object_key=self.investigation_id,
            details={
                "from_investigation_id": other.investigation_id,
                "into_investigation_id": self.investigation_id,
                "from_investigation_name": other.investigation_name,
                "into_investigation_name": self.investigation_name,
                "object_changes": merge_summary,
            },
        )
