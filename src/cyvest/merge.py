"""
Merge strategies for combining investigation objects.

Provides logic for merging checks, observables, threat intel, enrichments,
and containers from different investigation threads or processes.
"""

from cyvest.model import Check, Container, Enrichment, Observable, ThreatIntel


def merge_check(existing: Check, incoming: Check) -> Check:
    """
    Merge an incoming check into an existing check.

    Strategy:
    - Update score (take maximum)
    - Update level (take maximum)
    - Update extra (merge dicts)
    - Replace comment with incoming

    Args:
        existing: The existing check
        incoming: The incoming check to merge

    Returns:
        The merged check (existing is modified in place)
    """
    # Take the higher score
    if incoming.score > existing.score:
        existing.update_score(incoming.score, reason=f"Merged from {incoming.key}")

    # Take the higher level
    if incoming.level > existing.level:
        existing.set_level(incoming.level)

    # Update extra (merge dictionaries)
    existing.extra.update(incoming.extra)

    # Replace comment
    if incoming.comment:
        existing.comment = incoming.comment

    # Merge observables (avoid duplicates)
    for obs in incoming.observables:
        if obs not in existing.observables:
            existing.add_observable(obs)

    return existing


def merge_observable(existing: Observable, incoming: Observable) -> Observable:
    """
    Merge an incoming observable into an existing observable.

    Strategy:
    - Update score (take maximum)
    - Update level (take maximum)
    - Update extra (merge dicts)
    - Concatenate comments
    - Merge threat intels
    - Merge relationships

    Args:
        existing: The existing observable
        incoming: The incoming observable to merge

    Returns:
        The merged observable (existing is modified in place)
    """
    # Take the higher score
    if incoming.score > existing.score:
        existing.update_score(incoming.score, reason=f"Merged from {incoming.key}")

    # Take the higher level
    if incoming.level > existing.level:
        existing.set_level(incoming.level)

    # Update extra (merge dictionaries)
    existing.extra.update(incoming.extra)

    # Concatenate comments
    if incoming.comment:
        if existing.comment:
            existing.comment += "\n\n" + incoming.comment
        else:
            existing.comment = incoming.comment

    # Merge whitelisted status (if either is whitelisted, result is whitelisted)
    existing.whitelisted = existing.whitelisted or incoming.whitelisted

    # Merge internal status (if either is external, result is external)
    existing.internal = existing.internal and incoming.internal

    # Merge threat intels (avoid duplicates by key)
    existing_ti_keys = {ti.key for ti in existing.threat_intels}
    for ti in incoming.threat_intels:
        if ti.key not in existing_ti_keys:
            existing.add_threat_intel(ti)

    # Merge relationships (avoid duplicates)
    existing_rels = {(r.target_key, r.relationship_type) for r in existing.relationships}
    for rel in incoming.relationships:
        rel_tuple = (rel.target_key, rel.relationship_type)
        if rel_tuple not in existing_rels:
            existing.add_relationship(rel.target_key, rel.relationship_type)

    # Merge generated_by_checks
    for check_key in incoming._generated_by_checks:
        if check_key not in existing._generated_by_checks:
            existing.mark_generated_by_check(check_key)

    return existing


def merge_threat_intel(existing: ThreatIntel, incoming: ThreatIntel) -> ThreatIntel:
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
        existing.score = incoming.score
        # Recalculate level
        if not existing._explicit_level:
            from cyvest.levels import get_level_from_score

            calculated_level = get_level_from_score(existing.score)
            if calculated_level > existing.level:
                existing.level = calculated_level

    # Take the higher level
    if incoming.level > existing.level:
        existing.set_level(incoming.level)

    # Update extra (merge dictionaries)
    existing.extra.update(incoming.extra)

    # Concatenate comments
    if incoming.comment:
        if existing.comment:
            existing.comment += "\n\n" + incoming.comment
        else:
            existing.comment = incoming.comment

    # Merge taxonomies (avoid duplicates)
    for taxonomy in incoming.taxonomies:
        if taxonomy not in existing.taxonomies:
            existing.taxonomies.append(taxonomy)

    return existing


def merge_enrichment(existing: Enrichment, incoming: Enrichment) -> Enrichment:
    """
    Merge an incoming enrichment into an existing enrichment.

    Strategy:
    - Replace data structure with incoming data

    Args:
        existing: The existing enrichment
        incoming: The incoming enrichment to merge

    Returns:
        The merged enrichment (existing is modified in place)
    """
    # Replace data structure
    existing.data = incoming.data.copy()
    existing.context = incoming.context
    return existing


def merge_container(existing: Container, incoming: Container) -> Container:
    """
    Merge an incoming container into an existing container.

    Strategy:
    - Traverse tree and merge checks
    - Merge sub-containers recursively

    Args:
        existing: The existing container
        incoming: The incoming container to merge

    Returns:
        The merged container (existing is modified in place)
    """
    # Update description if incoming has one
    if incoming.description:
        existing.description = incoming.description

    # Merge checks (by key)
    existing_check_keys = {check.key for check in existing.checks}
    for incoming_check in incoming.checks:
        if incoming_check.key in existing_check_keys:
            # Find and merge
            for existing_check in existing.checks:
                if existing_check.key == incoming_check.key:
                    merge_check(existing_check, incoming_check)
                    break
        else:
            # Add new check
            existing.add_check(incoming_check)

    # Merge sub-containers recursively
    for sub_key, incoming_sub in incoming.sub_containers.items():
        if sub_key in existing.sub_containers:
            # Merge existing sub-container
            merge_container(existing.sub_containers[sub_key], incoming_sub)
        else:
            # Add new sub-container
            existing.add_sub_container(incoming_sub)

    return existing


class InvestigationMerger:
    """
    High-level merger for combining complete investigations.

    Handles merging of all object types and maintains consistency
    across the investigation.
    """

    def __init__(self) -> None:
        """Initialize the merger."""
        self.observables: dict[str, Observable] = {}
        self.checks: dict[str, Check] = {}
        self.threat_intels: dict[str, ThreatIntel] = {}
        self.enrichments: dict[str, Enrichment] = {}
        self.containers: dict[str, Container] = {}

    def add_observable(self, observable: Observable) -> Observable:
        """
        Add or merge an observable.

        Args:
            observable: Observable to add or merge

        Returns:
            The resulting observable (either new or merged)
        """
        if observable.key in self.observables:
            return merge_observable(self.observables[observable.key], observable)
        else:
            self.observables[observable.key] = observable
            return observable

    def add_check(self, check: Check) -> Check:
        """
        Add or merge a check.

        Args:
            check: Check to add or merge

        Returns:
            The resulting check (either new or merged)
        """
        if check.key in self.checks:
            return merge_check(self.checks[check.key], check)
        else:
            self.checks[check.key] = check
            return check

    def add_threat_intel(self, ti: ThreatIntel) -> ThreatIntel:
        """
        Add or merge threat intel.

        Args:
            ti: Threat intel to add or merge

        Returns:
            The resulting threat intel (either new or merged)
        """
        if ti.key in self.threat_intels:
            return merge_threat_intel(self.threat_intels[ti.key], ti)
        else:
            self.threat_intels[ti.key] = ti
            return ti

    def add_enrichment(self, enrichment: Enrichment) -> Enrichment:
        """
        Add or merge enrichment.

        Args:
            enrichment: Enrichment to add or merge

        Returns:
            The resulting enrichment (either new or merged)
        """
        if enrichment.key in self.enrichments:
            return merge_enrichment(self.enrichments[enrichment.key], enrichment)
        else:
            self.enrichments[enrichment.key] = enrichment
            return enrichment

    def add_container(self, container: Container) -> Container:
        """
        Add or merge container.

        Args:
            container: Container to add or merge

        Returns:
            The resulting container (either new or merged)
        """
        if container.key in self.containers:
            return merge_container(self.containers[container.key], container)
        else:
            self.containers[container.key] = container
            return container
