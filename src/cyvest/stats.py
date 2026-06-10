"""
Statistics and aggregation engine for Cyvest investigations.

Provides live counters and aggregations for observables, findings, threat intel,
and other investigation metrics.
"""

from __future__ import annotations

from collections import defaultdict

from cyvest.levels import Level
from cyvest.model import Evidence, Finding, Observable, Tag, ThreatIntel
from cyvest.model_schema import StatisticsSchema


class InvestigationStats:
    """
    Tracks and aggregates statistics for an investigation.

    Provides real-time metrics about observables, findings, threat intel,
    and other investigation components.
    """

    def __init__(self) -> None:
        """Initialize statistics tracking."""
        self._observables: dict[str, Observable] = {}
        self._findings: dict[str, Finding] = {}
        self._evidences: dict[str, Evidence] = {}
        self._threat_intels: dict[str, ThreatIntel] = {}
        self._tags: dict[str, Tag] = {}

    def register_observable(self, observable: Observable) -> None:
        """
        Register an observable for statistics tracking.

        Args:
            observable: Observable to track
        """
        self._observables[observable.key] = observable

    def register_finding(self, finding: Finding) -> None:
        """
        Register a finding for statistics tracking.

        Args:
            finding: Finding to track
        """
        self._findings[finding.key] = finding

    def register_evidence(self, evidence: Evidence) -> None:
        """Register evidence for statistics tracking."""
        self._evidences[evidence.key] = evidence

    def register_threat_intel(self, ti: ThreatIntel) -> None:
        """
        Register threat intel for statistics tracking.

        Args:
            ti: Threat intel to track
        """
        self._threat_intels[ti.key] = ti

    def register_tag(self, tag: Tag) -> None:
        """
        Register a tag for statistics tracking.

        Args:
            tag: Tag to track
        """
        self._tags[tag.key] = tag

    def get_observable_count_by_type(self) -> dict[str, int]:
        """
        Get count of observables by type.

        Returns:
            Dictionary mapping observable type to count
        """
        counts: dict[str, int] = defaultdict(int)
        for obs in self._observables.values():
            counts[obs.obs_type] += 1
        return dict(counts)

    def get_observable_count_by_level(self, obs_type: str | None = None) -> dict[Level, int]:
        """
        Get count of observables by level, optionally filtered by type.

        Args:
            obs_type: Optional observable type to filter by

        Returns:
            Dictionary mapping level to count
        """
        counts: dict[Level, int] = defaultdict(int)
        for obs in self._observables.values():
            if obs_type is None or obs.obs_type == obs_type:
                counts[obs.level] += 1
        return dict(counts)

    def get_observable_count_by_type_and_level(self) -> dict[str, dict[Level, int]]:
        """
        Get count of observables by type and level.

        Returns:
            Nested dictionary: {type: {level: count}}
        """
        counts: dict[str, dict[Level, int]] = defaultdict(lambda: defaultdict(int))
        for obs in self._observables.values():
            counts[obs.obs_type][obs.level] += 1
        # Convert defaultdicts to regular dicts
        return {k: dict(v) for k, v in counts.items()}

    def get_total_observable_count(self) -> int:
        """
        Get total number of observables.

        Returns:
            Total observable count
        """
        return len(self._observables)

    def get_internal_observable_count(self) -> int:
        """
        Get count of internal observables.

        Returns:
            Count of internal observables
        """
        return sum(1 for obs in self._observables.values() if obs.internal)

    def get_external_observable_count(self) -> int:
        """
        Get count of external observables.

        Returns:
            Count of external observables
        """
        return sum(1 for obs in self._observables.values() if not obs.internal)

    def get_whitelisted_observable_count(self) -> int:
        """
        Get count of whitelisted observables.

        Returns:
            Count of whitelisted observables
        """
        return sum(1 for obs in self._observables.values() if obs.whitelisted)

    def get_finding_count_by_level(self) -> dict[Level, int]:
        """
        Get count of findings by level.

        Returns:
            Dictionary mapping level to count
        """
        counts: dict[Level, int] = defaultdict(int)
        for finding in self._findings.values():
            counts[finding.level] += 1
        return dict(counts)

    def get_finding_keys_by_level(self) -> dict[Level, list[str]]:
        """
        Get finding keys grouped by level.

        Returns:
            Dictionary mapping level to list of finding keys
        """
        keys: dict[Level, list[str]] = defaultdict(list)
        for finding in self._findings.values():
            keys[finding.level].append(finding.key)
        return dict(keys)

    def get_applied_finding_count(self) -> int:
        """
        Get count of findings that were applied (level != NONE).

        Returns:
            Count of applied findings
        """
        return sum(1 for finding in self._findings.values() if finding.level != Level.NONE)

    def get_total_finding_count(self) -> int:
        """
        Get total number of findings.

        Returns:
            Total finding count
        """
        return len(self._findings)

    def get_evidence_count_by_type(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for evidence in self._evidences.values():
            counts[evidence.evidence_type] += 1
        return dict(counts)

    def get_evidence_count_by_source(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for evidence in self._evidences.values():
            counts[evidence.source] += 1
        return dict(counts)

    def get_threat_intel_count(self) -> int:
        """
        Get total number of threat intel sources queried.

        Returns:
            Total threat intel count
        """
        return len(self._threat_intels)

    def get_threat_intel_count_by_source(self) -> dict[str, int]:
        """
        Get count of threat intel by source.

        Returns:
            Dictionary mapping source name to count
        """
        counts: dict[str, int] = defaultdict(int)
        for ti in self._threat_intels.values():
            counts[ti.source] += 1
        return dict(counts)

    def get_threat_intel_count_by_level(self) -> dict[Level, int]:
        """
        Get count of threat intel by level.

        Returns:
            Dictionary mapping level to count
        """
        counts: dict[Level, int] = defaultdict(int)
        for ti in self._threat_intels.values():
            counts[ti.level] += 1
        return dict(counts)

    def get_tag_count(self) -> int:
        """
        Get total number of tags.

        Returns:
            Total tag count
        """
        return len(self._tags)

    def get_findings_by_level(self, level: Level) -> list[Finding]:
        """
        Get all findings with a specific level.

        Args:
            level: Level to filter by

        Returns:
            List of findings with the specified level
        """
        return [finding for finding in self._findings.values() if finding.level == level]

    def get_observables_by_level(self, level: Level) -> list[Observable]:
        """
        Get all observables with a specific level.

        Args:
            level: Level to filter by

        Returns:
            List of observables with the specified level
        """
        return [obs for obs in self._observables.values() if obs.level == level]

    def get_observables_by_type(self, obs_type: str) -> list[Observable]:
        """
        Get all observables of a specific type.

        Args:
            obs_type: Type to filter by

        Returns:
            List of observables with the specified type
        """
        return [obs for obs in self._observables.values() if obs.obs_type == obs_type]

    def get_summary(self) -> StatisticsSchema:
        """
        Get a comprehensive summary of all statistics.

        Returns:
            StatisticsSchema instance with all statistics
        """

        return StatisticsSchema(
            total_observables=self.get_total_observable_count(),
            internal_observables=self.get_internal_observable_count(),
            external_observables=self.get_external_observable_count(),
            whitelisted_observables=self.get_whitelisted_observable_count(),
            observables_by_type=self.get_observable_count_by_type(),
            observables_by_level={str(k): v for k, v in self.get_observable_count_by_level().items()},
            observables_by_type_and_level={
                obs_type: {str(lvl): count for lvl, count in levels.items()}
                for obs_type, levels in self.get_observable_count_by_type_and_level().items()
            },
            total_findings=self.get_total_finding_count(),
            applied_findings=self.get_applied_finding_count(),
            findings_by_level={str(k): v for k, v in self.get_finding_keys_by_level().items()},
            total_evidences=len(self._evidences),
            evidences_by_type=self.get_evidence_count_by_type(),
            evidences_by_source=self.get_evidence_count_by_source(),
            total_threat_intel=self.get_threat_intel_count(),
            threat_intel_by_source=self.get_threat_intel_count_by_source(),
            threat_intel_by_level={str(k): v for k, v in self.get_threat_intel_count_by_level().items()},
            total_tags=self.get_tag_count(),
        )
