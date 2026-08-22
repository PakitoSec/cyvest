"""
Cyvest — cybersecurity investigation framework.

v7 rests on three layers: immutable **facts**, a declarative **policy**, and a pure
**evaluation** that recomputes a report instead of storing scores on the facts.
"""

from cyvest.compare import (
    DiffItem,
    DiffStatus,
    EngineMismatchError,
    ExpectedResult,
    ObservableDiff,
    compare_investigations,
)
from cyvest.cyvest import Cyvest
from cyvest.enums import (
    Aggregation,
    Confidence,
    DecisionKind,
    Effect,
    ObservableSubtype,
    ObservableType,
    RelationKind,
    Salience,
    Scope,
    SourceClass,
    Status,
    Verdict,
    Weight,
)
from cyvest.evaluation import (
    Contribution,
    FindingResult,
    InvestigationResult,
    ObservableResult,
    Report,
    ResolvedScope,
    TimelineEntry,
    evaluate,
    verdict_from_score,
)
from cyvest.facts import (
    Decision,
    Evidence,
    Fact,
    Finding,
    Label,
    Observable,
    ObservableAlias,
    ObservableIdentity,
    ObservableLink,
    ObservableSignal,
    Relation,
    SourceRef,
    Tag,
    ThreatIntel,
)
from cyvest.policy import DEFAULT_POLICY, Policy
from cyvest.proxies import (
    DecisionProxy,
    EvidenceProxy,
    FindingProxy,
    ObservableProxy,
    TagProxy,
    ThreatIntelProxy,
)
from cyvest.resolvers import ObservableResolution, ObservableResolver
from cyvest.signal_schema import SIGNAL_SCHEMA_VERSION, SignalEnvelope

__version__ = "7.0.0"

__all__ = [
    "DEFAULT_POLICY",
    "Aggregation",
    "Confidence",
    "Contribution",
    "SIGNAL_SCHEMA_VERSION",
    "SignalEnvelope",
    "Cyvest",
    "DiffItem",
    "DiffStatus",
    "EngineMismatchError",
    "ExpectedResult",
    "ObservableDiff",
    "compare_investigations",
    "Decision",
    "DecisionKind",
    "DecisionProxy",
    "Effect",
    "Evidence",
    "EvidenceProxy",
    "Fact",
    "Finding",
    "FindingProxy",
    "FindingResult",
    "InvestigationResult",
    "Label",
    "Observable",
    "ObservableAlias",
    "ObservableIdentity",
    "ObservableLink",
    "ObservableProxy",
    "ObservableResolution",
    "ObservableResolver",
    "ObservableResult",
    "ObservableSignal",
    "ObservableSubtype",
    "ObservableType",
    "Policy",
    "Relation",
    "RelationKind",
    "Report",
    "ResolvedScope",
    "Salience",
    "Scope",
    "SourceClass",
    "SourceRef",
    "Status",
    "Tag",
    "TagProxy",
    "ThreatIntel",
    "ThreatIntelProxy",
    "TimelineEntry",
    "Verdict",
    "Weight",
    "evaluate",
    "verdict_from_score",
]
