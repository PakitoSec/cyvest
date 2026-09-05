"""
Relation planning: let an agent *propose* edges, let the library *validate and apply* them.

A model reading an investigation sees relationships an extraction rule cannot — this process
launched that one, this account logged on that host. It should not write them straight into the
store: it may name a key that does not exist, link a node to itself, or duplicate an edge that is
already there. So the flow is a plan against a known **revision** of the graph, a preview that
lists what would be accepted and why the rest would not, and an application that is refused
while the preview carries an error.

v7 has three relation kinds. The semantic verb a model wants to state — ``resolves-to``,
``executes`` — goes in ``comment``; the kind decides whether the edge propagates a score.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

from cyvest import keys
from cyvest.enums import RelationKind, SourceClass
from cyvest.facts.base import SourceRef

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest

RelationKindName = Literal["extraction", "pivot", "related-to"]

#: Who asserts a relation applied from a plan.
AGENT_RELATION_SOURCE = SourceRef(name="cyvest.relation-plan", source_class=SourceClass.INTERNAL_TOOL)

LOW_CONFIDENCE_THRESHOLD = 0.5


class RelationProposal(BaseModel):
    """One edge a planner wants drawn. ``source_key`` is the parent, ``target_key`` the child."""

    model_config = ConfigDict(extra="forbid")

    source_key: str = Field(..., min_length=1, description="Key of the parent observable (obs:...)")
    target_key: str = Field(..., min_length=1, description="Key of the child observable (obs:...)")
    kind: RelationKindName = Field(
        default="related-to",
        description="extraction and pivot propagate the child's score to the parent; related-to does not",
    )
    confidence: float = Field(default=1.0, gt=0.0, le=1.0)
    rationale: str = Field(..., min_length=1, max_length=1000, description="Why this edge is established")
    comment: str = Field(default="", description="Semantic verb, e.g. resolves-to, executes, authenticated-to")


class RelationPlan(BaseModel):
    """A set of proposals made against one revision of the graph."""

    model_config = ConfigDict(extra="forbid")

    revision: str = Field(..., min_length=1, description="The graph revision the plan was built against")
    proposals: list[RelationProposal] = Field(default_factory=list, max_length=100)
    summary: str = Field(default="")


class RelationIssue(BaseModel):
    """One reason a proposal is refused (error) or worth a look (warning)."""

    model_config = ConfigDict(frozen=True)

    severity: Literal["error", "warning"]
    code: str
    message: str
    index: int | None = None


class RelationPlanPreview(BaseModel):
    """What applying the plan would do. ``valid`` means no error anywhere, plan-level ones included."""

    model_config = ConfigDict(frozen=True)

    revision: str
    valid: bool
    accepted: tuple[RelationProposal, ...] = ()
    issues: tuple[RelationIssue, ...] = ()

    @property
    def errors(self) -> tuple[RelationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity == "error")


class RelationApplyResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    revision_before: str
    revision_after: str
    applied_keys: tuple[str, ...] = ()
    skipped: int = 0


class RelationContextObservable(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    type: str
    value: str
    internal: bool
    is_root: bool = False
    verdict: str
    score: float | None = None


class RelationContextEdge(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    source_key: str
    target_key: str
    kind: str
    confidence: float
    comment: str
    asserted_by: str


class RelationContext(BaseModel):
    """The graph as a planner should see it: nodes, edges, and the revision to plan against."""

    model_config = ConfigDict(frozen=True)

    revision: str
    root_key: str
    observables: tuple[RelationContextObservable, ...] = ()
    relations: tuple[RelationContextEdge, ...] = ()

    def to_markdown(self) -> str:
        lines = [f"Graph revision: `{self.revision}`", f"Root: `{self.root_key}`", "", "## Observables"]
        for observable in self.observables:
            root = " (root)" if observable.is_root else ""
            score = "—" if observable.score is None else f"{observable.score:.2f}"
            lines.append(
                f"- `{observable.key}` | {observable.type} | `{observable.value}` | {observable.verdict} {score}{root}"
            )
        lines += ["", "## Existing relations"]
        if not self.relations:
            lines.append("- none")
        for edge in self.relations:
            comment = f" — {edge.comment}" if edge.comment else ""
            lines.append(f"- `{edge.source_key}` →[{edge.kind}]→ `{edge.target_key}` (by {edge.asserted_by}){comment}")
        return "\n".join(lines)


def relation_revision(cv: Cyvest) -> str:
    """A short digest of the node and edge keys — changes whenever the graph's shape does."""
    payload = json.dumps(
        [sorted(cv.observable_get_all()), sorted(cv.relation_get_all())],
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def relation_context(cv: Cyvest) -> RelationContext:
    root_key = cv.root().key
    report = cv.get_report()
    observables = []
    for key, proxy in sorted(cv.observable_get_all().items()):
        result = report.observable(key)
        observables.append(
            RelationContextObservable(
                key=key,
                type=str(getattr(proxy.obs_type, "value", proxy.obs_type)),
                value=proxy.value,
                internal=proxy.internal,
                is_root=key == root_key,
                verdict=proxy.verdict.value,
                score=None if result is None else result.score,
            )
        )
    relations = [
        RelationContextEdge(
            key=key,
            source_key=relation.source_key,
            target_key=relation.target_key,
            kind=relation.kind.value,
            confidence=relation.confidence,
            comment=relation.comment,
            asserted_by=relation.source.name,
        )
        for key, relation in sorted(cv.relation_get_all().items())
    ]
    return RelationContext(
        revision=relation_revision(cv),
        root_key=root_key,
        observables=tuple(observables),
        relations=tuple(relations),
    )


def _reaches(start: str, goal: str, adjacency: dict[str, set[str]]) -> bool:
    seen = {start}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        if node == goal:
            return True
        for child in adjacency.get(node, ()):
            if child not in seen:
                seen.add(child)
                queue.append(child)
    return False


def validate_relation_plan(cv: Cyvest, plan: RelationPlan, *, require_revision: bool = True) -> RelationPlanPreview:
    """
    Check a plan against the live graph without touching it.

    Errors refuse a proposal: unknown keys, a self-loop, an edge that already exists, a proposal
    repeated within the plan, and — plan-wide — a revision that no longer matches. Warnings keep
    the proposal but flag it: a cycle, an edge that would make the root a child, the reverse edge
    already existing, a confidence under :data:`LOW_CONFIDENCE_THRESHOLD`.
    """
    revision = relation_revision(cv)
    issues: list[RelationIssue] = []
    if require_revision and plan.revision != revision:
        issues.append(
            RelationIssue(
                severity="error",
                code="stale_revision",
                message=f"plan was built against revision {plan.revision}, graph is now at {revision}",
            )
        )

    observables = set(cv.observable_get_all())
    existing = cv.relation_get_all()
    root_key = cv.root().key
    adjacency: dict[str, set[str]] = {}
    for relation in existing.values():
        adjacency.setdefault(relation.source_key, set()).add(relation.target_key)

    accepted: list[RelationProposal] = []
    seen: set[tuple[str, str, str]] = set()
    for index, proposal in enumerate(plan.proposals):
        errors: list[RelationIssue] = []
        if proposal.source_key not in observables:
            errors.append(_issue("error", "unknown_source", f"no observable {proposal.source_key}", index))
        if proposal.target_key not in observables:
            errors.append(_issue("error", "unknown_target", f"no observable {proposal.target_key}", index))
        if proposal.source_key == proposal.target_key:
            errors.append(_issue("error", "self_loop", "an observable cannot be related to itself", index))
        signature = (proposal.source_key, proposal.target_key, proposal.kind)
        if signature in seen:
            errors.append(_issue("error", "duplicate_proposal", "the same edge is proposed twice", index))
        seen.add(signature)
        key = keys.generate_relation_key(proposal.source_key, proposal.target_key, proposal.kind)
        if key in existing:
            errors.append(_issue("error", "duplicate_relation", f"relation {key} already exists", index))
        if errors:
            issues.extend(errors)
            continue

        if proposal.target_key == root_key:
            issues.append(_issue("warning", "targets_root", "the root would become a child", index))
        reverse = keys.generate_relation_key(proposal.target_key, proposal.source_key, proposal.kind)
        if reverse in existing:
            issues.append(_issue("warning", "reverse_exists", f"the reverse edge {reverse} exists", index))
        if _reaches(proposal.target_key, proposal.source_key, adjacency):
            issues.append(_issue("warning", "creates_cycle", "this edge closes a cycle", index))
        if proposal.confidence < LOW_CONFIDENCE_THRESHOLD:
            issues.append(_issue("warning", "low_confidence", f"confidence {proposal.confidence:.2f}", index))
        adjacency.setdefault(proposal.source_key, set()).add(proposal.target_key)
        accepted.append(proposal)

    return RelationPlanPreview(
        revision=revision,
        valid=not any(issue.severity == "error" for issue in issues),
        accepted=tuple(accepted),
        issues=tuple(issues),
    )


def _issue(severity: Literal["error", "warning"], code: str, message: str, index: int | None) -> RelationIssue:
    return RelationIssue(severity=severity, code=code, message=message, index=index)


def apply_relation_plan(
    cv: Cyvest,
    plan: RelationPlan,
    *,
    asserted_by: SourceRef = AGENT_RELATION_SOURCE,
    require_revision: bool = True,
    partial: bool = False,
) -> RelationApplyResult:
    """
    Draw the accepted edges of a plan.

    Refused with ``ValueError`` while the preview has an error, unless ``partial`` is set — then
    the accepted proposals land and the rest are counted in ``skipped``. A stale revision is never
    applied partially: the model planned against a graph that no longer exists.
    """
    preview = validate_relation_plan(cv, plan, require_revision=require_revision)
    stale = any(issue.code == "stale_revision" for issue in preview.errors)
    if stale or (preview.errors and not partial):
        messages = "; ".join(f"[{issue.index}] {issue.code}: {issue.message}" for issue in preview.errors)
        raise ValueError(f"relation plan refused: {messages}")

    applied: list[str] = []
    for proposal in preview.accepted:
        cv.observable_add_relation(
            proposal.source_key,
            proposal.target_key,
            RelationKind(proposal.kind),
            confidence=proposal.confidence,
            comment=proposal.comment or proposal.rationale,
            asserted_by=asserted_by,
        )
        applied.append(keys.generate_relation_key(proposal.source_key, proposal.target_key, proposal.kind))
    return RelationApplyResult(
        revision_before=preview.revision,
        revision_after=relation_revision(cv),
        applied_keys=tuple(applied),
        skipped=len(plan.proposals) - len(applied),
    )


__all__ = [
    "AGENT_RELATION_SOURCE",
    "LOW_CONFIDENCE_THRESHOLD",
    "RelationApplyResult",
    "RelationContext",
    "RelationContextEdge",
    "RelationContextObservable",
    "RelationIssue",
    "RelationKindName",
    "RelationPlan",
    "RelationPlanPreview",
    "RelationProposal",
    "apply_relation_plan",
    "relation_context",
    "relation_revision",
    "validate_relation_plan",
]
