"""Agent-friendly contracts for planning semantic observable relationships."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from enum import Enum
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from cyvest.model_enums import RelationshipDirection, RelationshipType

if TYPE_CHECKING:
    from cyvest.model import Observable


class RelationshipOperation(str, Enum):
    """Mutation requested by a relationship proposal."""

    ADD = "add"
    REMOVE = "remove"


class RelationshipFamily(str, Enum):
    """Stable semantic families shared with graph renderers."""

    STRUCTURAL = "structural"
    INFRASTRUCTURE = "infrastructure"
    BEHAVIORAL = "behavioral"
    ASSOCIATION = "association"


class RelationshipDefinition(BaseModel):
    """Machine-readable guidance for one canonical relationship type."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    relationship_type: RelationshipType
    family: RelationshipFamily
    description: str
    source_role: str
    target_role: str
    default_direction: RelationshipDirection
    symmetric: bool = False
    examples: tuple[str, ...] = ()
    counter_examples: tuple[str, ...] = ()


RELATIONSHIP_CATALOG: dict[RelationshipType, RelationshipDefinition] = {
    RelationshipType.CONTAINS: RelationshipDefinition(
        relationship_type=RelationshipType.CONTAINS,
        family=RelationshipFamily.STRUCTURAL,
        description="The source includes the target as physical or logical content.",
        source_role="container",
        target_role="contained observable",
        default_direction=RelationshipDirection.OUTBOUND,
        examples=("email contains attachment", "HTML body contains URL"),
        counter_examples=("domain hosts URL",),
    ),
    RelationshipType.DERIVED_FROM: RelationshipDefinition(
        relationship_type=RelationshipType.DERIVED_FROM,
        family=RelationshipFamily.STRUCTURAL,
        description="The source was extracted, calculated, or transformed from the target.",
        source_role="derived observable",
        target_role="origin observable",
        default_direction=RelationshipDirection.OUTBOUND,
        examples=("hash derived from file", "decoded artifact derived from payload"),
        counter_examples=("file contains hash",),
    ),
    RelationshipType.RESOLVES_TO: RelationshipDefinition(
        relationship_type=RelationshipType.RESOLVES_TO,
        family=RelationshipFamily.INFRASTRUCTURE,
        description="The source name resolves to the target network address.",
        source_role="name or domain",
        target_role="network address",
        default_direction=RelationshipDirection.OUTBOUND,
        examples=("domain resolves to IPv4",),
        counter_examples=("URL resolves to domain",),
    ),
    RelationshipType.HOSTS: RelationshipDefinition(
        relationship_type=RelationshipType.HOSTS,
        family=RelationshipFamily.INFRASTRUCTURE,
        description="The source infrastructure serves or hosts the target resource.",
        source_role="hosting infrastructure",
        target_role="hosted resource",
        default_direction=RelationshipDirection.OUTBOUND,
        examples=("domain hosts URL", "host hosts file share"),
        counter_examples=("domain hosts email address",),
    ),
    RelationshipType.COMMUNICATES_WITH: RelationshipDefinition(
        relationship_type=RelationshipType.COMMUNICATES_WITH,
        family=RelationshipFamily.BEHAVIORAL,
        description="The endpoints exchange network traffic or messages.",
        source_role="communication endpoint",
        target_role="communication endpoint",
        default_direction=RelationshipDirection.BIDIRECTIONAL,
        symmetric=True,
        examples=("process communicates with IP", "host communicates with domain"),
    ),
    RelationshipType.EXECUTES: RelationshipDefinition(
        relationship_type=RelationshipType.EXECUTES,
        family=RelationshipFamily.BEHAVIORAL,
        description="The source launches or runs the target executable, process, or command.",
        source_role="executor",
        target_role="executed observable",
        default_direction=RelationshipDirection.OUTBOUND,
        examples=("process executes command line", "user executes file"),
        counter_examples=("file derived from URL",),
    ),
    RelationshipType.RELATED_TO: RelationshipDefinition(
        relationship_type=RelationshipType.RELATED_TO,
        family=RelationshipFamily.ASSOCIATION,
        description="The observables are correlated, but no more precise mechanism is established.",
        source_role="associated observable",
        target_role="associated observable",
        default_direction=RelationshipDirection.BIDIRECTIONAL,
        symmetric=True,
        examples=("two indicators co-occur in a report",),
        counter_examples=("domain resolves to IP", "email contains attachment"),
    ),
}


class RelationshipProposal(BaseModel):
    """One evidence-backed relationship mutation proposed by an agent."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=True)

    operation: RelationshipOperation = RelationshipOperation.ADD
    source_key: Annotated[str, Field(min_length=1)]
    target_key: Annotated[str, Field(min_length=1)]
    relationship_type: RelationshipType | str
    direction: RelationshipDirection | None = None
    confidence: Annotated[float, Field(ge=0, le=1)]
    rationale: Annotated[str, Field(min_length=1, max_length=1000)]
    evidence_refs: tuple[str, ...] = ()

    @field_validator("source_key", "target_key", "rationale", mode="before")
    @classmethod
    def strip_required_text(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("relationship_type", mode="before")
    @classmethod
    def normalize_relationship_type(cls, value: object) -> object:
        if isinstance(value, str):
            normalized = value.strip().lower()
            try:
                return RelationshipType(normalized)
            except ValueError:
                return normalized
        return value

    @model_validator(mode="after")
    def set_semantic_direction(self) -> RelationshipProposal:
        if self.direction is not None:
            return self
        try:
            relationship_type = RelationshipType(self.relationship_type)
        except ValueError:
            direction = RelationshipDirection.OUTBOUND
        else:
            direction = relationship_type.get_default_direction()
        object.__setattr__(self, "direction", direction)
        return self


class RelationshipPlan(BaseModel):
    """Structured output expected from a relationship-planning agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    graph_revision: Annotated[str, Field(min_length=1)]
    proposals: tuple[RelationshipProposal, ...]
    summary: str = ""
    model: str | None = None
    tool: str | None = None


class RelationshipValidationIssue(BaseModel):
    """One validation error or warning associated with a proposal."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: Literal["error", "warning"]
    code: str
    message: str
    proposal_index: int | None = None


class RelationshipPlanPreview(BaseModel):
    """Pure validation result returned before graph mutation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    graph_revision: str
    valid: bool
    accepted: tuple[RelationshipProposal, ...] = ()
    issues: tuple[RelationshipValidationIssue, ...] = ()


class RelationshipApplyResult(BaseModel):
    """Result of atomically applying a validated relationship plan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_digest: str
    graph_revision_before: str
    graph_revision_after: str
    applied_count: int
    skipped_count: int
    audit_event_id: str | None = None


class RelationshipContextObservable(BaseModel):
    """Minimal observable representation sent to a relationship agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str
    observable_type: str
    value: str
    is_root: bool = False
    internal: bool = False
    whitelisted: bool = False


class RelationshipContextEdge(BaseModel):
    """Existing edge representation sent to a relationship agent."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_key: str
    target_key: str
    relationship_type: str
    direction: RelationshipDirection


class RelationshipContext(BaseModel):
    """Compact, revisioned graph context for agent prompts and tools."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    graph_revision: str
    root_key: str
    observables: tuple[RelationshipContextObservable, ...]
    relationships: tuple[RelationshipContextEdge, ...]

    def to_markdown(self) -> str:
        """Render a compact prompt-oriented representation."""

        lines = [f"Graph revision: `{self.graph_revision}`", f"Root: `{self.root_key}`", "", "## Observables"]
        for observable in self.observables:
            root = " (root)" if observable.is_root else ""
            lines.append(f"- `{observable.key}` | {observable.observable_type} | `{observable.value}`{root}")
        lines.extend(["", "## Existing relationships"])
        if not self.relationships:
            lines.append("- None")
        for relationship in self.relationships:
            lines.append(
                f"- `{relationship.source_key}` {relationship.direction.value} "
                f"`{relationship.target_key}` | {relationship.relationship_type}"
            )
        return "\n".join(lines)


def get_relationship_catalog() -> tuple[RelationshipDefinition, ...]:
    """Return the canonical relationship catalog in enum declaration order."""

    return tuple(RELATIONSHIP_CATALOG[relationship_type] for relationship_type in RelationshipType)


def _relationship_rows(observables: Mapping[str, Observable]) -> list[tuple[str, str, str, str]]:
    return sorted(
        (
            source_key,
            relationship.target_key,
            relationship.relationship_type_name,
            relationship.direction.value,
        )
        for source_key, observable in observables.items()
        for relationship in observable.relationships
    )


def get_graph_revision(observables: Mapping[str, Observable]) -> str:
    """Return a stable digest of observable identities and relationships."""

    identities = sorted(
        (
            key,
            observable.obs_type.value if hasattr(observable.obs_type, "value") else str(observable.obs_type),
            observable.value,
        )
        for key, observable in observables.items()
    )
    payload = json.dumps(
        {"observables": identities, "relationships": _relationship_rows(observables)},
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_relationship_plan_digest(plan: RelationshipPlan) -> str:
    """Return a stable digest for audit and validated-plan handoff."""

    payload = json.dumps(plan.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_relationship_context(
    observables: Mapping[str, Observable],
    root_key: str,
) -> RelationshipContext:
    """Build the compact graph context expected by relationship agents."""

    context_observables = tuple(
        RelationshipContextObservable(
            key=key,
            observable_type=(
                observable.obs_type.value
                if hasattr(observable.obs_type, "value")
                else str(observable.obs_type)
            ),
            value=observable.value,
            is_root=key == root_key,
            internal=observable.internal,
            whitelisted=observable.whitelisted,
        )
        for key, observable in sorted(observables.items())
    )
    context_edges = tuple(
        RelationshipContextEdge(
            source_key=source_key,
            target_key=target_key,
            relationship_type=relationship_type,
            direction=RelationshipDirection(direction),
        )
        for source_key, target_key, relationship_type, direction in _relationship_rows(observables)
    )
    return RelationshipContext(
        graph_revision=get_graph_revision(observables),
        root_key=root_key,
        observables=context_observables,
        relationships=context_edges,
    )


_RECOMMENDED_TYPE_PAIRS: dict[RelationshipType, set[tuple[str, str]]] = {
    RelationshipType.RESOLVES_TO: {
        ("domain", "ipv4"),
        ("domain", "ipv6"),
        ("host", "ipv4"),
        ("host", "ipv6"),
    },
    RelationshipType.HOSTS: {
        ("domain", "url"),
        ("host", "url"),
        ("host", "file"),
        ("ipv4", "url"),
        ("ipv6", "url"),
    },
    RelationshipType.EXECUTES: {
        ("process", "process"),
        ("process", "file"),
        ("process", "command_line"),
        ("user", "file"),
        ("user", "command_line"),
    },
}

_ACYCLIC_RELATIONSHIP_TYPES = {
    RelationshipType.CONTAINS,
    RelationshipType.DERIVED_FROM,
}


def _proposal_issue(
    index: int,
    severity: Literal["error", "warning"],
    code: str,
    message: str,
) -> RelationshipValidationIssue:
    return RelationshipValidationIssue(
        severity=severity,
        code=code,
        message=message,
        proposal_index=index,
    )


def _has_path(edges: set[tuple[str, str]], start: str, destination: str) -> bool:
    pending = [start]
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current == destination:
            return True
        if current in visited:
            continue
        visited.add(current)
        pending.extend(target for source, target in edges if source == current)
    return False


def validate_relationship_plan(
    observables: Mapping[str, Observable],
    plan: RelationshipPlan,
    *,
    allow_custom_types: bool = False,
) -> RelationshipPlanPreview:
    """Validate a relationship plan without mutating the investigation."""

    revision = get_graph_revision(observables)
    issues: list[RelationshipValidationIssue] = []
    accepted: list[RelationshipProposal] = []
    if plan.graph_revision != revision:
        issues.append(
            RelationshipValidationIssue(
                severity="error",
                code="stale_graph_revision",
                message="The graph changed after this plan was created.",
            )
        )

    existing = set(_relationship_rows(observables))
    seen: set[tuple[str, str, str, str, str]] = set()
    planned_edges = set(existing)
    for index, proposal in enumerate(plan.proposals):
        proposal_issues: list[RelationshipValidationIssue] = []

        source = observables.get(proposal.source_key)
        target = observables.get(proposal.target_key)
        if source is None:
            proposal_issues.append(
                _proposal_issue(index, "error", "source_not_found", f"Unknown source observable: {proposal.source_key}")
            )
        if target is None:
            proposal_issues.append(
                _proposal_issue(index, "error", "target_not_found", f"Unknown target observable: {proposal.target_key}")
            )
        if proposal.source_key == proposal.target_key:
            proposal_issues.append(
                _proposal_issue(index, "error", "self_relationship", "An observable cannot relate to itself.")
            )

        try:
            canonical_type = RelationshipType(proposal.relationship_type)
        except ValueError:
            canonical_type = None
            if not allow_custom_types:
                proposal_issues.append(
                    _proposal_issue(
                        index,
                        "error",
                        "custom_type_not_allowed",
                        "Agent plans must use a canonical relationship type.",
                    )
                )

        direction = RelationshipDirection(proposal.direction)
        row = (
            proposal.source_key,
            proposal.target_key,
            str(proposal.relationship_type),
            direction.value,
        )
        signature = (proposal.operation, *row)
        if signature in seen:
            proposal_issues.append(
                _proposal_issue(
                    index,
                    "error",
                    "duplicate_proposal",
                    "The plan contains this operation more than once.",
                )
            )
        seen.add(signature)
        if proposal.operation == RelationshipOperation.ADD and row in existing:
            proposal_issues.append(
                _proposal_issue(
                    index,
                    "warning",
                    "relationship_exists",
                    "This relationship already exists and will be ignored.",
                )
            )
        if proposal.operation == RelationshipOperation.REMOVE and row not in existing:
            proposal_issues.append(
                _proposal_issue(
                    index,
                    "error",
                    "relationship_not_found",
                    "The relationship selected for removal does not exist.",
                )
            )

        if source is not None and target is not None and canonical_type in _RECOMMENDED_TYPE_PAIRS:
            source_type = source.obs_type.value if hasattr(source.obs_type, "value") else str(source.obs_type)
            target_type = target.obs_type.value if hasattr(target.obs_type, "value") else str(target.obs_type)
            if (source_type, target_type) not in _RECOMMENDED_TYPE_PAIRS[canonical_type]:
                proposal_issues.append(
                    _proposal_issue(
                        index,
                        "warning",
                        "unusual_type_pair",
                        f"{canonical_type.value} is unusual from {source_type} to {target_type}.",
                    )
                )
        if canonical_type == RelationshipType.RELATED_TO and proposal.confidence >= 0.8:
            proposal_issues.append(
                _proposal_issue(
                    index,
                    "warning",
                    "imprecise_high_confidence",
                    "High-confidence evidence should usually use a more precise relationship type.",
                )
            )
        if canonical_type is not None:
            definition = RELATIONSHIP_CATALOG[canonical_type]
            if direction != definition.default_direction:
                proposal_issues.append(
                    _proposal_issue(
                        index,
                        "warning",
                        "unusual_direction",
                        f"{canonical_type.value} normally uses {definition.default_direction.value} direction.",
                    )
                )
        if (
            proposal.operation == RelationshipOperation.ADD
            and canonical_type in _ACYCLIC_RELATIONSHIP_TYPES
            and source is not None
            and target is not None
        ):
            typed_edges = {
                (source_key, target_key)
                for source_key, target_key, relationship_type, _ in planned_edges
                if relationship_type == canonical_type.value
            }
            if _has_path(typed_edges, proposal.target_key, proposal.source_key):
                proposal_issues.append(
                    _proposal_issue(
                        index,
                        "error",
                        "relationship_cycle",
                        f"Adding {canonical_type.value} would create a semantic cycle.",
                    )
                )

        issues.extend(proposal_issues)
        if not any(issue.severity == "error" for issue in proposal_issues):
            accepted.append(proposal)
            if proposal.operation == RelationshipOperation.ADD:
                planned_edges.add(row)
            else:
                planned_edges.discard(row)

    if plan.graph_revision != revision:
        accepted.clear()
    return RelationshipPlanPreview(
        graph_revision=revision,
        valid=not any(issue.severity == "error" for issue in issues),
        accepted=tuple(accepted),
        issues=tuple(issues),
    )
