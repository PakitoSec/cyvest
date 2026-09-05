"""
Batched operations: a list of typed writes, validated as a whole, applied all-or-nothing.

A model driving an investigation through one tool call per fact is slow and chatty; one that
writes facts it did not check leaves the store half right. This module sits in between: the
caller hands over a batch, every operation is checked against the store and against the batch
itself, and only a batch with no error lands. A failing operation rolls the whole batch back —
the investigation is exactly what it was.

The operation model is deliberately **flat**: one class, every field optional except ``op``.
A discriminated union would be cleaner to read but compiles to a tool schema some providers
refuse; a flat object with literal enums does not. Which fields an ``op`` needs is enforced by
a validator and documented in :data:`REQUIRED_FIELDS`.

Operations may name each other: an operation with ``ref="url"`` makes the key it creates
available as ``"$url"`` to every later operation in the same batch.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from cyvest.enums import (
    Confidence,
    DecisionKind,
    Effect,
    LinkBasis,
    RelationKind,
    SourceClass,
    Status,
    Tactic,
    Verdict,
    Weight,
)
from cyvest.facts.base import SourceRef
from cyvest.facts.taxonomy import Taxonomy
from cyvest.relations import AGENT_RELATION_SOURCE

if TYPE_CHECKING:
    from cyvest.cyvest import Cyvest

OpKind = Literal[
    "observable",
    "threat_intel",
    "evidence",
    "finding",
    "conclusion",
    "link_observable",
    "link_evidence",
    "decision",
    "relation",
]
VerdictName = Literal["SAFE", "INFO", "NOTABLE", "SUSPICIOUS", "MALICIOUS"]
StatusName = Literal["EVALUATED", "PENDING", "NOT_APPLICABLE"]
SourceClassName = Literal["vendor_feed", "sandbox", "osint", "internal_tool", "org_analyst", "org_policy", "unknown"]
BasisName = Literal["OBSERVABLE", "SIGNALS", "NONE"]
DecisionKindName = Literal["UPHOLD", "REFUTE", "VACATED"]
RelationKindName = Literal["extraction", "pivot", "related-to"]
# Spelled out rather than built from the enum: a Literal is what the tool schema compiles to.
# ``tests/test_operations.py`` checks it against ``Tactic`` so the two cannot drift.
TacticName = Literal[
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

#: Operations that carry a moment in the world: the field each one stores ``occurred_at`` under.
DATED_OPS: dict[str, str] = {
    "finding": "occurred_at",
    "evidence": "captured_at",
    "threat_intel": "observed_at",
    "relation": "observed_at",
    "decision": "occurred_at",
}

#: Fields an operation must carry, per kind. ``evidence`` additionally needs ``content_text`` or ``uri``.
REQUIRED_FIELDS: dict[str, tuple[str, ...]] = {
    "observable": ("type", "value"),
    "threat_intel": ("observable", "source"),
    "evidence": ("evidence_type", "title"),
    "finding": ("rule_id",),
    "conclusion": ("rule_id", "verdict"),
    "link_observable": ("finding", "observable"),
    "link_evidence": ("finding", "evidence"),
    "decision": ("target", "kind", "justification"),
    "relation": ("parent", "child"),
}

#: What kind of key each op creates, so a ``$ref`` can be checked for the slot it fills.
_CREATES: dict[str, str] = {
    "observable": "observable",
    "threat_intel": "signal",
    "evidence": "evidence",
    "finding": "finding",
    "conclusion": "finding",
    "relation": "relation",
    "decision": "decision",
}

_REF_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
_RULE_ID = re.compile(r"^[a-z0-9]+(?:[-_.][a-z0-9]+)*$")

#: Who asserts a decision recorded through a batch when the caller names nobody.
AGENT_DECISION_SOURCE = "agent"

# The scales the model reads in the schema come from the enums, so they cannot drift from them.
_WEIGHT_SCALE = ", ".join(f"{member.name} {member.value:g}" for member in Weight)
_CONFIDENCE_SCALE = ", ".join(f"{member.name} {member.value:g}" for member in Confidence)


class Operation(BaseModel):
    """One write. See :data:`REQUIRED_FIELDS` for what each ``op`` needs."""

    model_config = ConfigDict(extra="forbid")

    op: OpKind = Field(..., description="Which write to perform")
    ref: str | None = Field(
        default=None,
        description="Name for the key this operation creates; later operations may use it as '$name'",
    )

    # observable
    type: str | None = Field(default=None, description="Observable type: ipv4, ipv6, domain, url, hash, email, host...")
    value: str | None = Field(default=None, description="Observable value")
    subtype: str | None = Field(default=None, description="Observable subtype when the type requires one")
    namespace: str | None = Field(default=None, description="Observable namespace when the subtype requires one")
    internal: bool | None = Field(default=None, description="True for an owned asset")
    comment: str | None = Field(default=None, description="Free text: observable comment, finding body, relation verb")

    # targets — an existing key or a '$ref'
    observable: str | None = Field(default=None, description="Observable key or $ref")
    finding: str | None = Field(default=None, description="Finding key or $ref")
    evidence: str | None = Field(default=None, description="Evidence key or $ref")
    target: str | None = Field(default=None, description="Decision target: observable or finding key, or $ref")
    parent: str | None = Field(default=None, description="Relation parent observable key or $ref")
    child: str | None = Field(default=None, description="Relation child observable key or $ref")

    # threat_intel / evidence provenance
    source: str | None = Field(default=None, description="Source name (feed, tool, analyst)")
    source_class: SourceClassName | None = Field(default=None)
    verdict: VerdictName | None = Field(default=None, description="Judgment direction")
    weight: float | None = Field(default=None, ge=0.0, description=f"Judgment magnitude ({_WEIGHT_SCALE})")
    confidence: float | None = Field(default=None, gt=0.0, le=1.0, description=f"Certainty ({_CONFIDENCE_SCALE})")
    taxonomies: list[Taxonomy] | None = Field(default=None, description="Descriptive entries; never affect scoring")
    external_id: str | None = Field(default=None, description="Stable id at the source; keeps history apart")

    # evidence
    evidence_type: str | None = Field(
        default=None, description="Kind of material: log_line, ticket, analyzer_report..."
    )
    title: str | None = Field(default=None)
    content_text: str | None = Field(default=None, description="The material itself, as text")
    uri: str | None = Field(default=None, description="Link back to the material")

    # finding / conclusion
    rule_id: str | None = Field(default=None, description="Stable kebab-case identity of the finding")
    name: str | None = Field(default=None, description="Human-readable title")
    status: StatusName | None = Field(default=None)
    extra_json: str | None = Field(default=None, description="JSON object of extra attributes")
    tactic: TacticName | None = Field(
        default=None, description="finding only: the ATT&CK tactic the activity itself demonstrates"
    )

    # when it happened — finding, evidence, threat_intel, relation, decision
    occurred_at: str | None = Field(
        default=None,
        description="When it happened in the world, ISO 8601 UTC (2026-08-07T10:00:00Z): the source's time, not yours",
    )

    # link_observable
    basis: BasisName | None = Field(default=None, description="OBSERVABLE (default) scores on the observable")

    # decision
    kind: DecisionKindName | None = Field(default=None, description="UPHOLD forces, REFUTE neutralises, VACATED lifts")
    justification: str | None = Field(default=None)
    decided_by: str | None = Field(default=None)

    # relation
    relation_kind: RelationKindName | None = Field(
        default=None, description="extraction/pivot propagate; related-to not"
    )

    @model_validator(mode="after")
    def _check_required(self) -> Operation:
        missing = [field for field in REQUIRED_FIELDS[self.op] if getattr(self, field) in (None, "")]
        if missing:
            raise ValueError(f"{self.op} requires {', '.join(missing)}")
        if self.op == "evidence" and not (self.content_text or self.uri):
            raise ValueError("evidence requires content_text or uri")
        if self.op == "conclusion" and self.weight is not None:
            raise ValueError("a conclusion takes no weight; its magnitude is the bound of its verdict")
        if self.op in ("finding", "conclusion") and self.rule_id and not _RULE_ID.match(self.rule_id):
            raise ValueError(f"rule_id {self.rule_id!r} must be lowercase kebab-case")
        if self.ref is not None and not _REF_NAME.match(self.ref):
            raise ValueError(f"ref {self.ref!r} must match {_REF_NAME.pattern}")
        if self.tactic is not None and self.op != "finding":
            raise ValueError(f"{self.op} takes no tactic; only a finding demonstrates one")
        if self.occurred_at is not None:
            if self.op not in DATED_OPS:
                raise ValueError(f"{self.op} takes no occurred_at; it is not a moment in the world")
            parse_when(self.occurred_at)
        if self.extra_json is not None:
            try:
                parsed = json.loads(self.extra_json)
            except ValueError as exc:
                raise ValueError(f"extra_json is not valid JSON: {exc}") from exc
            if not isinstance(parsed, dict):
                raise ValueError("extra_json must encode a JSON object")
        return self


def parse_when(value: str) -> datetime:
    """
    An ISO 8601 timestamp as a timezone-aware datetime; ``Z`` is accepted, a naive value is UTC.

    Raises ``ValueError`` with the offending text, so a refused batch tells the model what to fix.
    """
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text)
    except ValueError as exc:
        raise ValueError(f"occurred_at {value!r} is not ISO 8601 (expected e.g. 2026-08-07T10:00:00Z)") from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _when(operation: Operation) -> datetime | None:
    return parse_when(operation.occurred_at) if operation.occurred_at else None


class RecordBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operations: list[Operation] = Field(..., min_length=1, max_length=50)


class AppliedOp(BaseModel):
    model_config = ConfigDict(frozen=True)

    index: int
    op: OpKind
    key: str
    ref: str | None = None


class OpError(BaseModel):
    model_config = ConfigDict(frozen=True)

    index: int | None
    message: str


class BatchResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    ok: bool
    applied: tuple[AppliedOp, ...] = ()
    errors: tuple[OpError, ...] = ()


# --------------------------------------------------------------------------- validation

_SLOT_KINDS: dict[str, tuple[str, ...]] = {
    "observable": ("observable",),
    "finding": ("finding",),
    "evidence": ("evidence",),
    "target": ("observable", "finding"),
    "parent": ("observable",),
    "child": ("observable",),
}


def validate_operations(cv: Cyvest, operations: Sequence[Operation]) -> list[OpError]:
    """
    Static checks on a batch: every ``$ref`` is defined earlier by an operation of the right kind,
    and no ``ref`` is defined twice. Nothing is written.

    Literal keys are *not* checked here, on purpose: an earlier operation of the same batch may
    create them — including through auto-link, which derives a domain from a URL. The core checks
    them when the operation runs (``KeyError``), and that rolls the batch back like any failure.
    """
    errors: list[OpError] = []
    refs: dict[str, str] = {}
    for index, operation in enumerate(operations):
        for slot, kinds in _SLOT_KINDS.items():
            value = getattr(operation, slot)
            if value is None or not value.startswith("$"):
                continue
            name = value[1:]
            if name not in refs:
                errors.append(OpError(index=index, message=f"{slot} references undefined ${name}"))
            elif refs[name] not in kinds:
                errors.append(
                    OpError(index=index, message=f"{slot} expects {' or '.join(kinds)}, ${name} is a {refs[name]}")
                )
        if operation.ref is not None:
            if operation.op not in _CREATES:
                errors.append(OpError(index=index, message=f"{operation.op} creates no key to name ${operation.ref}"))
            elif operation.ref in refs:
                errors.append(OpError(index=index, message=f"ref ${operation.ref} is defined twice"))
            else:
                refs[operation.ref] = _CREATES[operation.op]
    return errors


# --------------------------------------------------------------------------- application


def _resolve(value: str | None, refs: dict[str, str]) -> str:
    """A slot's key: a ``$ref`` resolved from the batch, or a literal key the core will check."""
    if value is None:
        raise ValueError("missing target")
    return refs[value[1:]] if value.startswith("$") else value


def _apply_one(cv: Cyvest, operation: Operation, refs: dict[str, str], observable_key: str | None) -> str:
    """Apply every kind but ``observable`` (already created by the caller, sync or async)."""
    op = operation.op
    if op == "observable":
        assert observable_key is not None
        return observable_key
    if op == "threat_intel":
        signal = cv.observable_add_threat_intel(
            _resolve(operation.observable, refs),
            operation.source or "",
            verdict=operation.verdict or Verdict.INFO,
            weight=operation.weight,
            confidence=operation.confidence if operation.confidence is not None else 1.0,
            source_class=SourceClass(operation.source_class) if operation.source_class else SourceClass.VENDOR_FEED,
            taxonomies=tuple(operation.taxonomies or ()),
            comment=operation.comment or "",
            observed_at=_when(operation),
            external_id=operation.external_id,
        )
        return signal.key
    if op == "evidence":
        evidence = cv.evidence_create(
            operation.evidence_type or "",
            title=operation.title or "",
            content=operation.content_text,
            uri=operation.uri,
            source=operation.source or AGENT_DECISION_SOURCE,
            captured_at=_when(operation),
            external_id=operation.external_id,
        )
        return evidence.key
    if op in ("finding", "conclusion"):
        extra = json.loads(operation.extra_json) if operation.extra_json else None
        if op == "conclusion":
            finding = cv.conclusion_create(
                operation.rule_id or "",
                operation.name or "",
                operation.comment or "",
                verdict=operation.verdict or Verdict.INFO,
                confidence=operation.confidence if operation.confidence is not None else 1.0,
                extra=extra,
                external_id=operation.external_id,
            )
        else:
            finding = cv.finding_create(
                operation.rule_id or "",
                operation.name or "",
                operation.comment or "",
                verdict=operation.verdict,
                weight=operation.weight,
                confidence=operation.confidence if operation.confidence is not None else 1.0,
                status=Status(operation.status) if operation.status else Status.EVALUATED,
                effect=Effect.ADDITIVE,
                tactic=Tactic(operation.tactic) if operation.tactic else None,
                occurred_at=_when(operation),
                extra=extra,
                external_id=operation.external_id,
            )
        return finding.key
    if op == "link_observable":
        finding_key = _resolve(operation.finding, refs)
        cv.finding_link_observable(
            finding_key,
            _resolve(operation.observable, refs),
            LinkBasis(operation.basis) if operation.basis else LinkBasis.OBSERVABLE,
        )
        return finding_key
    if op == "link_evidence":
        finding_key = _resolve(operation.finding, refs)
        cv.finding_link_evidence(finding_key, _resolve(operation.evidence, refs))
        return finding_key
    if op == "decision":
        decision = cv.decision_create(
            _resolve(operation.target, refs),
            DecisionKind(operation.kind or "REFUTE"),
            operation.justification or "",
            decided_by=operation.decided_by or AGENT_DECISION_SOURCE,
            occurred_at=_when(operation),
        )
        return decision.key
    if op == "relation":
        parent = _resolve(operation.parent, refs)
        child = _resolve(operation.child, refs)
        kind = RelationKind(operation.relation_kind or "related-to")
        cv.observable_add_relation(
            parent,
            child,
            kind,
            confidence=operation.confidence if operation.confidence is not None else 1.0,
            comment=operation.comment or "",
            observed_at=_when(operation),
            asserted_by=_relation_source(operation),
        )
        from cyvest import keys

        return keys.generate_relation_key(parent, child, kind.value)
    raise ValueError(f"unsupported operation {op}")  # pragma: no cover - the Literal forbids it


def _relation_source(operation: Operation) -> SourceRef:
    if operation.source:
        return SourceRef(name=operation.source, source_class=SourceClass.INTERNAL_TOOL)
    return AGENT_RELATION_SOURCE


def _observable_kwargs(operation: Operation) -> dict[str, Any]:
    return {
        "obs_type": operation.type or "",
        "value": operation.value or "",
        "subtype": operation.subtype,
        "namespace": operation.namespace,
        "internal": bool(operation.internal),
        "comment": operation.comment or "",
    }


def _begin(cv: Cyvest, operations: Sequence[Operation]) -> tuple[BatchResult | None, Any]:
    """Validate, then snapshot the store so a failure can be undone."""
    errors = validate_operations(cv, operations)
    if errors:
        return BatchResult(ok=False, errors=tuple(errors)), None
    return None, cv._investigation.store.copy()


def _rollback(cv: Cyvest, backup: Any) -> None:
    cv._investigation.store = backup
    cv._investigation.invalidate()


def apply_operations(cv: Cyvest, operations: Sequence[Operation]) -> BatchResult:
    """
    Apply a batch, or none of it.

    Observables are created through the synchronous path, so an async identity resolver
    registered on ``cv`` makes the batch fail; use :func:`aapply_operations` there.
    """
    refused, backup = _begin(cv, operations)
    if refused is not None:
        return refused
    applied: list[AppliedOp] = []
    refs: dict[str, str] = {}
    for index, operation in enumerate(operations):
        try:
            created = None
            if operation.op == "observable":
                created = cv.observable_create(**_observable_kwargs(operation)).key
            key = _apply_one(cv, operation, refs, created)
        except Exception as exc:  # noqa: BLE001 - any failure voids the whole batch
            _rollback(cv, backup)
            return BatchResult(ok=False, errors=(OpError(index=index, message=str(exc)),))
        if operation.ref is not None:
            refs[operation.ref] = key
        applied.append(AppliedOp(index=index, op=operation.op, key=key, ref=operation.ref))
    return BatchResult(ok=True, applied=tuple(applied))


async def aapply_operations(cv: Cyvest, operations: Sequence[Operation]) -> BatchResult:
    """Async twin of :func:`apply_operations`; observables go through the resolvers' async path."""
    refused, backup = _begin(cv, operations)
    if refused is not None:
        return refused
    applied: list[AppliedOp] = []
    refs: dict[str, str] = {}
    for index, operation in enumerate(operations):
        try:
            created = None
            if operation.op == "observable":
                created = (await cv.observable_acreate(**_observable_kwargs(operation))).key
            key = _apply_one(cv, operation, refs, created)
        except Exception as exc:  # noqa: BLE001 - any failure voids the whole batch
            _rollback(cv, backup)
            return BatchResult(ok=False, errors=(OpError(index=index, message=str(exc)),))
        if operation.ref is not None:
            refs[operation.ref] = key
        applied.append(AppliedOp(index=index, op=operation.op, key=key, ref=operation.ref))
    return BatchResult(ok=True, applied=tuple(applied))


__all__ = [
    "DATED_OPS",
    "REQUIRED_FIELDS",
    "AppliedOp",
    "BatchResult",
    "OpError",
    "OpKind",
    "Operation",
    "RecordBatch",
    "TacticName",
    "VerdictName",
    "aapply_operations",
    "apply_operations",
    "parse_when",
    "validate_operations",
]
