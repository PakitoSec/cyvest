"""Tests for agent-friendly semantic relationship contracts."""

import pytest
from pydantic import ValidationError

from cyvest import Cyvest, RelationshipDirection, RelationshipType
from cyvest.semantics import (
    RelationshipPlan,
    RelationshipProposal,
    build_relationship_context,
    get_relationship_catalog,
    validate_relationship_plan,
)


def test_relationship_catalog_covers_canonical_types() -> None:
    catalog = get_relationship_catalog()

    assert {definition.relationship_type for definition in catalog} == set(RelationshipType)
    assert all(definition.description for definition in catalog)
    assert all(definition.source_role and definition.target_role for definition in catalog)


def test_relationship_proposal_normalizes_defaults() -> None:
    proposal = RelationshipProposal(
        source_key=" obs:domain:example.com ",
        target_key="obs:ipv4:192.0.2.1",
        relationship_type="resolves-to",
        confidence=0.9,
        rationale=" DNS evidence ",
        evidence_refs=("finding:dns",),
    )

    assert proposal.source_key == "obs:domain:example.com"
    assert proposal.relationship_type == RelationshipType.RESOLVES_TO
    assert proposal.direction == RelationshipDirection.OUTBOUND
    assert proposal.rationale == "DNS evidence"


def test_relationship_plan_schema_is_structured_output_ready() -> None:
    schema = RelationshipPlan.model_json_schema()
    proposal_schema = schema["$defs"]["RelationshipProposal"]

    assert schema["additionalProperties"] is False
    assert proposal_schema["additionalProperties"] is False
    assert {"graph_revision", "proposals"} <= set(schema["required"])


def test_relationship_proposal_rejects_invalid_confidence() -> None:
    with pytest.raises(ValidationError):
        RelationshipProposal(
            source_key="obs:domain:example.com",
            target_key="obs:ipv4:192.0.2.1",
            relationship_type="resolves-to",
            confidence=1.1,
            rationale="DNS evidence",
        )


def test_relationship_context_is_compact_and_revisioned() -> None:
    cv = Cyvest(investigation_name="DNS case")
    domain = cv.observable(Cyvest.OBS.DOMAIN, "example.com")
    ip = cv.observable(Cyvest.OBS.IPV4, "192.0.2.1")
    context = build_relationship_context(
        cv._investigation.get_all_observables(),
        cv.root().key,
    )

    assert len(context.graph_revision) == 64
    assert {item.key for item in context.observables} >= {domain.key, ip.key}
    assert "## Observables" in context.to_markdown()
    assert domain.key in context.to_markdown()


def test_validate_relationship_plan_accepts_canonical_edge() -> None:
    cv = Cyvest()
    domain = cv.observable(Cyvest.OBS.DOMAIN, "example.com")
    ip = cv.observable(Cyvest.OBS.IPV4, "192.0.2.1")
    context = build_relationship_context(cv._investigation.get_all_observables(), cv.root().key)
    plan = RelationshipPlan(
        graph_revision=context.graph_revision,
        proposals=(
            RelationshipProposal(
                source_key=domain.key,
                target_key=ip.key,
                relationship_type="resolves-to",
                confidence=0.95,
                rationale="Observed in DNS answer",
            ),
        ),
    )

    preview = validate_relationship_plan(cv._investigation.get_all_observables(), plan)

    assert preview.valid
    assert preview.accepted == plan.proposals
    assert preview.issues == ()


def test_validate_relationship_plan_rejects_stale_and_unknown_keys() -> None:
    cv = Cyvest()
    context = build_relationship_context(cv._investigation.get_all_observables(), cv.root().key)
    cv.observable(Cyvest.OBS.DOMAIN, "new.example")
    plan = RelationshipPlan(
        graph_revision=context.graph_revision,
        proposals=(
            RelationshipProposal(
                source_key="obs:domain:missing.example",
                target_key=cv.root().key,
                relationship_type="custom-link",
                confidence=0.5,
                rationale="Unverified",
            ),
        ),
    )

    preview = validate_relationship_plan(cv._investigation.get_all_observables(), plan)

    assert not preview.valid
    assert {issue.code for issue in preview.issues} == {
        "stale_graph_revision",
        "source_not_found",
        "custom_type_not_allowed",
    }
    assert preview.accepted == ()


def test_apply_relationship_plan_is_audited_and_revisioned() -> None:
    cv = Cyvest()
    domain = cv.observable(Cyvest.OBS.DOMAIN, "example.com")
    ip = cv.observable(Cyvest.OBS.IPV4, "192.0.2.1")
    context = cv.relationship_context_get()
    plan = RelationshipPlan(
        graph_revision=context.graph_revision,
        model="test-model",
        tool="semantic-planner",
        proposals=(
            RelationshipProposal(
                source_key=domain.key,
                target_key=ip.key,
                relationship_type="resolves-to",
                confidence=0.95,
                rationale="Observed in DNS answer",
                evidence_refs=("finding:dns",),
            ),
        ),
    )

    result = cv.relationship_plan_apply(plan)

    assert result.applied_count == 1
    assert result.graph_revision_before == context.graph_revision
    assert result.graph_revision_after != result.graph_revision_before
    assert domain.relationships[0].target_key == ip.key
    event = cv.investigation_get_audit_log()[-1]
    assert event.event_type == "RELATIONSHIP_PLAN_APPLIED"
    assert event.details["model"] == "test-model"
    assert event.details["proposals"][0]["rationale"] == "Observed in DNS answer"


def test_remove_relationship_and_apply_remove_plan() -> None:
    cv = Cyvest()
    domain = cv.observable(Cyvest.OBS.DOMAIN, "example.com")
    ip = cv.observable(Cyvest.OBS.IPV4, "192.0.2.1")
    cv.observable_add_relationship(domain, ip, Cyvest.REL.RESOLVES_TO)
    context = cv.relationship_context_get()
    plan = RelationshipPlan(
        graph_revision=context.graph_revision,
        proposals=(
            RelationshipProposal(
                operation="remove",
                source_key=domain.key,
                target_key=ip.key,
                relationship_type="resolves-to",
                confidence=1,
                rationale="DNS evidence was retracted",
            ),
        ),
    )

    result = cv.relationship_plan_apply(plan)

    assert result.applied_count == 1
    assert domain.relationships == []


def test_validate_relationship_plan_rejects_structural_cycle() -> None:
    cv = Cyvest()
    parent = cv.observable(Cyvest.OBS.FILE, "parent.eml")
    child = cv.observable(Cyvest.OBS.FILE, "child.txt")
    cv.observable_add_relationship(parent, child, Cyvest.REL.CONTAINS)
    context = cv.relationship_context_get()
    plan = RelationshipPlan(
        graph_revision=context.graph_revision,
        proposals=(
            RelationshipProposal(
                source_key=child.key,
                target_key=parent.key,
                relationship_type="contains",
                confidence=0.8,
                rationale="Incorrect inverse containment",
            ),
        ),
    )

    preview = cv.relationship_plan_validate(plan)

    assert not preview.valid
    assert [issue.code for issue in preview.issues] == ["relationship_cycle"]


def test_validate_relationship_plan_warns_on_unusual_direction() -> None:
    cv = Cyvest()
    domain = cv.observable(Cyvest.OBS.DOMAIN, "example.com")
    ip = cv.observable(Cyvest.OBS.IPV4, "192.0.2.1")
    context = cv.relationship_context_get()
    plan = RelationshipPlan(
        graph_revision=context.graph_revision,
        proposals=(
            RelationshipProposal(
                source_key=domain.key,
                target_key=ip.key,
                relationship_type="resolves-to",
                direction="inbound",
                confidence=0.7,
                rationale="Direction supplied by an external model",
            ),
        ),
    )

    preview = cv.relationship_plan_validate(plan)

    assert preview.valid
    assert [issue.code for issue in preview.issues] == ["unusual_direction"]