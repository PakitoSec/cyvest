"""Relation plans: context, validation codes, atomic application."""

from __future__ import annotations

import pytest

from cyvest import Cyvest, RelationPlan, RelationProposal, apply_relation_plan, relation_context, validate_relation_plan
from cyvest.relations import AGENT_RELATION_SOURCE, relation_revision


def _graph() -> tuple[Cyvest, str, str, str]:
    cv = Cyvest(root_data={"case": "graph"})
    host = cv.observable(cv.OBS.HOST, "srv-01", subtype=cv.SUB.HOST_HOSTNAME, namespace="corp").key
    ip = cv.observable(cv.OBS.IPV4, "203.0.113.5").key
    domain = cv.observable(cv.OBS.DOMAIN, "evil.example").key
    cv.observable_add_relation(domain, ip, cv.REL.PIVOT, comment="resolves-to")
    return cv, host, ip, domain


def _plan(cv: Cyvest, *proposals: RelationProposal, revision: str | None = None) -> RelationPlan:
    return RelationPlan(revision=revision or relation_revision(cv), proposals=list(proposals))


class TestContext:
    def test_revision_changes_with_the_graph_shape(self) -> None:
        cv, host, ip, _domain = _graph()
        before = relation_revision(cv)
        cv.observable_add_relation(host, ip)
        assert relation_revision(cv) != before

    def test_markdown_lists_nodes_and_edges(self) -> None:
        cv, _host, ip, domain = _graph()
        text = relation_context(cv).to_markdown()
        assert f"`{domain}` →[pivot]→ `{ip}`" in text
        assert "(root)" in text
        assert relation_context(cv).revision in text


class TestValidate:
    def test_unknown_keys_and_self_loops_are_errors(self) -> None:
        cv, host, _ip, _domain = _graph()
        preview = validate_relation_plan(
            cv,
            _plan(
                cv,
                RelationProposal(source_key="obs:ipv4:9.9.9.9", target_key=host, rationale="x"),
                RelationProposal(source_key=host, target_key=host, rationale="x"),
            ),
        )
        assert not preview.valid
        assert {issue.code for issue in preview.errors} == {"unknown_source", "self_loop"}
        assert preview.accepted == ()

    def test_existing_and_repeated_edges_are_errors(self) -> None:
        cv, host, ip, domain = _graph()
        preview = validate_relation_plan(
            cv,
            _plan(
                cv,
                RelationProposal(source_key=domain, target_key=ip, kind="pivot", rationale="dup"),
                RelationProposal(source_key=host, target_key=ip, rationale="ok"),
                RelationProposal(source_key=host, target_key=ip, rationale="again"),
            ),
        )
        codes = {(issue.index, issue.code) for issue in preview.errors}
        assert codes == {(0, "duplicate_relation"), (2, "duplicate_proposal")}
        assert [proposal.source_key for proposal in preview.accepted] == [host]

    def test_a_stale_revision_refuses_the_whole_plan(self) -> None:
        cv, host, ip, _domain = _graph()
        preview = validate_relation_plan(
            cv, _plan(cv, RelationProposal(source_key=host, target_key=ip, rationale="x"), revision="old")
        )
        assert not preview.valid
        assert preview.errors[0].code == "stale_revision"
        assert len(preview.accepted) == 1  # the proposal itself is fine; the plan is not

    def test_cycles_root_targets_and_low_confidence_are_warnings(self) -> None:
        cv, _host, ip, domain = _graph()
        preview = validate_relation_plan(
            cv,
            _plan(
                cv,
                RelationProposal(source_key=ip, target_key=domain, rationale="loop", confidence=0.2),
                RelationProposal(source_key=ip, target_key=cv.root().key, rationale="root"),
            ),
        )
        assert preview.valid
        assert {issue.code for issue in preview.issues} == {"creates_cycle", "low_confidence", "targets_root"}


class TestApply:
    def test_an_invalid_plan_is_refused_and_nothing_is_written(self) -> None:
        cv, host, _ip, _domain = _graph()
        before = dict(cv.relation_get_all())
        plan = _plan(cv, RelationProposal(source_key=host, target_key="obs:ipv4:9.9.9.9", rationale="x"))
        with pytest.raises(ValueError, match="unknown_target"):
            apply_relation_plan(cv, plan)
        assert cv.relation_get_all() == before

    def test_partial_application_keeps_the_accepted_proposals(self) -> None:
        cv, host, ip, _domain = _graph()
        plan = _plan(
            cv,
            RelationProposal(source_key=host, target_key="obs:ipv4:9.9.9.9", rationale="x"),
            RelationProposal(source_key=host, target_key=ip, rationale="ok"),
        )
        result = apply_relation_plan(cv, plan, partial=True)
        assert len(result.applied_keys) == 1 and result.skipped == 1

    def test_applied_edges_carry_the_agent_source_and_the_verb(self) -> None:
        cv, host, ip, _domain = _graph()
        plan = _plan(
            cv,
            RelationProposal(
                source_key=host, target_key=ip, kind="pivot", rationale="seen", comment="communicates-with"
            ),
        )
        result = apply_relation_plan(cv, plan)
        relation = cv.relation_get_all()[result.applied_keys[0]]
        assert relation.source == AGENT_RELATION_SOURCE
        assert relation.comment == "communicates-with"
        assert relation.kind is cv.REL.PIVOT
        assert result.revision_after == relation_revision(cv) != result.revision_before
