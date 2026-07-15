from __future__ import annotations

import pytest

pytest.importorskip("langchain_core")

from cyvest import Cyvest
from cyvest.langchain import RELATIONSHIP_PLANNER_SYSTEM_PROMPT, create_relationship_tools
from cyvest.semantics import RelationshipPlan, RelationshipProposal


def test_relationship_planner_prompt_defines_safe_workflow() -> None:
    assert "cyvest_relationship_catalog before planning" in RELATIONSHIP_PLANNER_SYSTEM_PROMPT
    assert "cyvest_relationship_context" in RELATIONSHIP_PLANNER_SYSTEM_PROMPT
    assert "cyvest_relationship_plan_validate" in RELATIONSHIP_PLANNER_SYSTEM_PROMPT
    assert "Never apply a plan" in RELATIONSHIP_PLANNER_SYSTEM_PROMPT


def test_relationship_toolkit_is_read_only_by_default() -> None:
    tools = create_relationship_tools(Cyvest())

    assert [tool.name for tool in tools] == [
        "cyvest_relationship_catalog",
        "cyvest_relationship_context",
        "cyvest_relationship_plan_validate",
    ]


def test_relationship_apply_tool_requires_confirmation() -> None:
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
                confidence=0.9,
                rationale="DNS answer",
            ),
        ),
    )
    apply_tool = create_relationship_tools(cv, include_apply=True)[-1]

    with pytest.raises(ValueError, match="confirmation"):
        apply_tool.invoke({"plan": plan.model_dump(mode="json"), "confirm": False})

    result = apply_tool.invoke({"plan": plan.model_dump(mode="json"), "confirm": True})
    assert result["applied_count"] == 1