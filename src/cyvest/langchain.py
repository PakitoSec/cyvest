"""Optional LangChain tools for semantic relationship planning."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from cyvest.semantics import RelationshipPlan, get_relationship_catalog

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from cyvest.cyvest import Cyvest


RELATIONSHIP_PLANNER_SYSTEM_PROMPT = """\
You are a cybersecurity relationship planner for Cyvest.

Your task is to propose precise semantic relationships between existing
observables. Never create observables or modify their values.

Required workflow:
1. Read cyvest_relationship_catalog before planning.
2. Read cyvest_relationship_context and retain its graph revision.
3. Use only observable keys present in that context.
4. Prefer the most precise canonical relationship type.
5. Use related-to only when no stronger mechanism is established.
6. Support every proposal with a concise rationale, confidence, and evidence references.
7. Validate the complete plan with cyvest_relationship_plan_validate.
8. Correct validation errors before returning the plan.
9. Treat validation warnings as points requiring explicit review.
10. Never apply a plan; return the validated plan to the calling application for approval.
"""


class RelationshipPlanToolInput(BaseModel):
    """Structured input shared by validation and application tools."""

    model_config = ConfigDict(extra="forbid")

    plan: RelationshipPlan


class RelationshipApplyToolInput(RelationshipPlanToolInput):
    """Application input requiring explicit confirmation."""

    confirm: bool = Field(
        default=False,
        description="Must be true only after the relationship plan has been reviewed and approved.",
    )


def create_relationship_tools(
    cyvest: Cyvest,
    *,
    include_apply: bool = False,
    allow_custom_types: bool = False,
    actor: str = "agent",
) -> tuple[BaseTool, ...]:
    """Create LangChain-compatible tools for relationship planning.

    The returned toolkit is read-only unless ``include_apply`` is explicitly enabled.
    """

    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - depends on optional installation
        raise ImportError(
            "LangChain support is optional. Install it with `pip install 'cyvest[langchain]'`."
        ) from exc

    def relationship_catalog() -> list[dict[str, Any]]:
        """Get the canonical relationship vocabulary and semantic defaults."""

        return [definition.model_dump(mode="json") for definition in get_relationship_catalog()]

    def relationship_context() -> dict[str, Any]:
        """Get the current compact graph, observable keys, existing edges, and revision."""

        return cyvest.relationship_context_get().model_dump(mode="json")

    def relationship_plan_validate(plan: RelationshipPlan) -> dict[str, Any]:
        """Validate a proposed relationship plan without changing the investigation."""

        return cyvest.relationship_plan_validate(
            plan,
            allow_custom_types=allow_custom_types,
        ).model_dump(mode="json")

    tools: list[BaseTool] = [
        StructuredTool.from_function(
            func=relationship_catalog,
            name="cyvest_relationship_catalog",
            description="Read Cyvest's canonical relationship types before proposing graph changes.",
        ),
        StructuredTool.from_function(
            func=relationship_context,
            name="cyvest_relationship_context",
            description="Read the compact investigation graph and its current revision.",
        ),
        StructuredTool.from_function(
            func=relationship_plan_validate,
            name="cyvest_relationship_plan_validate",
            description="Validate relationship proposals without mutating the investigation.",
            args_schema=RelationshipPlanToolInput,
        ),
    ]

    if include_apply:

        def relationship_plan_apply(plan: RelationshipPlan, confirm: bool = False) -> dict[str, Any]:
            """Atomically apply an approved relationship plan when confirm is true."""

            if not confirm:
                raise ValueError("Explicit confirmation is required to apply a relationship plan.")
            return cyvest.relationship_plan_apply(
                plan,
                allow_custom_types=allow_custom_types,
                actor=actor,
                tool="langchain",
            ).model_dump(mode="json")

        tools.append(
            StructuredTool.from_function(
                func=relationship_plan_apply,
                name="cyvest_relationship_plan_apply",
                description="Apply a reviewed relationship plan atomically. Set confirm=true to proceed.",
                args_schema=RelationshipApplyToolInput,
            )
        )

    return tuple(tools)