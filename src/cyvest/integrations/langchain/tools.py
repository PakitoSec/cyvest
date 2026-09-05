"""
The tools a model uses to read and write the investigation.

Every tool rebuilds the facade from the state channel, so tools compose with any middleware and
with parallel tool calls. Read tools return Markdown; write tools return a ``Command`` carrying
the new document and a ``ToolMessage`` — or, when the write was refused, only the message, so a
bad batch never touches the state.

Tools are built with an explicit argument schema: the injected ``runtime`` parameter must not
leak into what the model sees, and a schema written by hand is also the one place to keep the
model-facing field descriptions.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from langchain.tools import ToolRuntime
from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool, StructuredTool
from langgraph.types import Command
from pydantic import BaseModel, Field

from cyvest.cyvest import Cyvest, InvestigationSpec
from cyvest.integrations.langchain.state import INVESTIGATION_KEY, investigation_from_state
from cyvest.io.markdown import (
    FindingFilter,
    explain_text,
    findings_markdown,
    observables_markdown,
    render_llm_summary,
    timeline_markdown,
)
from cyvest.operations import Operation, aapply_operations, apply_operations
from cyvest.relations import RelationPlan, apply_relation_plan, relation_context, validate_relation_plan


class ExplainArgs(BaseModel):
    key: str = Field(..., description="A finding key (fnd:...) or an observable key (obs:...)")


class ObservablesArgs(BaseModel):
    type: str | None = Field(default=None, description="Keep one observable type only, e.g. domain")
    min_abs_score: float = Field(default=0.0, ge=0.0, description="Hide observables scoring closer to zero")
    limit: int = Field(default=50, ge=1, le=500)


class FindingsArgs(BaseModel):
    status: FindingFilter = Field(default="all", description="all, evaluated, pending, or conclusions")


class TimelineArgs(BaseModel):
    limit: int = Field(default=50, ge=1, le=500)


class RecordArgs(BaseModel):
    operations: list[Operation] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="Writes applied in order, all or nothing; a later one may reference an earlier one by $ref",
    )


class RelationPlanArgs(BaseModel):
    plan: RelationPlan


class RelationApplyArgs(RelationPlanArgs):
    confirm: bool = Field(default=False, description="Must be true; set it only after the plan was validated")


def _dump(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, default=str)


def _load(runtime: ToolRuntime, defaults: InvestigationSpec) -> Cyvest:
    return investigation_from_state(runtime.state, defaults) or defaults.new()


def _commit(cv: Cyvest, runtime: ToolRuntime, payload: dict[str, Any], name: str) -> Command:
    return Command(
        update={
            INVESTIGATION_KEY: cv.io_to_dict(),
            "messages": [ToolMessage(content=_dump(payload), tool_call_id=runtime.tool_call_id, name=name)],
        }
    )


def build_cyvest_tools(
    defaults: InvestigationSpec | None = None,
    *,
    read: bool = True,
    write: bool = True,
    relations: bool = True,
    max_findings: int = 30,
    max_observables: int = 30,
) -> list[BaseTool]:
    """
    The cyvest toolset, bound to how the investigation is rebuilt.

    ``read`` gives the model the report, explanations, listings and the timeline; ``write`` the
    batched ``cyvest_record``; ``relations`` the plan → validate → apply trio for edges.
    """
    defaults = defaults or InvestigationSpec()
    tools: list[BaseTool] = []

    # ------------------------------------------------------------------ read

    def report(runtime: ToolRuntime) -> str:
        return render_llm_summary(_load(runtime, defaults), max_findings=max_findings, max_observables=max_observables)

    def explain(key: str, runtime: ToolRuntime) -> str:
        try:
            return explain_text(_load(runtime, defaults), key)
        except KeyError:
            return f"unknown key {key!r}: use a key listed by cyvest_report"

    def observables(runtime: ToolRuntime, type: str | None = None, min_abs_score: float = 0.0, limit: int = 50) -> str:  # noqa: A002
        return observables_markdown(_load(runtime, defaults), obs_type=type, min_abs_score=min_abs_score, limit=limit)

    def findings(runtime: ToolRuntime, status: FindingFilter = "all") -> str:
        return findings_markdown(_load(runtime, defaults), status=status)

    def timeline(runtime: ToolRuntime, limit: int = 50) -> str:
        return timeline_markdown(_load(runtime, defaults), limit=limit)

    if read:
        tools += [
            _tool(
                report,
                "cyvest_report",
                "Read the investigation: global score and verdict, conclusions, findings, observables, "
                "decisions and contradictions. Call it before concluding.",
            ),
            _tool(
                explain,
                "cyvest_explain",
                "Explain a finding's or an observable's score: every contribution.",
                ExplainArgs,
            ),
            _tool(observables, "cyvest_observables", "List observables with their verdict and score.", ObservablesArgs),
            _tool(findings, "cyvest_findings", "List findings, optionally filtered by status.", FindingsArgs),
            _tool(
                timeline,
                "cyvest_timeline",
                "The timeline projected from the dated facts, oldest first, with the tactic of each dated "
                "finding; undated facts appear at the moment they were recorded, marked (asserted).",
                TimelineArgs,
            ),
        ]

    # ------------------------------------------------------------------ write

    def _record_payload(result: Any, cv: Cyvest) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": result.ok,
            "applied": [applied.model_dump() for applied in result.applied],
            "errors": [error.model_dump() for error in result.errors],
        }
        if result.ok:
            payload["report"] = render_llm_summary(cv, max_findings=max_findings, max_observables=max_observables)
        return payload

    def record(operations: Sequence[Operation], runtime: ToolRuntime) -> Command | str:
        cv = _load(runtime, defaults)
        result = apply_operations(cv, list(operations))
        payload = _record_payload(result, cv)
        return _commit(cv, runtime, payload, "cyvest_record") if result.ok else _dump(payload)

    async def arecord(operations: Sequence[Operation], runtime: ToolRuntime) -> Command | str:
        cv = _load(runtime, defaults)
        result = await aapply_operations(cv, list(operations))
        payload = _record_payload(result, cv)
        return _commit(cv, runtime, payload, "cyvest_record") if result.ok else _dump(payload)

    if write:
        tools.append(
            _tool(
                record,
                "cyvest_record",
                "Write to the investigation: a batch of operations (observable, threat_intel, evidence, finding, "
                "conclusion, link_observable, link_evidence, decision, relation) applied all or nothing. "
                "Create before you link; name a created key with ref and use '$ref' in later operations. "
                "Date a finding, evidence, signal, relation or decision with occurred_at (ISO 8601 UTC) and "
                "name the tactic a finding demonstrates: the timeline is built from them. "
                "Returns what was applied, or the errors to fix and resend.",
                RecordArgs,
                coroutine=arecord,
            )
        )

    # ------------------------------------------------------------------ relations

    def context(runtime: ToolRuntime) -> str:
        return relation_context(_load(runtime, defaults)).to_markdown()

    def validate(plan: RelationPlan, runtime: ToolRuntime) -> str:
        return _dump(validate_relation_plan(_load(runtime, defaults), plan).model_dump())

    def apply(plan: RelationPlan, runtime: ToolRuntime, confirm: bool = False) -> Command | str:
        if not confirm:
            return _dump({"ok": False, "error": "set confirm=true after validating the plan"})
        cv = _load(runtime, defaults)
        try:
            result = apply_relation_plan(cv, plan)
        except ValueError as exc:
            return _dump({"ok": False, "error": str(exc)})
        return _commit(cv, runtime, {"ok": True, **result.model_dump()}, "cyvest_relation_plan_apply")

    if relations:
        tools += [
            _tool(
                context,
                "cyvest_relation_context",
                "The observable graph with its revision: read it before proposing relations.",
            ),
            _tool(
                validate,
                "cyvest_relation_plan_validate",
                "Check a relation plan without changing anything; returns accepted proposals and issues.",
                RelationPlanArgs,
            ),
            _tool(
                apply,
                "cyvest_relation_plan_apply",
                "Draw the relations of a validated plan. Requires confirm=true.",
                RelationApplyArgs,
            ),
        ]
    return tools


def _tool(
    func: Any,
    name: str,
    description: str,
    args_schema: type[BaseModel] | None = None,
    *,
    coroutine: Any = None,
) -> BaseTool:
    """
    Sync and async entry points on one tool; the read tools are pure, so their async twin is trivial.

    A tool without model-facing arguments must let the schema be inferred from its signature: with
    an explicit empty schema, ``StructuredTool`` skips argument parsing altogether and the injected
    ``runtime`` never reaches the function.
    """
    if coroutine is None:

        async def coroutine(**kwargs: Any) -> Any:  # noqa: ANN401
            return func(**kwargs)

    return StructuredTool.from_function(
        func=func,
        coroutine=coroutine,
        name=name,
        description=description,
        args_schema=args_schema,
    )


__all__ = [
    "ExplainArgs",
    "FindingsArgs",
    "ObservablesArgs",
    "RecordArgs",
    "RelationApplyArgs",
    "RelationPlanArgs",
    "TimelineArgs",
    "build_cyvest_tools",
]
