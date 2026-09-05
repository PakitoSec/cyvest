"""
``CyvestMiddleware``: one object that gives an agent an investigation.

It declares the state channel, ships the tools, seeds an empty investigation before the first
model call, and appends two blocks to the system message on every call: the instructions, and a
report recomputed from the current state. The report goes last so the static part of the prompt
stays identical from turn to turn and a provider's prompt cache keeps hitting it.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from langchain.agents.middleware import AgentMiddleware, ModelRequest
from langchain_core.messages import SystemMessage

from cyvest.autolink import AutoLink
from cyvest.cyvest import Cyvest, InvestigationSpec
from cyvest.enums import ObservableType
from cyvest.integrations.langchain.prompts import CYVEST_TOOLS_PROMPT
from cyvest.integrations.langchain.state import INVESTIGATION_KEY, CyvestState, investigation_from_state
from cyvest.integrations.langchain.tools import build_cyvest_tools
from cyvest.io.markdown import render_llm_summary
from cyvest.policy import DEFAULT_POLICY, Policy


def _has_facts(cv: Cyvest) -> bool:
    """Anything beyond the root observable — an empty report is noise in the prompt."""
    return (
        len(cv.observable_get_all()) > 1
        or bool(cv.finding_get_all())
        or bool(cv.threat_intel_get_all())
        or bool(cv.decision_get_all())
    )


class CyvestMiddleware(AgentMiddleware[CyvestState, Any, Any]):
    """
    Carry a cyvest investigation in the agent state and expose it to the model.

    Pass ``configure`` to register identity resolvers: they run on every facade rebuilt from the
    state, which is the only way code that is not a fact can follow the document around.
    """

    state_schema = CyvestState

    def __init__(
        self,
        *,
        root_data: Any = None,
        root_type: ObservableType | str = "artifact",
        investigation_name: str | None = None,
        investigation_id: str | None = None,
        auto_link: AutoLink | None = None,
        policy: Policy | None = None,
        engine: str | None = None,
        configure: Callable[[Cyvest], None] | None = None,
        inject_report: bool = True,
        report_tag: str = "cyvest_report",
        prompt: str | None = CYVEST_TOOLS_PROMPT,
        prompt_tag: str = "cyvest_tools",
        read_tools: bool = True,
        write_tools: bool = True,
        relation_tools: bool = True,
        finalize_on_exit: bool = True,
        max_findings: int = 30,
        max_observables: int = 30,
    ) -> None:
        super().__init__()
        if policy is not None and policy.version != DEFAULT_POLICY.version:
            # The document records the policy by version only, so a custom body would be lost on
            # the first reload and the tools would score with a policy the caller never chose.
            raise ValueError("v7 persists the default policy only; a custom policy cannot travel in the agent state")
        self.defaults = InvestigationSpec(
            root_data=root_data,
            root_type=root_type,
            investigation_name=investigation_name,
            investigation_id=investigation_id,
            auto_link=auto_link,
            policy=policy,
            engine=engine,
            configure=configure,
        )
        self.inject_report = inject_report
        self.report_tag = report_tag
        self.prompt = prompt
        self.prompt_tag = prompt_tag
        self.finalize_on_exit = finalize_on_exit
        self.max_findings = max_findings
        self.max_observables = max_observables
        self.tools = build_cyvest_tools(
            self.defaults,
            read=read_tools,
            write=write_tools,
            relations=relation_tools,
            max_findings=max_findings,
            max_observables=max_observables,
        )

    # ------------------------------------------------------------------ seed

    def _seed(self, state: Any) -> dict[str, Any] | None:
        current = state.get(INVESTIGATION_KEY) if isinstance(state, dict) else None
        if current:
            return None
        return {INVESTIGATION_KEY: self.defaults.new().io_to_dict()}

    def before_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:  # noqa: ARG002
        return self._seed(state)

    async def abefore_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:  # noqa: ARG002
        return self._seed(state)

    # ------------------------------------------------------------------ prompt

    def render_report(self, state: Any) -> str | None:
        """The report block's text for a state, or ``None`` when there is nothing worth showing."""
        cv = investigation_from_state(state, self.defaults)
        if cv is None or not _has_facts(cv):
            return None
        return render_llm_summary(cv, max_findings=self.max_findings, max_observables=self.max_observables)

    def _augment(self, request: ModelRequest[Any]) -> ModelRequest[Any] | None:
        blocks = list(request.system_message.content_blocks) if request.system_message is not None else []
        appended = False
        if self.prompt and self.tools:
            blocks.append({"type": "text", "text": f"<{self.prompt_tag}>\n{self.prompt}\n</{self.prompt_tag}>"})
            appended = True
        if self.inject_report:
            report = self.render_report(getattr(request, "state", None) or {})
            if report is not None:
                blocks.append({"type": "text", "text": f"<{self.report_tag}>\n{report}\n</{self.report_tag}>"})
                appended = True
        if not appended:
            return None
        return request.override(system_message=SystemMessage(content_blocks=blocks))

    def wrap_model_call(self, request: ModelRequest[Any], handler: Callable[..., Any]) -> Any:
        augmented = self._augment(request)
        return handler(augmented if augmented is not None else request)

    async def awrap_model_call(self, request: ModelRequest[Any], handler: Callable[..., Any]) -> Any:
        augmented = self._augment(request)
        return await handler(augmented if augmented is not None else request)

    # ------------------------------------------------------------------ finalize

    def _finalize(self, state: Any) -> dict[str, Any] | None:
        if not self.finalize_on_exit:
            return None
        cv = investigation_from_state(state, self.defaults)
        if cv is None:
            return None
        before = len(cv.relation_get_all())
        cv.finalize_relationships()
        if len(cv.relation_get_all()) == before:
            return None
        return {INVESTIGATION_KEY: cv.io_to_dict()}

    def after_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:  # noqa: ARG002
        return self._finalize(state)

    async def aafter_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:  # noqa: ARG002
        return self._finalize(state)


__all__ = ["CyvestMiddleware"]
