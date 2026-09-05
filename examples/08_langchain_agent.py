"""
Example 9: An agent that keeps its investigation in Cyvest

The model never computes a score. It records observables, signals, findings and one conclusion
through `cyvest_record`; the middleware keeps the investigation in the agent state and shows the
recomputed report on every turn. A scripted model stands in for a provider so the example runs
offline: swap it for `model="anthropic:claude-sonnet-4-6"` and the rest is unchanged.

Requires the optional extra: `pip install 'cyvest[langchain]'`.
"""

from __future__ import annotations

from typing import Any

from langchain.agents import create_agent
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from logurich import get_logger, init_logger

from cyvest import AutoLink, Cyvest
from cyvest.integrations.langchain import INVESTIGATION_KEY, CyvestMiddleware

logger = get_logger(__name__)


class ScriptedToolCallingModel(BaseChatModel):
    """Replays a fixed list of AI messages — enough to drive the tools without a provider."""

    script: list[BaseMessage]

    def bind_tools(self, tools: Any, **_kwargs: Any) -> ScriptedToolCallingModel:
        return self

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def _generate(self, messages: list[BaseMessage], stop: Any = None, run_manager: Any = None, **_: Any) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=self.script.pop(0))])


FIRST_BATCH = [
    {
        "op": "observable",
        "ref": "url",
        "type": "url",
        "value": "hxxps://invoice-portal[.]example/pay",
        "internal": False,
    },
    {"op": "threat_intel", "observable": "$url", "source": "virustotal", "verdict": "NOTABLE", "weight": 1.2},
    {
        "op": "evidence",
        "ref": "hdr",
        "evidence_type": "email_headers",
        "title": "Received chain",
        "content_text": "spf=fail",
        "source": "mail-gateway",
    },
    {
        "op": "finding",
        "ref": "spf",
        "rule_id": "spf-fail",
        "name": "SPF failure",
        "verdict": "SUSPICIOUS",
        "weight": 2.0,
    },
    {"op": "link_evidence", "finding": "$spf", "evidence": "$hdr"},
    {"op": "finding", "ref": "rep", "rule_id": "url-reputation", "name": "URL weakly flagged"},
    {"op": "link_observable", "finding": "$rep", "observable": "$url"},
]

# The domain was derived by auto-link when the URL was created; the second batch names it directly.
# The click is dated with the gateway's time and names the tactic it demonstrates: that is what the
# timeline is projected from — nothing is written to a timeline itself.
SECOND_BATCH = [
    {
        "op": "threat_intel",
        "observable": "obs:domain:invoice-portal.example",
        "source": "urlscan",
        "verdict": "MALICIOUS",
        "weight": 7.0,
    },
    {
        "op": "finding",
        "ref": "click",
        "rule_id": "link-clicked",
        "name": "`jdoe` opened the landing page from the mail",
        "verdict": "NOTABLE",
        "tactic": "initial-access",
        "occurred_at": "2026-08-07T10:02:00Z",
    },
    # A $ref lives for one batch only: the URL created earlier is named by its key here.
    {"op": "link_observable", "finding": "$click", "observable": "obs:url:hxxps://invoice-portal[.]example/pay"},
    {
        "op": "conclusion",
        "rule_id": "ia",
        "name": "Confirmed phishing",
        "verdict": "MALICIOUS",
        "comment": "Two independent sources flag the landing domain; SPF fails on the sender.",
    },
]

SCRIPT: list[BaseMessage] = [
    AIMessage(content="", tool_calls=[{"name": "cyvest_record", "args": {"operations": FIRST_BATCH}, "id": "call-1"}]),
    AIMessage(
        content="",
        tool_calls=[
            {"name": "cyvest_explain", "args": {"key": "obs:url:hxxps://invoice-portal[.]example/pay"}, "id": "call-2"}
        ],
    ),
    AIMessage(content="", tool_calls=[{"name": "cyvest_record", "args": {"operations": SECOND_BATCH}, "id": "call-3"}]),
    AIMessage(content="Phishing confirmed; the conclusion is recorded."),
]


def main() -> None:
    init_logger("INFO")
    agent = create_agent(
        ScriptedToolCallingModel(script=list(SCRIPT)),
        tools=[],
        system_prompt="You are a SOC analyst triaging one e-mail.",
        middleware=[CyvestMiddleware(root_data={"type": "email", "subject": "Unpaid invoice"}, auto_link=AutoLink())],
    )
    state = agent.invoke({"messages": [{"role": "user", "content": "Triage this e-mail."}]})

    for message in state["messages"]:
        if isinstance(message, ToolMessage):
            logger.info("[bold]%s[/] → %s", message.name, message.content[:160].replace("\n", " "))

    cv = Cyvest.io_load_dict(state[INVESTIGATION_KEY])
    logger.info("score=%.2f verdict=%s", cv.get_global_score(), cv.get_global_verdict().value)
    cv.display_summary()
    cv.display_timeline()


if __name__ == "__main__":
    main()
