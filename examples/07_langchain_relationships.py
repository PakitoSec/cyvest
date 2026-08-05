"""Example 7: LangChain Relationship Planning

Demonstrates Cyvest's LangChain tools with a real model-backed agent.

Install the optional dependency first:
    pip install -e ".[langchain]"
"""

import argparse
from typing import Any

from langchain.agents import create_agent
from langchain.chat_models import init_chat_model
from logurich import get_logger, init_logger

from cyvest import Cyvest, RelationshipPlan
from cyvest.langchain import RELATIONSHIP_PLANNER_SYSTEM_PROMPT, create_relationship_tools

logger = get_logger(__name__)


def plan_with_agent(cv: Cyvest, model: Any, request: str) -> RelationshipPlan:
    """Create and invoke a real LangChain relationship-planning agent."""

    agent = create_agent(
        model=model,
        tools=create_relationship_tools(cv),
        system_prompt=RELATIONSHIP_PLANNER_SYSTEM_PROMPT,
        response_format=RelationshipPlan,
    )
    result = agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": request,
                }
            ]
        }
    )
    return RelationshipPlan.model_validate(result["structured_response"])


def main(model_name: str | None = None) -> None:
    """Plan, validate, and explicitly apply one semantic relationship."""

    if not model_name:
        raise ValueError(
            "A LangChain model is required. Pass --model, for example "
            "bedrock_converse:anthropic.claude-3-5-sonnet-20240620-v1:0."
        )

    cv = Cyvest(investigation_name="LangChain relationship example")
    domain = cv.observable(cv.OBS.DOMAIN, "suspicious.example", internal=False)
    ip = cv.observable(cv.OBS.IPV4, "192.0.2.42", internal=False)

    # The default toolkit is read-only and safe to give to an autonomous agent.
    read_only_tools = create_relationship_tools(cv)
    tools_by_name = {tool.name: tool for tool in read_only_tools}
    logger.info("Read-only tools: %s", ", ".join(tools_by_name))
    logger.info("Planner system prompt loaded: %s", RELATIONSHIP_PLANNER_SYSTEM_PROMPT.splitlines()[0])

    catalog = tools_by_name["cyvest_relationship_catalog"].invoke({})
    context = tools_by_name["cyvest_relationship_context"].invoke({})
    logger.info("Canonical relationship types: %s", len(catalog))
    logger.info("Graph revision: %s", context["graph_revision"])

    request = (
        "Analyze the existing domain and IPv4 observables. Propose and validate "
        "their most precise relationship using the DNS resolution finding."
    )
    logger.info("Creating LangChain agent with model: %s", model_name)
    try:
        model = init_chat_model(model_name)
    except ImportError as exc:
        if model_name.startswith("bedrock"):
            raise RuntimeError(
                "Bedrock support requires Cyvest's Bedrock extra. Run "
                "`uv run --extra bedrock python examples/07_langchain_relationships.py "
                f"--model {model_name!r}`."
            ) from exc
        raise
    plan = plan_with_agent(cv, model, request)

    preview = tools_by_name["cyvest_relationship_plan_validate"].invoke(
        {"plan": plan.model_dump(mode="json")}
    )
    logger.info("Plan valid: %s", preview["valid"])
    logger.info("Validation issues: %s", preview["issues"] or "none")
    if not preview["valid"]:
        return

    # The calling application enables mutation only after reviewing the preview.
    apply_tools = create_relationship_tools(
        cv,
        include_apply=True,
        actor="relationship-example-agent",
    )
    apply_tool = next(tool for tool in apply_tools if tool.name == "cyvest_relationship_plan_apply")
    result = apply_tool.invoke(
        {
            "plan": plan.model_dump(mode="json"),
            "confirm": True,
        }
    )

    logger.info("Applied relationships: %s", result["applied_count"])
    logger.info("New graph revision: %s", result["graph_revision_after"])
    logger.info("Audit event: %s", result["audit_event_id"])
    logger.info(
        "Created edge: %s --%s--> %s",
        domain.value,
        domain.relationships[0].relationship_type_name,
        ip.value,
    )


if __name__ == "__main__":
    init_logger("INFO")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model",
        help="LangChain model identifier, for example bedrock_converse:anthropic.claude-3-5-sonnet-20240620-v1:0.",
    )
    arguments = parser.parse_args()
    main(arguments.model)
