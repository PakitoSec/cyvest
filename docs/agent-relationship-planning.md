# Agent Relationship Planning

Cyvest exposes a framework-independent planning contract for agents that infer semantic relationships between existing observables. Agents propose semantics, while Cyvest owns graph integrity, scoring, audit, and mutation.

## Safe workflow

1. Read `get_relationship_catalog()` to understand the canonical vocabulary.
2. Read `cv.relationship_context_get()` to obtain observable keys, existing edges, and the graph revision.
3. Produce a structured `RelationshipPlan` using the returned revision.
4. Call `cv.relationship_plan_validate(plan)` without mutating the investigation.
5. Review errors and warnings, then call `cv.relationship_plan_apply(plan)` if approved.

Plans are rejected when their revision is stale. Application is atomic, recalculates scores once, and records the plan digest, model, tool, confidence, rationale, and evidence references in the audit log.

```python
from cyvest import Cyvest, RelationshipPlan, RelationshipProposal

cv = Cyvest()
domain = cv.observable(cv.OBS.DOMAIN, "example.com")
ip = cv.observable(cv.OBS.IPV4, "192.0.2.1")
context = cv.relationship_context_get()

plan = RelationshipPlan(
    graph_revision=context.graph_revision,
    model="relationship-planner-v1",
    proposals=(
        RelationshipProposal(
            source_key=domain.key,
            target_key=ip.key,
            relationship_type="resolves-to",
            confidence=0.96,
            rationale="The address appeared in the domain's DNS answer.",
            evidence_refs=("finding:dns-resolution",),
        ),
    ),
)

preview = cv.relationship_plan_validate(plan)
if preview.valid:
    result = cv.relationship_plan_apply(plan, actor="dns-agent")
```

`RelationshipPlan.model_json_schema()` can be passed directly to providers that support structured output. The core planning API does not depend on an agent framework.

## LangChain and Deep Agents

Install the optional adapter:

```bash
pip install "cyvest[langchain]"
```

The generated tools implement LangChain's `BaseTool` contract and can be supplied to LangChain agents or Deep Agents.

```python
from cyvest.langchain import (
    RELATIONSHIP_PLANNER_SYSTEM_PROMPT,
    create_relationship_tools,
)

tools = create_relationship_tools(cv)
```

This toolkit is read-only by default. It contains tools for the relationship catalog, graph context, and plan validation.

Use the reusable prompt when creating a LangChain planner:

```python
from langchain.agents import create_agent

agent = create_agent(
    model=model,
    tools=tools,
    system_prompt=RELATIONSHIP_PLANNER_SYSTEM_PROMPT,
    response_format=RelationshipPlan,
)
```

The system prompt guides the planner through catalog, context, and validation tools. It instructs the agent to return the validated plan without applying it. After human or application approval, apply the plan outside the planner:

```python
result = cv.relationship_plan_apply(plan, actor="approved-relationship-agent")
```

For trusted orchestrators that require a tool interface, `create_relationship_tools(cv, include_apply=True)` adds the apply tool. Do not expose it to an autonomous planner as an approval boundary: an LLM can set `confirm=true` itself. Custom relationship types are rejected by default; set `allow_custom_types=True` only when the surrounding application governs that vocabulary.

The example requires a real model. For AWS Bedrock, use the project extra and a model available in your configured region:

```bash
uv run --extra bedrock python examples/07_langchain_relationships.py \
    --model "bedrock_converse:anthropic.claude-3-5-sonnet-20240620-v1:0"
```

With pip, install `cyvest[bedrock]` before running the same script. `uv run --with langchain` is not equivalent: it installs LangChain itself, but not the `langchain-aws` provider integration.

LangChain uses the standard AWS credential chain and `AWS_REGION` or `AWS_DEFAULT_REGION`. The example raises an exception when `--model` is omitted. Its model-backed path uses `init_chat_model`, `RELATIONSHIP_PLANNER_SYSTEM_PROMPT`, the read-only Cyvest tools, and `response_format=RelationshipPlan`.

## Validation behavior

Errors prevent application in strict mode:

- stale graph revision
- unknown source or target keys
- self-relationships
- duplicate operations in one plan
- custom types when disabled
- removal of a relationship that does not exist
- a cycle in `contains` or `derived-from` relationships

Warnings preserve analyst flexibility:

- an add operation already exists
- a canonical relationship is unusual for the observable type pair
- a canonical relationship uses an unusual direction
- a high-confidence proposal uses the generic `related-to` type