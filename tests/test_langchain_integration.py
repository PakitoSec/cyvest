"""The LangChain layer, driven by a scripted tool-calling model — no network, no provider."""

from __future__ import annotations

import json
from typing import Any, get_args, get_origin, get_type_hints

import pytest
from typing_extensions import NotRequired

pytest.importorskip("langchain")

from langchain.agents import create_agent  # noqa: E402
from langchain_core.language_models import BaseChatModel  # noqa: E402
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage  # noqa: E402
from langchain_core.outputs import ChatGeneration, ChatResult  # noqa: E402

from cyvest import AutoLink, Cyvest, merge_documents  # noqa: E402
from cyvest.integrations.langchain import (  # noqa: E402
    INVESTIGATION_KEY,
    CyvestDefaults,
    CyvestMiddleware,
    CyvestState,
    build_cyvest_tools,
    investigation_from_state,
)


class ScriptedToolCallingModel(BaseChatModel):
    """Replays a list of AI messages; records every prompt it was shown."""

    script: list[BaseMessage]
    prompts: list[list[BaseMessage]] = []

    def bind_tools(self, tools: Any, **_kwargs: Any) -> ScriptedToolCallingModel:
        return self

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def _generate(self, messages: list[BaseMessage], stop: Any = None, run_manager: Any = None, **_: Any) -> ChatResult:
        self.prompts.append(list(messages))
        return ChatResult(generations=[ChatGeneration(message=self.script.pop(0))])


def _call(name: str, call_id: str, **args: Any) -> dict[str, Any]:
    return {"name": name, "args": args, "id": call_id}


RECORD = [
    {"op": "observable", "ref": "url", "type": "url", "value": "hxxp://evil[.]example/x"},
    {
        "op": "threat_intel",
        "observable": "obs:domain:evil.example",
        "source": "virustotal",
        "verdict": "MALICIOUS",
        "weight": 7,
    },
    {"op": "finding", "ref": "f", "rule_id": "url-in-body", "name": "URL in body", "verdict": "SUSPICIOUS"},
    {"op": "link_observable", "finding": "$f", "observable": "$url"},
    {"op": "conclusion", "rule_id": "triage-verdict", "verdict": "MALICIOUS", "comment": "corroborated"},
]


def _run(script: list[BaseMessage], middleware: CyvestMiddleware) -> tuple[dict[str, Any], ScriptedToolCallingModel]:
    model = ScriptedToolCallingModel(script=script, prompts=[])
    agent = create_agent(model, tools=[], middleware=[middleware], system_prompt="You are an analyst.")
    return agent.invoke({"messages": [{"role": "user", "content": "triage this"}]}), model


def _tool_messages(state: dict[str, Any]) -> list[ToolMessage]:
    return [message for message in state["messages"] if isinstance(message, ToolMessage)]


class TestState:
    def test_the_channel_is_merged_by_union(self) -> None:
        hint = get_type_hints(CyvestState, include_extras=True)[INVESTIGATION_KEY]
        if get_origin(hint) is NotRequired:  # kept by some Python versions, stripped by others
            hint = get_args(hint)[0]
        assert merge_documents in get_args(hint)

    def test_defaults_rebuild_and_configure(self) -> None:
        seen = []
        defaults = CyvestDefaults(root_data={"case": "x"}, investigation_id="x", configure=seen.append)
        document = defaults.new().io_to_dict()
        loaded = investigation_from_state({INVESTIGATION_KEY: document}, defaults)
        assert loaded is not None and loaded.investigation_id == "x"
        assert len(seen) == 2
        assert investigation_from_state({}, defaults) is None


class TestTools:
    def test_the_record_schema_stays_small_and_flat(self) -> None:
        (record,) = [
            tool for tool in build_cyvest_tools(CyvestDefaults(), relations=False) if tool.name == "cyvest_record"
        ]
        schema = json.dumps(record.tool_call_schema.model_json_schema())
        assert len(schema) < 12_000
        assert "anyOf" not in json.dumps(
            record.tool_call_schema.model_json_schema()["$defs"]["Operation"]["properties"]["op"]
        )

    def test_the_prompt_lists_the_tactics_from_the_enum(self) -> None:
        from cyvest import Tactic
        from cyvest.integrations.langchain.prompts import build_tools_prompt

        prompt = build_tools_prompt()
        assert all(tactic.value in prompt for tactic in Tactic)
        assert "occurred_at" in prompt and "(asserted)" in prompt

    def test_selection_flags(self) -> None:
        names = {tool.name for tool in build_cyvest_tools(CyvestDefaults(), write=False, relations=False)}
        assert names == {"cyvest_report", "cyvest_explain", "cyvest_observables", "cyvest_findings", "cyvest_timeline"}
        assert {tool.name for tool in CyvestMiddleware(read_tools=False, relation_tools=False).tools} == {
            "cyvest_record"
        }

    def test_record_updates_the_state_and_reports_back(self) -> None:
        state, _model = _run(
            [
                AIMessage(content="", tool_calls=[_call("cyvest_record", "c1", operations=RECORD)]),
                AIMessage(
                    content="",
                    tool_calls=[_call("cyvest_report", "c2"), _call("cyvest_explain", "c3", key="fnd:url-in-body")],
                ),
                AIMessage(content="done"),
            ],
            CyvestMiddleware(root_data={"case": "demo"}, investigation_name="demo", auto_link=AutoLink()),
        )
        cv = Cyvest.io_load_dict(state[INVESTIGATION_KEY])
        assert set(cv.finding_get_all()) == {"fnd:url-in-body", "fnd:triage-verdict"}
        assert cv.get_global_verdict() is cv.VERDICT.MALICIOUS
        record, report, explain = _tool_messages(state)
        payload = json.loads(record.content)
        assert payload["ok"] and payload["applied"][0]["ref"] == "url" and "# Investigation `demo`" in payload["report"]
        assert report.content.startswith("# Investigation `demo`")
        assert "extraction" in explain.content or "url-in-body" in explain.content

    def test_parallel_writes_in_one_step_are_both_kept(self) -> None:
        first = [{"op": "finding", "rule_id": "from-first", "verdict": "SUSPICIOUS"}]
        second = [{"op": "finding", "rule_id": "from-second", "verdict": "SAFE"}]
        state, _model = _run(
            [
                AIMessage(
                    content="",
                    tool_calls=[
                        _call("cyvest_record", "c1", operations=first),
                        _call("cyvest_record", "c2", operations=second),
                    ],
                ),
                AIMessage(content="done"),
            ],
            CyvestMiddleware(),
        )
        assert set(state[INVESTIGATION_KEY]["facts"]["findings"]) == {"fnd:from-first", "fnd:from-second"}

    def test_a_refused_batch_leaves_the_state_alone(self) -> None:
        bad = [{"op": "link_observable", "finding": "fnd:nope", "observable": "$x"}]
        state, _model = _run(
            [
                AIMessage(content="", tool_calls=[_call("cyvest_record", "c1", operations=bad)]),
                AIMessage(content="done"),
            ],
            CyvestMiddleware(),
        )
        payload = json.loads(_tool_messages(state)[0].content)
        assert payload["ok"] is False and payload["errors"]
        assert Cyvest.io_load_dict(state[INVESTIGATION_KEY]).finding_get_all() == {}

    def test_relation_plan_apply_requires_confirmation(self) -> None:
        cv = CyvestDefaults(investigation_id="rel").new()
        a = cv.observable(cv.OBS.DOMAIN, "a.example").key
        b = cv.observable(cv.OBS.IPV4, "203.0.113.5").key
        from cyvest.relations import relation_revision

        plan = {
            "revision": relation_revision(cv),
            "proposals": [{"source_key": a, "target_key": b, "kind": "pivot", "rationale": "dns"}],
        }
        model = ScriptedToolCallingModel(
            script=[
                AIMessage(content="", tool_calls=[_call("cyvest_relation_plan_apply", "c1", plan=plan)]),
                AIMessage(content="", tool_calls=[_call("cyvest_relation_plan_apply", "c2", plan=plan, confirm=True)]),
                AIMessage(content="done"),
            ],
            prompts=[],
        )
        agent = create_agent(
            model, tools=[], middleware=[CyvestMiddleware(investigation_id="rel", finalize_on_exit=False)]
        )
        state = agent.invoke({"messages": [{"role": "user", "content": "go"}], INVESTIGATION_KEY: cv.io_to_dict()})
        refused, applied = _tool_messages(state)
        assert "confirm" in refused.content
        assert json.loads(applied.content)["ok"] is True
        assert len(Cyvest.io_load_dict(state[INVESTIGATION_KEY]).relation_get_all()) == 1


class TestMiddleware:
    def test_before_agent_seeds_an_empty_investigation_once(self) -> None:
        middleware = CyvestMiddleware(root_data={"case": "seed"}, investigation_id="seed")
        update = middleware.before_agent({}, None)
        assert update is not None and update[INVESTIGATION_KEY]["header"]["investigation_id"] == "seed"
        assert middleware.before_agent(update, None) is None

    def test_prompt_and_report_blocks_follow_the_system_prompt(self) -> None:
        _state, model = _run(
            [
                AIMessage(content="", tool_calls=[_call("cyvest_record", "c1", operations=RECORD)]),
                AIMessage(content="done"),
            ],
            CyvestMiddleware(auto_link=AutoLink()),
        )
        first, last = model.prompts[0][0], model.prompts[-1][0]
        assert [block["type"] for block in first.content_blocks] == ["text", "text"]
        assert first.content_blocks[0]["text"] == "You are an analyst."
        assert first.content_blocks[1]["text"].startswith("<cyvest_tools>")
        assert last.content_blocks[2]["text"].startswith("<cyvest_report>\n# Investigation")

    def test_no_report_block_while_only_the_root_exists(self) -> None:
        middleware = CyvestMiddleware()
        assert middleware.render_report(middleware.before_agent({}, None)) is None

    def test_after_agent_attaches_orphans_when_asked(self) -> None:
        cv = Cyvest()
        cv.observable(cv.OBS.DOMAIN, "lonely.example")
        state = {INVESTIGATION_KEY: cv.io_to_dict()}
        assert CyvestMiddleware(finalize_on_exit=False).after_agent(state, None) is None
        update = CyvestMiddleware().after_agent(state, None)
        assert update is not None and len(update[INVESTIGATION_KEY]["facts"]["relations"]) == 1
        assert CyvestMiddleware().after_agent(update, None) is None

    def test_a_custom_policy_is_refused(self) -> None:
        from cyvest import Policy

        with pytest.raises(ValueError, match="default policy"):
            CyvestMiddleware(policy=Policy(version="custom-v1"))

    @pytest.mark.anyio
    async def test_the_async_path_matches_the_sync_one(self) -> None:
        model = ScriptedToolCallingModel(
            script=[
                AIMessage(content="", tool_calls=[_call("cyvest_record", "c1", operations=RECORD)]),
                AIMessage(content="done"),
            ],
            prompts=[],
        )
        agent = create_agent(model, tools=[], middleware=[CyvestMiddleware(auto_link=AutoLink())])
        state = await agent.ainvoke({"messages": [{"role": "user", "content": "go"}]})
        assert "fnd:triage-verdict" in state[INVESTIGATION_KEY]["facts"]["findings"]
