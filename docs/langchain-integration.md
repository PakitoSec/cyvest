# LangChain Integration

An agent that investigates should keep its facts somewhere that computes the verdict for it.
`cyvest.integrations.langchain` puts the investigation in the agent state, gives the model tools to
read and write it, and shows it the current report on every turn.

```bash
pip install 'cyvest[langchain]'          # langchain >= 1.0
```

```python
from langchain.agents import create_agent
from cyvest import AutoLink
from cyvest.integrations.langchain import CyvestMiddleware, INVESTIGATION_KEY

agent = create_agent(
    model="anthropic:claude-sonnet-4-6",
    tools=[search_logs, lookup_reputation],
    system_prompt="You are a SOC analyst.",
    middleware=[CyvestMiddleware(root_data={"case": "IR-2431"}, auto_link=AutoLink())],
)

state = agent.invoke({"messages": [{"role": "user", "content": "Triage this alert: ..."}]})
document = state[INVESTIGATION_KEY]          # the serialized investigation
```

---

## What the middleware does

`CyvestMiddleware` is one `AgentMiddleware` that:

1. **declares the state channel** `investigation`, a serialized document merged by union — two
   parallel tool calls that both write end up with both writes;
2. **ships the tools** below, so the host graph declares none of them;
3. **seeds** an empty investigation before the first model call;
4. **appends two blocks to the system message** on every model call: `<cyvest_tools>` (the
   instructions) and `<cyvest_report>` (the report recomputed from the current state). The report
   comes last so the static part of the prompt stays byte-identical between turns. Besides the
   facts it lists what disagrees (`Contradictions`) and what may be said twice (`Possible
   duplicates`: two findings of one polarity over mostly the same observables); nothing is merged
   for the model, it decides and refutes the redundant finding;
5. **attaches orphans to the root** when the agent finishes (`finalize_on_exit`).

```python
CyvestMiddleware(
    root_data=None, root_type="artifact",
    investigation_name=None, investigation_id=None,
    auto_link=None, engine=None,
    configure=None,                 # callable(cv) run on every rebuilt facade — register resolvers here
    inject_report=True, report_tag="cyvest_report",
    prompt=CYVEST_TOOLS_PROMPT, prompt_tag="cyvest_tools",
    read_tools=True, write_tools=True, relation_tools=True,
    finalize_on_exit=True,
    max_findings=30, max_observables=30,
)
```

!!! note "Resolvers are code, not facts"
    A document carries no identity resolver. Pass `configure=lambda cv: cv.observable_resolver_register(...)`:
    it runs on every facade the integration rebuilds from the state, new or loaded.

---

## The state

The investigation travels as the dict `Cyvest.io_to_dict()` produces. That is what a checkpointer
stores, what survives a restart, and what two branches of a graph can be merged from. The channel's
reducer is `merge_documents`, the dict form of `FactStore.union`: idempotent, commutative,
associative. A sequential run never pays for the union — a document that contains everything the
previous one did wins on a dict comparison.

```python
from cyvest.integrations.langchain import CyvestState, investigation_from_state

class MyState(CyvestState):        # or declare the same Annotated channel on your own state
    ticket_id: str

cv = investigation_from_state(state, middleware.defaults)   # a Cyvest facade, or None
```

If your graph declares its own `state_schema`, its `investigation` annotation wins over the
middleware's: declare it with the same reducer.

---

## The tools

| Tool | Does |
|---|---|
| `cyvest_report` | the compact report: score, verdict, conclusions, findings, observables, decisions, contradictions, possible duplicates |
| `cyvest_explain(key)` | every contribution behind a finding or an observable |
| `cyvest_observables(type, min_abs_score, limit)` | observables, strongest first |
| `cyvest_findings(status)` | findings; `all`, `evaluated`, `pending` or `conclusions` |
| `cyvest_timeline(limit)` | the timeline projected from the dated facts, oldest first, with each finding's tactic |
| `cyvest_record(operations)` | **the one write tool**: a batch applied all or nothing |
| `cyvest_relation_context` | the observable graph and its revision |
| `cyvest_relation_plan_validate(plan)` | what a relation plan would do, and why parts of it would not |
| `cyvest_relation_plan_apply(plan, confirm)` | draw a validated plan's edges; `confirm=true` required |

Every tool rebuilds the facade from the state, acts, and — for writes — returns a `Command` that
carries the new document plus the tool message. A refused write returns the message only, so the
state never sees a half-applied batch.

### `cyvest_record`

A list of flat operations, each with an `op` and the fields that op needs:

| `op` | required | notable optional |
|---|---|---|
| `observable` | `type`, `value` | `subtype`, `namespace`, `internal`, `comment` |
| `threat_intel` | `observable`, `source` | `verdict`, `weight`, `confidence`, `source_class`, `taxonomies`, `external_id`, `occurred_at` |
| `evidence` | `evidence_type`, `title`, and `content_text` or `uri` | `source`, `external_id`, `occurred_at` |
| `finding` | `rule_id` | `name`, `comment`, `verdict`, `weight`, `confidence`, `status`, `extra_json`, `occurred_at`, `tactic` |
| `conclusion` | `rule_id`, `verdict` | `name`, `comment`, `confidence` — no `weight`, no `occurred_at` |
| `link_observable` | `finding`, `observable` | `basis` |
| `link_evidence` | `finding`, `evidence` | |
| `decision` | `target`, `kind`, `justification` | `decided_by`, `occurred_at` |
| `relation` | `parent`, `child` | `relation_kind`, `confidence`, `comment`, `occurred_at` |

`occurred_at` (ISO 8601 UTC) is the moment in the world — the source's timestamp, never the time
the model wrote the operation — and lands on the fact under its family's name (`captured_at` for
evidence, `observed_at` for signals and relations). `tactic` is one of the fourteen ATT&CK
Enterprise tactics in kebab-case, stated only when the finding's activity demonstrates it. The
timeline is projected from these, see [Timeline](timeline.md).

An operation may name the key it creates with `ref`, and later operations in the same batch refer
to it as `"$name"`:

```json
{"operations": [
  {"op": "observable", "ref": "url", "type": "url", "value": "hxxp://evil[.]example/x"},
  {"op": "threat_intel", "observable": "obs:domain:evil.example", "source": "virustotal", "verdict": "MALICIOUS", "weight": 7},
  {"op": "finding", "ref": "f", "rule_id": "url-in-body", "name": "URL in body", "verdict": "SUSPICIOUS"},
  {"op": "link_observable", "finding": "$f", "observable": "$url"},
  {"op": "finding", "rule_id": "link-clicked", "name": "`jdoe` opened the landing page", "verdict": "NOTABLE",
   "tactic": "initial-access", "occurred_at": "2026-08-07T10:02:00Z"},
  {"op": "conclusion", "rule_id": "triage-verdict", "verdict": "MALICIOUS", "comment": "corroborated"}
]}
```

References are checked before anything runs; literal keys are checked when their operation runs,
because an earlier operation — or auto-link, as with the domain above — may have just created them.
Any failure rolls the whole batch back and the tool returns the errors to fix.

The model is deliberately **flat** (one object, literal enums, no union): some providers refuse the
tool grammar a discriminated union compiles to. The same batch API is available without LangChain
as `cyvest.apply_operations(cv, operations)` / `aapply_operations`.

### Relation plans

A model sees relationships an extraction rule cannot. It proposes them against a **revision** of
the graph, the library validates, and only a plan without error is applied:

```python
from cyvest import RelationPlan, RelationProposal, relation_context, validate_relation_plan, apply_relation_plan

context = relation_context(cv)                     # nodes, edges, revision
plan = RelationPlan(revision=context.revision, proposals=[
    RelationProposal(source_key=host, target_key=ip, kind="pivot", rationale="seen in netflow", comment="communicates-with"),
])
preview = validate_relation_plan(cv, plan)         # accepted proposals + issues
apply_relation_plan(cv, plan)                      # ValueError while an error remains
```

Errors: `stale_revision`, `unknown_source`, `unknown_target`, `self_loop`, `duplicate_relation`,
`duplicate_proposal`. Warnings: `creates_cycle`, `targets_root`, `reverse_exists`, `low_confidence`.
v7 has three relation kinds; the semantic verb goes in `comment`.

---

## Deep agents and subagents

A deepagents subagent runs as its own graph with its own state: whatever it records does not flow
back to the parent by itself. Two patterns work:

- the **supervisor** carries the middleware and the tools; subagents report structured findings,
  and a middleware on the supervisor ingests them into the state investigation with
  `investigation_from_state` + `Cyvest` calls + a `Command` update;
- each **subagent** carries its own `CyvestMiddleware` and returns its document, which the parent
  folds in with `merge_documents`.

Either way the reducer does the merging; nothing needs a lock.

---

## Without an agent

Everything the tools do is available on the core library, LangChain installed or not:

```python
from cyvest import Cyvest, Operation, apply_operations, render_llm_summary

result = apply_operations(cv, [Operation(op="finding", rule_id="spf-fail", verdict="SUSPICIOUS")])
print(render_llm_summary(cv))
```

---

## API summary

| Name | Purpose |
|---|---|
| `CyvestMiddleware(...)` | state channel + tools + prompt blocks + finalize |
| `CyvestState` | `AgentState` plus the `investigation` channel |
| `INVESTIGATION_KEY` | `"investigation"` |
| `InvestigationSpec(...)` (alias `CyvestDefaults`) | how a facade is built or rebuilt; `.new()`, `.load(data)`; the object `SharedInvestigationContext` builds its workers from |
| `investigation_from_state(state, defaults)` | a `Cyvest` over the state's document, or `None` |
| `build_cyvest_tools(defaults, read=, write=, relations=)` | the tools without the middleware |
| `CYVEST_TOOLS_PROMPT` | the instructions block |
| `merge_documents(current, incoming)` | the reducer (`cyvest.merge_documents`) |
| `Operation`, `apply_operations`, `aapply_operations` | the batch API, LangChain-free |
| `render_llm_summary(cv)` | the report block's text |
