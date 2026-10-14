# Agent Integration

`cyvest.agent` is the seam between an investigation and an agent harness. It depends on no agent
framework: the harness owns the tools, the prompts and when the model sees what; Cyvest owns the
facts and how they are rendered.

The division of labour it supports:

- **tools produce the evidence**: the harness records each tool call as evidence, keyed by the call;
- **the model interprets**: it writes findings that cite those keys, and decisions;
- **Cyvest computes**: scores and verdicts are derived, and the model is not shown them.

## Capturing tool outputs

```python
from cyvest.agent import record_tool_output

evidence = record_tool_output(
    cv,
    source="splunk",              # the evidence source
    call_id="toolu_01",           # the tool call id: replaying the call is a no-op
    tool="run_query",
    title="Logons from 203.0.113.7",
    output=rows,
    arguments={"query": spl},
    uri="s3://bucket/runs/42/toolu_01.json",   # where the full output lives, when it was stored
    max_chars=8_000,
)
evidence.key   # "evd:splunk:toolu_01"
```

The content is `{tool, arguments, output, truncated, sha256}`. An output longer than `max_chars`
(measured on its canonical JSON text) is cut and flagged; the hash is always of the full text.
`bounded_content(content, max_chars)` exposes the same bounding.

## Showing the facts, not the computation

```python
from cyvest.agent import facts_status

facts_status(cv)                              # no signals shown
facts_status(cv, signals_for={"obs:ipv4:203.0.113.7"})   # signals of the observables the model asked about
```

`render_llm_summary` shows the score and the derived verdicts; `facts_status` shows only what was
recorded: findings with their asserted verdict, dates, tactic, cited evidence and observables;
observables with their decisions (and signals only where `signals_for` allows); decisions; and
disagreements, i.e. findings of opposite polarity about the same observable. The output is
deterministic, so a harness can place it in a prompt without breaking a prompt cache needlessly.

## Checking a write

```python
from cyvest.agent import ledger_delta, missing_references

missing_references(cv, evidence_keys=cited, observable_keys=linked)   # [] when every key exists
ledger_delta(before_document, cv.io_to_dict())   # {"findings": ["fnd:..."], "evidences": [...]}
```

Refuse a finding whose cited keys are missing rather than creating placeholders: an invented key
is a claim without material.

## The guide

`build_agent_guide()` renders what a model must know about Cyvest itself (fact kinds, dating
rules, the verdict, weight, confidence and tactic scales) from the current enums. The harness
appends its own tool names and output contract.

## From 7.3

The LangChain integration (`cyvest.integrations.langchain`, the `langchain` extra) was removed in
7.4. Its middleware owned tools, prompt and state in one place, which left a harness no room to
decide what the model sees. Keep the investigation in your agent state as the serialized document
(`cv.io_to_dict()`, merged with `merge_documents`), write through the facade or
`apply_operations`, and use the helpers above.
