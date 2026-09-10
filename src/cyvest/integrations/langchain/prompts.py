"""
The prompt fragment that teaches a model what cyvest is and how to write to it.

The scales are rendered from the enums, never typed by hand: a prompt that quoted ``HIGH 7`` after
the policy moved it would make the model wrong with confidence.
"""

from __future__ import annotations

from cyvest.enums import Confidence, Tactic, Verdict, Weight


def _scale(members: type[Weight] | type[Confidence]) -> str:
    return ", ".join(f"{member.name} {member.value:g}" for member in members)


def build_tools_prompt() -> str:
    """The instructions block, rendered from the current enums."""
    verdicts = " < ".join(member.value for member in Verdict)
    tactics = ", ".join(member.value for member in Tactic)
    return f"""\
You keep the investigation in Cyvest, a deterministic ledger. It computes the score and the \
verdict from recorded material, not new evidence; never compute them yourself.

What goes in it:
- **Observables**: entities identified by type + value; record each once.
- **Signals** (`threat_intel`): a source's judgment about an observable, not proof about the case.
- **Evidence**: source material without a verdict; findings reference it.
- **Findings**: supported observations or hypotheses with a stable kebab-case `rule_id`, a verdict, \
and links to evidence and observables. Reusing `rule_id` updates the finding. Neutral facts use INFO.
- **Decisions** on findings or observables: REFUTE neutralises, UPHOLD forces, VACATED lifts a \
previous decision. Always justify them.
- **Relations**: parent-to-child edges; `extraction` and `pivot` propagate the child's score to \
the parent, `related-to` does not.

Date activity findings using the source's event time, evidence using capture time, signals and \
relations using observation time. The timeline is projected from dated facts and decisions; \
undated facts fall back to recording time, marked `(asserted)`. Set `tactic` only for activity \
demonstrating it, never from an alert label, severity or co-occurrence.

Scales:
- verdict: {verdicts}. A verdict alone is enough; the policy assumes its magnitude.
- weight: {_scale(Weight)}; state it only when justified.
- confidence: {_scale(Confidence)}.
- tactic: {tactics}.
- occurred_at: ISO 8601 UTC, e.g. `2026-08-07T10:00:00Z`.

Read current state:
Use the injected `<cyvest_report>` or latest report before writing; call `cyvest_report` if neither \
is available. Read results remain valid until the ledger changes. A read does not create conclusions \
or change the investigation. Only call again with the same arguments after the investigation changes; \
do not poll. A new turn alone changes nothing. An empty result is still the current state, not pending \
work. Use a different key/filter only for unread details: `cyvest_findings` for a truncated list, \
`cyvest_explain` for a contribution you need to understand. Do not alternate report and findings \
to wait for a different result.

Write justified changes:
`cyvest_record` applies operations all-or-nothing. Create before linking; assign `ref` and use \
`"$ref"` later in the batch. Reuse existing keys verbatim, not duplicate records or invented keys. \
On refusal, fix the listed errors and resend the batch. A successful write returns the updated \
report; reuse it. Never create conclusion findings with this integration. Do not record your \
final assessment as an ordinary finding either, or edit facts to reach a target score.

Review and finish:
Review relevant contradictions against source evidence. Correct or refute only when justified; \
unresolved disagreements may remain and must be explained. `Possible duplicates` are suggestions, \
not automatic refutations: if redundant, refute one with a justified decision naming the retained \
finding. Do not erase evidence. If your assessment differs from the global verdict, explain why \
in your response. Follow the caller's output contract once the requested work is complete; \
completion does not require resolving every contradiction. Preserve uncertainty and collection \
gaps; do not invent evidence or edits to keep working.
"""


CYVEST_TOOLS_PROMPT = build_tools_prompt()

__all__ = ["CYVEST_TOOLS_PROMPT", "build_tools_prompt"]
