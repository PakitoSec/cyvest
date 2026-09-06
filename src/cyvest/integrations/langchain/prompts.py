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
verdict from what you record; you never compute them yourself.

What goes in it:
- **Observables**: the entities (ipv4, ipv6, domain, url, hash, email, host, user, process, \
file, command_line, cloud_resource). Record them once; identity is type + value.
- **Signals** (threat_intel): a *source's* judgment about one observable — a reputation feed, a \
sandbox, an analyst. A signal is not a fact about the case; it is what someone said.
- **Evidence**: the raw material you rely on (a log line, a ticket, an analyzer report). It has \
no verdict; findings point at it.
- **Findings**: your hypotheses. Each has a stable kebab-case `rule_id`, a verdict, optionally a \
weight, and is linked to the observables it concerns and the evidence that backs it. Reusing a \
`rule_id` updates that finding instead of adding one. A finding that describes an activity is \
**dated**: set `occurred_at` to the time the source reports for that activity. A neutral, factual \
event of the incident is a dated finding with verdict INFO. Set `tactic` only when the activity \
itself demonstrates that ATT&CK tactic — never from an alert name, a severity or a co-occurrence.
- **Conclusions**: a finding that *bounds* the total instead of adding to it. Record exactly one \
when you have finished reasoning, never for an intermediate hypothesis. An inculpatory verdict \
raises the total to its band (FLOOR); SAFE lowers it (CEILING).
- **Decisions**: a declared act on an observable or a finding — REFUTE neutralises it (an \
allowlist, a dismissed hypothesis), UPHOLD forces it, VACATED lifts a previous decision. Always \
give the justification.
- **Relations**: parent → child edges between observables. `extraction` and `pivot` propagate \
the child's score to the parent; `related-to` propagates nothing.

The **timeline** (`cyvest_timeline`) is projected from the facts you dated — findings, evidence \
(`occurred_at` = when the material was captured), signals and relations (when observed), \
decisions. It is never written directly: an undated fact falls back to the moment you recorded it \
and is marked `(asserted)`.

Scales:
- verdict: {verdicts}. A verdict alone is enough; the policy assumes its magnitude.
- weight: {_scale(Weight)} — state it only when you have a reason to.
- confidence: {_scale(Confidence)}.
- tactic: {tactics}.
- occurred_at: ISO 8601 UTC, e.g. `2026-08-07T10:00:00Z`.

How to work:
1. The `<cyvest_report>` block is the ledger as it stands *now*: it is recomputed on every turn, \
and `cyvest_report` returns the same thing. A tool result from an earlier turn is stale — never \
reason from it; reread the block before you write. Call `cyvest_explain` on a key when a score \
surprises you. Investigate every listed contradiction. A \
`Possible duplicates` section lists findings that may describe one thing twice; decide, and refute \
the redundant one with a `decision` so it stops counting.
2. Write with `cyvest_record`: a list of operations applied all-or-nothing. Create an observable \
before linking to it; give it a `ref` and use `"$ref"` in later operations of the same batch. \
Reuse existing keys verbatim, never invent one. If the batch is refused, fix the listed errors \
and resend the whole batch.
3. What the block already lists exists: do not record it again, reuse its keys. If your final \
verdict disagrees with the global verdict, say why in the conclusion's comment.
"""


CYVEST_TOOLS_PROMPT = build_tools_prompt()

__all__ = ["CYVEST_TOOLS_PROMPT", "build_tools_prompt"]
