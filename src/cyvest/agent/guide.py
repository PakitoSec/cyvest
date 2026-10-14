"""
What a model needs to know about cyvest to write sound facts, whatever the tools around it.

The scales are rendered from the enums, never typed by hand: a guide that quoted ``HIGH 7`` after
the policy moved it would make the model wrong with confidence. Tool names and the output contract
belong to the harness, which appends its own instructions.
"""

from __future__ import annotations

from cyvest.enums import Confidence, Tactic, Verdict, Weight


def _scale(members: type[Weight] | type[Confidence]) -> str:
    return ", ".join(f"{member.name} {member.value:g}" for member in members)


def build_agent_guide() -> str:
    """The framework-neutral guide, rendered from the current enums."""
    verdicts = " < ".join(member.value for member in Verdict)
    tactics = ", ".join(member.value for member in Tactic)
    return f"""\
The investigation is kept in Cyvest, a deterministic ledger of facts. It derives scores from the \
recorded material; you never compute or target a score.

- **Observables**: entities identified by type and value.
- **Signals**: a source's judgment about an observable, not proof about the case.
- **Evidence**: source material, without a verdict. Tool outputs are captured as evidence for you; \
cite their `evd:` keys, never retype their content.
- **Findings**: supported observations with a stable kebab-case `rule_id`, an asserted verdict, \
and links to the evidence and observables that support them. Reusing a `rule_id` updates the \
finding. Neutral facts use INFO.
- **Decisions** on findings or observables: REFUTE neutralises, UPHOLD forces, VACATED lifts a \
previous decision. Always justify them.

Date activity findings with the source's event time. Set `tactic` only for activity demonstrating \
it, never from an alert label, a severity or co-occurrence. Record what the material shows, \
including what clears a hypothesis; a finding without evidence is an opinion.

Scales:
- verdict: {verdicts}. A verdict alone is enough; the policy assumes its magnitude.
- weight: {_scale(Weight)}; state it only when justified.
- confidence: {_scale(Confidence)}.
- tactic: {tactics}.
- occurred_at: ISO 8601 UTC, e.g. `2026-08-07T10:00:00Z`.
"""


__all__ = ["build_agent_guide"]
