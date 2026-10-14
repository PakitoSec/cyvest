"""
What an agent harness needs from cyvest, without depending on any agent framework.

The harness owns the tools, the prompts and when the model sees what; cyvest owns the facts and
how they are rendered. These helpers are the seam: record a tool's output as evidence, render the
facts a model may read, see what changed, and check that a claim cites material that exists.
"""

from __future__ import annotations

from cyvest.agent.evidence import bounded_content, record_tool_output
from cyvest.agent.guide import build_agent_guide
from cyvest.agent.status import FACT_FAMILIES, facts_status, ledger_delta, missing_references

__all__ = [
    "FACT_FAMILIES",
    "bounded_content",
    "build_agent_guide",
    "facts_status",
    "ledger_delta",
    "missing_references",
    "record_tool_output",
]
