"""
LangChain integration: an investigation in the agent state, tools to read and write it, a
middleware that wires both and keeps the model informed.

Optional dependency: ``pip install 'cyvest[langchain]'``.
"""

from __future__ import annotations

try:
    import langchain.agents.middleware  # noqa: F401
    import langchain.tools  # noqa: F401
except ImportError as exc:  # pragma: no cover - depends on the optional extra
    raise ImportError(
        "cyvest's LangChain integration is optional; install it with `pip install 'cyvest[langchain]'`"
    ) from exc

from cyvest.autolink import AutoLink
from cyvest.integrations.langchain.middleware import CyvestMiddleware
from cyvest.integrations.langchain.prompts import CYVEST_TOOLS_PROMPT
from cyvest.integrations.langchain.state import (
    INVESTIGATION_KEY,
    CyvestDefaults,
    CyvestState,
    InvestigationSpec,
    investigation_from_state,
)
from cyvest.integrations.langchain.tools import build_cyvest_tools
from cyvest.io.serialization import merge_documents
from cyvest.operations import Operation, RecordBatch, aapply_operations, apply_operations
from cyvest.relations import RelationPlan, RelationProposal

__all__ = [
    "CYVEST_TOOLS_PROMPT",
    "INVESTIGATION_KEY",
    "AutoLink",
    "CyvestDefaults",
    "CyvestMiddleware",
    "CyvestState",
    "InvestigationSpec",
    "Operation",
    "RecordBatch",
    "RelationPlan",
    "RelationProposal",
    "aapply_operations",
    "apply_operations",
    "build_cyvest_tools",
    "investigation_from_state",
    "merge_documents",
]
