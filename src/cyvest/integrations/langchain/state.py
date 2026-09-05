"""
The state channel an agent carries the investigation in, and how a tool gets a facade back.

The investigation travels as its serialized document. That is what a checkpointer can store, what
two parallel branches can be merged from, and what survives a process restart; a live ``Cyvest``
object is none of those. Tools and middleware rebuild a facade from the dict, act, and write the
dict back — the reducer on the channel folds concurrent writes with the same union law the store
uses everywhere else.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated, Any, Final

from langchain.agents.middleware import AgentState
from typing_extensions import NotRequired

from cyvest.cyvest import Cyvest, InvestigationSpec
from cyvest.io.serialization import merge_documents

#: Name of the state channel. Fixed rather than configurable: tools, middleware and the host
#: graph must all agree on it, and a constant is the cheapest way to make them.
INVESTIGATION_KEY: Final = "investigation"


class CyvestState(AgentState):
    """Adds the ``investigation`` channel to the agent state. Merged by union, never overwritten."""

    investigation: NotRequired[Annotated[dict[str, Any] | None, merge_documents]]


#: The spec an agent rebuilds its facade from. Same object as the core's; the alias keeps the
#: integration's vocabulary ("defaults") while there is one definition.
CyvestDefaults = InvestigationSpec


def investigation_from_state(state: Any, spec: InvestigationSpec | None = None) -> Cyvest | None:
    """The facade over the state's investigation, or ``None`` when the channel is empty."""
    if isinstance(state, Mapping):
        data = state.get(INVESTIGATION_KEY)
    else:
        data = getattr(state, INVESTIGATION_KEY, None)
    if not data:
        return None
    return (spec or InvestigationSpec()).load(data)


__all__ = ["INVESTIGATION_KEY", "CyvestDefaults", "CyvestState", "InvestigationSpec", "investigation_from_state"]
