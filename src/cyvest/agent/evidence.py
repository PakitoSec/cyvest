"""Tool output as evidence: the material a claim cites, captured by the harness rather than retyped by a model."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from cyvest.cyvest import Cyvest
from cyvest.proxies import EvidenceProxy

#: Evidence type of a captured tool call.
TOOL_OUTPUT = "tool-output"


def _canonical(content: Any) -> str:
    if isinstance(content, str):
        return content
    return json.dumps(content, ensure_ascii=False, sort_keys=True, default=str)


def bounded_content(content: Any, max_chars: int) -> tuple[Any, bool, str]:
    """
    ``(content, truncated, sha256)``: the content itself when its canonical text fits, else that text cut.

    The hash is always of the full canonical text, so a truncated capture still identifies what was seen.
    """
    text = _canonical(content)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if len(text) <= max_chars:
        return content, False, digest
    return text[: max(0, max_chars - 1)] + "…", True, digest


def record_tool_output(
    cv: Cyvest,
    *,
    source: str,
    call_id: str,
    tool: str,
    title: str,
    output: Any,
    arguments: dict[str, Any] | None = None,
    uri: str | None = None,
    captured_at: datetime | None = None,
    max_chars: int = 8_000,
) -> EvidenceProxy:
    """
    Record one tool call as evidence keyed by ``source`` and ``call_id``: replaying the call is a no-op.

    ``output`` is bounded to ``max_chars``; pass ``uri`` when the full material is stored elsewhere.
    """
    data, truncated, digest = bounded_content(output, max_chars)
    content = {"tool": tool, "arguments": arguments or {}, "output": data, "truncated": truncated, "sha256": digest}
    return cv.evidence_create(
        TOOL_OUTPUT,
        title=title,
        content=content,
        uri=uri,
        source=source,
        captured_at=captured_at,
        external_id=call_id,
    )


__all__ = ["TOOL_OUTPUT", "bounded_content", "record_tool_output"]
