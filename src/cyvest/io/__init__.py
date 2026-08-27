"""
Boundary layer: turning an investigation into bytes, and bytes back into an investigation.

The *shapes* crossing that boundary live in ``cyvest.schema``; this package only moves data.

Deliberately empty of re-exports. ``render`` pulls in ``rich``, and the facade imports
``serialization`` lazily so that saving a JSON file never pays for a terminal renderer — an
eager ``__init__`` would defeat that. Import the submodule you need.
"""

from __future__ import annotations
