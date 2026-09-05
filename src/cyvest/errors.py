"""
Errors shared across modules.

Kept in one place so a check made at merge time and the same check made at comparison time raise
the same class — a caller handling ``EngineMismatchError`` should not care which path hit it.
"""

from __future__ import annotations


class EngineMismatchError(RuntimeError):
    """Raised when two investigations were scored by different engines."""


class PolicyMismatchError(RuntimeError):
    """Raised when two investigations were scored under different policies."""


class RootMismatchError(RuntimeError):
    """Raised when two investigations anchor on different roots — they are not one case."""


__all__ = ["EngineMismatchError", "PolicyMismatchError", "RootMismatchError"]
