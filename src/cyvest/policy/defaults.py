"""The single policy set shipped in v7."""

from __future__ import annotations

from cyvest.policy.model import Policy

DEFAULT_POLICY = Policy()

__all__ = ["DEFAULT_POLICY", "Policy"]
