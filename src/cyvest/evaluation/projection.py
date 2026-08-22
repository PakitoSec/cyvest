"""
Score → verdict, and back.

:func:`verdict_from_score` *is* v6's ``get_level_from_score``. Because ``Verdict`` absorbed
``Level``, a divergence between the two is structurally impossible — there is nothing left to
keep in sync. :func:`score_floor_for` inverts it, for conclusions that must reach a stated
verdict rather than assert a magnitude.

The bands below are ``basic-v1``'s convention, not a rule of the report contract: a probabilistic
engine maps its own posterior thresholds onto the same five labels.
"""

from __future__ import annotations

from cyvest.enums import Verdict

SUSPICIOUS_THRESHOLD = 3.0
MALICIOUS_THRESHOLD = 5.0


def verdict_from_score(score: float) -> Verdict:
    """Map a magnitude onto the five verdict bands, exactly as v6 mapped it onto levels."""
    if score < 0.0:
        return Verdict.SAFE
    if score == 0.0:
        return Verdict.INFO
    if score < SUSPICIOUS_THRESHOLD:
        return Verdict.NOTABLE
    if score < MALICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS


def score_floor_for(verdict: Verdict, *, epsilon: float) -> float | None:
    """
    Smallest score that reads as ``verdict`` — the inverse of :func:`verdict_from_score`.

    ``None`` for ``SAFE`` and ``INFO``: their bands lie at or below zero, so no score *raises* a
    total into them. ``NOTABLE`` has no closed lower bound (``]0, 3[``), hence ``epsilon``.
    """
    if verdict is Verdict.NOTABLE:
        return epsilon
    if verdict is Verdict.SUSPICIOUS:
        return SUSPICIOUS_THRESHOLD
    if verdict is Verdict.MALICIOUS:
        return MALICIOUS_THRESHOLD
    return None


__all__ = ["MALICIOUS_THRESHOLD", "SUSPICIOUS_THRESHOLD", "score_floor_for", "verdict_from_score"]
