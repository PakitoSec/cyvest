"""
Enumerations for Cyvest v7.

Merges the former ``model_enums``, ``levels`` and ``ScoreMode`` modules into a single
dependency-free module, so every other layer can import it without cycles.

Design note: this module carries no scoring arithmetic. ``Verdict`` exposes an intrinsic
``polarity`` (a benign claim points down, a malicious one points up — every engine agrees),
but the mapping between score ranges and verdicts belongs to a specific engine and lives in
``cyvest.evaluation.projection``.

Every enum a human ever reads defines ``__str__``. A bare ``str, Enum`` is a trap: ``str()``
yields ``"ObservableType.DOMAIN"`` on every version, while an f-string yields ``"domain"`` on
3.10 but ``"ObservableType.DOMAIN"`` on 3.11+, because 3.11 changed ``Enum.__format__`` to defer
to ``__str__``. Rendering would then depend on the interpreter running it. Defining ``__str__``
pins the value on both, and spares every call site a defensive ``.value``.
"""

from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    """
    Direction of a judgment, and the displayed level — they are the same thing.

    v7 merges the former ``Level`` into ``Verdict``. The five values line up one-for-one with
    the score bands ``basic-v1`` inherits from v6 (``< 0``, ``= 0``, ``]0,3[``, ``[3,5[``,
    ``>= 5``), which makes a verdict/level divergence structurally impossible.

    Those bands are ``basic-v1``'s convention, **not** part of the enum's contract: a
    probabilistic engine maps its own posterior thresholds onto the same labels.

    Two v6 levels deliberately left this axis: ``NONE`` became :class:`Status` and ``TRUSTED``
    became a :class:`DecisionKind` (or plain ``SAFE`` when it was merely a negative score).
    """

    SAFE = "SAFE"
    INFO = "INFO"
    NOTABLE = "NOTABLE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"

    @property
    def polarity(self) -> int:
        """Direction the judgment pushes: ``-1`` exculpatory, ``0`` neutral, ``+1`` inculpatory."""
        if self is Verdict.SAFE:
            return -1
        if self is Verdict.INFO:
            return 0
        return 1

    def __str__(self) -> str:
        return self.value


class Confidence(float, Enum):
    """How sure the source is of its own claim."""

    LOW = 0.3
    MEDIUM = 0.65
    HIGH = 1.0


class Weight(float, Enum):
    """
    How grave the claim is, *if* it holds.

    The three values are the midpoints of ``basic-v1``'s score bands: ``1.5`` for ``]0,3[``,
    ``4.0`` for ``[3,5[``, and ``7.0`` for ``[5,∞[`` — the last band being open, its width is
    extrapolated from the previous one. ``SAFE`` reuses the ``NOTABLE`` magnitude; polarity
    carries the sign.

    Midpoints rather than thresholds: a scale aligned on ``3.0``/``5.0`` would put every ordinal
    exactly on a boundary, so any confidence below the maximum would drop the reported verdict by
    one notch.
    """

    LOW = 1.5
    MEDIUM = 4.0
    HIGH = 7.0


class Status(str, Enum):
    """
    Whether a finding takes part in the evaluation at all.

    Anything other than ``EVALUATED`` is excluded from the score *and* from aggregation
    denominators, while staying visible in the report.
    """

    NOT_APPLICABLE = "NOT_APPLICABLE"
    PENDING = "PENDING"
    EVALUATED = "EVALUATED"


class Effect(str, Enum):
    """
    How a finding enters the investigation total. :class:`Status` says *whether*, this says *how*.

    ``ADDITIVE`` is every finding v6 ever had: a term of the sum.

    ``FLOOR`` and ``CEILING`` are the two halves of a **conclusion** — typically an analysis that
    read the other findings. Neither is a term: a floor raises the total just enough to reach the
    verdict it asserts, a ceiling lowers it just enough. Both add nothing once the investigation
    is already there, so conclusions never compound and several analysers may conclude on the
    same case without inflating — or deflating — each other.

    A ceiling is what states a **declared benign context**: an awareness campaign, a sanctioned
    pentest window, an authorised scanner. Without it the model could force a case up but never
    down, and the only way to say "whatever the evidence, this is benign" would be to guess a
    large negative weight — the v6 mistake.

    The band a verdict maps to is ``basic-v1``'s convention, like every other number here — see
    :mod:`cyvest.evaluation.projection`.
    """

    ADDITIVE = "ADDITIVE"
    FLOOR = "FLOOR"
    CEILING = "CEILING"

    @property
    def concludes(self) -> bool:
        """Whether this effect bounds the total instead of adding a term to it."""
        return self is not Effect.ADDITIVE


class SourceClass(str, Enum):
    """Family a source belongs to, used by the policy to weigh its reliability."""

    VENDOR_FEED = "vendor_feed"
    SANDBOX = "sandbox"
    OSINT = "osint"
    INTERNAL_TOOL = "internal_tool"
    ORG_ANALYST = "org_analyst"
    ORG_POLICY = "org_policy"
    UNKNOWN = "unknown"


class DecisionKind(str, Enum):
    """
    A named override of the computation.

    Forcing a score has to be a declared act — never the side effect of an inflated weight.

    The kind states the **intent**; the mechanism follows from the family of the target, which
    the key already carries. An earlier design enumerated one value per ``(intent, family)``
    pair — ``ALLOWLISTED``/``BLOCKLISTED``/``CONFIRMED``/``DISMISSED`` — and then needed a
    validator to forbid the half of that product which made no sense. An enum requiring a
    validator to reject half its combinations encodes one axis too many: the family is the
    target's business, not the decision's.

    The domain vocabulary survives untouched on the façade (``allowlist``, ``blocklist``,
    ``confirm``, ``dismiss``), where it belongs.
    """

    UPHOLD = "UPHOLD"
    REFUTE = "REFUTE"
    VACATED = "VACATED"

    @property
    def bounds(self) -> bool:
        """
        Whether the kind constrains the result at all.

        ``VACATED`` is the identity: recorded, reported, and without effect. Withdrawing a
        judgment must be expressible without asserting the opposite one — which would be a lie —
        and an append-only model cannot express it by deletion.
        """
        return self is not DecisionKind.VACATED


class Scope(str, Enum):
    """
    How far a Finding→Observable link looks when evaluating its observable.

    Replaces v6's ``PropagationMode`` one-for-one. ``OWN_FRAGMENT`` resolves to *the fragment of
    the finding that carries the link*, so it denotes a different scope for each fragment — the
    report indexes observable results by the resolved scope, never by this label.
    """

    OWN_FRAGMENT = "OWN_FRAGMENT"
    ALL = "ALL"


class Aggregation(str, Enum):
    """How an observable combines the contributions of its children (ex-``ScoreMode``)."""

    MAX = "max"
    SUM = "sum"


class Salience(str, Enum):
    """How much a timeline entry deserves attention. Derived from the report, never stored."""

    BACKGROUND = "background"
    NOTABLE = "notable"
    KEY = "key"

    @property
    def rank(self) -> int:
        return _SALIENCE_ORDER[self.value]


_SALIENCE_ORDER = {"background": 0, "notable": 1, "key": 2}


class RelationKind(str, Enum):
    """
    The analyst pivot that produced the target from the source.

    Direction is implied: ``source_key`` is the parent, ``target_key`` the child. ``RELATED_TO``
    is symmetric and excluded from propagation, which makes v6's ``EXTRACTION`` +
    ``BIDIRECTIONAL`` combination inexpressible.
    """

    EXTRACTION = "extraction"
    PIVOT = "pivot"
    RELATED_TO = "related-to"

    @property
    def propagates(self) -> bool:
        return self is not RelationKind.RELATED_TO


class ObservableType(str, Enum):
    """Cyber observable types."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    FILE = "file"
    ARTIFACT = "artifact"
    HOST = "host"
    PROCESS = "process"
    USER = "user"
    COMMAND_LINE = "command_line"
    CLOUD_RESOURCE = "cloud_resource"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def normalize_root_type(cls, root_type: ObservableType | str | None) -> ObservableType:
        if root_type is None:
            return cls.FILE
        if isinstance(root_type, cls):
            normalized = root_type
        elif isinstance(root_type, str):
            try:
                normalized = cls(root_type.lower())
            except ValueError as exc:
                raise ValueError("root_type must be ObservableType.FILE or ObservableType.ARTIFACT") from exc
        else:
            raise TypeError("root_type must be ObservableType.FILE or ObservableType.ARTIFACT")

        if normalized not in (cls.FILE, cls.ARTIFACT):
            raise ValueError("root_type must be ObservableType.FILE or ObservableType.ARTIFACT")
        return normalized


class ObservableSubtype(str, Enum):
    """Built-in observable representations."""

    USER_EMAIL = "email"
    USER_SID = "sid"
    USER_UPN = "upn"
    USER_OKTA_ID = "okta_id"
    USER_USERNAME = "username"
    USER_UID = "uid"
    HOST_HOSTNAME = "hostname"
    HOST_FQDN = "fqdn"
    HOST_NETBIOS = "netbios"
    HOST_DEVICE_ID = "device_id"
    PROCESS_PID = "pid"
    PROCESS_GUID = "process_guid"
    FILE_PATH = "path"
    CLOUD_AWS_ARN = "aws_arn"
    CLOUD_AZURE_RESOURCE_ID = "azure_resource_id"
    CLOUD_GCP_RESOURCE_NAME = "gcp_resource_name"

    def __str__(self) -> str:
        return self.value


__all__ = [
    "Aggregation",
    "Confidence",
    "DecisionKind",
    "Effect",
    "ObservableSubtype",
    "ObservableType",
    "RelationKind",
    "Salience",
    "Scope",
    "SourceClass",
    "Status",
    "Verdict",
    "Weight",
]
