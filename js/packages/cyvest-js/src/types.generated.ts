// AUTO-GENERATED FROM cyvest.schema.json — DO NOT EDIT

export type RootKey = string | null;
export type FragmentIds = string[];
export type OccurredAt = string | null;
/**
 * Family a source belongs to, used by the policy to weigh its reliability.
 */
export type SourceClass =
  "vendor_feed" | "sandbox" | "osint" | "internal_tool" | "org_analyst" | "org_policy" | "unknown";
export type ExternalId = string | null;
export type EvidenceKeys = string[];
export type Subtype = string | null;
export type Namespace = string | null;
export type Subtype1 = string | null;
export type Namespace1 = string | null;
export type Aliases = ObservableAlias[];
export type OccurredAt1 = string | null;
export type ExternalId1 = string | null;
export type EvidenceKeys1 = string[];
/**
 * The analyst pivot that produced the target from the source.
 *
 * Direction is implied: ``source_key`` is the parent, ``target_key`` the child. ``RELATED_TO``
 * is symmetric and excluded from propagation, which makes v6's ``EXTRACTION`` +
 * ``BIDIRECTIONAL`` combination inexpressible.
 */
export type RelationKind = "extraction" | "pivot" | "related-to";
export type ObservedAt = string | null;
/**
 * Direction of a judgment, and the displayed level — they are the same thing.
 *
 * v7 merges the former ``Level`` into ``Verdict``. The five values line up one-for-one with
 * the score bands ``basic-v1`` inherits from v6 (``< 0``, ``= 0``, ``]0,3[``, ``[3,5[``,
 * ``>= 5``), which makes a verdict/level divergence structurally impossible.
 *
 * Those bands are ``basic-v1``'s convention, **not** part of the enum's contract: a
 * probabilistic engine maps its own posterior thresholds onto the same labels.
 *
 * Two v6 levels deliberately left this axis: ``NONE`` became :class:`Status` and ``TRUSTED``
 * became a :class:`DecisionKind` (or plain ``SAFE`` when it was merely a negative score).
 */
export type Verdict = "SAFE" | "INFO" | "NOTABLE" | "SUSPICIOUS" | "MALICIOUS";
export type Weight = number | null;
export type OccurredAt2 = string | null;
export type ExternalId2 = string | null;
export type EvidenceKeys2 = string[];
export type ObservedAt1 = string | null;
export type Labels = Label[];
export type Taxonomies = string[];
export type OccurredAt3 = string | null;
export type ExternalId3 = string | null;
export type EvidenceKeys3 = string[];
export type Uri = string | null;
export type CapturedAt = string | null;
export type Weight1 = number | null;
export type OccurredAt4 = string | null;
export type ExternalId4 = string | null;
export type EvidenceKeys4 = string[];
/**
 * Whether a finding takes part in the evaluation at all.
 *
 * Anything other than ``EVALUATED`` is excluded from the score *and* from aggregation
 * denominators, while staying visible in the report.
 */
export type Status = "NOT_APPLICABLE" | "PENDING" | "EVALUATED";
/**
 * How a finding enters the investigation total. :class:`Status` says *whether*, this says *how*.
 *
 * ``ADDITIVE`` is every finding v6 ever had: a term of the sum.
 *
 * ``FLOOR`` and ``CEILING`` are the two halves of a **conclusion** — typically an analysis that
 * read the other findings. Neither is a term: a floor raises the total just enough to reach the
 * verdict it asserts, a ceiling lowers it just enough. Both add nothing once the investigation
 * is already there, so conclusions never compound and several analysers may conclude on the
 * same case without inflating — or deflating — each other.
 *
 * A ceiling is what states a **declared benign context**: an awareness campaign, a sanctioned
 * pentest window, an authorised scanner. Without it the model could force a case up but never
 * down, and the only way to say "whatever the evidence, this is benign" would be to guess a
 * large negative weight — the v6 mistake.
 *
 * The band a verdict maps to is ``basic-v1``'s convention, like every other number here — see
 * :mod:`cyvest.evaluation.projection`.
 */
export type Effect = "ADDITIVE" | "FLOOR" | "CEILING";
/**
 * What a Finding→Observable link scores on.
 *
 * One question, three answers, none of which depends on how the run was threaded:
 *
 * - ``OBSERVABLE`` — the observable as it stands, whoever contributed to it;
 * - ``SIGNALS`` — the signals the link names, and nothing else, which is how a finding that
 *   fetched its own threat intel holds that value while the observable keeps accumulating;
 * - ``NONE`` — nothing: the edge is kept for the graph and the narrative, but it is inert.
 *
 * v7.0 briefly carried a fourth, ``FRAGMENT``, gating the observable on the fragment that wrote
 * each fact. It was dropped before release: it damped a merged total but never a local one, so
 * the same rules scored differently depending on whether enrichment ran in its own worker.
 * ``SIGNALS`` states that intent directly, and ``NONE`` covers the inert link it was standing in
 * for when migrating v6 documents.
 */
export type LinkBasis = "OBSERVABLE" | "SIGNALS" | "NONE";
export type SignalKeys = string[];
export type ObservableLinks = ObservableLink[];
export type Labels1 = Label[];
/**
 * A MITRE ATT&CK Enterprise tactic — the phase of the kill chain a finding demonstrates.
 *
 * Kebab-case values, in kill-chain order. A tactic is a classification the timeline displays,
 * never a term the engine scores: whether the activity is malicious is the verdict's job.
 */
export type Tactic =
  | "reconnaissance"
  | "resource-development"
  | "initial-access"
  | "execution"
  | "persistence"
  | "privilege-escalation"
  | "defense-evasion"
  | "credential-access"
  | "discovery"
  | "lateral-movement"
  | "collection"
  | "command-and-control"
  | "exfiltration"
  | "impact";
export type OccurredAt5 = string | null;
export type ExternalId5 = string | null;
export type EvidenceKeys5 = string[];
/**
 * A named override of the computation.
 *
 * Forcing a score has to be a declared act — never the side effect of an inflated weight.
 *
 * The kind states the **intent**; the mechanism follows from the family of the target, which
 * the key already carries. An earlier design enumerated one value per ``(intent, family)``
 * pair — ``ALLOWLISTED``/``BLOCKLISTED``/``CONFIRMED``/``DISMISSED`` — and then needed a
 * validator to forbid the half of that product which made no sense. An enum requiring a
 * validator to reject half its combinations encodes one axis too many: the family is the
 * target's business, not the decision's.
 *
 * The domain vocabulary survives untouched on the façade (``allowlist``, ``blocklist``,
 * ``confirm``, ``dismiss``), where it belongs.
 */
export type DecisionKind = "UPHOLD" | "REFUTE" | "VACATED";
export type OccurredAt6 = string | null;
export type ExternalId6 = string | null;
export type EvidenceKeys6 = string[];
export type FindingKeys = string[];
export type Score = number | null;
export type Contributions = Contribution[];
export type Score1 = number | null;
export type Contributions1 = Contribution[];
export type Score2 = number | null;
export type Contributions2 = Contribution[];

/**
 * A complete serialized investigation.
 */
export interface InvestigationSchema {
  schema_version?: string;
  header: InvestigationHeader;
  policy_version?: string;
  engine_id?: string;
  facts?: FactsSchema;
  decisions?: Decisions;
  tags?: Tags;
  report: Report;
}
/**
 * What used to be a ``Case`` fact: metadata about the store rather than a fact inside it.
 *
 * ``engine_id`` is denormalized here so an investigation stays replayable identically years
 * later, even after a newer stable engine ships.
 */
export interface InvestigationHeader {
  investigation_id: string;
  name?: string;
  root_key?: RootKey;
  opened_at?: string;
  policy_version?: string;
  engine_id?: string;
  fragment_ids?: FragmentIds;
  [k: string]: unknown;
}
/**
 * The fact collections, each keyed by its semantic key.
 */
export interface FactsSchema {
  observables?: Observables;
  relations?: Relations;
  signals?: Signals;
  evidences?: Evidences;
  findings?: Findings;
}
export interface Observables {
  [k: string]: Observable;
}
/**
 * A cyber observable. Identity is ``(type, subtype, namespace, value)``, nothing else.
 */
export interface Observable {
  key: string;
  seq: string;
  asserted_at: string;
  occurred_at?: OccurredAt;
  source: SourceRef;
  fragment_id: string;
  external_id?: ExternalId;
  evidence_keys?: EvidenceKeys;
  type: string;
  subtype?: Subtype;
  namespace?: Namespace;
  value: string;
  internal?: boolean;
  comment?: string;
  extra?: Extra;
  aliases?: Aliases;
  occurrences?: Occurrences;
}
/**
 * Who or what asserted a fact.
 */
export interface SourceRef {
  name: string;
  source_class?: SourceClass;
  [k: string]: unknown;
}
export interface Extra {
  [k: string]: unknown;
}
/**
 * A source identity that resolved to a canonical observable.
 */
export interface ObservableAlias {
  type: string;
  subtype?: Subtype1;
  namespace?: Namespace1;
  value: string;
  counts?: Counts;
  [k: string]: unknown;
}
export interface Counts {
  [k: string]: number;
}
export interface Occurrences {
  [k: string]: number;
}
export interface Relations {
  [k: string]: Relation;
}
/**
 * A directed edge between two observables, labelled by the analyst pivot that produced it.
 */
export interface Relation {
  key: string;
  seq: string;
  asserted_at: string;
  occurred_at?: OccurredAt1;
  source: SourceRef;
  fragment_id: string;
  external_id?: ExternalId1;
  evidence_keys?: EvidenceKeys1;
  source_key: string;
  target_key: string;
  kind?: RelationKind;
  observed_at?: ObservedAt;
  confidence?: number;
  comment?: string;
}
export interface Signals {
  [k: string]: ThreatIntel;
}
/**
 * A verdict from a threat-intelligence source.
 *
 * Identity is ``(source, subject_key)``, so a source re-asserting the same observable updates
 * in place instead of piling up duplicates. Pass ``external_id`` to keep history on purpose.
 */
export interface ThreatIntel {
  verdict?: Verdict;
  confidence?: number;
  weight?: Weight;
  key: string;
  seq: string;
  asserted_at: string;
  occurred_at?: OccurredAt2;
  source: SourceRef;
  fragment_id: string;
  external_id?: ExternalId2;
  evidence_keys?: EvidenceKeys2;
  subject_key: string;
  kind?: "threat_intel";
  observed_at?: ObservedAt1;
  labels?: Labels;
  payload?: Payload;
  source_class?: SourceClass;
  taxonomies?: Taxonomies;
  comment?: string;
}
/**
 * A typed tag on a fact: ``axis`` says what kind of statement ``value`` makes.
 */
export interface Label {
  axis: string;
  value: string;
  [k: string]: unknown;
}
export interface Payload {
  [k: string]: unknown;
}
export interface Evidences {
  [k: string]: Evidence;
}
/**
 * A captured artefact: an API response, a header dump, an enrichment payload.
 */
export interface Evidence {
  key: string;
  seq: string;
  asserted_at: string;
  occurred_at?: OccurredAt3;
  source: SourceRef;
  fragment_id: string;
  external_id?: ExternalId3;
  evidence_keys?: EvidenceKeys3;
  evidence_type: string;
  title?: string;
  content?: Content;
  uri?: Uri;
  captured_at?: CapturedAt;
}
export interface Content {
  [k: string]: unknown;
}
export interface Findings {
  [k: string]: Finding;
}
/**
 * A rule outcome. Identity is ``rule_id`` alone, plus ``external_id`` when one is given.
 *
 * A finding names no subject: what it is about is its ``observable_links``, which are also what
 * it scores on. Use ``external_id`` when the same rule must yield several findings — typically
 * once per observable, ``external_id=url.key``.
 *
 * A finding that describes an activity is **dated** through the envelope's ``occurred_at`` —
 * when the activity happened, as opposed to when the rule fired — and may name the ATT&CK
 * ``tactic`` it demonstrates. Both are what the timeline reads; neither enters the score.
 */
export interface Finding {
  verdict?: Verdict;
  confidence?: number;
  weight?: Weight1;
  key: string;
  seq: string;
  asserted_at: string;
  occurred_at?: OccurredAt4;
  source: SourceRef;
  fragment_id: string;
  external_id?: ExternalId4;
  evidence_keys?: EvidenceKeys4;
  rule_id: string;
  rule_version?: string;
  name?: string;
  comment?: string;
  status?: Status;
  effect?: Effect;
  observable_links?: ObservableLinks;
  labels?: Labels1;
  tactic?: Tactic | null;
  extra?: Extra1;
}
/**
 * A link from a finding to one of its observables, with the basis it is evaluated on.
 *
 * Basis is **per link**, exactly like v6's ``propagation_mode``: a finding may mix bases, and
 * may even link the same observable twice under two of them. Deduplication is on the triple
 * ``(observable_key, basis, signal_keys)``.
 *
 * ``signal_keys`` is sorted and deduplicated so that two links naming the same signals in a
 * different order are the same link, and merging stays idempotent.
 */
export interface ObservableLink {
  observable_key: string;
  basis?: LinkBasis;
  signal_keys?: SignalKeys;
  [k: string]: unknown;
}
export interface Extra1 {
  [k: string]: unknown;
}
export interface Decisions {
  [k: string]: Decision;
}
/**
 * A human (or automated) call that overrides the computed result for one target.
 *
 * ``UPHOLD`` forces the target to the policy floor, ``REFUTE`` neutralises it, ``VACATED``
 * withdraws a previous stance and restores the computed value. How each is applied depends on
 * the family of the target — an observable is bounded, a claim is taken out of the count — but
 * that is the engine's dispatch, not a second axis of this model.
 *
 * ``justification`` is required: an override whose reason is optional is an override that
 * cannot be audited, which defeats the point of recording it as a fact at all.
 */
export interface Decision {
  key: string;
  seq: string;
  asserted_at: string;
  occurred_at?: OccurredAt5;
  source: SourceRef;
  fragment_id: string;
  external_id?: ExternalId5;
  evidence_keys?: EvidenceKeys5;
  target_key: string;
  kind: DecisionKind;
  justification: string;
}
export interface Tags {
  [k: string]: Tag;
}
/**
 * A label grouping findings. Merging two tags unions their finding keys.
 */
export interface Tag {
  key: string;
  seq: string;
  asserted_at: string;
  occurred_at?: OccurredAt6;
  source: SourceRef;
  fragment_id: string;
  external_id?: ExternalId6;
  evidence_keys?: EvidenceKeys6;
  name: string;
  description?: string;
  finding_keys?: FindingKeys;
}
/**
 * A full evaluation. Derived, never stored on the facts, recomputed from them.
 */
export interface Report {
  engine_id: string;
  policy_version: string;
  investigation: InvestigationResult;
  findings?: Findings1;
  observables?: Observables1;
  [k: string]: unknown;
}
/**
 * The investigation-level verdict.
 */
export interface InvestigationResult {
  key: string;
  verdict?: Verdict;
  confidence?: number;
  score?: Score;
  contributions?: Contributions;
  suppressed_by_decision?: boolean;
  raw?: Raw;
  [k: string]: unknown;
}
/**
 * One named term that fed a result, kept so the report can explain itself.
 */
export interface Contribution {
  source_key: string;
  label: string;
  value: number;
  retained?: boolean;
  detail?: string;
  [k: string]: unknown;
}
export interface Raw {
  [k: string]: unknown;
}
export interface Findings1 {
  [k: string]: FindingResult;
}
/**
 * A finding's verdict.
 *
 * ``own_term_suppressed`` flags that the rule's own claim was overridden by a stronger link —
 * a contradiction worth surfacing rather than silently dropping.
 *
 * Three combinations of ``(counted, score)`` are meaningful, and a consumer must not conflate
 * the last two:
 *
 * - ``(True, float)`` — an additive finding, a term of the total;
 * - ``(False, None)`` — dismissed or not evaluated: visible, but out of the evaluation;
 * - ``(True, None)`` — a conclusion (``effect`` is ``FLOOR`` or ``CEILING``): it takes part, but
 *   it has no magnitude of its own. Its effect is a bound on the investigation total, reported
 *   as a contribution of :class:`InvestigationResult`.
 */
export interface FindingResult {
  key: string;
  verdict?: Verdict;
  confidence?: number;
  score?: Score1;
  contributions?: Contributions1;
  suppressed_by_decision?: boolean;
  raw?: Raw1;
  status?: Status;
  effect?: Effect;
  own_term_suppressed?: boolean;
  counted?: boolean;
  [k: string]: unknown;
}
export interface Raw1 {
  [k: string]: unknown;
}
export interface Observables1 {
  [k: string]: ObservableResult;
}
/**
 * An observable's verdict. One per observable: the graph holds every fact anyone contributed.
 */
export interface ObservableResult {
  key: string;
  verdict?: Verdict;
  confidence?: number;
  score?: Score2;
  contributions?: Contributions2;
  suppressed_by_decision?: boolean;
  raw?: Raw2;
  [k: string]: unknown;
}
export interface Raw2 {
  [k: string]: unknown;
}
