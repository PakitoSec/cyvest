// AUTO-GENERATED FROM cyvest.schema.json — DO NOT EDIT

/**
 * Investigation start time (UTC).
 */
export type StartedAt = string;
/**
 * Global investigation score.
 */
export type Score = number;
/**
 * Security level classification for checks, observables, and threat intelligence.
 *
 * Levels are ordered from lowest (NONE) to highest (MALICIOUS) severity.
 */
export type Level = "NONE" | "TRUSTED" | "INFO" | "SAFE" | "NOTABLE" | "SUSPICIOUS" | "MALICIOUS";
/**
 * Whether the investigation is whitelisted.
 */
export type Whitelisted = boolean;
export type Identifier = string;
export type Name = string;
export type Justification = string | null;
/**
 * List of whitelist entries applied to this investigation.
 */
export type Whitelists = InvestigationWhitelist[];
export type Type = string;
export type Value = string;
export type Internal = boolean;
export type Whitelisted1 = boolean;
export type Comment = string;
export type Score1 = number;
export type ThreatIntels = string[];
export type TargetKey = string;
export type RelationshipType = string;
/**
 * Direction of a relationship between observables.
 */
export type RelationshipDirection = "outbound" | "inbound" | "bidirectional";
export type Relationships = Relationship[];
export type Key = string;
/**
 * Checks that generated this observable.
 */
export type GeneratedByChecks = string[];
export type CheckId = string;
export type Scope = string;
export type Description = string;
export type Comment1 = string;
export type Score2 = number;
export type Observables1 = string[];
/**
 * Controls how a check reacts to linked observables.
 */
export type CheckScorePolicy = "auto" | "manual";
export type Key1 = string;
export type Source = string;
export type ObservableKey = string;
export type Comment2 = string;
export type Score3 = number;
export type Taxonomies = {
  [k: string]: unknown;
}[];
export type Key2 = string;
export type Name1 = string;
export type Context = string;
export type Key3 = string;
export type Path = string;
export type Description1 = string;
export type Checks1 = string[];
export type Key4 = string;
export type AggregatedScore = number;
export type TotalObservables = number;
export type InternalObservables = number;
export type ExternalObservables = number;
export type WhitelistedObservables = number;
export type TotalChecks = number;
export type AppliedChecks = number;
export type TotalThreatIntel = number;
export type TotalContainers = number;
export type Checks2 = number;
export type Applied = number;
/**
 * Root observable type used during data extraction.
 */
export type RootType = string | null;
/**
 * Score calculation mode for observables.
 */
export type ScoreMode = "max" | "sum";

/**
 * Schema for a complete serialized investigation.
 *
 * This model describes the output of `serialize_investigation()` from
 * `cyvest.io_serialization`. It is the top-level schema for exported investigations.
 *
 * Entity types reference the runtime models directly. When generating schemas with
 * `mode='serialization'`, Pydantic respects field_serializer decorators and produces
 * schemas matching the actual model_dump() output.
 */
export interface CyvestInvestigation {
  started_at: StartedAt;
  score: Score;
  level: Level;
  whitelisted: Whitelisted;
  whitelists: Whitelists;
  observables: Observables;
  checks: Checks;
  checks_by_level: ChecksByLevel;
  threat_intels: ThreatIntels1;
  enrichments: Enrichments;
  containers: Containers;
  stats: StatisticsSchema;
  stats_checks: StatsChecksSchema;
  data_extraction: DataExtractionSchema;
}
/**
 * Represents a whitelist entry on an investigation.
 */
export interface InvestigationWhitelist {
  identifier: Identifier;
  name: Name;
  justification?: Justification;
  [k: string]: unknown;
}
/**
 * Observables keyed by their unique key.
 */
export interface Observables {
  [k: string]: Observable;
}
/**
 * Represents a cyber observable (IP, URL, domain, hash, etc.).
 *
 * Observables can be linked to threat intelligence, checks, and other observables
 * through relationships.
 */
export interface Observable {
  type: Type;
  value: Value;
  internal: Internal;
  whitelisted: Whitelisted1;
  comment: Comment;
  extra: Extra;
  score: Score1;
  level: Level;
  threat_intels: ThreatIntels;
  relationships: Relationships;
  key: Key;
  generated_by_checks: GeneratedByChecks;
  [k: string]: unknown;
}
export interface Extra {
  [k: string]: unknown;
}
/**
 * Represents a relationship between observables.
 */
export interface Relationship {
  target_key: TargetKey;
  relationship_type: RelationshipType;
  direction: RelationshipDirection;
  [k: string]: unknown;
}
/**
 * Checks organized by scope.
 */
export interface Checks {
  [k: string]: Check[];
}
/**
 * Represents a verification step in the investigation.
 *
 * A check validates a specific aspect of the data under investigation
 * and contributes to the overall investigation score.
 */
export interface Check {
  check_id: CheckId;
  scope: Scope;
  description: Description;
  comment: Comment1;
  extra: Extra1;
  score: Score2;
  level: Level;
  observables: Observables1;
  score_policy?: CheckScorePolicy;
  key: Key1;
  [k: string]: unknown;
}
export interface Extra1 {
  [k: string]: unknown;
}
/**
 * Check keys organized by level name.
 */
export interface ChecksByLevel {
  [k: string]: string[];
}
/**
 * Threat intelligence entries keyed by their unique key.
 */
export interface ThreatIntels1 {
  [k: string]: ThreatIntel;
}
/**
 * Represents threat intelligence from an external source.
 *
 * Threat intelligence provides verdicts about observables from sources
 * like VirusTotal, URLScan.io, etc.
 */
export interface ThreatIntel {
  source: Source;
  observable_key: ObservableKey;
  comment: Comment2;
  extra: Extra2;
  score: Score3;
  level: Level;
  taxonomies: Taxonomies;
  key: Key2;
  [k: string]: unknown;
}
export interface Extra2 {
  [k: string]: unknown;
}
/**
 * Enrichment entries keyed by their unique key.
 */
export interface Enrichments {
  [k: string]: Enrichment;
}
/**
 * Represents structured data enrichment for the investigation.
 *
 * Enrichments store arbitrary structured data that provides additional
 * context but doesn't directly contribute to scoring.
 */
export interface Enrichment {
  name: Name1;
  data: Data;
  context: Context;
  key: Key3;
  [k: string]: unknown;
}
export interface Data {
  [k: string]: unknown;
}
/**
 * Containers keyed by their unique key.
 */
export interface Containers {
  [k: string]: Container;
}
/**
 * Groups checks and sub-containers for hierarchical organization.
 *
 * Containers allow structuring the investigation into logical sections
 * with aggregated scores and levels.
 */
export interface Container {
  path: Path;
  description?: Description1;
  checks: Checks1;
  sub_containers: SubContainers;
  key: Key4;
  aggregated_score: AggregatedScore;
  aggregated_level: Level;
}
export interface SubContainers {
  [k: string]: Container;
}
/**
 * Schema for investigation statistics.
 *
 * Mirrors the output of `InvestigationStats.get_summary()`.
 */
export interface StatisticsSchema {
  total_observables: TotalObservables;
  internal_observables: InternalObservables;
  external_observables: ExternalObservables;
  whitelisted_observables: WhitelistedObservables;
  observables_by_type?: ObservablesByType;
  observables_by_level?: ObservablesByLevel;
  observables_by_type_and_level?: ObservablesByTypeAndLevel;
  total_checks: TotalChecks;
  applied_checks: AppliedChecks;
  checks_by_scope?: ChecksByScope;
  checks_by_level?: ChecksByLevel1;
  total_threat_intel: TotalThreatIntel;
  threat_intel_by_source?: ThreatIntelBySource;
  threat_intel_by_level?: ThreatIntelByLevel;
  total_containers: TotalContainers;
}
export interface ObservablesByType {
  [k: string]: number;
}
export interface ObservablesByLevel {
  [k: string]: number;
}
export interface ObservablesByTypeAndLevel {
  [k: string]: {
    [k: string]: number;
  };
}
export interface ChecksByScope {
  [k: string]: number;
}
export interface ChecksByLevel1 {
  [k: string]: number;
}
export interface ThreatIntelBySource {
  [k: string]: number;
}
export interface ThreatIntelByLevel {
  [k: string]: number;
}
/**
 * Schema for check statistics summary.
 */
export interface StatsChecksSchema {
  checks: Checks2;
  applied: Applied;
}
/**
 * Schema for data extraction metadata.
 */
export interface DataExtractionSchema {
  root_type?: RootType;
  score_mode: ScoreMode;
}
