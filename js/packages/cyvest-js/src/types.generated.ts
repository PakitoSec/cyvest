// AUTO-GENERATED FROM cyvest.schema.json — DO NOT EDIT

/**
 * Optional human-readable investigation name.
 */
export type InvestigationName = string | null;
/**
 * Security level classification for checks, observables, and threat intelligence.
 *
 * Levels are ordered from lowest (NONE) to highest (MALICIOUS) severity.
 */
export type Level = "NONE" | "TRUSTED" | "INFO" | "SAFE" | "NOTABLE" | "SUSPICIOUS" | "MALICIOUS";
export type Justification = string | null;
/**
 * List of whitelist entries applied to this investigation.
 */
export type Whitelists = InvestigationWhitelist[];
export type Actor = string | null;
export type Reason = string | null;
export type Tool = string | null;
export type ObjectType = string | null;
export type ObjectKey = string | null;
/**
 * Append-only investigation audit log.
 */
export type EventLog = AuditEvent[];
export type ThreatIntels = string[];
/**
 * Direction of a relationship between observables.
 */
export type RelationshipDirection = "outbound" | "inbound" | "bidirectional";
export type Relationships = Relationship[];
/**
 * Checks that currently link to this observable (navigation-only).
 */
export type CheckLinks = string[];
/**
 * Controls how a Check↔Observable link propagates across merged investigations.
 */
export type PropagationMode = "LOCAL_ONLY" | "GLOBAL";
export type ObservableLinks = ObservableLink[];
export type Taxonomies = {
  [k: string]: unknown;
}[];
export type Checks1 = string[];
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
  /**
   * Stable investigation identity (ULID).
   */
  investigation_id: string;
  investigation_name?: InvestigationName;
  /**
   * Investigation start time (UTC).
   */
  started_at: string;
  /**
   * Global investigation score.
   */
  score: number;
  level: Level;
  /**
   * Whether the investigation is whitelisted.
   */
  whitelisted: boolean;
  whitelists: Whitelists;
  event_log?: EventLog;
  observables: Observables;
  checks: Checks;
  checks_by_level: ChecksByLevel;
  threat_intels: ThreatIntels1;
  enrichments: Enrichments;
  containers: Containers;
  stats: StatisticsSchema;
  stats_checks: StatsChecksSchema;
  data_extraction: DataExtractionSchema;
  /**
   * Global investigation score formatted as fixed-point x.xx.
   */
  score_display: string;
}
/**
 * Represents a whitelist entry on an investigation.
 */
export interface InvestigationWhitelist {
  identifier: string;
  name: string;
  justification?: Justification;
  [k: string]: unknown;
}
/**
 * Centralized audit event for investigation-level changes.
 */
export interface AuditEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  actor?: Actor;
  reason?: Reason;
  tool?: Tool;
  object_type?: ObjectType;
  object_key?: ObjectKey;
  details?: Details;
  [k: string]: unknown;
}
export interface Details {
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
  type: string;
  value: string;
  internal: boolean;
  whitelisted: boolean;
  comment: string;
  extra: Extra;
  score: number;
  level: Level;
  threat_intels: ThreatIntels;
  relationships: Relationships;
  key: string;
  check_links: CheckLinks;
  score_display: string;
  [k: string]: unknown;
}
export interface Extra {
  [k: string]: unknown;
}
/**
 * Represents a relationship between observables.
 */
export interface Relationship {
  target_key: string;
  relationship_type: string;
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
  check_id: string;
  scope: string;
  description: string;
  comment: string;
  extra: Extra1;
  score: number;
  level: Level;
  origin_investigation_id: string;
  observable_links: ObservableLinks;
  key: string;
  score_display: string;
  [k: string]: unknown;
}
export interface Extra1 {
  [k: string]: unknown;
}
/**
 * Edge metadata for a Check↔Observable association.
 */
export interface ObservableLink {
  observable_key: string;
  propagation_mode?: PropagationMode;
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
  source: string;
  observable_key: string;
  comment: string;
  extra: Extra2;
  score: number;
  level: Level;
  taxonomies: Taxonomies;
  key: string;
  score_display: string;
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
  name: string;
  data: Data;
  context: string;
  key: string;
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
  path: string;
  description?: string;
  checks: Checks1;
  sub_containers: SubContainers;
  key: string;
  aggregated_score: number;
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
  total_observables: number;
  internal_observables: number;
  external_observables: number;
  whitelisted_observables: number;
  observables_by_type?: ObservablesByType;
  observables_by_level?: ObservablesByLevel;
  observables_by_type_and_level?: ObservablesByTypeAndLevel;
  total_checks: number;
  applied_checks: number;
  checks_by_scope?: ChecksByScope;
  checks_by_level?: ChecksByLevel1;
  total_threat_intel: number;
  threat_intel_by_source?: ThreatIntelBySource;
  threat_intel_by_level?: ThreatIntelByLevel;
  total_containers: number;
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
  checks: number;
  applied: number;
}
/**
 * Schema for data extraction metadata.
 */
export interface DataExtractionSchema {
  root_type?: RootType;
  score_mode: ScoreMode;
}
