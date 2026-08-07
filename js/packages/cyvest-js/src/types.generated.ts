// AUTO-GENERATED FROM cyvest.schema.json — DO NOT EDIT

/**
 * Optional human-readable investigation name.
 */
export type InvestigationName = string | null;
/**
 * Security level classification for findings, observables, and threat intelligence.
 *
 * Levels are ordered from lowest (NONE) to highest (MALICIOUS) severity.
 */
export type Level = "NONE" | "TRUSTED" | "INFO" | "SAFE" | "NOTABLE" | "SUSPICIOUS" | "MALICIOUS";
export type Justification = string | null;
/**
 * List of whitelist entries applied to this investigation.
 */
export type Whitelists = InvestigationWhitelist[];
export type Subtype = string | null;
export type Namespace = string | null;
export type Subtype1 = string | null;
export type Namespace1 = string | null;
export type Aliases = ObservableAlias[];
export type ThreatIntels = string[];
/**
 * Direction of a relationship between observables.
 */
export type RelationshipDirection = "outbound" | "inbound" | "bidirectional";
export type Relationships = Relationship[];
/**
 * Findings that currently link to this observable (navigation-only).
 */
export type FindingLinks = string[];
/**
 * Controls how a Finding↔Observable link propagates across merged investigations.
 */
export type PropagationMode = "LOCAL_ONLY" | "GLOBAL";
export type ObservableLinks = ObservableLink[];
export type EvidenceLinks = EvidenceLink[];
export type ExternalId = string | null;
export type Uri = string | null;
/**
 * Findings that currently link to this evidence (navigation-only).
 */
export type FindingLinks1 = string[];
export type Taxonomies = Taxonomy[];
export type Findings1 = string[];
/**
 * Root observable type used during data extraction.
 */
export type RootType = ("file" | "artifact") | null;
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
  schema_version?: "6.0.0";
  /**
   * Stable investigation identity (ULID).
   */
  investigation_id: string;
  investigation_name?: InvestigationName;
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
  observables: Observables;
  findings: Findings;
  evidences: Evidences;
  threat_intels: ThreatIntels1;
  enrichments: Enrichments;
  tags: Tags;
  stats: StatisticsSchema;
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
 * Observables keyed by their unique key.
 */
export interface Observables {
  [k: string]: Observable;
}
/**
 * Represents a cyber observable (IP, URL, domain, hash, etc.).
 *
 * Observables can be linked to threat intelligence, findings, and other observables
 * through relationships.
 */
export interface Observable {
  type: string;
  subtype?: Subtype;
  namespace?: Namespace;
  value: string;
  internal: boolean;
  whitelisted: boolean;
  comment: string;
  extra: Extra;
  score: number;
  level: Level;
  aliases?: Aliases;
  occurrence_count?: number;
  threat_intels: ThreatIntels;
  relationships: Relationships;
  key: string;
  finding_links: FindingLinks;
  score_display: string;
  [k: string]: unknown;
}
export interface Extra {
  [k: string]: unknown;
}
/**
 * Source observable identity attached to a canonical observable.
 */
export interface ObservableAlias {
  type: string;
  subtype?: Subtype1;
  namespace?: Namespace1;
  value: string;
  count?: number;
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
 * Findings keyed by their unique key.
 */
export interface Findings {
  [k: string]: Finding;
}
/**
 * Represents a verification step in the investigation.
 *
 * A finding validates a specific aspect of the data under investigation
 * and contributes to the overall investigation score.
 */
export interface Finding {
  finding_name: string;
  description: string;
  comment: string;
  extra: Extra1;
  score: number;
  level: Level;
  origin_investigation_id: string;
  observable_links: ObservableLinks;
  evidence_links: EvidenceLinks;
  key: string;
  score_display: string;
  [k: string]: unknown;
}
export interface Extra1 {
  [k: string]: unknown;
}
/**
 * Edge metadata for a Finding↔Observable association.
 */
export interface ObservableLink {
  observable_key: string;
  propagation_mode?: PropagationMode;
}
/**
 * Edge metadata for a Finding↔Evidence association.
 */
export interface EvidenceLink {
  evidence_key: string;
}
/**
 * Evidence objects keyed by their unique key.
 */
export interface Evidences {
  [k: string]: Evidence;
}
/**
 * Structured material supporting one or more findings.
 */
export interface Evidence {
  type: string;
  title: string;
  description: string;
  source: string;
  external_id: ExternalId;
  content: unknown;
  uri: Uri;
  captured_at: string;
  extra: Extra2;
  key: string;
  finding_links: FindingLinks1;
  [k: string]: unknown;
}
export interface Extra2 {
  [k: string]: unknown;
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
  extra: Extra3;
  score: number;
  level: Level;
  taxonomies: Taxonomies;
  key: string;
  score_display: string;
  [k: string]: unknown;
}
export interface Extra3 {
  [k: string]: unknown;
}
/**
 * Represents a structured taxonomy entry for threat intelligence.
 */
export interface Taxonomy {
  level: Level;
  name: string;
  value: string;
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
 * Tags keyed by their unique key.
 */
export interface Tags {
  [k: string]: Tag;
}
/**
 * Groups findings for categorical organization.
 *
 * Tags allow structuring the investigation into logical sections
 * with aggregated scores and levels. Hierarchy is automatic based on
 * the ":" delimiter in tag names (e.g., "header:auth:dkim").
 */
export interface Tag {
  name: string;
  description?: string;
  findings: Findings1;
  key: string;
  /**
   * Calculate the score from direct findings only (no hierarchy).
   *
   * For hierarchical aggregation (including descendant tags), use
   * Investigation.get_tag_aggregated_score() or TagProxy.get_aggregated_score().
   *
   * Returns:
   *     Total score from direct findings
   */
  direct_score: number;
  direct_level: Level;
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
  total_findings: number;
  applied_findings: number;
  findings_by_level?: FindingsByLevel;
  total_evidences: number;
  evidences_by_type?: EvidencesByType;
  evidences_by_source?: EvidencesBySource;
  total_threat_intel: number;
  threat_intel_by_source?: ThreatIntelBySource;
  threat_intel_by_level?: ThreatIntelByLevel;
  total_tags: number;
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
export interface FindingsByLevel {
  [k: string]: string[];
}
export interface EvidencesByType {
  [k: string]: number;
}
export interface EvidencesBySource {
  [k: string]: number;
}
export interface ThreatIntelBySource {
  [k: string]: number;
}
export interface ThreatIntelByLevel {
  [k: string]: number;
}
/**
 * Schema for data extraction metadata.
 */
export interface DataExtractionSchema {
  root_type?: RootType;
  score_mode_obs: ScoreMode;
}
