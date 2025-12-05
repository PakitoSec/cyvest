// AUTO-GENERATED FROM cyvest.schema.json — DO NOT EDIT

/**
 * Security level classification from NONE (lowest) to MALICIOUS (highest).
 */
export type Level =
  | "NONE"
  | "TRUSTED"
  | "INFO"
  | "SAFE"
  | "NOTABLE"
  | "SUSPICIOUS"
  | "MALICIOUS";
/**
 * Direction of a relationship between observables.
 */
export type RelationshipDirection = "outbound" | "inbound" | "bidirectional";
/**
 * Score computation policy: 'auto' calculates from level, 'manual' uses explicit score.
 */
export type ScorePolicy = "auto" | "manual";
/**
 * Score aggregation mode: 'max' takes highest score, 'sum' adds all scores.
 */
export type ScoreMode = "max" | "sum";

export interface CyvestInvestigation {
  score: number;
  level: Level;
  whitelisted: boolean;
  whitelists: Whitelist[];
  observables: {
    [k: string]: Observable;
  };
  checks: {
    [k: string]: Check[];
  };
  checks_by_level: {
    [k: string]: string[];
  };
  threat_intels: {
    [k: string]: ThreatIntel;
  };
  enrichments: {
    [k: string]: Enrichment;
  };
  containers: {
    [k: string]: Container;
  };
  stats: Statistics;
  stats_checks: StatsChecks;
  data_extraction: DataExtraction;
}
export interface Whitelist {
  identifier: string;
  name: string;
  justification?: string | null;
}
export interface Observable {
  key: string;
  /**
   * Observable type (e.g., ipv4-addr, url). Custom values are allowed.
   */
  type: string;
  value: string;
  internal: boolean;
  whitelisted: boolean;
  comment: string;
  extra: {
    [k: string]: unknown;
  } | null;
  score: number;
  level: Level;
  relationships: Relationship[];
  threat_intels: string[];
  generated_by_checks: string[];
}
export interface Relationship {
  target_key: string;
  /**
   * Relationship label; defaults to related-to.
   */
  relationship_type: string;
  direction: RelationshipDirection;
}
export interface Check {
  key: string;
  check_id: string;
  scope: string;
  description: string;
  comment: string;
  extra: {
    [k: string]: unknown;
  } | null;
  score: number;
  level: Level;
  score_policy: ScorePolicy;
  observables: string[];
}
export interface ThreatIntel {
  key: string;
  source: string;
  observable_key: string;
  comment: string;
  extra: {
    [k: string]: unknown;
  } | null;
  score: number;
  level: Level;
  taxonomies: {
    [k: string]: unknown;
  }[];
}
export interface Enrichment {
  key: string;
  name: string;
  data: {
    [k: string]: unknown;
  };
  context: string;
}
export interface Container {
  key: string;
  path: string;
  description: string;
  checks: string[];
  sub_containers: {
    [k: string]: Container;
  };
  aggregated_score: number;
  aggregated_level: Level;
}
export interface Statistics {
  total_observables: number;
  internal_observables: number;
  external_observables: number;
  whitelisted_observables: number;
  observables_by_type: {
    [k: string]: number;
  };
  observables_by_level: {
    [k: string]: number;
  };
  observables_by_type_and_level: {
    [k: string]: {
      [k: string]: number;
    };
  };
  total_checks: number;
  applied_checks: number;
  checks_by_scope: {
    [k: string]: number;
  };
  checks_by_level: {
    [k: string]: number;
  };
  total_threat_intel: number;
  threat_intel_by_source: {
    [k: string]: number;
  };
  threat_intel_by_level: {
    [k: string]: number;
  };
  total_containers: number;
}
export interface StatsChecks {
  checks: number;
  applied: number;
}
export interface DataExtraction {
  /**
   * Root observable type used during data extraction.
   */
  root_type: string | null;
  score_mode: ScoreMode;
}
