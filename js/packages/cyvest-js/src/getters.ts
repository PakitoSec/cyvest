/**
 * Getter utilities for retrieving entities from a Cyvest Investigation.
 *
 * These functions provide type-safe access to observables, checks, threat intel,
 * enrichments, and tags by their keys.
 */

import type {
  CyvestInvestigation,
  Observable,
  Check,
  ThreatIntel,
  Enrichment,
  Tag,
  Level,
} from "./types.generated";
import { generateObservableKey, generateCheckKey, generateTagKey, isTagChildOf } from "./keys";
import { getLevelFromScore } from "./levels";

/**
 * Get an observable by its key.
 *
 * @param inv - The investigation to search
 * @param key - Observable key (e.g., "obs:ipv4:192.168.1.1")
 * @returns The observable or undefined if not found
 *
 * @example
 * ```ts
 * const obs = getObservable(investigation, "obs:ipv4:192.168.1.1");
 * if (obs) {
 *   console.log(obs.value, obs.level);
 * }
 * ```
 */
export function getObservable(
  inv: CyvestInvestigation,
  key: string
): Observable | undefined {
  return inv.observables[key];
}

/**
 * Get an observable by type and value.
 *
 * @param inv - The investigation to search
 * @param type - Observable type (e.g., "ipv4", "url")
 * @param value - Observable value
 * @returns The observable or undefined if not found
 *
 * @example
 * ```ts
 * const obs = getObservableByTypeValue(investigation, "ipv4", "192.168.1.1");
 * ```
 */
export function getObservableByTypeValue(
  inv: CyvestInvestigation,
  type: string,
  value: string
): Observable | undefined {
  const normalizedType = type.trim().toLowerCase();
  const normalizedValue = value.trim().toLowerCase();

  for (const obs of Object.values(inv.observables)) {
    if (
      obs.type.toLowerCase() === normalizedType &&
      obs.value.toLowerCase() === normalizedValue
    ) {
      return obs;
    }
  }
  return undefined;
}

/**
 * Get the root observable of the investigation.
 *
 * The root observable is identified using the `root_type` from data extraction
 * metadata combined with value="root".
 *
 * @param inv - The investigation
 * @returns The root observable, or undefined if not found
 *
 * @example
 * ```ts
 * const root = getRootObservable(investigation);
 * if (root) {
 *   console.log(`Root: ${root.type} = ${root.value}`);
 * }
 * ```
 */
export function getRootObservable(inv: CyvestInvestigation): Observable | undefined {
  const rootType = inv.data_extraction.root_type;
  if (!rootType) {
    return undefined;
  }
  const rootKey = generateObservableKey(rootType, "root");
  return inv.observables[rootKey];
}

/**
 * Get a check by its key.
 *
 * @param inv - The investigation to search
 * @param key - Check key (e.g., "chk:sender_verification:email_headers")
 * @returns The check or undefined if not found
 *
 * @example
 * ```ts
 * const check = getCheck(investigation, "chk:sender_verification:email_headers");
 * ```
 */
export function getCheck(
  inv: CyvestInvestigation,
  key: string
): Check | undefined {
  return inv.checks[key];
}

/**
 * Get a check by its name.
 *
 * @param inv - The investigation to search
 * @param checkName - Check name
 * @returns The check or undefined if not found
 *
 * @example
 * ```ts
 * const check = getCheckByName(investigation, "sender_verification");
 * ```
 */
export function getCheckByName(
  inv: CyvestInvestigation,
  checkName: string
): Check | undefined {
  const key = generateCheckKey(checkName);
  return inv.checks[key];
}

/**
 * Get all checks as an array.
 *
 * @param inv - The investigation
 * @returns Array of all checks
 *
 * @example
 * ```ts
 * const allChecks = getAllChecks(investigation);
 * console.log(`Total checks: ${allChecks.length}`);
 * ```
 */
export function getAllChecks(inv: CyvestInvestigation): Check[] {
  return Object.values(inv.checks);
}

/**
 * Get a threat intel entry by its key.
 *
 * @param inv - The investigation to search
 * @param key - Threat intel key (e.g., "ti:virustotal:obs:ipv4:192.168.1.1")
 * @returns The threat intel or undefined if not found
 */
export function getThreatIntel(
  inv: CyvestInvestigation,
  key: string
): ThreatIntel | undefined {
  return inv.threat_intels[key];
}

/**
 * Get a threat intel entry by source and observable key.
 *
 * @param inv - The investigation to search
 * @param source - Threat intel source name
 * @param observableKey - Key of the related observable
 * @returns The threat intel or undefined if not found
 */
export function getThreatIntelBySourceObservable(
  inv: CyvestInvestigation,
  source: string,
  observableKey: string
): ThreatIntel | undefined {
  const normalizedSource = source.trim().toLowerCase();

  for (const ti of Object.values(inv.threat_intels)) {
    if (
      ti.source.toLowerCase() === normalizedSource &&
      ti.observable_key === observableKey
    ) {
      return ti;
    }
  }
  return undefined;
}

/**
 * Get all threat intel entries as an array.
 *
 * @param inv - The investigation
 * @returns Array of all threat intel entries
 */
export function getAllThreatIntels(inv: CyvestInvestigation): ThreatIntel[] {
  return Object.values(inv.threat_intels);
}

/**
 * Get an enrichment by its key.
 *
 * @param inv - The investigation to search
 * @param key - Enrichment key (e.g., "enr:whois_data")
 * @returns The enrichment or undefined if not found
 */
export function getEnrichment(
  inv: CyvestInvestigation,
  key: string
): Enrichment | undefined {
  return inv.enrichments[key];
}

/**
 * Get an enrichment by name.
 *
 * @param inv - The investigation to search
 * @param name - Enrichment name
 * @returns The first matching enrichment or undefined if not found
 */
export function getEnrichmentByName(
  inv: CyvestInvestigation,
  name: string
): Enrichment | undefined {
  const normalizedName = name.trim().toLowerCase();

  for (const enr of Object.values(inv.enrichments)) {
    if (enr.name.toLowerCase() === normalizedName) {
      return enr;
    }
  }
  return undefined;
}

/**
 * Get all enrichments as an array.
 *
 * @param inv - The investigation
 * @returns Array of all enrichments
 */
export function getAllEnrichments(inv: CyvestInvestigation): Enrichment[] {
  return Object.values(inv.enrichments);
}

/**
 * Get a tag by its key.
 *
 * @param inv - The investigation to search
 * @param key - Tag key (e.g., "tag:header:auth")
 * @returns The tag or undefined if not found
 *
 * @example
 * ```ts
 * const tag = getTag(investigation, "tag:header:auth");
 * if (tag) {
 *   console.log(tag.name, tag.direct_level);
 * }
 * ```
 */
export function getTag(
  inv: CyvestInvestigation,
  key: string
): Tag | undefined {
  return inv.tags[key];
}

/**
 * Get a tag by its name.
 *
 * @param inv - The investigation to search
 * @param name - Tag name (e.g., "header:auth:dkim")
 * @returns The tag or undefined if not found
 *
 * @example
 * ```ts
 * const tag = getTagByName(investigation, "header:auth:dkim");
 * ```
 */
export function getTagByName(
  inv: CyvestInvestigation,
  name: string
): Tag | undefined {
  const key = generateTagKey(name);
  return inv.tags[key];
}

/**
 * Get all tags as an array.
 *
 * @param inv - The investigation
 * @returns Array of all tags
 *
 * @example
 * ```ts
 * const allTags = getAllTags(investigation);
 * console.log(`Total tags: ${allTags.length}`);
 * ```
 */
export function getAllTags(inv: CyvestInvestigation): Tag[] {
  return Object.values(inv.tags);
}

/**
 * Get all observables as an array.
 *
 * @param inv - The investigation
 * @returns Array of all observables
 */
export function getAllObservables(inv: CyvestInvestigation): Observable[] {
  return Object.values(inv.observables);
}

/**
 * Get all whitelists from the investigation.
 *
 * @param inv - The investigation
 * @returns Array of all whitelists
 */
export function getWhitelists(inv: CyvestInvestigation) {
  return inv.whitelists;
}

/**
 * Get the investigation statistics.
 *
 * @param inv - The investigation
 * @returns Statistics object
 */
export function getStats(inv: CyvestInvestigation) {
  return inv.stats;
}

/**
 * Get the data extraction configuration.
 *
 * @param inv - The investigation
 * @returns Data extraction config
 */
export function getDataExtraction(inv: CyvestInvestigation) {
  return inv.data_extraction;
}

/**
 * Count entities in the investigation.
 */
export interface InvestigationCounts {
  observables: number;
  checks: number;
  threatIntels: number;
  enrichments: number;
  tags: number;
  whitelists: number;
}

/**
 * Get counts of all entities in the investigation.
 *
 * @param inv - The investigation
 * @returns Object with counts for each entity type
 */
export function getCounts(inv: CyvestInvestigation): InvestigationCounts {
  return {
    observables: Object.keys(inv.observables).length,
    checks: getAllChecks(inv).length,
    threatIntels: Object.keys(inv.threat_intels).length,
    enrichments: Object.keys(inv.enrichments).length,
    tags: getAllTags(inv).length,
    whitelists: inv.whitelists.length,
  };
}

/**
 * Get the investigation start time from the event log.
 *
 * Looks for the INVESTIGATION_STARTED event and returns its timestamp.
 *
 * @param inv - The investigation
 * @returns The start timestamp string or undefined if not found
 *
 * @example
 * ```ts
 * const startedAt = getStartedAt(investigation);
 * if (startedAt) {
 *   console.log(`Started: ${startedAt}`);
 * }
 * ```
 */
export function getStartedAt(inv: CyvestInvestigation): string | undefined {
  const event = inv.audit_log?.find(
    (e) => e.event_type === "INVESTIGATION_STARTED"
  );
  return event?.timestamp;
}

// ============================================================================
// Tag Aggregation
// ============================================================================

/**
 * Get direct child tags of a given tag.
 *
 * @param inv - The investigation
 * @param tagName - Parent tag name
 * @returns Array of direct child tags
 *
 * @example
 * ```ts
 * const children = getTagChildren(investigation, "bodies");
 * // Returns tags like "bodies:urls", "bodies:domains" (but not "bodies:urls:something")
 * ```
 */
export function getTagChildren(inv: CyvestInvestigation, tagName: string): Tag[] {
  return Object.values(inv.tags).filter((tag) => isTagChildOf(tag.name, tagName));
}

/**
 * Get all descendant tags of a given tag (any depth).
 *
 * @param inv - The investigation
 * @param tagName - Ancestor tag name
 * @returns Array of all descendant tags
 *
 * @example
 * ```ts
 * const descendants = getTagDescendants(investigation, "bodies");
 * // Returns all tags starting with "bodies:"
 * ```
 */
export function getTagDescendants(inv: CyvestInvestigation, tagName: string): Tag[] {
  const prefix = tagName + ":";
  return Object.values(inv.tags).filter((tag) => tag.name.startsWith(prefix));
}

/**
 * Get the aggregated score for a tag including all descendant tags.
 *
 * The aggregated score includes:
 * - The tag's direct_score (from its direct checks)
 * - Recursively, the aggregated scores of all child tags
 *
 * @param inv - The investigation
 * @param tagName - Name of the tag
 * @returns Total aggregated score, or 0 if tag not found
 *
 * @example
 * ```ts
 * const score = getTagAggregatedScore(investigation, "bodies");
 * // Includes scores from bodies, bodies:urls, bodies:domains, etc.
 * ```
 */
export function getTagAggregatedScore(inv: CyvestInvestigation, tagName: string): number {
  const tag = getTagByName(inv, tagName);
  if (!tag) {
    return 0;
  }

  // Start with direct score
  let total = tag.direct_score;

  // Add scores from direct children (they will recursively add their children)
  const children = getTagChildren(inv, tagName);
  for (const child of children) {
    total += getTagAggregatedScore(inv, child.name);
  }

  return total;
}

/**
 * Get the aggregated level for a tag including all descendant tags.
 *
 * The level is calculated from the aggregated score using the standard
 * score-to-level mapping.
 *
 * @param inv - The investigation
 * @param tagName - Name of the tag
 * @returns Level based on aggregated score
 *
 * @example
 * ```ts
 * const level = getTagAggregatedLevel(investigation, "bodies");
 * // Returns "MALICIOUS" if aggregated score >= 5, etc.
 * ```
 */
export function getTagAggregatedLevel(inv: CyvestInvestigation, tagName: string): Level {
  return getLevelFromScore(getTagAggregatedScore(inv, tagName));
}
