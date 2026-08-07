/**
 * Finder utilities for querying and filtering Cyvest Investigation data.
 *
 * These functions provide filtering, searching, and cross-referencing
 * capabilities for observables, findings, and threat intel.
 */

import type {
  CyvestInvestigation,
  Observable,
  Finding,
  ThreatIntel,
  Tag,
  Level,
} from "./types.generated";
import { isLevelAtLeast, isLevelHigherThan, LEVEL_VALUES } from "./levels";

// ============================================================================
// Observable Finders
// ============================================================================

/**
 * Find all observables of a specific type.
 *
 * @param inv - The investigation to search
 * @param type - Observable type (e.g., "ipv4", "url", "domain")
 * @returns Array of matching observables
 *
 * @example
 * ```ts
 * const ips = findObservablesByType(investigation, "ipv4");
 * const urls = findObservablesByType(investigation, "url");
 * ```
 */
export function findObservablesByType(
  inv: CyvestInvestigation,
  type: string
): Observable[] {
  const normalizedType = type.trim().toLowerCase();
  return Object.values(inv.observables).filter(
    (obs) => obs.type.toLowerCase() === normalizedType
  );
}

/**
 * Find all observables at a specific level.
 *
 * @param inv - The investigation to search
 * @param level - Security level to filter by
 * @returns Array of matching observables
 *
 * @example
 * ```ts
 * const malicious = findObservablesByLevel(investigation, "MALICIOUS");
 * ```
 */
export function findObservablesByLevel(
  inv: CyvestInvestigation,
  level: Level
): Observable[] {
  return Object.values(inv.observables).filter((obs) => obs.level === level);
}

/**
 * Find all observables at or above a minimum level.
 *
 * @param inv - The investigation to search
 * @param minLevel - Minimum security level
 * @returns Array of matching observables
 *
 * @example
 * ```ts
 * const suspicious = findObservablesAtLeast(investigation, "SUSPICIOUS");
 * // Returns SUSPICIOUS and MALICIOUS observables
 * ```
 */
export function findObservablesAtLeast(
  inv: CyvestInvestigation,
  minLevel: Level
): Observable[] {
  return Object.values(inv.observables).filter((obs) =>
    isLevelAtLeast(obs.level, minLevel)
  );
}

/**
 * Find observables by exact value match.
 *
 * @param inv - The investigation to search
 * @param value - Value to search for
 * @param caseSensitive - Whether to perform case-sensitive match (default: false)
 * @returns Array of matching observables
 */
export function findObservablesByValue(
  inv: CyvestInvestigation,
  value: string,
  caseSensitive = false
): Observable[] {
  const searchValue = caseSensitive ? value : value.toLowerCase();
  return Object.values(inv.observables).filter((obs) => {
    const obsValue = caseSensitive ? obs.value : obs.value.toLowerCase();
    return obsValue === searchValue;
  });
}

/**
 * Find observables containing a substring in their value.
 *
 * @param inv - The investigation to search
 * @param substring - Substring to search for
 * @param caseSensitive - Whether to perform case-sensitive match (default: false)
 * @returns Array of matching observables
 */
export function findObservablesContaining(
  inv: CyvestInvestigation,
  substring: string,
  caseSensitive = false
): Observable[] {
  const searchStr = caseSensitive ? substring : substring.toLowerCase();
  return Object.values(inv.observables).filter((obs) => {
    const obsValue = caseSensitive ? obs.value : obs.value.toLowerCase();
    return obsValue.includes(searchStr);
  });
}

/**
 * Find observables matching a regular expression.
 *
 * @param inv - The investigation to search
 * @param pattern - Regular expression pattern
 * @returns Array of matching observables
 */
export function findObservablesMatching(
  inv: CyvestInvestigation,
  pattern: RegExp
): Observable[] {
  return Object.values(inv.observables).filter((obs) => pattern.test(obs.value));
}

/**
 * Find internal observables.
 *
 * @param inv - The investigation to search
 * @returns Array of internal observables
 */
export function findInternalObservables(inv: CyvestInvestigation): Observable[] {
  return Object.values(inv.observables).filter((obs) => obs.internal);
}

/**
 * Find external (non-internal) observables.
 *
 * @param inv - The investigation to search
 * @returns Array of external observables
 */
export function findExternalObservables(inv: CyvestInvestigation): Observable[] {
  return Object.values(inv.observables).filter((obs) => !obs.internal);
}

/**
 * Find whitelisted observables.
 *
 * @param inv - The investigation to search
 * @returns Array of whitelisted observables
 */
export function findWhitelistedObservables(
  inv: CyvestInvestigation
): Observable[] {
  return Object.values(inv.observables).filter((obs) => obs.whitelisted);
}

/**
 * Find observables with threat intelligence data.
 *
 * @param inv - The investigation to search
 * @returns Array of observables that have associated threat intel
 */
export function findObservablesWithThreatIntel(
  inv: CyvestInvestigation
): Observable[] {
  return Object.values(inv.observables).filter(
    (obs) => obs.threat_intels.length > 0
  );
}

// ============================================================================
// Finding Finders
// ============================================================================

/**
 * Find all findings at a specific level.
 *
 * @param inv - The investigation to search
 * @param level - Security level to filter by
 * @returns Array of matching findings
 */
export function findFindingsByLevel(
  inv: CyvestInvestigation,
  level: Level
): Finding[] {
  return Object.values(inv.findings).filter((finding) => finding.level === level);
}

/**
 * Find all findings at or above a minimum level.
 *
 * @param inv - The investigation to search
 * @param minLevel - Minimum security level
 * @returns Array of matching findings
 */
export function findFindingsAtLeast(
  inv: CyvestInvestigation,
  minLevel: Level
): Finding[] {
  return Object.values(inv.findings).filter((finding) =>
    isLevelAtLeast(finding.level, minLevel)
  );
}

/**
 * Find findings by finding name.
 *
 * @param inv - The investigation to search
 * @param findingName - Finding name to search for
 * @returns The matching finding or undefined
 */
export function findFindingByName(
  inv: CyvestInvestigation,
  findingName: string
): Finding | undefined {
  const normalizedName = findingName.trim().toLowerCase();
  return Object.values(inv.findings).find(
    (finding) => finding.finding_name.toLowerCase() === normalizedName
  );
}

// ============================================================================
// Threat Intel Finders
// ============================================================================

/**
 * Find all threat intel from a specific source.
 *
 * @param inv - The investigation to search
 * @param source - Source name (e.g., "virustotal", "otx")
 * @returns Array of threat intel from the source
 */
export function findThreatIntelBySource(
  inv: CyvestInvestigation,
  source: string
): ThreatIntel[] {
  const normalizedSource = source.trim().toLowerCase();
  return Object.values(inv.threat_intels).filter(
    (ti) => ti.source.toLowerCase() === normalizedSource
  );
}

/**
 * Find all threat intel at a specific level.
 *
 * @param inv - The investigation to search
 * @param level - Security level to filter by
 * @returns Array of matching threat intel
 */
export function findThreatIntelByLevel(
  inv: CyvestInvestigation,
  level: Level
): ThreatIntel[] {
  return Object.values(inv.threat_intels).filter((ti) => ti.level === level);
}

/**
 * Find all threat intel at or above a minimum level.
 *
 * @param inv - The investigation to search
 * @param minLevel - Minimum security level
 * @returns Array of matching threat intel
 */
export function findThreatIntelAtLeast(
  inv: CyvestInvestigation,
  minLevel: Level
): ThreatIntel[] {
  return Object.values(inv.threat_intels).filter((ti) =>
    isLevelAtLeast(ti.level, minLevel)
  );
}

// ============================================================================
// Tag Finders
// ============================================================================

/**
 * Find tags at a specific direct level.
 *
 * @param inv - The investigation to search
 * @param level - Direct level to filter by
 * @returns Array of matching tags
 */
export function findTagsByLevel(
  inv: CyvestInvestigation,
  level: Level
): Tag[] {
  return Object.values(inv.tags).filter((tag) => tag.direct_level === level);
}

/**
 * Find tags at or above a minimum direct level.
 *
 * @param inv - The investigation to search
 * @param minLevel - Minimum direct level
 * @returns Array of matching tags
 */
export function findTagsAtLeast(
  inv: CyvestInvestigation,
  minLevel: Level
): Tag[] {
  return Object.values(inv.tags).filter((tag) =>
    isLevelAtLeast(tag.direct_level, minLevel)
  );
}

/**
 * Find tags by name pattern.
 *
 * @param inv - The investigation to search
 * @param pattern - Pattern to match against tag names
 * @returns Array of matching tags
 */
export function findTagsByNamePattern(
  inv: CyvestInvestigation,
  pattern: RegExp
): Tag[] {
  return Object.values(inv.tags).filter((tag) => pattern.test(tag.name));
}

// ============================================================================
// Cross-Reference Finders
// ============================================================================

/**
 * Find all findings that generated or reference a specific observable.
 *
 * @param inv - The investigation to search
 * @param observableKey - Key of the observable
 * @returns Array of findings that reference this observable
 *
 * @example
 * ```ts
 * const findings = findFindingsForObservable(investigation, "obs:ipv4:192.168.1.1");
 * ```
 */
export function findFindingsForObservable(
  inv: CyvestInvestigation,
  observableKey: string
): Finding[] {
  const result: Finding[] = [];
  const seen = new Set<string>();

  const observable = inv.observables[observableKey];
  if (observable) {
    for (const findingKey of observable.finding_links) {
      const finding = inv.findings[findingKey];
      if (finding && !seen.has(finding.key)) {
        result.push(finding);
        seen.add(finding.key);
      }
    }
  }

  for (const finding of Object.values(inv.findings)) {
    if (seen.has(finding.key)) {
      continue;
    }

    if (finding.observable_links.some((link) => link.observable_key === observableKey)) {
      result.push(finding);
      seen.add(finding.key);
    }
  }

  return result;
}

/**
 * Find all threat intel entries for a specific observable.
 *
 * @param inv - The investigation to search
 * @param observableKey - Key of the observable
 * @returns Array of threat intel for this observable
 */
export function findThreatIntelsForObservable(
  inv: CyvestInvestigation,
  observableKey: string
): ThreatIntel[] {
  // First try using the observable's threat_intels array
  const observable = inv.observables[observableKey];
  if (observable) {
    return observable.threat_intels
      .map((tiKey) => inv.threat_intels[tiKey])
      .filter((ti): ti is ThreatIntel => ti !== undefined);
  }

  // Fallback: search all threat intel
  return Object.values(inv.threat_intels).filter(
    (ti) => ti.observable_key === observableKey
  );
}

/**
 * Find all observables referenced by a specific finding.
 *
 * @param inv - The investigation to search
 * @param findingKey - Key of the finding
 * @returns Array of observables referenced by this finding
 */
export function findObservablesForFinding(
  inv: CyvestInvestigation,
  findingKey: string
): Observable[] {
  const finding = inv.findings[findingKey];
  if (finding) {
    const keys = new Set<string>();
    for (const link of finding.observable_links) {
      keys.add(link.observable_key);
    }

    return Array.from(keys)
      .map((obsKey) => inv.observables[obsKey])
      .filter((obs): obs is Observable => obs !== undefined);
  }
  return [];
}

/**
 * Find all findings for a specific tag.
 *
 * @param inv - The investigation to search
 * @param tagKey - Key of the tag
 * @param recursive - Include findings from descendant tags (default: false)
 * @returns Array of findings in the tag
 */
export function findFindingsForTag(
  inv: CyvestInvestigation,
  tagKey: string,
  recursive = false
): Finding[] {
  const result: Finding[] = [];
  const tag = inv.tags[tagKey];

  if (!tag) {
    return result;
  }

  // Get direct findings
  for (const findingKey of tag.findings) {
    const finding = inv.findings[findingKey];
    if (finding) {
      result.push(finding);
    }
  }

  // If recursive, get findings from descendant tags
  if (recursive) {
    const prefix = tag.name + ":";
    for (const otherTag of Object.values(inv.tags)) {
      if (otherTag.name.startsWith(prefix)) {
        for (const findingKey of otherTag.findings) {
          const finding = inv.findings[findingKey];
          if (finding) {
            result.push(finding);
          }
        }
      }
    }
  }

  return result;
}

// ============================================================================
// Sorting Utilities
// ============================================================================

/**
 * Sort observables by score (descending - highest first).
 *
 * @param observables - Array of observables to sort
 * @returns Sorted array (new array, doesn't mutate input)
 */
export function sortObservablesByScore(observables: Observable[]): Observable[] {
  return observables.toSorted((a, b) => b.score - a.score);
}

/**
 * Sort findings by score (descending - highest first).
 *
 * @param findings - Array of findings to sort
 * @returns Sorted array (new array, doesn't mutate input)
 */
export function sortFindingsByScore(findings: Finding[]): Finding[] {
  return findings.toSorted((a, b) => b.score - a.score);
}

/**
 * Sort observables by level (descending - most severe first).
 *
 * @param observables - Array of observables to sort
 * @returns Sorted array (new array, doesn't mutate input)
 */
export function sortObservablesByLevel(observables: Observable[]): Observable[] {
  return observables.toSorted(
    (a, b) => LEVEL_VALUES[b.level] - LEVEL_VALUES[a.level]
  );
}

/**
 * Sort findings by level (descending - most severe first).
 *
 * @param findings - Array of findings to sort
 * @returns Sorted array (new array, doesn't mutate input)
 */
export function sortFindingsByLevel(findings: Finding[]): Finding[] {
  return findings.toSorted(
    (a, b) => LEVEL_VALUES[b.level] - LEVEL_VALUES[a.level]
  );
}

// ============================================================================
// Aggregation Utilities
// ============================================================================

/**
 * Find the highest scoring observables.
 *
 * @param inv - The investigation to search
 * @param n - Number of results to return (default: 10)
 * @returns Array of highest scoring observables
 */
export function findHighestScoringObservables(
  inv: CyvestInvestigation,
  n = 10
): Observable[] {
  return sortObservablesByScore(Object.values(inv.observables)).slice(0, n);
}

/**
 * Find the highest scoring findings.
 *
 * @param inv - The investigation to search
 * @param n - Number of results to return (default: 10)
 * @returns Array of highest scoring findings
 */
export function findHighestScoringFindings(
  inv: CyvestInvestigation,
  n = 10
): Finding[] {
  return sortFindingsByScore(Object.values(inv.findings)).slice(0, n);
}

/**
 * Find all malicious observables (convenience function).
 *
 * @param inv - The investigation to search
 * @returns Array of malicious observables
 */
export function findMaliciousObservables(inv: CyvestInvestigation): Observable[] {
  return findObservablesByLevel(inv, "MALICIOUS");
}

/**
 * Find all suspicious observables (convenience function).
 *
 * @param inv - The investigation to search
 * @returns Array of suspicious observables
 */
export function findSuspiciousObservables(inv: CyvestInvestigation): Observable[] {
  return findObservablesByLevel(inv, "SUSPICIOUS");
}

/**
 * Find all malicious findings (convenience function).
 *
 * @param inv - The investigation to search
 * @returns Array of malicious findings
 */
export function findMaliciousFindings(inv: CyvestInvestigation): Finding[] {
  return findFindingsByLevel(inv, "MALICIOUS");
}

/**
 * Find all suspicious findings (convenience function).
 *
 * @param inv - The investigation to search
 * @returns Array of suspicious findings
 */
export function findSuspiciousFindings(inv: CyvestInvestigation): Finding[] {
  return findFindingsByLevel(inv, "SUSPICIOUS");
}

/**
 * Get all finding keys in the investigation.
 *
 * @param inv - The investigation
 * @returns Array of finding keys
 */
export function getAllFindingKeys(inv: CyvestInvestigation): string[] {
  return Object.keys(inv.findings);
}

/**
 * Get all observable types present in the investigation.
 *
 * @param inv - The investigation
 * @returns Array of unique observable types
 */
export function getAllObservableTypes(inv: CyvestInvestigation): string[] {
  const types = new Set<string>();
  for (const obs of Object.values(inv.observables)) {
    types.add(obs.type);
  }
  return Array.from(types);
}

/**
 * Get all threat intel sources present in the investigation.
 *
 * @param inv - The investigation
 * @returns Array of unique source names
 */
export function getAllThreatIntelSources(inv: CyvestInvestigation): string[] {
  const sources = new Set<string>();
  for (const ti of Object.values(inv.threat_intels)) {
    sources.add(ti.source);
  }
  return Array.from(sources);
}
