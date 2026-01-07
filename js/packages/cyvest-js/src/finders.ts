/**
 * Finder utilities for querying and filtering Cyvest Investigation data.
 *
 * These functions provide filtering, searching, and cross-referencing
 * capabilities for observables, checks, and threat intel.
 */

import type {
  CyvestInvestigation,
  Observable,
  Check,
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
 * @param type - Observable type (e.g., "ipv4-addr", "url", "domain-name")
 * @returns Array of matching observables
 *
 * @example
 * ```ts
 * const ips = findObservablesByType(investigation, "ipv4-addr");
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
// Check Finders
// ============================================================================

/**
 * Find all checks at a specific level.
 *
 * @param inv - The investigation to search
 * @param level - Security level to filter by
 * @returns Array of matching checks
 */
export function findChecksByLevel(
  inv: CyvestInvestigation,
  level: Level
): Check[] {
  return Object.values(inv.checks).filter((check) => check.level === level);
}

/**
 * Find all checks at or above a minimum level.
 *
 * @param inv - The investigation to search
 * @param minLevel - Minimum security level
 * @returns Array of matching checks
 */
export function findChecksAtLeast(
  inv: CyvestInvestigation,
  minLevel: Level
): Check[] {
  return Object.values(inv.checks).filter((check) =>
    isLevelAtLeast(check.level, minLevel)
  );
}

/**
 * Find checks by check name.
 *
 * @param inv - The investigation to search
 * @param checkName - Check name to search for
 * @returns The matching check or undefined
 */
export function findCheckByName(
  inv: CyvestInvestigation,
  checkName: string
): Check | undefined {
  const normalizedName = checkName.trim().toLowerCase();
  return Object.values(inv.checks).find(
    (check) => check.check_name.toLowerCase() === normalizedName
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
 * Find all checks that generated or reference a specific observable.
 *
 * @param inv - The investigation to search
 * @param observableKey - Key of the observable
 * @returns Array of checks that reference this observable
 *
 * @example
 * ```ts
 * const checks = findChecksForObservable(investigation, "obs:ipv4-addr:192.168.1.1");
 * ```
 */
export function findChecksForObservable(
  inv: CyvestInvestigation,
  observableKey: string
): Check[] {
  const result: Check[] = [];
  const seen = new Set<string>();

  const observable = inv.observables[observableKey];
  if (observable) {
    for (const checkKey of observable.check_links) {
      const check = inv.checks[checkKey];
      if (check && !seen.has(check.key)) {
        result.push(check);
        seen.add(check.key);
      }
    }
  }

  for (const check of Object.values(inv.checks)) {
    if (seen.has(check.key)) {
      continue;
    }

    if (check.observable_links.some((link) => link.observable_key === observableKey)) {
      result.push(check);
      seen.add(check.key);
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
 * Find all observables referenced by a specific check.
 *
 * @param inv - The investigation to search
 * @param checkKey - Key of the check
 * @returns Array of observables referenced by this check
 */
export function findObservablesForCheck(
  inv: CyvestInvestigation,
  checkKey: string
): Observable[] {
  const check = inv.checks[checkKey];
  if (check) {
    const keys = new Set<string>();
    for (const link of check.observable_links) {
      keys.add(link.observable_key);
    }

    return Array.from(keys)
      .map((obsKey) => inv.observables[obsKey])
      .filter((obs): obs is Observable => obs !== undefined);
  }
  return [];
}

/**
 * Find all checks for a specific tag.
 *
 * @param inv - The investigation to search
 * @param tagKey - Key of the tag
 * @param recursive - Include checks from descendant tags (default: false)
 * @returns Array of checks in the tag
 */
export function findChecksForTag(
  inv: CyvestInvestigation,
  tagKey: string,
  recursive = false
): Check[] {
  const result: Check[] = [];
  const tag = inv.tags[tagKey];

  if (!tag) {
    return result;
  }

  // Get direct checks
  for (const checkKey of tag.checks) {
    const check = inv.checks[checkKey];
    if (check) {
      result.push(check);
    }
  }

  // If recursive, get checks from descendant tags
  if (recursive) {
    const prefix = tag.name + ":";
    for (const otherTag of Object.values(inv.tags)) {
      if (otherTag.name.startsWith(prefix)) {
        for (const checkKey of otherTag.checks) {
          const check = inv.checks[checkKey];
          if (check) {
            result.push(check);
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
  return [...observables].sort((a, b) => b.score - a.score);
}

/**
 * Sort checks by score (descending - highest first).
 *
 * @param checks - Array of checks to sort
 * @returns Sorted array (new array, doesn't mutate input)
 */
export function sortChecksByScore(checks: Check[]): Check[] {
  return [...checks].sort((a, b) => b.score - a.score);
}

/**
 * Sort observables by level (descending - most severe first).
 *
 * @param observables - Array of observables to sort
 * @returns Sorted array (new array, doesn't mutate input)
 */
export function sortObservablesByLevel(observables: Observable[]): Observable[] {
  return [...observables].sort(
    (a, b) => LEVEL_VALUES[b.level] - LEVEL_VALUES[a.level]
  );
}

/**
 * Sort checks by level (descending - most severe first).
 *
 * @param checks - Array of checks to sort
 * @returns Sorted array (new array, doesn't mutate input)
 */
export function sortChecksByLevel(checks: Check[]): Check[] {
  return [...checks].sort(
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
 * Find the highest scoring checks.
 *
 * @param inv - The investigation to search
 * @param n - Number of results to return (default: 10)
 * @returns Array of highest scoring checks
 */
export function findHighestScoringChecks(
  inv: CyvestInvestigation,
  n = 10
): Check[] {
  return sortChecksByScore(Object.values(inv.checks)).slice(0, n);
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
 * Find all malicious checks (convenience function).
 *
 * @param inv - The investigation to search
 * @returns Array of malicious checks
 */
export function findMaliciousChecks(inv: CyvestInvestigation): Check[] {
  return findChecksByLevel(inv, "MALICIOUS");
}

/**
 * Find all suspicious checks (convenience function).
 *
 * @param inv - The investigation to search
 * @returns Array of suspicious checks
 */
export function findSuspiciousChecks(inv: CyvestInvestigation): Check[] {
  return findChecksByLevel(inv, "SUSPICIOUS");
}

/**
 * Get all check keys in the investigation.
 *
 * @param inv - The investigation
 * @returns Array of check keys
 */
export function getAllCheckKeys(inv: CyvestInvestigation): string[] {
  return Object.keys(inv.checks);
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
