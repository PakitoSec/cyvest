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
  Container,
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
 * Find all checks in a specific scope.
 *
 * @param inv - The investigation to search
 * @param scope - Check scope
 * @returns Array of checks in the scope
 *
 * @example
 * ```ts
 * const emailChecks = findChecksByScope(investigation, "email_headers");
 * ```
 */
export function findChecksByScope(
  inv: CyvestInvestigation,
  scope: string
): Check[] {
  const normalizedScope = scope.trim().toLowerCase();

  // Try direct lookup first
  if (inv.checks[scope]) {
    return inv.checks[scope];
  }

  // Fallback to normalized search
  for (const [key, checks] of Object.entries(inv.checks)) {
    if (key.toLowerCase() === normalizedScope) {
      return checks;
    }
  }

  return [];
}

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
  const result: Check[] = [];
  for (const checks of Object.values(inv.checks)) {
    for (const check of checks) {
      if (check.level === level) {
        result.push(check);
      }
    }
  }
  return result;
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
  const result: Check[] = [];
  for (const checks of Object.values(inv.checks)) {
    for (const check of checks) {
      if (isLevelAtLeast(check.level, minLevel)) {
        result.push(check);
      }
    }
  }
  return result;
}

/**
 * Find checks by check ID (across all scopes).
 *
 * @param inv - The investigation to search
 * @param checkId - Check identifier to search for
 * @returns Array of matching checks
 */
export function findChecksByCheckId(
  inv: CyvestInvestigation,
  checkId: string
): Check[] {
  const normalizedId = checkId.trim().toLowerCase();
  const result: Check[] = [];

  for (const checks of Object.values(inv.checks)) {
    for (const check of checks) {
      if (check.check_id.toLowerCase() === normalizedId) {
        result.push(check);
      }
    }
  }
  return result;
}

/**
 * Find checks with score policy set to manual.
 *
 * @param inv - The investigation to search
 * @returns Array of manually scored checks
 */
export function findManuallyScored(inv: CyvestInvestigation): Check[] {
  const result: Check[] = [];
  for (const checks of Object.values(inv.checks)) {
    for (const check of checks) {
      if (check.score_policy === "manual") {
        result.push(check);
      }
    }
  }
  return result;
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
// Container Finders
// ============================================================================

/**
 * Find containers at a specific aggregated level.
 *
 * @param inv - The investigation to search
 * @param level - Aggregated level to filter by
 * @returns Array of matching containers
 */
export function findContainersByLevel(
  inv: CyvestInvestigation,
  level: Level
): Container[] {
  const result: Container[] = [];

  function searchContainers(containers: Record<string, Container>): void {
    for (const container of Object.values(containers)) {
      if (container.aggregated_level === level) {
        result.push(container);
      }
      searchContainers(container.sub_containers);
    }
  }

  searchContainers(inv.containers);
  return result;
}

/**
 * Find containers at or above a minimum aggregated level.
 *
 * @param inv - The investigation to search
 * @param minLevel - Minimum aggregated level
 * @returns Array of matching containers
 */
export function findContainersAtLeast(
  inv: CyvestInvestigation,
  minLevel: Level
): Container[] {
  const result: Container[] = [];

  function searchContainers(containers: Record<string, Container>): void {
    for (const container of Object.values(containers)) {
      if (isLevelAtLeast(container.aggregated_level, minLevel)) {
        result.push(container);
      }
      searchContainers(container.sub_containers);
    }
  }

  searchContainers(inv.containers);
  return result;
}

// ============================================================================
// Cross-Reference Finders
// ============================================================================

/**
 * Get all checks that generated or reference a specific observable.
 *
 * @param inv - The investigation to search
 * @param observableKey - Key of the observable
 * @returns Array of checks that reference this observable
 *
 * @example
 * ```ts
 * const checks = getChecksForObservable(investigation, "obs:ipv4-addr:192.168.1.1");
 * ```
 */
export function getChecksForObservable(
  inv: CyvestInvestigation,
  observableKey: string
): Check[] {
  const result: Check[] = [];

  for (const checks of Object.values(inv.checks)) {
    for (const check of checks) {
      if (check.observables.includes(observableKey)) {
        result.push(check);
      }
    }
  }

  return result;
}

/**
 * Get all threat intel entries for a specific observable.
 *
 * @param inv - The investigation to search
 * @param observableKey - Key of the observable
 * @returns Array of threat intel for this observable
 */
export function getThreatIntelsForObservable(
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
 * Get all observables referenced by a specific check.
 *
 * @param inv - The investigation to search
 * @param checkKey - Key of the check
 * @returns Array of observables referenced by this check
 */
export function getObservablesForCheck(
  inv: CyvestInvestigation,
  checkKey: string
): Observable[] {
  // Find the check
  for (const checks of Object.values(inv.checks)) {
    for (const check of checks) {
      if (check.key === checkKey) {
        return check.observables
          .map((obsKey) => inv.observables[obsKey])
          .filter((obs): obs is Observable => obs !== undefined);
      }
    }
  }
  return [];
}

/**
 * Get all checks for a specific container.
 *
 * @param inv - The investigation to search
 * @param containerKey - Key of the container
 * @param recursive - Include checks from sub-containers (default: false)
 * @returns Array of checks in the container
 */
export function getChecksForContainer(
  inv: CyvestInvestigation,
  containerKey: string,
  recursive = false
): Check[] {
  const result: Check[] = [];

  function findContainer(
    containers: Record<string, Container>
  ): Container | undefined {
    for (const container of Object.values(containers)) {
      if (container.key === containerKey) {
        return container;
      }
      const found = findContainer(container.sub_containers);
      if (found) return found;
    }
    return undefined;
  }

  function collectChecks(container: Container): void {
    for (const checkKey of container.checks) {
      for (const checks of Object.values(inv.checks)) {
        for (const check of checks) {
          if (check.key === checkKey) {
            result.push(check);
          }
        }
      }
    }

    if (recursive) {
      for (const subContainer of Object.values(container.sub_containers)) {
        collectChecks(subContainer);
      }
    }
  }

  const container = findContainer(inv.containers);
  if (container) {
    collectChecks(container);
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
 * Get the highest scoring observables.
 *
 * @param inv - The investigation to search
 * @param n - Number of results to return (default: 10)
 * @returns Array of highest scoring observables
 */
export function getHighestScoringObservables(
  inv: CyvestInvestigation,
  n = 10
): Observable[] {
  return sortObservablesByScore(Object.values(inv.observables)).slice(0, n);
}

/**
 * Get the highest scoring checks.
 *
 * @param inv - The investigation to search
 * @param n - Number of results to return (default: 10)
 * @returns Array of highest scoring checks
 */
export function getHighestScoringChecks(
  inv: CyvestInvestigation,
  n = 10
): Check[] {
  const allChecks: Check[] = [];
  for (const checks of Object.values(inv.checks)) {
    allChecks.push(...checks);
  }
  return sortChecksByScore(allChecks).slice(0, n);
}

/**
 * Get all malicious observables (convenience function).
 *
 * @param inv - The investigation to search
 * @returns Array of malicious observables
 */
export function getMaliciousObservables(inv: CyvestInvestigation): Observable[] {
  return findObservablesByLevel(inv, "MALICIOUS");
}

/**
 * Get all suspicious observables (convenience function).
 *
 * @param inv - The investigation to search
 * @returns Array of suspicious observables
 */
export function getSuspiciousObservables(inv: CyvestInvestigation): Observable[] {
  return findObservablesByLevel(inv, "SUSPICIOUS");
}

/**
 * Get all malicious checks (convenience function).
 *
 * @param inv - The investigation to search
 * @returns Array of malicious checks
 */
export function getMaliciousChecks(inv: CyvestInvestigation): Check[] {
  return findChecksByLevel(inv, "MALICIOUS");
}

/**
 * Get all suspicious checks (convenience function).
 *
 * @param inv - The investigation to search
 * @returns Array of suspicious checks
 */
export function getSuspiciousChecks(inv: CyvestInvestigation): Check[] {
  return findChecksByLevel(inv, "SUSPICIOUS");
}

/**
 * Get all scopes that have checks.
 *
 * @param inv - The investigation
 * @returns Array of scope names
 */
export function getAllScopes(inv: CyvestInvestigation): string[] {
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
