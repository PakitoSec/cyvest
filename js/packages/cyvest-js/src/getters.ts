/**
 * Getter utilities for retrieving entities from a Cyvest Investigation.
 *
 * These functions provide type-safe access to observables, checks, threat intel,
 * enrichments, and containers by their keys.
 */

import type {
  CyvestInvestigation,
  Observable,
  Check,
  ThreatIntel,
  Enrichment,
  Container,
} from "./types.generated";

/**
 * Get an observable by its key.
 *
 * @param inv - The investigation to search
 * @param key - Observable key (e.g., "obs:ipv4-addr:192.168.1.1")
 * @returns The observable or undefined if not found
 *
 * @example
 * ```ts
 * const obs = getObservable(investigation, "obs:ipv4-addr:192.168.1.1");
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
 * @param type - Observable type (e.g., "ipv4-addr", "url")
 * @param value - Observable value
 * @returns The observable or undefined if not found
 *
 * @example
 * ```ts
 * const obs = getObservableByTypeValue(investigation, "ipv4-addr", "192.168.1.1");
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
  for (const checks of Object.values(inv.checks)) {
    for (const check of checks) {
      if (check.key === key) {
        return check;
      }
    }
  }
  return undefined;
}

/**
 * Get a check by its ID and scope.
 *
 * @param inv - The investigation to search
 * @param checkId - Check identifier
 * @param scope - Check scope
 * @returns The check or undefined if not found
 *
 * @example
 * ```ts
 * const check = getCheckByIdScope(investigation, "sender_verification", "email_headers");
 * ```
 */
export function getCheckByIdScope(
  inv: CyvestInvestigation,
  checkId: string,
  scope: string
): Check | undefined {
  const normalizedId = checkId.trim().toLowerCase();
  const normalizedScope = scope.trim().toLowerCase();

  const scopeChecks = inv.checks[normalizedScope] || inv.checks[scope];
  if (scopeChecks) {
    return scopeChecks.find(
      (c) => c.check_id.toLowerCase() === normalizedId
    );
  }

  // Fallback: search all scopes
  for (const checks of Object.values(inv.checks)) {
    for (const check of checks) {
      if (
        check.check_id.toLowerCase() === normalizedId &&
        check.scope.toLowerCase() === normalizedScope
      ) {
        return check;
      }
    }
  }
  return undefined;
}

/**
 * Get all checks as a flat array (not grouped by scope).
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
  const result: Check[] = [];
  for (const checks of Object.values(inv.checks)) {
    result.push(...checks);
  }
  return result;
}

/**
 * Get a threat intel entry by its key.
 *
 * @param inv - The investigation to search
 * @param key - Threat intel key (e.g., "ti:virustotal:obs:ipv4-addr:192.168.1.1")
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
 * Get a container by its key.
 *
 * @param inv - The investigation to search
 * @param key - Container key (e.g., "ctr:email/headers")
 * @returns The container or undefined if not found
 */
export function getContainer(
  inv: CyvestInvestigation,
  key: string
): Container | undefined {
  // First check top-level containers
  if (inv.containers[key]) {
    return inv.containers[key];
  }

  // Search recursively in sub-containers
  function searchSubContainers(containers: Record<string, Container>): Container | undefined {
    for (const container of Object.values(containers)) {
      if (container.key === key) {
        return container;
      }
      const found = searchSubContainers(container.sub_containers);
      if (found) return found;
    }
    return undefined;
  }

  return searchSubContainers(inv.containers);
}

/**
 * Get a container by its path.
 *
 * @param inv - The investigation to search
 * @param path - Container path
 * @returns The container or undefined if not found
 */
export function getContainerByPath(
  inv: CyvestInvestigation,
  path: string
): Container | undefined {
  const normalizedPath = path.replace(/\\/g, "/").replace(/^\/+|\/+$/g, "").toLowerCase();

  function searchContainers(containers: Record<string, Container>): Container | undefined {
    for (const container of Object.values(containers)) {
      if (container.path.toLowerCase() === normalizedPath) {
        return container;
      }
      const found = searchContainers(container.sub_containers);
      if (found) return found;
    }
    return undefined;
  }

  return searchContainers(inv.containers);
}

/**
 * Get all containers as a flat array (including sub-containers).
 *
 * @param inv - The investigation
 * @returns Array of all containers
 */
export function getAllContainers(inv: CyvestInvestigation): Container[] {
  const result: Container[] = [];

  function collectContainers(containers: Record<string, Container>): void {
    for (const container of Object.values(containers)) {
      result.push(container);
      collectContainers(container.sub_containers);
    }
  }

  collectContainers(inv.containers);
  return result;
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
  containers: number;
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
    containers: getAllContainers(inv).length,
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
