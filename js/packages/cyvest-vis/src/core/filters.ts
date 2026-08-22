import {
  getObservableVerdict,
  isAllowlisted,
  type Investigation,
  type Verdict,
} from "@cyvest/cyvest-js";

import type { CyvestGraphFilterState } from "../types";

export const EMPTY_GRAPH_FILTERS: CyvestGraphFilterState = {
  query: "",
  observableTypes: [],
  verdicts: [],
  relationKinds: [],
  scope: "all",
};

export function normalizeGraphFilters(
  filters?: Partial<CyvestGraphFilterState>
): CyvestGraphFilterState {
  return {
    ...EMPTY_GRAPH_FILTERS,
    ...filters,
    observableTypes: [...(filters?.observableTypes ?? [])],
    verdicts: [...(filters?.verdicts ?? [])] as Verdict[],
    relationKinds: [...(filters?.relationKinds ?? [])],
  };
}

/**
 * Hide facts from the view without touching the report.
 *
 * Filtering is presentation only: scores stay as the engine computed them, so a filtered graph
 * keeps showing the numbers of the whole investigation rather than a re-derivation of a subset.
 */
export function filterInvestigation(
  investigation: Investigation,
  filters: CyvestGraphFilterState
): Investigation {
  const rootKey = investigation.header.root_key ?? undefined;
  const facts = investigation.facts ?? {};
  const observables = facts.observables ?? {};

  const visibleEntries = Object.entries(observables).filter(([key, observable]) => {
    if (key === rootKey) return true;
    if (
      filters.observableTypes.length > 0 &&
      !filters.observableTypes.includes(observable.type)
    ) {
      return false;
    }
    if (
      filters.verdicts.length > 0 &&
      !filters.verdicts.includes(getObservableVerdict(investigation, key))
    ) {
      return false;
    }
    if (filters.scope === "internal" && !observable.internal) return false;
    if (filters.scope === "external" && observable.internal) return false;
    if (filters.scope === "allowlisted" && !isAllowlisted(investigation, key)) return false;
    return true;
  });

  const visibleKeys = new Set(visibleEntries.map(([key]) => key));
  const relations = Object.entries(facts.relations ?? {}).filter(
    ([, relation]) =>
      visibleKeys.has(relation.source_key) &&
      visibleKeys.has(relation.target_key) &&
      (relation.source_key === rootKey ||
        relation.target_key === rootKey ||
        filters.relationKinds.length === 0 ||
        filters.relationKinds.includes(relation.kind ?? "related-to"))
  );

  return {
    ...investigation,
    facts: {
      ...facts,
      observables: Object.fromEntries(visibleEntries),
      relations: Object.fromEntries(relations),
    },
  };
}

export function matchesGraphQuery(
  data: Record<string, unknown>,
  query: string
): boolean {
  const normalized = query.trim().toLocaleLowerCase();
  if (!normalized) return true;
  return [data.id, data.labelFull, data.observableType, data.verdict]
    .filter((value) => value !== undefined && value !== null)
    .some((value) => String(value).toLocaleLowerCase().includes(normalized));
}
