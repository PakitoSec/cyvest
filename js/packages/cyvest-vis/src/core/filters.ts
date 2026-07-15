import {
  getRootObservable,
  type CyvestInvestigation,
  type Level,
} from "@cyvest/cyvest-js";

import type { CyvestGraphFilterState } from "../types";

export const EMPTY_GRAPH_FILTERS: CyvestGraphFilterState = {
  query: "",
  observableTypes: [],
  levels: [],
  relationshipTypes: [],
  scope: "all",
};

export function normalizeGraphFilters(
  filters?: Partial<CyvestGraphFilterState>
): CyvestGraphFilterState {
  return {
    ...EMPTY_GRAPH_FILTERS,
    ...filters,
    observableTypes: [...(filters?.observableTypes ?? [])],
    levels: [...(filters?.levels ?? [])] as Level[],
    relationshipTypes: [...(filters?.relationshipTypes ?? [])],
  };
}

export function filterInvestigation(
  investigation: CyvestInvestigation,
  filters: CyvestGraphFilterState
): CyvestInvestigation {
  const root = getRootObservable(investigation);
  const rootKey = root?.key;
  const presentationRootKey = root?.value === "root" && root.relationships.length === 1
    ? root.relationships[0].target_key
    : undefined;
  const visibleEntries = Object.entries(investigation.observables).filter(
    ([key, observable]) => {
      if (key === rootKey || key === presentationRootKey) return true;
      if (
        filters.observableTypes.length > 0 &&
        !filters.observableTypes.includes(observable.type)
      ) {
        return false;
      }
      if (filters.levels.length > 0 && !filters.levels.includes(observable.level)) {
        return false;
      }
      if (filters.scope === "internal" && !observable.internal) return false;
      if (filters.scope === "external" && observable.internal) return false;
      if (filters.scope === "whitelisted" && !observable.whitelisted) return false;
      return true;
    }
  );
  const visibleKeys = new Set(visibleEntries.map(([key]) => key));
  const observables = Object.fromEntries(
    visibleEntries.map(([key, observable]) => [
      key,
      {
        ...observable,
        relationships: observable.relationships.filter(
          (relationship) =>
            visibleKeys.has(relationship.target_key) &&
            (key === rootKey ||
              filters.relationshipTypes.length === 0 ||
              filters.relationshipTypes.includes(relationship.relationship_type))
        ),
      },
    ])
  );

  return { ...investigation, observables };
}

export function matchesGraphQuery(
  data: Record<string, unknown>,
  query: string
): boolean {
  const normalized = query.trim().toLocaleLowerCase();
  if (!normalized) return true;
  return [data.id, data.labelFull, data.observableType, data.level]
    .filter((value) => value !== undefined && value !== null)
    .some((value) => String(value).toLocaleLowerCase().includes(normalized));
}
