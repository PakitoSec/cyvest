import {
  countRelationsByKind,
  getAllObservables,
  getObservableVerdict,
  getRelationsForObservable,
  VERDICT_ORDER,
  type Verdict,
} from "@cyvest/cyvest-js";
import type { Core } from "cytoscape";
import React, { useCallback, useEffect, useMemo, useState } from "react";

import {
  EMPTY_GRAPH_FILTERS,
  filterInvestigation,
  matchesGraphQuery,
  normalizeGraphFilters,
} from "../core/filters";
import { createThemeStyle } from "../core/theme";
import { resolveRelationshipProfile } from "../core/relationships";
import type {
  CyEdgeSelectEvent,
  CyNodeSelectEvent,
  CyvestGraphFilterState,
  CyvestGraphProps,
} from "../types";
import { CyvestObservablesView } from "./CyvestObservablesView";

type GraphSelection = CyNodeSelectEvent | CyEdgeSelectEvent;

// Most severe first: a filter panel should lead with what an analyst is looking for.
const VERDICT_FILTER_ORDER: Verdict[] = [...VERDICT_ORDER].reverse();

function joinClassNames(...names: Array<string | undefined | false>): string {
  return names.filter(Boolean).join(" ");
}

function toggleValue<T>(values: T[], value: T): T[] {
  return values.includes(value)
    ? values.filter((item) => item !== value)
    : [...values, value];
}

function Icon({ name }: { name: "filter" | "reset" | "close" | "search" | "physics" }) {
  const paths = {
    filter: <path d="M4 5h16M7 12h10M10 19h4" />,
    reset: (
      <>
        <path d="M20 6v5h-5" />
        <path d="M18.4 17.2a8 8 0 1 1 .8-9.6L20 11" />
      </>
    ),
    close: <path d="m6 6 12 12M18 6 6 18" />,
    search: <><circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" /></>,
    physics: <><circle cx="7" cy="12" r="2" /><circle cx="17" cy="7" r="2" /><circle cx="17" cy="17" r="2" /><path d="m8.8 11 6.4-3M8.8 13l6.4 3" /></>,
  };
  return <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">{paths[name]}</svg>;
}

function Inspector({
  selection,
  investigation,
  onClear,
}: {
  selection: GraphSelection | null;
  investigation: CyvestGraphProps["investigation"];
  onClear: () => void;
}) {
  const nodeSelection = selection && "nodeId" in selection ? selection : null;
  const edgeSelection = selection && "edgeId" in selection ? selection : null;
  const entries = selection
    ? nodeSelection
      ? [
          ["Observable type", nodeSelection.data.observableType],
          ["Verdict", nodeSelection.data.verdict],
          ["Score", nodeSelection.data.score],
          ["Scope", nodeSelection.data.internal ? "Internal" : "External"],
          ["Allowlisted", nodeSelection.data.allowlisted ? "Yes" : "No"],
        ]
      : [
          ["Family", edgeSelection?.relationshipFamily],
          ["Kind", edgeSelection?.relationKind],
          ["Confidence", edgeSelection?.confidence],
          ["Carried score", edgeSelection?.data.carriedScore ? "Yes" : "No"],
          ["Source", edgeSelection?.sourceId],
          ["Target", edgeSelection?.targetId],
        ]
    : [];
  const neighbors = useMemo(() => {
    if (!nodeSelection) return [];
    const observables = getAllObservables(investigation);
    return getRelationsForObservable(investigation, nodeSelection.nodeId)
      .map((relation) => {
        const isOutbound = relation.source_key === nodeSelection.nodeId;
        const otherKey = isOutbound ? relation.target_key : relation.source_key;
        return {
          id: otherKey,
          label: observables[otherKey]?.value ?? otherKey,
          type: relation.kind ?? "related-to",
          // `related-to` is symmetric, so it gets no arrow in either direction.
          direction: relation.kind === "related-to" ? "↔" : isOutbound ? "→" : "←",
        };
      })
      .filter(
        (item, index, items) =>
          items.findIndex(
            (candidate) => candidate.id === item.id && candidate.type === item.type
          ) === index
      );
  }, [investigation, nodeSelection]);

  return (
    <aside className="cyvest-inspector" aria-live="polite">
      <div className="cyvest-inspector__header">
        <div>
          <span className="cyvest-inspector__eyebrow">Selection</span>
          <strong>{nodeSelection ? "Observable" : selection ? "Relationship" : "Nothing selected"}</strong>
        </div>
        {selection ? (
          <button type="button" onClick={onClear} aria-label="Clear selection">
            <Icon name="close" />
          </button>
        ) : null}
      </div>
      {selection ? (
        <div className="cyvest-inspector__content">
          <h3>
            {nodeSelection
              ? nodeSelection.label
              : edgeSelection?.relationKind ?? "Relationship"}
          </h3>
          <p className="cyvest-inspector__id">
            {nodeSelection ? nodeSelection.nodeId : edgeSelection?.edgeId}
          </p>
          <dl>
            {entries.map(([label, value]) => (
              <div key={String(label)}>
                <dt>{String(label)}</dt>
                <dd>{String(value ?? "—")}</dd>
              </div>
            ))}
          </dl>
          {neighbors.length > 0 ? (
            <div className="cyvest-inspector__neighbors">
              <span>Connected observables · {neighbors.length}</span>
              <ul>
                {neighbors.map((neighbor) => (
                  <li key={`${neighbor.id}-${neighbor.type}`}>
                    <i>{neighbor.direction}</i>
                    <div><strong>{neighbor.label}</strong><small>{neighbor.type}</small></div>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : (
        <p className="cyvest-inspector__empty">
          Select an observable or relationship to inspect its role in the investigation.
        </p>
      )}
    </aside>
  );
}

/** Render the complete observable relationship explorer for an investigation. */
export const CyvestGraph: React.FC<CyvestGraphProps> = ({
  investigation,
  height = 500,
  width = "100%",
  className,
  theme,
  onCyReady,
  onNodeSelect,
  onEdgeSelect,
  physics = true,
  showToolbar = true,
  controls = "full",
  showInspector = controls === "full",
  filterState,
  onFilterStateChange,
  relationshipProfiles,
  layout,
  maxLabelLength = 28,
}) => {
  const [internalFilters, setInternalFilters] = useState<CyvestGraphFilterState>(() =>
    normalizeGraphFilters(filterState)
  );
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [selection, setSelection] = useState<GraphSelection | null>(null);
  const [cy, setCy] = useState<Core | null>(null);
  const [physicsEnabled, setPhysicsEnabled] = useState(physics);
  const filters = useMemo(
    () => ({ ...internalFilters, ...filterState }),
    [filterState, internalFilters]
  ) as CyvestGraphFilterState;

  const updateFilters = useCallback(
    (next: CyvestGraphFilterState) => {
      setInternalFilters(next);
      onFilterStateChange?.(next);
      setSelection(null);
    },
    [onFilterStateChange]
  );

  useEffect(() => setPhysicsEnabled(physics), [physics]);

  const observableTypes = useMemo(
    () => [...new Set(Object.values(getAllObservables(investigation)).map((item) => item.type))].sort(),
    [investigation]
  );
  const verdicts = useMemo(
    () =>
      VERDICT_FILTER_ORDER.filter((verdict) =>
        Object.keys(getAllObservables(investigation)).some(
          (key) => getObservableVerdict(investigation, key) === verdict
        )
      ),
    [investigation]
  );
  const relationKinds = useMemo(
    () => Object.keys(countRelationsByKind(investigation)).sort(),
    [investigation]
  );
  const visibleInvestigation = useMemo(
    () => filterInvestigation(investigation, filters),
    [filters, investigation]
  );

  const handleCyReady = useCallback(
    (instance: Core) => {
      setCy(instance);
      onCyReady?.(instance);
    },
    [onCyReady]
  );

  useEffect(() => {
    if (!cy) return;
    const query = filters.query.trim();
    cy.nodes().removeClass("cyvest-search-match cyvest-search-dimmed");
    if (!query) return;
    const matches = cy.nodes().filter((node) =>
      matchesGraphQuery(node.data() as Record<string, unknown>, query)
    );
    cy.nodes().addClass("cyvest-search-dimmed");
    matches.removeClass("cyvest-search-dimmed").addClass("cyvest-search-match");
  }, [cy, filters.query, visibleInvestigation]);

  const focusFirstMatch = useCallback(() => {
    if (!cy || !filters.query.trim()) return;
    const match = cy.nodes().filter((node) =>
      matchesGraphQuery(node.data() as Record<string, unknown>, filters.query)
    ).first();
    if (match.empty()) return;
    cy.animate({ center: { eles: match }, zoom: Math.max(1.15, cy.zoom()) }, { duration: 320 });
    match.select();
    match.emit("tap");
  }, [cy, filters.query]);

  const handleNode = useCallback((event: CyNodeSelectEvent) => {
    setSelection(event);
    onNodeSelect?.(event);
  }, [onNodeSelect]);
  const handleEdge = useCallback((event: CyEdgeSelectEvent) => {
    setSelection(event);
    onEdgeSelect?.(event);
  }, [onEdgeSelect]);

  const isFiltered =
    filters.observableTypes.length > 0 ||
    filters.verdicts.length > 0 ||
    filters.relationKinds.length > 0 ||
    filters.scope !== "all";
  // The technical root is scaffolding, not an observable the analyst gathered.
  const countPresentedObservables = (value: CyvestGraphProps["investigation"]) => {
    const rootKey = value.header.root_key;
    const observables = getAllObservables(value);
    return Object.keys(observables).length - (rootKey && observables[rootKey] ? 1 : 0);
  };
  const visibleCount = countPresentedObservables(visibleInvestigation);
  const totalCount = countPresentedObservables(investigation);
  const wrapperStyle = useMemo(
    () => createThemeStyle(theme, width, height),
    [height, theme, width]
  );

  return (
    <section
      className={joinClassNames("cyvest-explorer", className)}
      style={wrapperStyle}
      aria-label="Observable relationship explorer"
    >
      <div className="cyvest-explorer__main">
        {controls === "full" ? (
          <div className="cyvest-commandbar">
            <div className="cyvest-search">
              <Icon name="search" />
              <input
                value={filters.query}
                onChange={(event) => updateFilters({ ...filters, query: event.target.value })}
                onKeyDown={(event) => {
                  if (event.key === "Enter") focusFirstMatch();
                }}
                placeholder="Find an observable…"
                aria-label="Find an observable"
              />
              {filters.query ? (
                <button
                  type="button"
                  onClick={() => updateFilters({ ...filters, query: "" })}
                  aria-label="Clear search"
                >
                  <Icon name="close" />
                </button>
              ) : null}
            </div>
            <button
              type="button"
              className={joinClassNames("cyvest-commandbar__button", (filtersOpen || isFiltered) && "is-active")}
              onClick={() => setFiltersOpen((value) => !value)}
              aria-expanded={filtersOpen}
            >
              <Icon name="filter" />
              Filters
              {isFiltered ? <span className="cyvest-commandbar__badge" /> : null}
            </button>
            <button
              type="button"
              className={joinClassNames("cyvest-commandbar__button", physicsEnabled && "is-active")}
              onClick={() => setPhysicsEnabled((value) => !value)}
              aria-pressed={physicsEnabled}
              title={physicsEnabled ? "Pause physics" : "Resume physics"}
            >
              <Icon name="physics" />
              Physics
            </button>
            {isFiltered ? (
              <button
                type="button"
                className="cyvest-commandbar__icon"
                onClick={() => updateFilters({ ...EMPTY_GRAPH_FILTERS, query: filters.query })}
                aria-label="Reset filters"
                title="Reset filters"
              >
                <Icon name="reset" />
              </button>
            ) : null}
          </div>
        ) : null}

        {filtersOpen && controls === "full" ? (
          <div className="cyvest-filter-panel">
            <div className="cyvest-filter-panel__group">
              <span>Scope</span>
              <div className="cyvest-chipset">
                {(["all", "internal", "external", "allowlisted"] as const).map((scope) => (
                  <button
                    type="button"
                    key={scope}
                    className={filters.scope === scope ? "is-active" : undefined}
                    onClick={() => updateFilters({ ...filters, scope })}
                  >
                    {scope[0].toUpperCase() + scope.slice(1)}
                  </button>
                ))}
              </div>
            </div>
            <div className="cyvest-filter-panel__group">
              <span>Observable type</span>
              <div className="cyvest-chipset">
                {observableTypes.map((type) => (
                  <button
                    type="button"
                    key={type}
                    className={filters.observableTypes.includes(type) ? "is-active" : undefined}
                    onClick={() => updateFilters({ ...filters, observableTypes: toggleValue(filters.observableTypes, type) })}
                  >{type}</button>
                ))}
              </div>
            </div>
            <div className="cyvest-filter-panel__group">
              <span>Verdict</span>
              <div className="cyvest-chipset">
                {verdicts.map((verdict) => (
                  <button
                    type="button"
                    key={verdict}
                    className={filters.verdicts.includes(verdict) ? "is-active" : undefined}
                    onClick={() => updateFilters({ ...filters, verdicts: toggleValue(filters.verdicts, verdict) })}
                  >{verdict}</button>
                ))}
              </div>
            </div>
            <div className="cyvest-filter-panel__group">
              <span>Relationships</span>
              <div className="cyvest-chipset cyvest-chipset--relationships">
                {relationKinds.map((kind) => {
                  const profile = resolveRelationshipProfile(kind, { theme, overrides: relationshipProfiles });
                  const active = filters.relationKinds.length === 0 || filters.relationKinds.includes(kind);
                  return (
                    <button
                      type="button"
                      key={kind}
                      className={active ? "is-active" : undefined}
                      aria-pressed={active}
                      onClick={() => {
                        const current = filters.relationKinds.length === 0 ? relationKinds : filters.relationKinds;
                        const next = toggleValue(current, kind);
                        updateFilters({ ...filters, relationKinds: next.length === relationKinds.length ? [] : next });
                      }}
                    >
                      <i
                        data-line-style={profile.lineStyle}
                        style={{ borderColor: profile.color }}
                      />
                      {profile.label}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        ) : null}

        <CyvestObservablesView
          investigation={visibleInvestigation}
          width="100%"
          height="100%"
          theme={theme}
          onCyReady={handleCyReady}
          onNodeSelect={handleNode}
          onEdgeSelect={handleEdge}
          physics={physicsEnabled}
          showToolbar={controls !== "none" && showToolbar}
          layout={layout}
          maxLabelLength={maxLabelLength}
          relationshipProfiles={relationshipProfiles}
        />

        <div className="cyvest-graph-status">
          <span>{visibleCount} / {totalCount} observables</span>
          {filters.query ? <span>Press Enter to focus</span> : null}
        </div>
      </div>
      {showInspector ? (
        <Inspector
          selection={selection}
          investigation={investigation}
          onClear={() => setSelection(null)}
        />
      ) : null}
    </section>
  );
};
