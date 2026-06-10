import type { CyvestInvestigation } from "@cyvest/cyvest-js";
import { getStartedAt } from "@cyvest/cyvest-js";
import {
  CyvestGraph,
  DARK_CYVEST_THEME,
  type CyNodeSelectEvent,
} from "@cyvest/cyvest-vis";
import React, { useEffect, useMemo, useState } from "react";

import { loadInvestigation, INVESTIGATIONS, type InvestigationKey } from "./api";

function formatNodeValue(value: unknown): string | null {
  if (value === undefined || value === null || value === "") {
    return null;
  }
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(2);
  }
  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }
  return String(value);
}

export const App: React.FC = () => {
  const [investigation, setInvestigation] =
    useState<CyvestInvestigation | null>(null);
  const [selectedKey, setSelectedKey] =
    useState<InvestigationKey>("cyvest_visual");
  const [selectedNode, setSelectedNode] = useState<CyNodeSelectEvent | null>(
    null
  );
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [darkMode, setDarkMode] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setSelectedNode(null);
    loadInvestigation(selectedKey)
      .then(setInvestigation)
      .catch((err) => {
        console.error(err);
        setError("Failed to load investigation");
      })
      .finally(() => setLoading(false));
  }, [selectedKey]);

  const selectedDetails = useMemo(() => {
    if (!selectedNode) return [];
    return [
      ["Type", selectedNode.nodeType],
      ["Level", selectedNode.data.level],
      ["Score", selectedNode.data.score],
      ["Observable type", selectedNode.data.observableType],
      ["Internal", selectedNode.data.internal],
      ["Whitelisted", selectedNode.data.whitelisted],
    ]
      .map(([label, value]) => [label, formatNodeValue(value)] as const)
      .filter((entry): entry is readonly [string, string] => entry[1] !== null);
  }, [selectedNode]);

  return (
    <main className="app-shell" data-theme={darkMode ? "dark" : "light"}>
      <header className="app-header">
        <div>
          <div className="app-eyebrow">CYVEST</div>
          <h1>Investigation graph</h1>
        </div>
        <div className="app-header__controls">
          <button
            type="button"
            className="app-theme-toggle"
            aria-pressed={darkMode}
            onClick={() => setDarkMode((value) => !value)}
          >
            {darkMode ? "Light mode" : "Dark mode"}
          </button>
          <label className="app-investigation-picker">
            <span>Dataset</span>
            <select
              value={selectedKey}
              onChange={(event) =>
                setSelectedKey(event.target.value as InvestigationKey)
              }
            >
              {Object.entries(INVESTIGATIONS).map(([key, { name }]) => (
                <option key={key} value={key}>
                  {name}
                </option>
              ))}
            </select>
          </label>
        </div>
      </header>

      {error ? <div className="app-state app-state--error">{error}</div> : null}
      {loading ? <div className="app-state">Loading investigation…</div> : null}

      {!loading && investigation ? (
        <>
          <section className="app-summary">
            <div>
              <h2>
                {investigation.investigation_name ??
                  investigation.investigation_id}
              </h2>
              <p>
                Started {getStartedAt(investigation) ?? "N/A"} · Schema{" "}
                {investigation.schema_version}
              </p>
            </div>
            <dl className="app-metrics">
              <div>
                <dt>Level</dt>
                <dd>{investigation.level}</dd>
              </div>
              <div>
                <dt>Score</dt>
                <dd>{investigation.score_display}</dd>
              </div>
              <div>
                <dt>Observables</dt>
                <dd>{Object.keys(investigation.observables).length}</dd>
              </div>
              <div>
                <dt>Findings</dt>
                <dd>{Object.keys(investigation.findings).length}</dd>
              </div>
              <div>
                <dt>Evidence</dt>
                <dd>{Object.keys(investigation.evidences).length}</dd>
              </div>
            </dl>
          </section>

          <section className="app-workspace">
            <div className="app-graph">
              <CyvestGraph
                investigation={investigation}
                height="100%"
                theme={darkMode ? DARK_CYVEST_THEME : undefined}
                onNodeSelect={setSelectedNode}
                showViewToggle
                showToolbar
                observablesLayout={{
                  linkDistance: 116,
                  radialStep: 126,
                }}
                investigationLayout={{
                  linkDistance: 132,
                  radialStep: 142,
                }}
              />
            </div>

            <aside className="app-inspector" aria-live="polite">
              <div className="app-inspector__heading">
                <span>Selection</span>
                {selectedNode ? (
                  <button type="button" onClick={() => setSelectedNode(null)}>
                    Clear
                  </button>
                ) : null}
              </div>
              {selectedNode ? (
                <>
                  <h3>{selectedNode.label}</h3>
                  <p className="app-inspector__id">{selectedNode.nodeId}</p>
                  <dl>
                    {selectedDetails.map(([label, value]) => (
                      <div key={label}>
                        <dt>{label}</dt>
                        <dd>{value}</dd>
                      </div>
                    ))}
                  </dl>
                </>
              ) : (
                <p className="app-inspector__empty">
                  Select a node to inspect its identity, score, and graph role.
                  Hover a node to isolate its immediate neighborhood.
                </p>
              )}
            </aside>
          </section>
        </>
      ) : null}
    </main>
  );
};
