import {
  getAllEvidences,
  getAllFindings,
  getAllObservables,
  getGlobalScore,
  getGlobalVerdict,
  type Investigation,
} from "@cyvest/cyvest-js";
import {
  CyvestGraph,
  DARK_CYVEST_THEME,
} from "@cyvest/cyvest-vis";
import React, { useEffect, useState } from "react";

import { loadInvestigation, INVESTIGATIONS, type InvestigationKey } from "./api";

export const App: React.FC = () => {
  const [investigation, setInvestigation] =
    useState<Investigation | null>(null);
  const [selectedKey, setSelectedKey] =
    useState<InvestigationKey>("cyvest_visual");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [darkMode, setDarkMode] = useState(false);

  useEffect(() => {
    setLoading(true);
    setError(null);
    loadInvestigation(selectedKey)
      .then(setInvestigation)
      .catch((err) => {
        console.error(err);
        setError("Failed to load investigation");
      })
      .finally(() => setLoading(false));
  }, [selectedKey]);

  return (
    <main className="app-shell" data-theme={darkMode ? "dark" : "light"}>
      <header className="app-header">
        <div>
          <div className="app-eyebrow">CYVEST</div>
          <h1>Observable graph</h1>
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
                {investigation.header.name || investigation.header.investigation_id}
              </h2>
              <p>
                Schema {investigation.schema_version} · engine {investigation.report.engine_id}
              </p>
            </div>
            <dl className="app-metrics">
              <div>
                <dt>Verdict</dt>
                <dd>{getGlobalVerdict(investigation)}</dd>
              </div>
              <div>
                <dt>Score</dt>
                <dd>{getGlobalScore(investigation).toFixed(2)}</dd>
              </div>
              <div>
                <dt>Observables</dt>
                <dd>{Object.keys(getAllObservables(investigation)).length}</dd>
              </div>
              <div>
                <dt>Findings</dt>
                <dd>{Object.keys(getAllFindings(investigation)).length}</dd>
              </div>
              <div>
                <dt>Evidence</dt>
                <dd>{Object.keys(getAllEvidences(investigation)).length}</dd>
              </div>
            </dl>
          </section>

          <section className="app-workspace">
            <div className="app-graph">
              <CyvestGraph
                investigation={investigation}
                height="100%"
                theme={darkMode ? DARK_CYVEST_THEME : undefined}
                controls="full"
                showInspector
              />
            </div>
          </section>
        </>
      ) : null}
    </main>
  );
};
