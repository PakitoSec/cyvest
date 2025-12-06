import type { CyvestInvestigation } from "@cyvest/cyvest-js";
import { CyvestGraph } from "@cyvest/cyvest-vis";
import React, { useEffect, useState } from "react";
import { loadInvestigation, INVESTIGATIONS, type InvestigationKey } from "./api";

export const App: React.FC = () => {
  const [investigation, setInvestigation] =
    useState<CyvestInvestigation | null>(null);
  const [selectedKey, setSelectedKey] = useState<InvestigationKey>("cyvest_visual");
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setSelectedNodeId(null);
    loadInvestigation(selectedKey)
      .then(setInvestigation)
      .catch((err) => {
        console.error(err);
        setError("Failed to load investigation");
      })
      .finally(() => setLoading(false));
  }, [selectedKey]);

  if (error) return <div style={{ padding: 16, color: "red" }}>{error}</div>;

  return (
    <div style={{ padding: 16, fontFamily: "system-ui, sans-serif" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>Cyvest Demo</h1>
        <select
          value={selectedKey}
          onChange={(e) => setSelectedKey(e.target.value as InvestigationKey)}
          style={{
            padding: "8px 12px",
            fontSize: 14,
            borderRadius: 6,
            border: "1px solid #d1d5db",
            background: "white",
            cursor: "pointer",
          }}
        >
          {Object.entries(INVESTIGATIONS).map(([key, { name }]) => (
            <option key={key} value={key}>
              {name}
            </option>
          ))}
        </select>
      </div>

      {loading ? (
        <div style={{ padding: 16 }}>Loading…</div>
      ) : investigation ? (
        <>
          <h2>Score {investigation.score} • Level {investigation.level}</h2>

          <CyvestGraph
            investigation={investigation}
            height={500}
            onNodeClick={setSelectedNodeId}
            showViewToggle={true}
          />

          {selectedNodeId && (
            <div style={{ marginTop: 16, padding: 12, background: "#f3f4f6", borderRadius: 8 }}>
              <strong>Selected node:</strong> {selectedNodeId}
            </div>
          )}
        </>
      ) : null}
    </div>
  );
};