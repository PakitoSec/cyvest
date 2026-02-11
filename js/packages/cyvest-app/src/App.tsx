import type { CyvestInvestigation } from "@cyvest/cyvest-js";
import { getStartedAt } from "@cyvest/cyvest-js";
import { CyvestGraph, type CyNodeSelectEvent } from "@cyvest/cyvest-vis";
import React, { useEffect, useState } from "react";
import { loadInvestigation, INVESTIGATIONS, type InvestigationKey } from "./api";

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

  if (error) {
    return <div style={{ padding: 16, color: "#b91c1c" }}>{error}</div>;
  }

  return (
    <div
      style={{
        height: "100%",
        display: "flex",
        flexDirection: "column",
        fontFamily:
          "'IBM Plex Sans', 'Segoe UI', 'Helvetica Neue', Arial, sans-serif",
        background: "#eff3f8",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 16,
          padding: 16,
        }}
      >
        <h1 style={{ margin: 0, color: "#0f172a" }}>Cyvest Demo</h1>
        <select
          value={selectedKey}
          onChange={(event) =>
            setSelectedKey(event.target.value as InvestigationKey)
          }
          style={{
            padding: "8px 12px",
            fontSize: 14,
            borderRadius: 8,
            border: "1px solid #cfd7e4",
            background: "#ffffff",
            cursor: "pointer",
            color: "#12213a",
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
        <div style={{ padding: 16, color: "#334155" }}>Loading…</div>
      ) : investigation ? (
        <>
          <div style={{ padding: "0 16px 8px" }}>
            <h2 style={{ margin: 0, color: "#0f172a" }}>
              {investigation.investigation_name ?? investigation.investigation_id}
            </h2>
            <div style={{ color: "#5a667f", fontSize: 13, marginTop: 4 }}>
              <span>Score {investigation.score_display}</span>
              <span> | Level {investigation.level}</span>
              <span> | Started {getStartedAt(investigation) ?? "N/A"}</span>
            </div>
          </div>

          <div style={{ flex: 1, minHeight: 0, padding: "0 16px 0" }}>
            <CyvestGraph
              investigation={investigation}
              height="100%"
              onNodeSelect={setSelectedNode}
              showViewToggle={true}
              showToolbar={true}
              observablesLayout={{
                algorithm: "stress",
                spacingNodeNode: 72,
              }}
              investigationLayout={{
                algorithm: "layered",
                direction: "RIGHT",
              }}
            />
          </div>

          {selectedNode && (
            <div
              style={{
                margin: "12px 16px 16px",
                padding: 12,
                borderRadius: 10,
                border: "1px solid #cfd7e4",
                background: "#ffffff",
                color: "#172033",
                fontSize: 13,
              }}
            >
              <strong>Selected node:</strong> {selectedNode.label}
              <span style={{ color: "#5a667f" }}>
                {" "}
                ({selectedNode.nodeType}, {selectedNode.nodeId})
              </span>
            </div>
          )}
        </>
      ) : null}
    </div>
  );
};
