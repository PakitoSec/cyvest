import type { CyvestInvestigation } from "@cyvest/cyvest-js";
import { CyvestGraph } from "@cyvest/cyvest-vis";
import React, { useEffect, useState } from "react";
import { loadInvestigation } from "./api";

export const App: React.FC = () => {
  const [investigation, setInvestigation] =
    useState<CyvestInvestigation | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadInvestigation()
      .then(setInvestigation)
      .catch((err) => {
        console.error(err);
        setError("Failed to load investigation");
      });
  }, []);

  if (error) return <div style={{ padding: 16, color: "red" }}>{error}</div>;
  if (!investigation) return <div style={{ padding: 16 }}>Loading…</div>;

  return (
    <div style={{ padding: 16, fontFamily: "system-ui, sans-serif" }}>
      <h1>Cyvest Demo</h1>
      <h2>Score {investigation.score}</h2>

      <CyvestGraph
        investigation={investigation}
        height={300}
        onNodeClick={setSelectedNodeId}
      />

      {selectedNodeId && (
        <div style={{ marginTop: 16 }}>
          <strong>Selected node:</strong> {selectedNodeId}
        </div>
      )}
    </div>
  );
};
