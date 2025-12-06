/**
 * CyvestGraph component - combined view with toggle between observables and investigation views.
 */

import React, { useState, useCallback } from "react";
import type { CyvestGraphProps, InvestigationNodeType } from "../types";
import { ObservablesGraph } from "./ObservablesGraph";
import { InvestigationGraph } from "./InvestigationGraph";

/**
 * View toggle button component.
 */
const ViewToggle: React.FC<{
  currentView: "observables" | "investigation";
  onChange: (view: "observables" | "investigation") => void;
}> = ({ currentView, onChange }) => {
  return (
    <div
      style={{
        position: "absolute",
        top: 10,
        left: 10,
        display: "flex",
        gap: 4,
        background: "white",
        padding: 4,
        borderRadius: 8,
        boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
        zIndex: 10,
        fontFamily: "system-ui, sans-serif",
      }}
    >
      <button
        onClick={() => onChange("observables")}
        style={{
          padding: "6px 12px",
          border: "none",
          borderRadius: 4,
          cursor: "pointer",
          fontSize: 12,
          fontWeight: currentView === "observables" ? 600 : 400,
          background: currentView === "observables" ? "#3b82f6" : "#f3f4f6",
          color: currentView === "observables" ? "white" : "#374151",
        }}
      >
        Observables
      </button>
      <button
        onClick={() => onChange("investigation")}
        style={{
          padding: "6px 12px",
          border: "none",
          borderRadius: 4,
          cursor: "pointer",
          fontSize: 12,
          fontWeight: currentView === "investigation" ? 600 : 400,
          background: currentView === "investigation" ? "#3b82f6" : "#f3f4f6",
          color: currentView === "investigation" ? "white" : "#374151",
        }}
      >
        Investigation
      </button>
    </div>
  );
};

/**
 * CyvestGraph component - provides toggle between ObservablesGraph and InvestigationGraph.
 */
export const CyvestGraph: React.FC<CyvestGraphProps> = ({
  investigation,
  height = 500,
  width = "100%",
  initialView = "observables",
  onNodeClick,
  className,
  showViewToggle = true,
}) => {
  const [view, setView] = useState<"observables" | "investigation">(initialView);

  const handleNodeClick = useCallback(
    (nodeId: string, _nodeType?: InvestigationNodeType) => {
      onNodeClick?.(nodeId);
    },
    [onNodeClick]
  );

  return (
    <div
      className={className}
      style={{
        width,
        height,
        position: "relative",
      }}
    >
      {showViewToggle && <ViewToggle currentView={view} onChange={setView} />}

      {view === "observables" ? (
        <ObservablesGraph
          investigation={investigation}
          height="100%"
          width="100%"
          onNodeClick={handleNodeClick}
          showControls={true}
        />
      ) : (
        <InvestigationGraph
          investigation={investigation}
          height="100%"
          width="100%"
          onNodeClick={handleNodeClick}
        />
      )}
    </div>
  );
};
