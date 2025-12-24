/**
 * CyvestGraph component - combined view with toggle between observables and investigation views.
 */

import React, { useState, useCallback, useMemo } from "react";
import type { CyvestGraphProps, InvestigationNodeType } from "../types";
import { ObservablesGraph } from "./ObservablesGraph";
import { InvestigationGraph } from "./InvestigationGraph";

/**
 * View toggle button component with modern design.
 */
const ViewToggle: React.FC<{
  currentView: "observables" | "investigation";
  onChange: (view: "observables" | "investigation") => void;
}> = ({ currentView, onChange }) => {
  const containerStyle: React.CSSProperties = useMemo(
    () => ({
      position: "absolute",
      top: 12,
      left: 12,
      display: "flex",
      gap: 2,
      background: "rgba(255, 255, 255, 0.95)",
      backdropFilter: "blur(8px)",
      padding: 4,
      borderRadius: 10,
      boxShadow: "0 2px 12px rgba(0,0,0,0.1)",
      zIndex: 10,
      fontFamily:
        "'SF Pro Text', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
      border: "1px solid rgba(0,0,0,0.06)",
    }),
    []
  );

  const getButtonStyle = useCallback(
    (isActive: boolean): React.CSSProperties => ({
      padding: "8px 14px",
      border: "none",
      borderRadius: 7,
      cursor: "pointer",
      fontSize: 12,
      fontWeight: isActive ? 600 : 500,
      background: isActive
        ? "linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)"
        : "transparent",
      color: isActive ? "white" : "#4b5563",
      transition: "all 0.15s ease",
      letterSpacing: "-0.01em",
    }),
    []
  );

  return (
    <div style={containerStyle}>
      <button
        onClick={() => onChange("observables")}
        style={getButtonStyle(currentView === "observables")}
        onMouseEnter={(e) => {
          if (currentView !== "observables") {
            e.currentTarget.style.background = "rgba(59, 130, 246, 0.1)";
            e.currentTarget.style.color = "#3b82f6";
          }
        }}
        onMouseLeave={(e) => {
          if (currentView !== "observables") {
            e.currentTarget.style.background = "transparent";
            e.currentTarget.style.color = "#4b5563";
          }
        }}
      >
        <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <circle cx="12" cy="12" r="3" />
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="2" x2="12" y2="4" />
            <line x1="12" y1="20" x2="12" y2="22" />
            <line x1="2" y1="12" x2="4" y2="12" />
            <line x1="20" y1="12" x2="22" y2="12" />
          </svg>
          Observables
        </span>
      </button>
      <button
        onClick={() => onChange("investigation")}
        style={getButtonStyle(currentView === "investigation")}
        onMouseEnter={(e) => {
          if (currentView !== "investigation") {
            e.currentTarget.style.background = "rgba(59, 130, 246, 0.1)";
            e.currentTarget.style.color = "#3b82f6";
          }
        }}
        onMouseLeave={(e) => {
          if (currentView !== "investigation") {
            e.currentTarget.style.background = "transparent";
            e.currentTarget.style.color = "#4b5563";
          }
        }}
      >
        <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <path d="M9 3v18" />
            <path d="M3 9h18" />
          </svg>
          Investigation
        </span>
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
  const [view, setView] = useState<"observables" | "investigation">(
    initialView
  );

  const handleNodeClick = useCallback(
    (nodeId: string, _nodeType?: InvestigationNodeType) => {
      onNodeClick?.(nodeId);
    },
    [onNodeClick]
  );

  const containerStyle: React.CSSProperties = useMemo(
    () => ({
      width,
      height,
      position: "relative",
    }),
    [width, height]
  );

  return (
    <div className={className} style={containerStyle}>
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
