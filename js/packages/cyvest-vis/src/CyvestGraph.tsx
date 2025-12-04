import type { CyvestInvestigation, Observable } from "@cyvest/cyvest-js";
import React from "react";

export interface CyvestGraphProps {
  investigation: CyvestInvestigation;
  height?: number | string;
  onNodeClick?: (nodeId: string) => void;
}

export const CyvestGraph: React.FC<CyvestGraphProps> = ({
  investigation,
  height = 400,
  onNodeClick,
}) => {
  return (
    <div style={{ border: "1px solid #ddd", borderRadius: 4, padding: 8 }}>
      <div style={{ marginBottom: 8 }}>
        Graph: {Object.keys(investigation.observables).length} observables,{" "}
        {Object.keys(investigation.checks).length} edges
      </div>
      <div style={{ height, overflow: "auto", fontSize: 12 }}>
        {Object.values(investigation.observables).map((node: Observable) => (
          <div
            key={node.key}
            style={{
              padding: "2px 4px",
              cursor: onNodeClick ? "pointer" : "default",
            }}
            onClick={() => onNodeClick?.(node.value)}
          >
            • {node.level} — {"label" in node ? (node as any).label : ""}
          </div>
        ))}
      </div>
    </div>
  );
};
