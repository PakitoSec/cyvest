/**
 * Custom node component for the Investigation Graph (Dagre layout).
 * Renders root, check, and container nodes.
 */

import React, { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { InvestigationNodeData } from "../types";
import { getLevelColor, getLevelBackgroundColor } from "../utils/observables";

/**
 * Investigation node component.
 */
function InvestigationNodeComponent({
  data,
  selected,
}: NodeProps) {
  const nodeData = data as unknown as InvestigationNodeData;
  const {
    label,
    emoji,
    nodeType,
    level,
    description,
  } = nodeData;

  const borderColor = getLevelColor(level);
  const backgroundColor = getLevelBackgroundColor(level);

  // Different styles based on node type
  const getNodeStyle = () => {
    switch (nodeType) {
      case "root":
        return {
          minWidth: 120,
          padding: "8px 16px",
          borderRadius: 8,
          fontWeight: 600 as const,
        };
      case "check":
        return {
          minWidth: 100,
          padding: "6px 12px",
          borderRadius: 4,
          fontWeight: 400 as const,
        };
      case "container":
        return {
          minWidth: 100,
          padding: "6px 12px",
          borderRadius: 12,
          fontWeight: 400 as const,
        };
      default:
        return {
          minWidth: 80,
          padding: "6px 12px",
          borderRadius: 4,
          fontWeight: 400 as const,
        };
    }
  };

  const style = getNodeStyle();

  return (
    <div
      className="investigation-node"
      style={{
        ...style,
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        backgroundColor,
        border: `${selected ? 3 : 2}px solid ${borderColor}`,
        cursor: "pointer",
        fontFamily: "system-ui, sans-serif",
      }}
    >
      {/* Header with emoji and label */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
        }}
      >
        <span style={{ fontSize: 14 }}>{emoji}</span>
        <span
          style={{
            fontSize: 12,
            fontWeight: style.fontWeight,
            maxWidth: 150,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
          title={label}
        >
          {label}
        </span>
      </div>

      {/* Description for checks */}
      {description && (
        <div
          style={{
            marginTop: 4,
            fontSize: 10,
            color: "#6b7280",
            maxWidth: 140,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
          title={description}
        >
          {description}
        </div>
      )}

      {/* Handles for edges */}
      <Handle
        type="target"
        position={Position.Left}
        style={{
          width: 8,
          height: 8,
          background: borderColor,
        }}
      />
      <Handle
        type="source"
        position={Position.Right}
        style={{
          width: 8,
          height: 8,
          background: borderColor,
        }}
      />
    </div>
  );
}

export const InvestigationNode = memo(InvestigationNodeComponent);
