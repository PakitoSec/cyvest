/**
 * Custom node component for the Investigation Graph (Dagre layout).
 * Professional design with SVG icons for root, check, and container nodes.
 */

import React, { memo, useMemo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { InvestigationNodeData } from "../types";
import { getLevelColor, getLevelBackgroundColor } from "../utils/observables";
import { getInvestigationIcon } from "./Icons";

/**
 * Node style configuration by type
 */
const NODE_CONFIG = {
  root: {
    minWidth: 140,
    padding: "10px 18px",
    borderRadius: 20,
    fontWeight: 600 as const,
    fontSize: 13,
    iconSize: 18,
    showIcon: true,
    alignCenter: true,
  },
  check: {
    minWidth: 140,
    padding: "8px 14px",
    borderRadius: 8,
    fontWeight: 500 as const,
    fontSize: 12,
    iconSize: 14,
    showIcon: false, // No icon for checks
    alignCenter: false, // Left-aligned
  },
  container: {
    minWidth: 120,
    padding: "8px 14px",
    borderRadius: 16,
    fontWeight: 500 as const,
    fontSize: 12,
    iconSize: 16,
    showIcon: true,
    alignCenter: true,
  },
} as const;

/**
 * Investigation node component with professional design.
 */
function InvestigationNodeComponent({ data, selected }: NodeProps) {
  const nodeData = data as unknown as InvestigationNodeData;
  const { label, nodeType, level, description } = nodeData;

  const borderColor = getLevelColor(level);
  const backgroundColor = getLevelBackgroundColor(level);
  const config = NODE_CONFIG[nodeType] || NODE_CONFIG.check;

  // Get the appropriate icon component
  const IconComponent = useMemo(
    () => getInvestigationIcon(nodeType),
    [nodeType]
  );

  // Memoize node style
  const nodeStyle = useMemo(
    () => ({
      minWidth: config.minWidth,
      padding: config.padding,
      borderRadius: config.borderRadius,
      display: "flex",
      flexDirection: "column" as const,
      alignItems: config.alignCenter ? "center" : "flex-start",
      backgroundColor,
      border: `2px solid ${borderColor}`,
      boxShadow: selected
        ? `0 0 0 3px ${borderColor}40, 0 4px 12px rgba(0,0,0,0.15)`
        : "0 2px 8px rgba(0,0,0,0.08)",
      cursor: "pointer",
      fontFamily:
        "'SF Pro Text', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
      transition: "box-shadow 0.15s ease-out, transform 0.1s ease-out",
    }),
    [config, backgroundColor, borderColor, selected]
  );

  const headerStyle = useMemo(
    () => ({
      display: "flex",
      alignItems: "center",
      gap: 8,
      width: config.alignCenter ? "auto" : "100%",
    }),
    [config.alignCenter]
  );

  const labelStyle = useMemo(
    () => ({
      fontSize: config.fontSize,
      fontWeight: config.fontWeight,
      maxWidth: 180,
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap" as const,
      color: "#1f2937",
      letterSpacing: "-0.01em",
    }),
    [config]
  );

  const descriptionStyle = useMemo(
    () => ({
      marginTop: 4,
      fontSize: 10,
      color: "#6b7280",
      maxWidth: 170,
      overflow: "hidden",
      textOverflow: "ellipsis",
      whiteSpace: "nowrap" as const,
      lineHeight: 1.3,
      width: "100%",
      textAlign: config.alignCenter ? ("center" as const) : ("left" as const),
    }),
    [config.alignCenter]
  );

  // Hidden handle style - edges connect but no visible dots
  const handleStyle: React.CSSProperties = {
    width: 1,
    height: 1,
    background: "transparent",
    border: "none",
    opacity: 0,
  };

  return (
    <div className="investigation-node" style={nodeStyle}>
      {/* Header with optional icon and label */}
      <div style={headerStyle}>
        {config.showIcon && (
          <IconComponent size={config.iconSize} color={borderColor} />
        )}
        <span style={labelStyle} title={label}>
          {label}
        </span>
      </div>

      {/* Description for checks */}
      {description && (
        <div style={descriptionStyle} title={description}>
          {description}
        </div>
      )}

      {/* Hidden handles for edges - edges still connect but no visible dots */}
      <Handle type="target" position={Position.Left} style={handleStyle} />
      <Handle type="source" position={Position.Right} style={handleStyle} />
    </div>
  );
}

export const InvestigationNode = memo(InvestigationNodeComponent);
