/**
 * Custom node component for the Observables Graph.
 * Renders nodes with different shapes based on observable type.
 */

import React, { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { ObservableNodeData, ObservableShape } from "../types";
import { getLevelColor, getLevelBackgroundColor } from "../utils/observables";

/**
 * Node size constants - keep small for nice force layout
 */
const NODE_SIZE = 28;
const ROOT_NODE_SIZE = 36;

/**
 * Observable node component with centered connection points.
 */
function ObservableNodeComponent({
  data,
  selected,
}: NodeProps) {
  const nodeData = data as unknown as ObservableNodeData;
  const {
    label,
    emoji,
    shape,
    level,
    isRoot,
    whitelisted,
    fullValue,
  } = nodeData;

  const size = isRoot ? ROOT_NODE_SIZE : NODE_SIZE;
  const borderColor = getLevelColor(level);
  const backgroundColor = getLevelBackgroundColor(level);

  // Get shape styles
  const getShapeStyle = (): React.CSSProperties => {
    const baseStyle: React.CSSProperties = {
      width: size,
      height: size,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      backgroundColor,
      border: `${selected ? 3 : 2}px solid ${borderColor}`,
      opacity: whitelisted ? 0.5 : 1,
      fontSize: isRoot ? 14 : 12,
    };

    switch (shape) {
      case "square":
        return { ...baseStyle, borderRadius: 4 };
      case "circle":
        return { ...baseStyle, borderRadius: "50%" };
      case "triangle":
        // Use clip-path for triangle
        return {
          ...baseStyle,
          borderRadius: 0,
          border: "none",
          background: `linear-gradient(to bottom right, ${backgroundColor} 50%, transparent 50%)`,
          clipPath: "polygon(50% 0%, 100% 100%, 0% 100%)",
          position: "relative",
        };
      case "rectangle":
      default:
        return { ...baseStyle, width: size * 1.4, borderRadius: 6 };
    }
  };

  // For triangle, we need a different approach
  const isTriangle = shape === "triangle";

  return (
    <div
      className="observable-node"
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        cursor: "pointer",
      }}
    >
      {/* Shape container */}
      <div style={{ position: "relative" }}>
        {isTriangle ? (
          // Triangle using SVG
          <svg width={size} height={size} viewBox="0 0 100 100">
            <polygon
              points="50,10 90,90 10,90"
              fill={backgroundColor}
              stroke={borderColor}
              strokeWidth={selected ? 6 : 4}
              opacity={whitelisted ? 0.5 : 1}
            />
            <text
              x="50"
              y="65"
              textAnchor="middle"
              fontSize="32"
              dominantBaseline="middle"
            >
              {emoji}
            </text>
          </svg>
        ) : (
          // Other shapes using CSS
          <div style={getShapeStyle()}>
            <span style={{ userSelect: "none" }}>{emoji}</span>
          </div>
        )}

        {/* Center handle for source connections */}
        <Handle
          type="source"
          position={Position.Right}
          id="source"
          style={{
            position: "absolute",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: 1,
            height: 1,
            background: "transparent",
            border: "none",
            opacity: 0,
          }}
        />
        {/* Center handle for target connections */}
        <Handle
          type="target"
          position={Position.Left}
          id="target"
          style={{
            position: "absolute",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: 1,
            height: 1,
            background: "transparent",
            border: "none",
            opacity: 0,
          }}
        />
      </div>

      {/* Label below the shape */}
      <div
        style={{
          marginTop: 2,
          fontSize: 9,
          maxWidth: 70,
          textAlign: "center",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          color: "#374151",
          fontFamily: "system-ui, sans-serif",
        }}
        title={fullValue}
      >
        {label}
      </div>
    </div>
  );
}

export const ObservableNode = memo(ObservableNodeComponent);
