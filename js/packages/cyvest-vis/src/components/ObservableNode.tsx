/**
 * Custom node component for the Observables Graph.
 * Professional design with circular nodes and SVG icons.
 */

import React, { memo, useMemo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import type { ObservableNodeData } from "../types";
import { getLevelColor, getLevelBackgroundColor } from "../utils/observables";
import { getObservableIcon, CrosshairIcon } from "./Icons";

/**
 * Node size constants
 */
const NODE_SIZE = 40;
const ROOT_NODE_WIDTH = 56;
const ROOT_NODE_HEIGHT = 40;
const ICON_SIZE = 18;
const ROOT_ICON_SIZE = 20;

/**
 * CSS styles for the node
 */
const nodeStyles = {
  container: {
    display: "flex",
    flexDirection: "column" as const,
    alignItems: "center",
    cursor: "grab",
    transition: "transform 0.1s ease-out",
  },
  shapeWrapper: {
    position: "relative" as const,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  label: {
    marginTop: 4,
    fontSize: 10,
    fontWeight: 500,
    maxWidth: 80,
    textAlign: "center" as const,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap" as const,
    fontFamily:
      "'SF Pro Text', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    letterSpacing: "-0.01em",
    lineHeight: 1.2,
  },
  handle: {
    position: "absolute" as const,
    top: "50%",
    left: "50%",
    transform: "translate(-50%, -50%)",
    width: 1,
    height: 1,
    background: "transparent",
    border: "none",
    opacity: 0,
    pointerEvents: "none" as const,
  },
};

/**
 * Observable node component with professional circular design.
 */
function ObservableNodeComponent({ data, selected }: NodeProps) {
  const nodeData = data as unknown as ObservableNodeData;
  const { label, level, isRoot, whitelisted, fullValue, observableType } =
    nodeData;

  const borderColor = getLevelColor(level);
  const backgroundColor = getLevelBackgroundColor(level);

  // Get the appropriate icon component
  const IconComponent = useMemo(() => {
    if (isRoot) return CrosshairIcon;
    return getObservableIcon(observableType);
  }, [isRoot, observableType]);

  // Memoize styles to prevent recalculation
  const shapeStyle = useMemo(() => {
    if (isRoot) {
      // Root node is a rounded rectangle (pill shape)
      return {
        width: ROOT_NODE_WIDTH,
        height: ROOT_NODE_HEIGHT,
        borderRadius: ROOT_NODE_HEIGHT / 2,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        backgroundColor,
        border: `2.5px solid ${borderColor}`,
        boxShadow: selected
          ? `0 0 0 3px ${borderColor}40, 0 4px 12px rgba(0,0,0,0.15)`
          : "0 2px 8px rgba(0,0,0,0.08)",
        opacity: whitelisted ? 0.5 : 1,
        transition: "box-shadow 0.15s ease-out, transform 0.1s ease-out",
      };
    }

    // All other nodes are circles
    return {
      width: NODE_SIZE,
      height: NODE_SIZE,
      borderRadius: "50%",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      backgroundColor,
      border: `2px solid ${borderColor}`,
      boxShadow: selected
        ? `0 0 0 3px ${borderColor}40, 0 4px 12px rgba(0,0,0,0.15)`
        : "0 2px 6px rgba(0,0,0,0.08)",
      opacity: whitelisted ? 0.5 : 1,
      transition: "box-shadow 0.15s ease-out, transform 0.1s ease-out",
    };
  }, [isRoot, backgroundColor, borderColor, selected, whitelisted]);

  const labelStyle = useMemo(
    () => ({
      ...nodeStyles.label,
      color: whitelisted ? "#9ca3af" : "#374151",
    }),
    [whitelisted]
  );

  return (
    <div className="observable-node" style={nodeStyles.container}>
      {/* Shape container */}
      <div style={nodeStyles.shapeWrapper}>
        <div style={shapeStyle}>
          <IconComponent
            size={isRoot ? ROOT_ICON_SIZE : ICON_SIZE}
            color={borderColor}
          />
        </div>

        {/* Hidden handles for edge connections - centered */}
        <Handle type="source" position={Position.Right} style={nodeStyles.handle} />
        <Handle type="target" position={Position.Left} style={nodeStyles.handle} />
      </div>

      {/* Label below the shape */}
      <div style={labelStyle} title={fullValue}>
        {label}
      </div>
    </div>
  );
}

export const ObservableNode = memo(ObservableNodeComponent);
