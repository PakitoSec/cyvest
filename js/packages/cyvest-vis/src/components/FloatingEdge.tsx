/**
 * Floating Edge component for use with force-directed layout.
 * Uses simple straight lines that connect to node edges.
 */

import React, { memo } from "react";
import { BaseEdge, getStraightPath, type EdgeProps } from "@xyflow/react";

/**
 * Floating edge component that uses straight lines.
 * React Flow passes sourceX, sourceY, targetX, targetY based on node positions.
 */
function FloatingEdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  style,
  markerEnd,
}: EdgeProps) {
  const [edgePath] = getStraightPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
  });

  return (
    <BaseEdge
      id={id}
      path={edgePath}
      style={{
        strokeWidth: 1.5,
        stroke: "#94a3b8",
        ...style,
      }}
      markerEnd={markerEnd}
    />
  );
}

export const FloatingEdge = memo(FloatingEdgeComponent);
