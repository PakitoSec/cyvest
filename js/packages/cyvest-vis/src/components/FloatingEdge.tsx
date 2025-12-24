/**
 * Floating Edge component for use with force-directed layout.
 * Uses smooth bezier curves that connect to node centers.
 */

import React, { memo, useMemo } from "react";
import { BaseEdge, getBezierPath, type EdgeProps } from "@xyflow/react";

/**
 * Calculate control point offset based on distance.
 * Longer edges get more curve for better visibility.
 */
function getControlOffset(
  sourceX: number,
  sourceY: number,
  targetX: number,
  targetY: number
): number {
  const dx = targetX - sourceX;
  const dy = targetY - sourceY;
  const distance = Math.sqrt(dx * dx + dy * dy);
  // Scale curve intensity with distance, capped
  return Math.min(Math.max(distance * 0.15, 20), 60);
}

/**
 * Floating edge component with smooth bezier curves.
 * The curve adapts to the edge length for optimal visibility.
 */
function FloatingEdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  style,
  markerEnd,
  selected,
}: EdgeProps) {
  const offset = useMemo(
    () => getControlOffset(sourceX, sourceY, targetX, targetY),
    [sourceX, sourceY, targetX, targetY]
  );

  const [edgePath] = getBezierPath({
    sourceX,
    sourceY,
    targetX,
    targetY,
    curvature: 0.15,
  });

  const edgeStyle = useMemo(
    () => ({
      strokeWidth: selected ? 2.5 : 1.5,
      stroke: selected ? "#3b82f6" : "#94a3b8",
      transition: "stroke 0.15s ease, stroke-width 0.15s ease",
      ...style,
    }),
    [selected, style]
  );

  return (
    <BaseEdge
      id={id}
      path={edgePath}
      style={edgeStyle}
      markerEnd={markerEnd}
    />
  );
}

export const FloatingEdge = memo(FloatingEdgeComponent);
