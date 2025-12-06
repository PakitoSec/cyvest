/**
 * Hook for computing Dagre layout (hierarchical).
 */

import { useMemo } from "react";
import Dagre from "@dagrejs/dagre";
import type { Node, Edge } from "@xyflow/react";

/**
 * Dagre layout options.
 */
export interface DagreLayoutOptions {
  /** Direction of the layout: TB (top-bottom), BT, LR (left-right), RL */
  direction?: "TB" | "BT" | "LR" | "RL";
  /** Horizontal spacing between nodes */
  nodeSpacing?: number;
  /** Vertical spacing between ranks */
  rankSpacing?: number;
}

const DEFAULT_OPTIONS: Required<DagreLayoutOptions> = {
  direction: "LR", // Horizontal layout by default
  nodeSpacing: 50,
  rankSpacing: 100,
};

/**
 * Apply Dagre layout to nodes and edges.
 */
export function computeDagreLayout(
  nodes: Node[],
  edges: Edge[],
  options: DagreLayoutOptions = {}
): { nodes: Node[]; edges: Edge[] } {
  if (nodes.length === 0) {
    return { nodes, edges };
  }

  const opts = { ...DEFAULT_OPTIONS, ...options };

  // Create dagre graph
  const g = new Dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));

  g.setGraph({
    rankdir: opts.direction,
    nodesep: opts.nodeSpacing,
    ranksep: opts.rankSpacing,
    marginx: 20,
    marginy: 20,
  });

  // Add nodes to graph
  for (const node of nodes) {
    // Estimate node dimensions
    const width = node.measured?.width ?? 150;
    const height = node.measured?.height ?? 50;
    g.setNode(node.id, { width, height });
  }

  // Add edges to graph
  for (const edge of edges) {
    g.setEdge(edge.source, edge.target);
  }

  // Compute layout
  Dagre.layout(g);

  // Update node positions
  const positionedNodes = nodes.map((node) => {
    const dagNode = g.node(node.id);
    // Dagre returns center positions, adjust for React Flow (top-left)
    const width = node.measured?.width ?? 150;
    const height = node.measured?.height ?? 50;
    return {
      ...node,
      position: {
        x: dagNode.x - width / 2,
        y: dagNode.y - height / 2,
      },
    };
  });

  return { nodes: positionedNodes, edges };
}

/**
 * Hook for Dagre layout computation.
 */
export function useDagreLayout(
  initialNodes: Node[],
  initialEdges: Edge[],
  options: DagreLayoutOptions = {}
): {
  nodes: Node[];
  edges: Edge[];
} {
  const { nodes, edges } = useMemo(() => {
    return computeDagreLayout(initialNodes, initialEdges, options);
  }, [initialNodes, initialEdges, options]);

  return { nodes, edges };
}
