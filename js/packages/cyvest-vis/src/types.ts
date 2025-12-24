/**
 * Type definitions for cyvest-vis visualization library.
 */

import type { Node, Edge } from "@xyflow/react";
import type { Level } from "@cyvest/cyvest-js";

// ============================================================================
// Observable Graph Types
// ============================================================================

/**
 * Shape types for observable nodes.
 * In the current design, all non-root nodes are circles.
 */
export type ObservableShape = "circle" | "rectangle";

/**
 * Data attached to observable graph nodes.
 */
export interface ObservableNodeData extends Record<string, unknown> {
  /** Display label (may be truncated) */
  label: string;
  /** Full observable value */
  fullValue: string;
  /** Observable type (e.g., "domain-name", "ipv4-addr") */
  observableType: string;
  /** Security level */
  level: Level;
  /** Numeric score */
  score: number;
  /** Shape for this node type */
  shape: ObservableShape;
  /** Whether this is the root observable */
  isRoot: boolean;
  /** Whether the observable is whitelisted */
  whitelisted: boolean;
  /** Whether the observable is internal */
  internal: boolean;
}

/**
 * Observable graph node type.
 */
export type ObservableNode = Node<ObservableNodeData, "observable">;

/**
 * Data attached to observable graph edges.
 */
export interface ObservableEdgeData extends Record<string, unknown> {
  /** Relationship type (e.g., "related-to") */
  relationshipType: string;
  /** Whether this is a bidirectional relationship */
  bidirectional: boolean;
}

/**
 * Observable graph edge type.
 */
export type ObservableEdge = Edge<ObservableEdgeData>;

// ============================================================================
// Investigation Graph Types (Dagre Layout)
// ============================================================================

/**
 * Node types for the investigation graph view.
 */
export type InvestigationNodeType = "root" | "check" | "container";

/**
 * Data attached to investigation graph nodes.
 */
export interface InvestigationNodeData extends Record<string, unknown> {
  /** Display label */
  label: string;
  /** Node type (root, check, or container) */
  nodeType: InvestigationNodeType;
  /** Security level */
  level: Level;
  /** Numeric score */
  score: number;
  /** Description (for checks) */
  description?: string;
  /** Path (for containers) */
  path?: string;
}

/**
 * Investigation graph node type.
 */
export type InvestigationNode = Node<InvestigationNodeData, "investigation">;

/**
 * Investigation graph edge type.
 */
export type InvestigationEdge = Edge;

// ============================================================================
// Force Layout Configuration
// ============================================================================

/**
 * Configuration options for d3-force layout.
 */
export interface ForceLayoutConfig {
  /** Strength of the charge force (repulsion). Default: -200 */
  chargeStrength: number;
  /** Target distance between linked nodes. Default: 80 */
  linkDistance: number;
  /** Strength of the centering force. Default: 0.05 */
  centerStrength: number;
  /** Radius for collision detection. Default: 40 */
  collisionRadius: number;
  /** Number of simulation iterations (for static layout). Default: 300 */
  iterations: number;
}

/**
 * Default force layout configuration.
 * Tuned for good visual separation and smooth animations.
 */
export const DEFAULT_FORCE_CONFIG: ForceLayoutConfig = {
  chargeStrength: -200,
  linkDistance: 80,
  centerStrength: 0.05,
  collisionRadius: 45,
  iterations: 300,
};

// ============================================================================
// Component Props
// ============================================================================

/**
 * Props for the ObservablesGraph component.
 */
export interface ObservablesGraphProps {
  /** The Cyvest investigation to visualize */
  investigation: import("@cyvest/cyvest-js").CyvestInvestigation;
  /** Height of the graph container */
  height?: number | string;
  /** Width of the graph container */
  width?: number | string;
  /** Force layout configuration */
  forceConfig?: Partial<ForceLayoutConfig>;
  /** Callback when a node is clicked */
  onNodeClick?: (nodeId: string) => void;
  /** Callback when a node is double-clicked */
  onNodeDoubleClick?: (nodeId: string) => void;
  /** Custom class name for the container */
  className?: string;
  /** Whether to show the force controls panel */
  showControls?: boolean;
}

/**
 * Props for the InvestigationGraph component.
 */
export interface InvestigationGraphProps {
  /** The Cyvest investigation to visualize */
  investigation: import("@cyvest/cyvest-js").CyvestInvestigation;
  /** Height of the graph container */
  height?: number | string;
  /** Width of the graph container */
  width?: number | string;
  /** Callback when a node is clicked */
  onNodeClick?: (nodeId: string, nodeType: InvestigationNodeType) => void;
  /** Custom class name for the container */
  className?: string;
}

/**
 * Props for the CyvestGraph component (combined view).
 */
export interface CyvestGraphProps {
  /** The Cyvest investigation to visualize */
  investigation: import("@cyvest/cyvest-js").CyvestInvestigation;
  /** Height of the graph container */
  height?: number | string;
  /** Width of the graph container */
  width?: number | string;
  /** Initial view to display */
  initialView?: "observables" | "investigation";
  /** Callback when a node is clicked */
  onNodeClick?: (nodeId: string) => void;
  /** Custom class name for the container */
  className?: string;
  /** Whether to show view toggle */
  showViewToggle?: boolean;
}
