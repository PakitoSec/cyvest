/**
 * Cyvest Visualization Library
 *
 * React components for visualizing Cyvest investigations using React Flow.
 *
 * @packageDocumentation
 */

// Main component exports
export { CyvestGraph } from "./components/CyvestGraph";
export { ObservablesGraph } from "./components/ObservablesGraph";
export { InvestigationGraph } from "./components/InvestigationGraph";

// Icon exports for customization
export {
  getObservableIcon,
  getInvestigationIcon,
  OBSERVABLE_ICON_MAP,
  INVESTIGATION_ICON_MAP,
  type IconProps,
} from "./components/Icons";

// Re-export types for consumers
export type {
  CyvestGraphProps,
  ObservablesGraphProps,
  InvestigationGraphProps,
  ForceLayoutConfig,
  ObservableNodeData,
  ObservableEdgeData,
  InvestigationNodeData,
  InvestigationNodeType,
  ObservableShape,
} from "./types";

export { DEFAULT_FORCE_CONFIG } from "./types";
