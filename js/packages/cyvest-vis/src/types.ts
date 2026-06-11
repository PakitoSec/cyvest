import type { CyvestInvestigation, Level, RelationshipDirection } from "@cyvest/cyvest-js";
import type { Core, EdgeSingular, NodeSingular } from "cytoscape";

export interface CyvestThemeTokens {
  background: string;
  gridColor: string;
  panelBackground: string;
  panelBorder: string;
  panelText: string;
  panelTextMuted: string;
  accent: string;
  edgeColor: string;
  edgeSelectedColor: string;
  fontFamily: string;
  /** Default fill for internal observable nodes. */
  nodeSurface: string;
  /** Root node fill. */
  rootSurface: string;
  /** Icon/text color used on the root node. */
  rootText: string;
  /** Primary icon stroke color. */
  iconColor: string;
  /** Muted icon stroke color (non-root nodes). */
  iconMutedColor: string;
  /** Color that level-based backgrounds are mixed toward. */
  levelSurfaceMix: string;
  /** Mix ratio (0-1) toward {@link levelSurfaceMix}. */
  levelSurfaceMixRatio: number;
}

export const DEFAULT_CYVEST_THEME: CyvestThemeTokens = {
  background: "#f8fafc",
  gridColor: "#e2e8f0",
  panelBackground: "rgba(255, 255, 255, 0.97)",
  panelBorder: "#e2e8f0",
  panelText: "#0f172a",
  panelTextMuted: "#64748b",
  accent: "#334155",
  edgeColor: "#cbd5e1",
  edgeSelectedColor: "#475569",
  fontFamily:
    "IBM Plex Sans, Segoe UI, Helvetica Neue, Arial, sans-serif",
  nodeSurface: "#ffffff",
  rootSurface: "#1e293b",
  rootText: "#ffffff",
  iconColor: "#314264",
  iconMutedColor: "#475569",
  levelSurfaceMix: "#ffffff",
  levelSurfaceMixRatio: 0.94,
};

export const DARK_CYVEST_THEME: CyvestThemeTokens = {
  background: "#0f172a",
  gridColor: "#1e293b",
  panelBackground: "rgba(15, 23, 42, 0.97)",
  panelBorder: "#334155",
  panelText: "#e2e8f0",
  panelTextMuted: "#94a3b8",
  accent: "#cbd5e1",
  edgeColor: "#475569",
  edgeSelectedColor: "#cbd5e1",
  fontFamily:
    "IBM Plex Sans, Segoe UI, Helvetica Neue, Arial, sans-serif",
  nodeSurface: "#1e293b",
  rootSurface: "#020617",
  rootText: "#f8fafc",
  iconColor: "#cbd5e1",
  iconMutedColor: "#cbd5e1",
  levelSurfaceMix: "#0f172a",
  levelSurfaceMixRatio: 0.7,
};

export interface CyvestForceOptions {
  linkDistance?: number;
  linkStrength?: number;
  chargeStrength?: number;
  collisionPadding?: number;
  radialStep?: number;
  radialStrength?: number;
  centerStrength?: number;
  iterations?: number;
  padding?: number;
  fit?: boolean;
  animate?: boolean;
  animationDuration?: number;
}

export interface CyNodeSelectEvent {
  view: "observables";
  nodeId: string;
  nodeType: string;
  label: string;
  data: Record<string, unknown>;
  element: NodeSingular;
}

export interface CyEdgeSelectEvent {
  view: "observables";
  edgeId: string;
  sourceId: string;
  targetId: string;
  relationshipType?: string;
  data: Record<string, unknown>;
  element: EdgeSingular;
}

export interface CyvestBaseViewProps {
  investigation: CyvestInvestigation;
  height?: number | string;
  width?: number | string;
  className?: string;
  theme?: Partial<CyvestThemeTokens>;
  /** Keep the d3-force simulation active and reheat it while nodes are dragged. */
  physics?: boolean;
  onCyReady?: (cy: Core) => void;
  onNodeSelect?: (event: CyNodeSelectEvent) => void;
  onEdgeSelect?: (event: CyEdgeSelectEvent) => void;
}

export interface CyvestObservablesViewProps extends CyvestBaseViewProps {
  layout?: CyvestForceOptions;
  showToolbar?: boolean;
  maxLabelLength?: number;
}

export interface CyvestGraphProps extends CyvestBaseViewProps {
  showToolbar?: boolean;
  layout?: CyvestForceOptions;
  maxLabelLength?: number;
}

export interface ObservableCyNodeData extends Record<string, unknown> {
  id: string;
  nodeType: "observable";
  labelShort: string;
  labelFull: string;
  observableType: string;
  level: Level;
  score: number;
  isRoot: boolean;
  whitelisted: boolean;
  internal: boolean;
  shape: "ellipse" | "round-rectangle" | "rectangle" | "diamond";
  width: number;
  height: number;
  borderWidth: number;
  borderColor: string;
  fillColor: string;
  icon: string;
  opacity: number;
}

export interface ObservableCyEdgeData extends Record<string, unknown> {
  id: string;
  relationshipType: string;
  direction: RelationshipDirection;
  color: string;
  width: number;
  sourceArrowShape: "none" | "triangle";
  targetArrowShape: "none" | "triangle";
}
