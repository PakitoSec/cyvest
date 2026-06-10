import type { CyvestInvestigation, Level, RelationshipDirection } from "@cyvest/cyvest-js";
import type { Core, EdgeSingular, NodeSingular } from "cytoscape";

export type CyvestViewMode = "observables" | "investigation";

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
  /** Default node fill (e.g. internal observables, findings). */
  nodeSurface: string;
  /** Secondary node fill (tags, evidence). */
  nodeSurfaceMuted: string;
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
  /** Background of the active view-toggle button. */
  toggleActiveSurface: string;
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
  nodeSurfaceMuted: "#f1f5f9",
  rootSurface: "#1e293b",
  rootText: "#ffffff",
  iconColor: "#314264",
  iconMutedColor: "#475569",
  levelSurfaceMix: "#ffffff",
  levelSurfaceMixRatio: 0.94,
  toggleActiveSurface: "#eef2f6",
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
  nodeSurfaceMuted: "#334155",
  rootSurface: "#020617",
  rootText: "#f8fafc",
  iconColor: "#cbd5e1",
  iconMutedColor: "#cbd5e1",
  levelSurfaceMix: "#0f172a",
  levelSurfaceMixRatio: 0.7,
  toggleActiveSurface: "#334155",
};

export type CyvestElkDirection = "RIGHT" | "LEFT" | "UP" | "DOWN";

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

/** @deprecated Use CyvestForceOptions. */
export type CyvestElkOptions = CyvestForceOptions;

export interface CyNodeSelectEvent {
  view: CyvestViewMode;
  nodeId: string;
  nodeType: string;
  label: string;
  data: Record<string, unknown>;
  element: NodeSingular;
}

export interface CyEdgeSelectEvent {
  view: CyvestViewMode;
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
  onCyReady?: (cy: Core) => void;
  onNodeSelect?: (event: CyNodeSelectEvent) => void;
  onEdgeSelect?: (event: CyEdgeSelectEvent) => void;
}

export interface CyvestObservablesViewProps extends CyvestBaseViewProps {
  layout?: CyvestForceOptions;
  showToolbar?: boolean;
  maxLabelLength?: number;
}

export interface CyvestInvestigationViewProps extends CyvestBaseViewProps {
  layout?: CyvestForceOptions;
  showToolbar?: boolean;
  maxLabelLength?: number;
}

export interface CyvestGraphProps extends CyvestBaseViewProps {
  initialView?: CyvestViewMode;
  showViewToggle?: boolean;
  onViewChange?: (view: CyvestViewMode) => void;
  showToolbar?: boolean;
  observablesLayout?: CyvestForceOptions;
  investigationLayout?: CyvestForceOptions;
  maxObservableLabelLength?: number;
  maxInvestigationLabelLength?: number;
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

export type InvestigationCyNodeType = "root" | "tag" | "finding" | "evidence";

export interface InvestigationCyNodeData extends Record<string, unknown> {
  id: string;
  nodeType: InvestigationCyNodeType;
  labelShort: string;
  labelFull: string;
  level: Level;
  score: number;
  borderColor: string;
  fillColor: string;
  icon: string;
  width: number;
  height: number;
  shape: "ellipse" | "round-rectangle" | "diamond";
  borderWidth: number;
}

export interface InvestigationCyEdgeData extends Record<string, unknown> {
  id: string;
  relationshipType: string;
  color: string;
  width: number;
  sourceArrowShape: "none" | "triangle";
  targetArrowShape: "none" | "triangle";
}
