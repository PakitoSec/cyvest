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
}

export const DEFAULT_CYVEST_THEME: CyvestThemeTokens = {
  background: "#f4f7fb",
  gridColor: "#d7dfeb",
  panelBackground: "rgba(255, 255, 255, 0.96)",
  panelBorder: "#d3dae6",
  panelText: "#172033",
  panelTextMuted: "#556079",
  accent: "#1f6feb",
  edgeColor: "#8a95aa",
  edgeSelectedColor: "#1f6feb",
  fontFamily:
    "'IBM Plex Sans', 'Segoe UI', 'Helvetica Neue', Arial, sans-serif",
};

export type CyvestElkDirection = "RIGHT" | "LEFT" | "UP" | "DOWN";

export interface CyvestElkOptions {
  algorithm?: string;
  direction?: CyvestElkDirection;
  spacingNodeNode?: number;
  spacingEdgeNode?: number;
  spacingBetweenLayers?: number;
  padding?: number;
  fit?: boolean;
  animate?: boolean;
  extra?: Record<string, string | number | boolean>;
}

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
  layout?: CyvestElkOptions;
  showToolbar?: boolean;
  maxLabelLength?: number;
}

export interface CyvestInvestigationViewProps extends CyvestBaseViewProps {
  layout?: CyvestElkOptions;
  showToolbar?: boolean;
  maxLabelLength?: number;
}

export interface CyvestGraphProps extends CyvestBaseViewProps {
  initialView?: CyvestViewMode;
  showViewToggle?: boolean;
  onViewChange?: (view: CyvestViewMode) => void;
  showToolbar?: boolean;
  observablesLayout?: CyvestElkOptions;
  investigationLayout?: CyvestElkOptions;
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
  shape: "ellipse" | "round-rectangle" | "rectangle";
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
  shape: "round-rectangle";
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
