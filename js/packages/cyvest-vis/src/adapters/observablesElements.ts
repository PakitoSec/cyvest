import {
  getObservableGraph,
  getRootObservable,
  type CyvestInvestigation,
  type GraphEdge,
  type InvestigationGraph,
} from "@cyvest/cyvest-js";
import type { ElementDefinition } from "cytoscape";

import type {
  CyvestThemeTokens,
  ObservableCyEdgeData,
  ObservableCyNodeData,
} from "../types";
import { getObservableIconSvg } from "../icons/svg";
import { getLevelBackgroundColor, getLevelColor, resolveTheme } from "../utils/colors";
import { truncateLabel } from "../utils/labels";

export interface ObservablesAdapterOptions {
  maxLabelLength?: number;
  edgeColor?: string;
  theme?: Partial<CyvestThemeTokens>;
}

function findFallbackRootId(graph: InvestigationGraph): string | undefined {
  if (graph.nodes.length === 0) {
    return undefined;
  }

  const incoming = new Map<string, number>();
  for (const node of graph.nodes) {
    incoming.set(node.id, 0);
  }

  for (const edge of graph.edges) {
    incoming.set(edge.target, (incoming.get(edge.target) ?? 0) + 1);
  }

  const sourceCandidates = graph.nodes.filter((node) => (incoming.get(node.id) ?? 0) === 0);
  if (sourceCandidates.length === 0) {
    return graph.nodes[0]?.id;
  }

  sourceCandidates.sort((a, b) => b.score - a.score);
  return sourceCandidates[0]?.id;
}

function getArrowShapes(edge: GraphEdge): {
  sourceArrowShape: "none" | "triangle";
  targetArrowShape: "none" | "triangle";
} {
  if (edge.direction === "bidirectional") {
    return {
      sourceArrowShape: "triangle",
      targetArrowShape: "triangle",
    };
  }

  if (edge.direction === "inbound") {
    return {
      sourceArrowShape: "triangle",
      targetArrowShape: "none",
    };
  }

  return {
    sourceArrowShape: "none",
    targetArrowShape: "triangle",
  };
}

export function buildObservablesElements(
  investigation: CyvestInvestigation,
  options?: ObservablesAdapterOptions
): ElementDefinition[] {
  const graph = getObservableGraph(investigation);
  const rootObservable = getRootObservable(investigation);
  const rootId = rootObservable?.key ?? findFallbackRootId(graph);
  const maxLabelLength = options?.maxLabelLength ?? 28;
  const theme = resolveTheme(options?.theme);
  const edgeColor = options?.edgeColor ?? theme.edgeColor;

  const nodes: ElementDefinition[] = graph.nodes.map((node) => {
    const isRoot = node.id === rootId;
    const borderColor = getLevelColor(node.level);
    const dimension = isRoot ? 52 : 38;
    const iconColor = isRoot ? theme.rootText : theme.iconMutedColor;

    const data: ObservableCyNodeData = {
      id: node.id,
      nodeType: "observable",
      labelShort: truncateLabel(node.value, maxLabelLength, true),
      labelFull: node.value,
      observableType: node.type,
      level: node.level,
      score: node.score,
      isRoot,
      whitelisted: node.whitelisted,
      internal: node.internal,
      shape: "ellipse",
      width: dimension,
      height: dimension,
      borderWidth: isRoot ? 1 : 2,
      borderColor: isRoot ? theme.rootSurface : borderColor,
      fillColor: isRoot
        ? theme.rootSurface
        : node.internal
          ? theme.nodeSurface
          : getLevelBackgroundColor(node.level, theme),
      icon: getObservableIconSvg(node.type, { color: iconColor }),
      opacity: node.whitelisted ? 0.52 : 1,
    };

    return {
      group: "nodes",
      data,
    };
  });

  const nodeIds = new Set(graph.nodes.map((node) => node.id));

  const edges: ElementDefinition[] = graph.edges
    .filter((edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target))
    .map((edge, index) => {
      const arrowShape = getArrowShapes(edge);
      const data: ObservableCyEdgeData = {
        id: `obs-edge-${index}-${edge.source}-${edge.target}-${edge.type}`,
        relationshipType: edge.type,
        direction: edge.direction,
        color: edgeColor,
        width: 1.15,
        sourceArrowShape: arrowShape.sourceArrowShape,
        targetArrowShape: arrowShape.targetArrowShape,
      };

      return {
        group: "edges",
        data: {
          ...data,
          source: edge.source,
          target: edge.target,
        },
      };
    });

  return [...nodes, ...edges];
}
