import {
  getObservableGraph,
  getRootObservable,
  type CyvestInvestigation,
  type GraphEdge,
  type InvestigationGraph,
} from "@cyvest/cyvest-js";
import type { ElementDefinition } from "cytoscape";

import type {
  ObservableCyEdgeData,
  ObservableCyNodeData,
} from "../types";
import { getObservableIconSvg } from "../icons/svg";
import { getLevelBackgroundColor, getLevelColor } from "../utils/colors";
import { truncateLabel } from "../utils/labels";

export interface ObservablesAdapterOptions {
  maxLabelLength?: number;
  edgeColor?: string;
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
  const edgeColor = options?.edgeColor ?? "#8a95aa";

  const nodes: ElementDefinition[] = graph.nodes.map((node) => {
    const isRoot = node.id === rootId;
    const borderColor = getLevelColor(node.level);

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
      width: 48,
      height: 48,
      borderWidth: 2,
      borderColor,
      fillColor: getLevelBackgroundColor(node.level),
      icon: getObservableIconSvg(node.type, { color: borderColor }),
      opacity: node.whitelisted ? 0.5 : 1,
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
        width: 1.6,
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
