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
import { resolveRelationshipProfile } from "../core/relationships";
import type { CyvestRelationshipProfileOverrides } from "../types";

export interface ObservablesAdapterOptions {
  maxLabelLength?: number;
  edgeColor?: string;
  theme?: Partial<CyvestThemeTokens>;
  relationshipProfiles?: CyvestRelationshipProfileOverrides;
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
  const technicalRootId = rootObservable?.value === "root" ? rootObservable.key : undefined;
  const technicalRootEdges = technicalRootId
    ? graph.edges.filter(
        (edge) => edge.source === technicalRootId || edge.target === technicalRootId
      )
    : [];
  const presentationRootId = technicalRootEdges.length === 1
    ? technicalRootEdges[0].source === technicalRootId
      ? technicalRootEdges[0].target
      : technicalRootEdges[0].source
    : undefined;
  const rootId = presentationRootId ?? rootObservable?.key ?? findFallbackRootId(graph);
  const graphNodes = presentationRootId
    ? graph.nodes.filter((node) => node.id !== technicalRootId)
    : graph.nodes;
  const graphEdges = presentationRootId
    ? graph.edges.filter(
        (edge) => edge.source !== technicalRootId && edge.target !== technicalRootId
      )
    : graph.edges;
  const maxLabelLength = options?.maxLabelLength ?? 28;
  const theme = resolveTheme(options?.theme);
  const edgeColor = options?.edgeColor ?? theme.edgeColor;
  const degreeByNode = new Map(graphNodes.map((node) => [node.id, 0]));
  for (const edge of graphEdges) {
    degreeByNode.set(edge.source, (degreeByNode.get(edge.source) ?? 0) + 1);
    degreeByNode.set(edge.target, (degreeByNode.get(edge.target) ?? 0) + 1);
  }

  const nodes: ElementDefinition[] = graphNodes.map((node) => {
    const isRoot = node.id === rootId;
    const borderColor = getLevelColor(node.level);
    const dimension = isRoot ? 52 : 38;
    const iconColor = isRoot ? theme.rootText : theme.iconMutedColor;
    const labelLength = node.type === "url"
      ? Math.min(maxLabelLength, 22)
      : maxLabelLength;
    const labelFull = isRoot && node.value === "root"
      ? investigation.investigation_name ?? "Investigation"
      : node.value;
    const labelShort = truncateLabel(labelFull, labelLength, true);

    const data: ObservableCyNodeData = {
      id: node.id,
      nodeType: "observable",
      labelShort,
      displayLabel: isRoot
        ? labelShort
        : (degreeByNode.get(node.id) ?? 0) >= 3
          ? labelShort
          : "",
      labelFull,
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

  const nodeIds = new Set(graphNodes.map((node) => node.id));

  const validEdges = graphEdges.filter(
    (edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target)
  );
  const parallelIndexes = new Map<string, number>();
  const parallelCounts = new Map<string, number>();
  for (const edge of validEdges) {
    const pair = [edge.source, edge.target].sort().join("--");
    parallelCounts.set(pair, (parallelCounts.get(pair) ?? 0) + 1);
  }

  const edges: ElementDefinition[] = validEdges
    .map((edge, index) => {
      const arrowShape = getArrowShapes(edge);
      const isRootLink = !presentationRootId && (
        edge.source === rootId || edge.target === rootId
      );
      const profile = resolveRelationshipProfile(edge.type, {
        theme,
        overrides: options?.relationshipProfiles,
        isRootLink,
      });
      const pair = [edge.source, edge.target].sort().join("--");
      const parallelIndex = parallelIndexes.get(pair) ?? 0;
      const parallelCount = parallelCounts.get(pair) ?? 1;
      parallelIndexes.set(pair, parallelIndex + 1);
      const curvature =
        parallelCount > 1
          ? (parallelIndex - (parallelCount - 1) / 2) * 34
          : edge.type === "communicates-with" || edge.type === "related-to"
            ? (index % 2 === 0 ? 52 : -52)
          : 0;
      const data: ObservableCyEdgeData = {
        id: `obs-edge-${index}-${edge.source}-${edge.target}-${edge.type}`,
        relationshipType: edge.type,
        direction: edge.direction,
        relationshipFamily: profile.family,
        relationshipLabel: profile.label,
        color: options?.edgeColor ?? profile.color ?? edgeColor,
        width: profile.width,
        opacity: profile.opacity,
        lineStyle: profile.lineStyle,
        dashPattern: profile.dashPattern,
        distance: profile.distance,
        strength: profile.strength,
        curvature,
        isRootLink,
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
