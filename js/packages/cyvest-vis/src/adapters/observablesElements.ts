import {
  getObservableGraph,
  isAllowlisted,
  type GraphEdge,
  type Investigation,
  type InvestigationGraph,
  type Verdict,
} from "@cyvest/cyvest-js";
import type { ElementDefinition } from "cytoscape";

import type {
  CyvestThemeTokens,
  ObservableCyEdgeData,
  ObservableCyNodeData,
} from "../types";
import { getObservableIconSvg } from "../icons/svg";
import { getVerdictBackgroundColor, getVerdictColor, resolveTheme } from "../utils/colors";
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

  const incoming = new Map<string, number>(graph.nodes.map((node) => [node.key, 0]));
  for (const edge of graph.edges) {
    incoming.set(edge.target, (incoming.get(edge.target) ?? 0) + 1);
  }

  const sourceCandidates = graph.nodes.filter((node) => (incoming.get(node.key) ?? 0) === 0);
  if (sourceCandidates.length === 0) {
    return graph.nodes[0]?.key;
  }

  sourceCandidates.sort((a, b) => b.score - a.score);
  return sourceCandidates[0]?.key;
}

/**
 * Arrow heads.
 *
 * v7 relations have no `direction`: `source_key` is the parent and `target_key` the child, and a
 * symmetric relation is expressed by the `related-to` kind rather than by a bidirectional flag.
 */
function getArrowShapes(edge: GraphEdge): {
  sourceArrowShape: "none" | "triangle";
  targetArrowShape: "none" | "triangle";
} {
  if (edge.kind === "related-to") {
    return { sourceArrowShape: "none", targetArrowShape: "none" };
  }
  return { sourceArrowShape: "none", targetArrowShape: "triangle" };
}

/** A low-confidence pivot should look tentative, so confidence modulates the family's opacity. */
function edgeOpacity(familyOpacity: number, confidence: number): number {
  const clamped = Math.max(0, Math.min(1, confidence));
  return familyOpacity * (0.3 + 0.7 * clamped);
}

export function buildObservablesElements(
  investigation: Investigation,
  options?: ObservablesAdapterOptions
): ElementDefinition[] {
  const graph = getObservableGraph(investigation);
  const technicalRootId = investigation.header.root_key ?? undefined;

  // A root with a single child is scaffolding: show the child as the root of the picture.
  const technicalRootEdges = technicalRootId
    ? graph.edges.filter(
        (edge) => edge.source === technicalRootId || edge.target === technicalRootId
      )
    : [];
  const presentationRootId =
    technicalRootEdges.length === 1
      ? technicalRootEdges[0].source === technicalRootId
        ? technicalRootEdges[0].target
        : technicalRootEdges[0].source
      : undefined;

  const rootId = presentationRootId ?? technicalRootId ?? findFallbackRootId(graph);
  const graphNodes = presentationRootId
    ? graph.nodes.filter((node) => node.key !== technicalRootId)
    : graph.nodes;
  const graphEdges = presentationRootId
    ? graph.edges.filter(
        (edge) => edge.source !== technicalRootId && edge.target !== technicalRootId
      )
    : graph.edges;

  const maxLabelLength = options?.maxLabelLength ?? 28;
  const theme = resolveTheme(options?.theme);
  const edgeColor = options?.edgeColor ?? theme.edgeColor;
  const degreeByNode = new Map(graphNodes.map((node) => [node.key, 0]));
  for (const edge of graphEdges) {
    degreeByNode.set(edge.source, (degreeByNode.get(edge.source) ?? 0) + 1);
    degreeByNode.set(edge.target, (degreeByNode.get(edge.target) ?? 0) + 1);
  }

  const nodes: ElementDefinition[] = graphNodes.map((node) => {
    const observable = node.observable;
    const isRoot = node.key === rootId;
    const verdict = node.verdict as Verdict;
    const allowlisted = isAllowlisted(investigation, node.key);
    const dimension = isRoot ? 52 : 38;
    const iconColor = isRoot ? theme.rootText : theme.iconMutedColor;
    const labelLength = observable.type === "url" ? Math.min(maxLabelLength, 22) : maxLabelLength;
    const labelFull =
      isRoot && node.key === technicalRootId
        ? (investigation.header.name ?? "Investigation")
        : observable.value;
    const labelShort = truncateLabel(labelFull, labelLength, true);

    const data: ObservableCyNodeData = {
      id: node.key,
      nodeType: "observable",
      labelShort,
      displayLabel:
        isRoot || (degreeByNode.get(node.key) ?? 0) >= 3 ? labelShort : "",
      labelFull,
      observableType: observable.type,
      verdict,
      score: node.score,
      isRoot,
      allowlisted,
      internal: observable.internal ?? false,
      shape: "ellipse",
      width: dimension,
      height: dimension,
      borderWidth: isRoot ? 1 : 2,
      borderColor: isRoot ? theme.rootSurface : getVerdictColor(verdict),
      fillColor: isRoot
        ? theme.rootSurface
        : observable.internal
          ? theme.nodeSurface
          : getVerdictBackgroundColor(verdict, theme),
      icon: getObservableIconSvg(observable.type, { color: iconColor }),
      opacity: allowlisted ? 0.52 : 1,
    };

    return { group: "nodes", data };
  });

  const nodeIds = new Set(graphNodes.map((node) => node.key));
  const validEdges = graphEdges.filter(
    (edge) => nodeIds.has(edge.source) && nodeIds.has(edge.target)
  );

  const parallelIndexes = new Map<string, number>();
  const parallelCounts = new Map<string, number>();
  for (const edge of validEdges) {
    const pair = [edge.source, edge.target].sort().join("--");
    parallelCounts.set(pair, (parallelCounts.get(pair) ?? 0) + 1);
  }

  const edges: ElementDefinition[] = validEdges.map((edge, index) => {
    const arrowShape = getArrowShapes(edge);
    const isRootLink =
      !presentationRootId && (edge.source === rootId || edge.target === rootId);
    const profile = resolveRelationshipProfile(edge.kind, {
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
        : edge.kind === "related-to"
          ? index % 2 === 0
            ? 52
            : -52
          : 0;

    const data: ObservableCyEdgeData = {
      id: edge.key,
      relationKind: edge.kind,
      confidence: edge.confidence,
      carriedScore: edge.carriedScore,
      relationshipFamily: profile.family,
      relationshipLabel: profile.label,
      color: options?.edgeColor ?? profile.color ?? edgeColor,
      // An edge the report actually credited deserves to stand out from one that merely exists.
      width: edge.carriedScore ? profile.width * 1.6 : profile.width,
      opacity: edgeOpacity(profile.opacity, edge.confidence),
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
      data: { ...data, source: edge.source, target: edge.target },
    };
  });

  return [...nodes, ...edges];
}
