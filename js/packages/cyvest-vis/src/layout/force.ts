import {
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";
import type {
  Core,
  ElementDefinition,
  EventObjectNode,
  LayoutOptions,
  Position,
} from "cytoscape";

import type { CyvestForceOptions, CyvestRelationshipFamily } from "../types";

interface ForceNode extends SimulationNodeDatum {
  id: string;
  radius: number;
  depth: number;
  isRoot: boolean;
  branchId: string;
  branchX: number;
  branchY: number;
}

interface ForceLink extends SimulationLinkDatum<ForceNode> {
  source: string | ForceNode;
  target: string | ForceNode;
  distance: number;
  strength: number;
  family: CyvestRelationshipFamily;
  relationshipType: string;
  direction: "outbound" | "inbound" | "bidirectional";
  isRootLink: boolean;
}

interface TopologyNode {
  depth: number;
  branchId: string;
  branchX: number;
  branchY: number;
}

export interface ForceSimulationController {
  reheat: () => void;
  stop: () => void;
}

const DEFAULT_OBSERVABLES_LAYOUT: Required<CyvestForceOptions> = {
  linkDistance: 176,
  linkStrength: 0.16,
  chargeStrength: -240,
  collisionPadding: 24,
  radialStep: 0,
  radialStrength: 0,
  centerStrength: 0.035,
  branchSpacing: 238,
  branchStrength: 0.55,
  layerSpacing: 148,
  layerStrength: 0.9,
  siblingSpacing: 132,
  rootLinkDistance: 160,
  rootLinkStrength: 0.24,
  iterations: 360,
  padding: 72,
  fit: true,
  animate: true,
  animationDuration: 460,
};

const LABEL_FONT_SIZE = 10.5;
const LABEL_MAX_WIDTH = 190;
const LABEL_HORIZONTAL_PADDING = 12;
const DENSE_LAYER_THRESHOLD = 4;
const DENSE_LAYER_OFFSET = 18;

export function getDefaultForceOptions(): Required<CyvestForceOptions> {
  return { ...DEFAULT_OBSERVABLES_LAYOUT };
}

function resolveOptions(overrides?: CyvestForceOptions): Required<CyvestForceOptions> {
  return { ...getDefaultForceOptions(), ...overrides };
}

function endpointId(endpoint: string | ForceNode): string {
  return typeof endpoint === "string" ? endpoint : endpoint.id;
}

function calculateDepths(
  nodeIds: string[],
  links: ForceLink[],
  rootId: string | undefined
): Map<string, number> {
  const depths = new Map<string, number>();
  if (!rootId) return depths;

  const neighbors = new Map(nodeIds.map((id) => [id, [] as string[]]));
  for (const link of links) {
    const source = endpointId(link.source);
    const target = endpointId(link.target);
    neighbors.get(source)?.push(target);
    neighbors.get(target)?.push(source);
  }

  const queue = [rootId];
  depths.set(rootId, 0);
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) continue;
    const nextDepth = (depths.get(current) ?? 0) + 1;
    for (const neighbor of neighbors.get(current) ?? []) {
      if (depths.has(neighbor)) continue;
      depths.set(neighbor, nextDepth);
      queue.push(neighbor);
    }
  }

  const fallbackDepth = Math.max(0, ...depths.values()) + 1;
  for (const nodeId of nodeIds) {
    if (!depths.has(nodeId)) depths.set(nodeId, fallbackDepth);
  }
  return depths;
}

/**
 * Build stable branches by removing the root and finding the remaining
 * connected components. This prevents weak context links from collapsing all
 * observables into one cloud while preserving legacy related-to graphs.
 */
function calculateTopology(
  nodeIds: string[],
  links: ForceLink[],
  rootId: string | undefined,
  footprintByNode: Map<string, number>,
  options: Pick<
    Required<CyvestForceOptions>,
    "layerSpacing" | "siblingSpacing"
  >
): Map<string, TopologyNode> {
  const depths = calculateDepths(nodeIds, links, rootId);
  if (!rootId) return new Map();

  const allNeighbors = new Map(nodeIds.map((id) => [id, [] as string[]]));
  const hierarchyNeighbors = new Map(nodeIds.map((id) => [id, [] as string[]]));
  const isHierarchyLink = (link: ForceLink) =>
    link.direction !== "bidirectional" && (
      link.family === "extraction" || link.family === "pivot"
    );

  for (const link of links) {
    const source = endpointId(link.source);
    const target = endpointId(link.target);
    allNeighbors.get(source)?.push(target);
    allNeighbors.get(target)?.push(source);
    if (isHierarchyLink(link)) {
      hierarchyNeighbors.get(source)?.push(target);
      hierarchyNeighbors.get(target)?.push(source);
    }
  }
  for (const neighbors of [...allNeighbors.values(), ...hierarchyNeighbors.values()]) {
    neighbors.sort();
  }

  const parent = new Map<string, string>();
  const hierarchyDepth = new Map<string, number>([[rootId, 0]]);
  const queue = [rootId];
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) continue;
    for (const neighbor of hierarchyNeighbors.get(current) ?? []) {
      if (hierarchyDepth.has(neighbor)) continue;
      hierarchyDepth.set(neighbor, (hierarchyDepth.get(current) ?? 0) + 1);
      parent.set(neighbor, current);
      queue.push(neighbor);
    }
  }

  const unresolved = new Set(nodeIds.filter((id) => !hierarchyDepth.has(id)));
  while (unresolved.size > 0) {
    const candidate = [...unresolved]
      .map((id) => ({
        id,
        neighbor: (allNeighbors.get(id) ?? []).find((item) => hierarchyDepth.has(item)),
        depth: depths.get(id) ?? Number.MAX_SAFE_INTEGER,
      }))
      .filter((item) => item.neighbor)
      .sort((left, right) => left.depth - right.depth || left.id.localeCompare(right.id))[0];
    if (!candidate?.neighbor) break;
    hierarchyDepth.set(candidate.id, (hierarchyDepth.get(candidate.neighbor) ?? 0) + 1);
    parent.set(candidate.id, candidate.neighbor);
    unresolved.delete(candidate.id);
  }
  for (const id of [...unresolved].sort()) {
    hierarchyDepth.set(id, 1);
    parent.set(id, rootId);
  }

  // Pivot links between siblings form a clearer local tree than a
  // chord across the same ring (for example domain -> hosted URL).
  for (const link of links) {
    if (link.family !== "pivot" || link.direction === "bidirectional") continue;
    const source = endpointId(link.source);
    const target = endpointId(link.target);
    const semanticParent = link.direction === "inbound" ? target : source;
    const semanticChild = link.direction === "inbound" ? source : target;
    if (
      semanticParent !== rootId &&
      parent.get(semanticParent) === parent.get(semanticChild)
    ) {
      parent.set(semanticChild, semanticParent);
    }
  }

  const children = new Map(nodeIds.map((id) => [id, [] as string[]]));
  for (const [child, parentId] of parent) children.get(parentId)?.push(child);
  for (const items of children.values()) items.sort();

  const rootBranches = children.get(rootId) ?? [];
  const getRootBranch = (id: string): string | undefined => {
    let current = id;
    while (parent.get(current) && parent.get(current) !== rootId) {
      current = parent.get(current) as string;
    }
    return parent.get(current) === rootId ? current : undefined;
  };
  const crossWeights = new Map<string, number>();
  const crossKey = (left: string, right: string) =>
    [left, right].sort().join("\u0000");
  for (const link of links) {
    const sourceBranch = getRootBranch(endpointId(link.source));
    const targetBranch = getRootBranch(endpointId(link.target));
    if (!sourceBranch || !targetBranch || sourceBranch === targetBranch) continue;
    const key = crossKey(sourceBranch, targetBranch);
    crossWeights.set(key, (crossWeights.get(key) ?? 0) + Math.max(0.1, link.strength));
  }
  if (rootBranches.length > 2 && crossWeights.size > 0) {
    const totalCrossWeight = (id: string) => rootBranches.reduce(
      (total, candidate) => total + (crossWeights.get(crossKey(id, candidate)) ?? 0),
      0
    );
    const remaining = [...rootBranches].sort(
      (left, right) => totalCrossWeight(right) - totalCrossWeight(left) || left.localeCompare(right)
    );
    const ordered = [remaining.shift() as string];
    while (remaining.length > 0) {
      remaining.sort((left, right) => {
        const affinity = (id: string) => ordered.reduce(
          (total, placed) => total + (crossWeights.get(crossKey(id, placed)) ?? 0),
          0
        );
        return affinity(right) - affinity(left) || left.localeCompare(right);
      });
      ordered.push(remaining.shift() as string);
    }
    rootBranches.splice(0, rootBranches.length, ...ordered);
  }

  hierarchyDepth.clear();
  hierarchyDepth.set(rootId, 0);
  const depthQueue = [rootId];
  while (depthQueue.length > 0) {
    const current = depthQueue.shift();
    if (!current) continue;
    for (const child of children.get(current) ?? []) {
      hierarchyDepth.set(child, (hierarchyDepth.get(current) ?? 0) + 1);
      depthQueue.push(child);
    }
  }

  const subtreeWeights = new Map<string, number>();
  const getSubtreeWeight = (id: string): number => {
    const descendants = children.get(id) ?? [];
    const ownWeight = Math.max(
      1,
      (footprintByNode.get(id) ?? options.siblingSpacing) / options.siblingSpacing
    );
    const descendantsWeight = descendants.reduce(
      (total, child) => total + getSubtreeWeight(child),
      0
    );
    const weight = Math.max(ownWeight, descendantsWeight);
    subtreeWeights.set(id, weight);
    return weight;
  };
  getSubtreeWeight(rootId);

  const angleByNode = new Map<string, number>([[rootId, 0]]);
  const placeChildren = (id: string, startAngle: number, endAngle: number): void => {
    const descendants = children.get(id) ?? [];
    const totalWeight = descendants.reduce(
      (total, child) => total + (subtreeWeights.get(child) ?? 1),
      0
    );
    let cursor = startAngle;
    for (const child of descendants) {
      const span = totalWeight > 0
        ? (endAngle - startAngle) * (subtreeWeights.get(child) ?? 1) / totalWeight
        : 0;
      const next = cursor + span;
      angleByNode.set(child, cursor + span / 2);
      placeChildren(child, cursor, next);
      cursor = next;
    }
  };
  placeChildren(rootId, -Math.PI / 2, Math.PI * 3 / 2);

  const layerIndexes = new Map<string, number>();
  const layerSizes = new Map<number, number>();
  for (const depth of hierarchyDepth.values()) {
    layerSizes.set(depth, (layerSizes.get(depth) ?? 0) + 1);
  }
  for (const [depth, ids] of Map.groupBy(nodeIds, (id) => hierarchyDepth.get(id) ?? 1)) {
    ids.sort((left, right) =>
      (angleByNode.get(left) ?? 0) - (angleByNode.get(right) ?? 0)
    );
    ids.forEach((id, index) => layerIndexes.set(id, index));
  }

  return new Map(
    nodeIds.map((id) => {
      let branchId = id;
      let ancestor = id;
      while (parent.get(ancestor) && parent.get(ancestor) !== rootId) {
        ancestor = parent.get(ancestor) as string;
      }
      if (id !== rootId) branchId = ancestor;
      const depth = hierarchyDepth.get(id) ?? depths.get(id) ?? 1;
      const radiusOffset = (layerSizes.get(depth) ?? 0) >= DENSE_LAYER_THRESHOLD
        ? (layerIndexes.get(id) ?? 0) % 2 * DENSE_LAYER_OFFSET
        : 0;
      const radius = depth * options.layerSpacing + radiusOffset;
      const angle = angleByNode.get(id) ?? 0;
      return [
        id,
        {
          depth,
          branchId,
          branchX: id === rootId ? 0 : Math.cos(angle) * radius,
          branchY: id === rootId ? 0 : Math.sin(angle) * radius,
        },
      ];
    })
  );
}

function seedNodePosition(node: ForceNode, stableIndex: number): void {
  if (node.isRoot) {
    node.x = 0;
    node.y = 0;
    node.fx = 0;
    node.fy = 0;
    return;
  }
  const angle = stableIndex * Math.PI * (3 - Math.sqrt(5));
  const radius = 22 + Math.sqrt(stableIndex + 1) * 13;
  node.x = node.branchX + Math.cos(angle) * radius;
  node.y = node.branchY + Math.sin(angle) * radius;
}

export function resolveForceLinkStrength(
  strength: number | undefined,
  isRootLink: boolean,
  options: Pick<Required<CyvestForceOptions>, "linkStrength" | "rootLinkStrength">
): number {
  return isRootLink ? options.rootLinkStrength : strength ?? options.linkStrength;
}

function configureSimulation(
  nodes: ForceNode[],
  links: ForceLink[],
  options: Required<CyvestForceOptions>
) {
  return forceSimulation<ForceNode>(nodes)
    .alpha(1)
    .alphaDecay(1 - Math.pow(0.001, 1 / options.iterations))
    .velocityDecay(0.38)
    .force(
      "link",
      forceLink<ForceNode, ForceLink>(links)
        .id((node) => node.id)
        .distance((link) =>
          link.isRootLink
            ? options.rootLinkDistance
            : link.distance || options.linkDistance
        )
        .strength((link) =>
          resolveForceLinkStrength(link.strength, link.isRootLink, options) * 0.32
        )
    )
    .force(
      "charge",
      forceManyBody<ForceNode>().strength((node) =>
        node.isRoot ? options.chargeStrength * 0.5 : options.chargeStrength
      )
    )
    .force(
      "collision",
      forceCollide<ForceNode>()
        .radius((node) => node.radius + options.collisionPadding)
        .strength(0.96)
        .iterations(4)
    )
    .force(
      "branch-x",
      forceX<ForceNode>((node) => node.branchX).strength((node) =>
        node.isRoot ? 1 : options.branchStrength
      )
    )
    .force(
      "branch-y",
      forceY<ForceNode>((node) => node.branchY).strength((node) =>
        node.isRoot ? 1 : options.layerStrength
      )
    );
}

function getNodeId(element: ElementDefinition): string {
  return String(element.data.id);
}

function getNodeRadius(element: ElementDefinition): number {
  const width = Number(element.data.width ?? 40);
  const height = Number(element.data.height ?? width);
  return Math.max(width, height) / 2;
}

function estimateNodeFootprint(label: unknown, diameter: number): number {
  const text = typeof label === "string" ? label : "";
  const labelWidth = Math.min(
    LABEL_MAX_WIDTH,
    text.length * LABEL_FONT_SIZE * 0.58 + LABEL_HORIZONTAL_PADDING
  );
  return Math.max(diameter, labelWidth);
}

function getElementFootprints(elements: ElementDefinition[]): Map<string, number> {
  return new Map(elements.map((element) => {
    const diameter = getNodeRadius(element) * 2;
    return [
      getNodeId(element),
      estimateNodeFootprint(element.data.labelShort, diameter),
    ];
  }));
}

function findRootId(nodes: ElementDefinition[]): string | undefined {
  const root = nodes.find(
    (node) => node.data.isRoot === true || node.data.nodeType === "root"
  );
  return root ? getNodeId(root) : nodes[0] ? getNodeId(nodes[0]) : undefined;
}

function elementToLink(edge: ElementDefinition, options: Required<CyvestForceOptions>): ForceLink {
  return {
    source: String(edge.data.source),
    target: String(edge.data.target),
    distance: Number(edge.data.distance ?? options.linkDistance),
    strength: Number(edge.data.strength ?? options.linkStrength),
    family: (edge.data.relationshipFamily ?? "association") as CyvestRelationshipFamily,
    relationshipType: String(edge.data.relationshipType ?? "related-to"),
    direction: (edge.data.direction ?? "outbound") as ForceLink["direction"],
    isRootLink: edge.data.isRootLink === true,
  };
}

export function computeSemanticTargets(
  elements: ElementDefinition[],
  overrides?: CyvestForceOptions
): Record<string, Position> {
  const options = resolveOptions(overrides);
  const nodeElements = elements.filter((element) => element.group === "nodes");
  const links = elements
    .filter((element) => element.group === "edges")
    .map((edge) => elementToLink(edge, options));
  const nodeIds = nodeElements.map(getNodeId);
  const topology = calculateTopology(
    nodeIds,
    links,
    findRootId(nodeElements),
    getElementFootprints(nodeElements),
    options
  );

  return Object.fromEntries(
    nodeIds.map((id) => {
      const target = topology.get(id);
      return [id, { x: target?.branchX ?? 0, y: target?.branchY ?? 0 }];
    })
  );
}

export function computeForcePositions(
  elements: ElementDefinition[],
  overrides?: CyvestForceOptions
): Record<string, Position> {
  const options = resolveOptions(overrides);
  const nodeElements = elements.filter((element) => element.group === "nodes");
  const edgeElements = elements.filter((element) => element.group === "edges");
  const nodeIds = nodeElements.map(getNodeId);
  const rootId = findRootId(nodeElements);
  const links = edgeElements.map((edge) => elementToLink(edge, options));
  const topology = calculateTopology(
    nodeIds,
    links,
    rootId,
    getElementFootprints(nodeElements),
    options
  );
  const branchIndexes = new Map<string, number>();

  const nodes: ForceNode[] = nodeElements.map((element) => {
    const id = getNodeId(element);
    const nodeTopology = topology.get(id) ?? {
      depth: 1,
      branchId: id,
      branchX: 0,
      branchY: 0,
    };
    const node: ForceNode = {
      id,
      radius: getNodeRadius(element),
      isRoot: id === rootId,
      ...nodeTopology,
    };
    const branchIndex = branchIndexes.get(node.branchId) ?? 0;
    branchIndexes.set(node.branchId, branchIndex + 1);
    seedNodePosition(node, branchIndex);
    return node;
  });

  const simulation = configureSimulation(nodes, links, options).stop();
  for (let index = 0; index < options.iterations; index += 1) simulation.tick();

  return Object.fromEntries(
    nodes.map((node) => [
      node.id,
      {
        x: Number.isFinite(node.x) ? node.x ?? 0 : 0,
        y: Number.isFinite(node.y) ? node.y ?? 0 : 0,
      },
    ])
  );
}

export function startForceSimulation(
  cy: Core,
  overrides?: CyvestForceOptions
): ForceSimulationController {
  if (cy.nodes().empty()) return { reheat: () => undefined, stop: () => undefined };

  const options = resolveOptions(overrides);
  const cyNodes = cy.nodes();
  const compact = cyNodes.filter(".cyvest-compact-label").nonempty();
  const simulationOptions = compact
    ? {
        ...options,
        chargeStrength: Math.max(options.chargeStrength, -170),
        collisionPadding: Math.min(options.collisionPadding, 16),
        layerSpacing: Math.min(options.layerSpacing, 108),
        siblingSpacing: Math.min(options.siblingSpacing, 84),
        rootLinkDistance: Math.min(options.rootLinkDistance, 132),
      }
    : options;
  const nodeIds = cyNodes.map((node) => node.id());
  const rootNode = cyNodes
    .filter((node) => node.data("isRoot") === true || node.data("nodeType") === "root")
    .first();
  const rootId = (!rootNode.empty() ? rootNode : cyNodes.first()).id();
  const links: ForceLink[] = cy.edges().map((edge) => ({
    source: edge.source().id(),
    target: edge.target().id(),
    distance:
      Number(edge.data("distance") ?? simulationOptions.linkDistance) *
      (compact ? 0.72 : 1),
    strength: Number(edge.data("strength") ?? simulationOptions.linkStrength),
    family: (edge.data("relationshipFamily") ?? "association") as CyvestRelationshipFamily,
    relationshipType: String(edge.data("relationshipType") ?? "related-to"),
    direction: (edge.data("direction") ?? "outbound") as ForceLink["direction"],
    isRootLink: edge.data("isRootLink") === true,
  }));
  const topology = calculateTopology(
    nodeIds,
    links,
    rootId,
    new Map(cyNodes.map((node) => {
      const diameter = Math.max(
        Number(node.data("width") ?? 40),
        Number(node.data("height") ?? 40)
      );
      return [
        node.id(),
        estimateNodeFootprint(
          node.hasClass("cyvest-compact-label")
            ? node.data("displayLabel")
            : node.data("labelShort"),
          diameter
        ),
      ];
    })),
    simulationOptions
  );
  const nodeById = new Map<string, ForceNode>();

  const nodes: ForceNode[] = cyNodes.map((node) => {
    const position = node.position();
    const nodeTopology = topology.get(node.id()) ?? {
      depth: 1,
      branchId: node.id(),
      branchX: 0,
      branchY: 0,
    };
    const forceNode: ForceNode = {
      id: node.id(),
      radius: Math.max(Number(node.data("width") ?? 40), Number(node.data("height") ?? 40)) / 2,
      isRoot: node.id() === rootId,
      x: position.x,
      y: position.y,
      ...nodeTopology,
    };
    if (forceNode.isRoot) {
      forceNode.fx = 0;
      forceNode.fy = 0;
    }
    nodeById.set(forceNode.id, forceNode);
    return forceNode;
  });

  const simulation = configureSimulation(nodes, links, simulationOptions)
    .alpha(0.38)
    .alphaTarget(0)
    .on("tick", () => {
      cy.batch(() => {
        for (const forceNode of nodes) {
          const cyNode = cy.getElementById(forceNode.id);
          if (cyNode.empty() || cyNode.grabbed()) continue;
          cyNode.position({ x: forceNode.x ?? 0, y: forceNode.y ?? 0 });
        }
      });
    });

  const handleGrab = (event: EventObjectNode) => {
    const node = nodeById.get(event.target.id());
    if (!node) return;
    const position = event.target.position();
    node.fx = position.x;
    node.fy = position.y;
    simulation.alphaTarget(0.2).restart();
  };
  const handleDrag = (event: EventObjectNode) => {
    const node = nodeById.get(event.target.id());
    if (!node) return;
    const position = event.target.position();
    node.fx = position.x;
    node.fy = position.y;
  };
  const handleFree = (event: EventObjectNode) => {
    const node = nodeById.get(event.target.id());
    if (!node) return;
    if (!node.isRoot) {
      node.fx = null;
      node.fy = null;
    }
    simulation.alphaTarget(0);
  };

  cy.on("grab", "node", handleGrab);
  cy.on("drag", "node", handleDrag);
  cy.on("free", "node", handleFree);

  return {
    reheat: () => simulation.alpha(0.72).alphaTarget(0).restart(),
    stop: () => {
      simulation.stop();
      cy.removeListener("grab", "node", handleGrab);
      cy.removeListener("drag", "node", handleDrag);
      cy.removeListener("free", "node", handleFree);
    },
  };
}

export function createForceLayout(
  elements: ElementDefinition[],
  overrides?: CyvestForceOptions
): LayoutOptions {
  const options = resolveOptions(overrides);
  return {
    name: "preset",
    positions: computeForcePositions(elements, overrides),
    fit: options.fit,
    padding: options.padding,
    animate: options.animate,
    animationDuration: options.animationDuration,
    animationEasing: "ease-out-cubic",
  } as LayoutOptions;
}
