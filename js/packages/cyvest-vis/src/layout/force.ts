import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceRadial,
  forceSimulation,
  forceX,
  forceY,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";
import type { ElementDefinition, LayoutOptions, Position } from "cytoscape";

import type {
  CyvestForceOptions,
  CyvestViewMode,
} from "../types";

interface ForceNode extends SimulationNodeDatum {
  id: string;
  radius: number;
  depth: number;
  isRoot: boolean;
}

interface ForceLink extends SimulationLinkDatum<ForceNode> {
  source: string | ForceNode;
  target: string | ForceNode;
}

const DEFAULT_OBSERVABLES_LAYOUT: Required<CyvestForceOptions> = {
  linkDistance: 118,
  linkStrength: 0.72,
  chargeStrength: -420,
  collisionPadding: 30,
  radialStep: 128,
  radialStrength: 0.38,
  centerStrength: 0.055,
  iterations: 320,
  padding: 72,
  fit: true,
  animate: true,
  animationDuration: 420,
};

const DEFAULT_INVESTIGATION_LAYOUT: Required<CyvestForceOptions> = {
  linkDistance: 132,
  linkStrength: 0.82,
  chargeStrength: -500,
  collisionPadding: 34,
  radialStep: 144,
  radialStrength: 0.5,
  centerStrength: 0.045,
  iterations: 360,
  padding: 78,
  fit: true,
  animate: true,
  animationDuration: 420,
};

export function getDefaultForceOptions(
  view: CyvestViewMode
): Required<CyvestForceOptions> {
  return view === "observables"
    ? { ...DEFAULT_OBSERVABLES_LAYOUT }
    : { ...DEFAULT_INVESTIGATION_LAYOUT };
}

function resolveOptions(
  view: CyvestViewMode,
  overrides?: CyvestForceOptions
): Required<CyvestForceOptions> {
  return {
    ...getDefaultForceOptions(view),
    ...overrides,
  };
}

function getNodeId(element: ElementDefinition): string {
  return String(element.data.id);
}

function getNodeRadius(element: ElementDefinition): number {
  const width = Number(element.data.width ?? 40);
  const height = Number(element.data.height ?? width);
  return Math.max(width, height) / 2;
}

function findRootId(nodes: ElementDefinition[]): string | undefined {
  const explicitRoot = nodes.find(
    (node) => node.data.isRoot === true || node.data.nodeType === "root"
  );
  return explicitRoot ? getNodeId(explicitRoot) : nodes[0] ? getNodeId(nodes[0]) : undefined;
}

function calculateDepths(
  nodeIds: string[],
  links: ForceLink[],
  rootId: string | undefined
): Map<string, number> {
  const depths = new Map<string, number>();
  if (!rootId) {
    return depths;
  }

  const neighbors = new Map<string, string[]>();
  for (const id of nodeIds) {
    neighbors.set(id, []);
  }
  for (const link of links) {
    const source = String(link.source);
    const target = String(link.target);
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

  const fallbackDepth = Math.max(1, ...depths.values()) + 1;
  for (const nodeId of nodeIds) {
    if (!depths.has(nodeId)) {
      depths.set(nodeId, fallbackDepth);
    }
  }
  return depths;
}

export function computeForcePositions(
  elements: ElementDefinition[],
  view: CyvestViewMode,
  overrides?: CyvestForceOptions
): Record<string, Position> {
  const options = resolveOptions(view, overrides);
  const nodeElements = elements.filter((element) => element.group === "nodes");
  const edgeElements = elements.filter((element) => element.group === "edges");
  const nodeIds = nodeElements.map(getNodeId);
  const rootId = findRootId(nodeElements);
  const links: ForceLink[] = edgeElements.map((edge) => ({
    source: String(edge.data.source),
    target: String(edge.data.target),
  }));
  const depths = calculateDepths(nodeIds, links, rootId);

  const nodes: ForceNode[] = nodeElements.map((element) => {
    const id = getNodeId(element);
    const isRoot = id === rootId;
    return {
      id,
      radius: getNodeRadius(element),
      depth: depths.get(id) ?? 1,
      isRoot,
      ...(isRoot ? { fx: 0, fy: 0 } : {}),
    };
  });

  const simulation = forceSimulation<ForceNode>(nodes)
    .alpha(1)
    .alphaDecay(1 - Math.pow(0.001, 1 / options.iterations))
    .velocityDecay(0.34)
    .force(
      "link",
      forceLink<ForceNode, ForceLink>(links)
        .id((node) => node.id)
        .distance((link) => {
          const sourceDepth =
            typeof link.source === "string" ? 0 : link.source.depth;
          const targetDepth =
            typeof link.target === "string" ? 0 : link.target.depth;
          return options.linkDistance + Math.abs(sourceDepth - targetDepth) * 8;
        })
        .strength(options.linkStrength)
    )
    .force("charge", forceManyBody().strength(options.chargeStrength))
    .force(
      "collision",
      forceCollide<ForceNode>()
        .radius((node) => node.radius + options.collisionPadding)
        .strength(0.92)
        .iterations(3)
    )
    .force(
      "radial",
      forceRadial<ForceNode>(
        (node) => node.depth * options.radialStep,
        0,
        0
      ).strength((node) => (node.isRoot ? 1 : options.radialStrength))
    )
    .force("center", forceCenter(0, 0).strength(options.centerStrength))
    .force("x", forceX<ForceNode>(0).strength(options.centerStrength))
    .force("y", forceY<ForceNode>(0).strength(options.centerStrength))
    .stop();

  for (let index = 0; index < options.iterations; index += 1) {
    simulation.tick();
  }

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

export function createForceLayout(
  elements: ElementDefinition[],
  view: CyvestViewMode,
  overrides?: CyvestForceOptions
): LayoutOptions {
  const options = resolveOptions(view, overrides);
  const positions = computeForcePositions(elements, view, overrides);

  return {
    name: "preset",
    positions,
    fit: options.fit,
    padding: options.padding,
    animate: options.animate,
    animationDuration: options.animationDuration,
    animationEasing: "ease-out-cubic",
  } as LayoutOptions;
}
