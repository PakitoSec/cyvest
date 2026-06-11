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
import type {
  Core,
  ElementDefinition,
  EventObjectNode,
  LayoutOptions,
  Position,
} from "cytoscape";

import type { CyvestForceOptions } from "../types";

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

export interface ForceSimulationController {
  reheat: () => void;
  stop: () => void;
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

export function getDefaultForceOptions(): Required<CyvestForceOptions> {
  return { ...DEFAULT_OBSERVABLES_LAYOUT };
}

function resolveOptions(
  overrides?: CyvestForceOptions
): Required<CyvestForceOptions> {
  return {
    ...getDefaultForceOptions(),
    ...overrides,
  };
}

function configureSimulation(
  nodes: ForceNode[],
  links: ForceLink[],
  options: Required<CyvestForceOptions>
) {
  return forceSimulation<ForceNode>(nodes)
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
    .force("y", forceY<ForceNode>(0).strength(options.centerStrength));
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
  overrides?: CyvestForceOptions
): Record<string, Position> {
  const options = resolveOptions(overrides);
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

  const simulation = configureSimulation(nodes, links, options).stop();

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

export function startForceSimulation(
  cy: Core,
  overrides?: CyvestForceOptions
): ForceSimulationController {
  if (cy.nodes().empty()) {
    return {
      reheat: () => undefined,
      stop: () => undefined,
    };
  }

  const options = resolveOptions(overrides);
  const cyNodes = cy.nodes();
  const nodeIds = cyNodes.map((node) => node.id());
  const rootNode = cyNodes
    .filter(
      (node) =>
        node.data("isRoot") === true || node.data("nodeType") === "root"
    )
    .first();
  const rootId = (!rootNode.empty() ? rootNode : cyNodes.first()).id();
  const links: ForceLink[] = cy.edges().map((edge) => ({
    source: edge.source().id(),
    target: edge.target().id(),
  }));
  const depths = calculateDepths(nodeIds, links, rootId);
  const nodeById = new Map<string, ForceNode>();

  const nodes: ForceNode[] = cyNodes.map((node) => {
    const position = node.position();
    const forceNode: ForceNode = {
      id: node.id(),
      radius:
        Math.max(
          Number(node.data("width") ?? 40),
          Number(node.data("height") ?? 40)
        ) / 2,
      depth: depths.get(node.id()) ?? 1,
      isRoot: node.id() === rootId,
      x: position.x,
      y: position.y,
    };
    if (forceNode.isRoot) {
      forceNode.fx = position.x;
      forceNode.fy = position.y;
    }
    nodeById.set(forceNode.id, forceNode);
    return forceNode;
  });

  const simulation = configureSimulation(nodes, links, options)
    .alpha(0.42)
    .alphaTarget(0)
    .on("tick", () => {
      cy.batch(() => {
        for (const forceNode of nodes) {
          const cyNode = cy.getElementById(forceNode.id);
          if (cyNode.empty() || cyNode.grabbed()) continue;
          cyNode.position({
            x: forceNode.x ?? 0,
            y: forceNode.y ?? 0,
          });
        }
      });
    });

  const handleGrab = (event: EventObjectNode) => {
    const forceNode = nodeById.get(event.target.id());
    if (!forceNode) return;
    const position = event.target.position();
    forceNode.fx = position.x;
    forceNode.fy = position.y;
    simulation.alphaTarget(0.22).restart();
  };

  const handleDrag = (event: EventObjectNode) => {
    const forceNode = nodeById.get(event.target.id());
    if (!forceNode) return;
    const position = event.target.position();
    forceNode.fx = position.x;
    forceNode.fy = position.y;
  };

  const handleFree = (event: EventObjectNode) => {
    const forceNode = nodeById.get(event.target.id());
    if (!forceNode) return;
    if (!forceNode.isRoot) {
      forceNode.fx = null;
      forceNode.fy = null;
    }
    simulation.alphaTarget(0);
  };

  cy.on("grab", "node", handleGrab);
  cy.on("drag", "node", handleDrag);
  cy.on("free", "node", handleFree);

  return {
    reheat: () => {
      simulation.alpha(0.72).alphaTarget(0).restart();
    },
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
  const positions = computeForcePositions(elements, overrides);

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
