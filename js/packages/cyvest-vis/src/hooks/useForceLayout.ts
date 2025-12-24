/**
 * Hook for computing force-directed layout using d3-force.
 * Uses a stable simulation that persists across renders.
 */

import { useEffect, useRef, useCallback, useMemo } from "react";
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCenter,
  forceCollide,
  forceX,
  forceY,
  type Simulation,
  type SimulationNodeDatum,
  type SimulationLinkDatum,
} from "d3-force";
import {
  useReactFlow,
  useNodesInitialized,
  useStore,
  type Node,
  type Edge,
} from "@xyflow/react";
import type { ForceLayoutConfig } from "../types";
import { DEFAULT_FORCE_CONFIG } from "../types";

/**
 * D3 simulation node with position.
 */
interface SimNode extends SimulationNodeDatum {
  id: string;
  x: number;
  y: number;
  fx?: number | null;
  fy?: number | null;
}

/**
 * D3 simulation link.
 */
interface SimLink extends SimulationLinkDatum<SimNode> {
  source: string | SimNode;
  target: string | SimNode;
}

/**
 * Selector to get node IDs for change detection
 */
const nodeIdsSelector = (state: { nodeLookup: Map<string, Node> }) => {
  const ids = Array.from(state.nodeLookup.keys()).sort();
  return ids.join(",");
};

/**
 * Hook that applies iterative force-directed layout to React Flow nodes.
 * The simulation runs continuously and updates node positions on each tick.
 */
export function useForceLayout(
  config: Partial<ForceLayoutConfig> = {},
  rootNodeId?: string
) {
  const { getNodes, getEdges, setNodes } = useReactFlow();
  const nodesInitialized = useNodesInitialized();
  const nodeIds = useStore(nodeIdsSelector);

  // Merge config with defaults
  const forceConfig = useMemo(
    () => ({ ...DEFAULT_FORCE_CONFIG, ...config }),
    [config]
  );

  // Store the simulation reference
  const simulationRef = useRef<Simulation<SimNode, SimLink> | null>(null);

  // Track dragging state with ref for immediate access
  const draggingRef = useRef<{
    nodeId: string | null;
    active: boolean;
  }>({ nodeId: null, active: false });

  // Store node positions in a ref to avoid React state conflicts during drag
  const nodePositionsRef = useRef<Map<string, { x: number; y: number }>>(
    new Map()
  );

  // Animation frame ref for smooth updates
  const rafRef = useRef<number | null>(null);

  // Initialize and run the simulation
  useEffect(() => {
    if (!nodesInitialized || !nodeIds) {
      return;
    }

    const nodes = getNodes();
    const edges = getEdges();

    if (nodes.length === 0) {
      return;
    }

    // Create simulation nodes from React Flow nodes
    const simNodes: SimNode[] = nodes.map((node) => {
      // Check if this node already exists in the simulation
      const existingNode = simulationRef.current
        ?.nodes()
        .find((n) => n.id === node.id);

      // Use existing position if available, otherwise use node position
      const x =
        existingNode?.x ??
        nodePositionsRef.current.get(node.id)?.x ??
        node.position.x ??
        Math.random() * 500 - 250;
      const y =
        existingNode?.y ??
        nodePositionsRef.current.get(node.id)?.y ??
        node.position.y ??
        Math.random() * 500 - 250;

      return {
        id: node.id,
        x,
        y,
        // Preserve fixed positions for dragged nodes or root
        fx: existingNode?.fx ?? null,
        fy: existingNode?.fy ?? null,
      };
    });

    // Fix root node at center
    if (rootNodeId) {
      const rootNode = simNodes.find((n) => n.id === rootNodeId);
      if (rootNode) {
        rootNode.x = 0;
        rootNode.y = 0;
        rootNode.fx = 0;
        rootNode.fy = 0;
      }
    }

    // Create simulation links from React Flow edges
    const simLinks: SimLink[] = edges.map((edge) => ({
      source: edge.source,
      target: edge.target,
    }));

    // Stop existing simulation
    if (simulationRef.current) {
      simulationRef.current.stop();
    }

    // Cancel any pending animation frame
    if (rafRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }

    // Create the force simulation
    const simulation = forceSimulation<SimNode>(simNodes)
      .force(
        "link",
        forceLink<SimNode, SimLink>(simLinks)
          .id((d) => d.id)
          .distance(forceConfig.linkDistance)
          .strength(0.4)
      )
      .force(
        "charge",
        forceManyBody<SimNode>().strength(forceConfig.chargeStrength)
      )
      .force("center", forceCenter(0, 0).strength(forceConfig.centerStrength))
      .force("collision", forceCollide<SimNode>(forceConfig.collisionRadius))
      .force("x", forceX<SimNode>(0).strength(0.008))
      .force("y", forceY<SimNode>(0).strength(0.008))
      .alphaDecay(0.02)
      .velocityDecay(0.35);

    // Batch updates using requestAnimationFrame for smoother rendering
    const updateNodes = () => {
      if (draggingRef.current.active) {
        // Don't update node positions while actively dragging
        rafRef.current = requestAnimationFrame(updateNodes);
        return;
      }

      const simNodes = simulation.nodes();

      // Update position cache
      for (const simNode of simNodes) {
        nodePositionsRef.current.set(simNode.id, { x: simNode.x, y: simNode.y });
      }

      // Batch update React Flow nodes
      setNodes((currentNodes) =>
        currentNodes.map((node) => {
          const simNode = simNodes.find((n) => n.id === node.id);
          if (!simNode) return node;

          // Skip update if position hasn't changed significantly
          const dx = Math.abs(node.position.x - simNode.x);
          const dy = Math.abs(node.position.y - simNode.y);
          if (dx < 0.1 && dy < 0.1) return node;

          return {
            ...node,
            position: {
              x: simNode.x,
              y: simNode.y,
            },
          };
        })
      );

      if (simulation.alpha() > 0.001) {
        rafRef.current = requestAnimationFrame(updateNodes);
      }
    };

    simulation.on("tick", () => {
      if (rafRef.current === null && simulation.alpha() > 0.001) {
        rafRef.current = requestAnimationFrame(updateNodes);
      }
    });

    simulationRef.current = simulation;

    // Cleanup: stop simulation when unmounting or dependencies change
    return () => {
      simulation.stop();
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [
    nodesInitialized,
    nodeIds,
    getNodes,
    getEdges,
    setNodes,
    forceConfig,
    rootNodeId,
  ]);

  /**
   * Handle drag start - fix the node position
   */
  const onNodeDragStart = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const simulation = simulationRef.current;
      if (!simulation) return;

      // Mark as dragging immediately
      draggingRef.current = { nodeId: node.id, active: true };

      // Find and fix the simulation node
      const simNode = simulation.nodes().find((n) => n.id === node.id);
      if (simNode) {
        simNode.fx = node.position.x;
        simNode.fy = node.position.y;
      }

      // Gently reheat the simulation
      simulation.alphaTarget(0.1).restart();
    },
    []
  );

  /**
   * Handle drag - update the fixed position without triggering React updates
   */
  const onNodeDrag = useCallback((_: React.MouseEvent, node: Node) => {
    const simulation = simulationRef.current;
    if (!simulation) return;

    const simNode = simulation.nodes().find((n) => n.id === node.id);
    if (simNode) {
      simNode.fx = node.position.x;
      simNode.fy = node.position.y;
      // Update cache
      nodePositionsRef.current.set(node.id, {
        x: node.position.x,
        y: node.position.y,
      });
    }
  }, []);

  /**
   * Handle drag end - unfix the node and let simulation cool down
   */
  const onNodeDragStop = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const simulation = simulationRef.current;

      // Clear dragging state first
      draggingRef.current = { nodeId: null, active: false };

      if (!simulation) return;

      // Let simulation cool down gradually
      simulation.alphaTarget(0);

      // Unfix the node (unless it's the root)
      if (node.id !== rootNodeId) {
        const simNode = simulation.nodes().find((n) => n.id === node.id);
        if (simNode) {
          simNode.fx = null;
          simNode.fy = null;
        }
      }

      // Schedule a gentle restart to let the graph settle
      setTimeout(() => {
        if (simulationRef.current && !draggingRef.current.active) {
          simulationRef.current.alpha(0.1).restart();
        }
      }, 50);
    },
    [rootNodeId]
  );

  /**
   * Update force configuration dynamically
   */
  const updateForceConfig = useCallback(
    (updates: Partial<ForceLayoutConfig>) => {
      const simulation = simulationRef.current;
      if (!simulation) return;

      if (updates.chargeStrength !== undefined) {
        simulation.force(
          "charge",
          forceManyBody<SimNode>().strength(updates.chargeStrength)
        );
      }

      if (updates.linkDistance !== undefined) {
        const linkForce = simulation.force("link") as
          | ReturnType<typeof forceLink<SimNode, SimLink>>
          | undefined;
        if (linkForce) {
          linkForce.distance(updates.linkDistance);
        }
      }

      if (updates.collisionRadius !== undefined) {
        simulation.force(
          "collision",
          forceCollide<SimNode>(updates.collisionRadius)
        );
      }

      // Reheat simulation to apply changes
      simulation.alpha(0.3).restart();
    },
    []
  );

  /**
   * Manually restart the simulation
   */
  const restartSimulation = useCallback(() => {
    const simulation = simulationRef.current;
    if (!simulation) return;

    simulation.alpha(1).restart();
  }, []);

  return {
    onNodeDragStart,
    onNodeDrag,
    onNodeDragStop,
    updateForceConfig,
    restartSimulation,
  };
}

/**
 * One-time force layout computation (for static layouts).
 * Use this when you don't need continuous simulation.
 */
export function computeForceLayout(
  nodes: Node[],
  edges: Edge[],
  config: ForceLayoutConfig,
  centerX: number = 0,
  centerY: number = 0,
  rootNodeId?: string
): { nodes: Node[]; edges: Edge[] } {
  if (nodes.length === 0) {
    return { nodes, edges };
  }

  // Create simulation nodes
  const simNodes: SimNode[] = nodes.map((node) => ({
    id: node.id,
    x: node.position.x || Math.random() * 400 - 200,
    y: node.position.y || Math.random() * 400 - 200,
    fx: null,
    fy: null,
  }));

  // Find root node and fix it at center
  if (rootNodeId) {
    const rootNode = simNodes.find((n) => n.id === rootNodeId);
    if (rootNode) {
      rootNode.x = centerX;
      rootNode.y = centerY;
      rootNode.fx = centerX;
      rootNode.fy = centerY;
    }
  }

  // Create simulation links
  const simLinks: SimLink[] = edges.map((edge) => ({
    source: edge.source,
    target: edge.target,
  }));

  // Create and run simulation
  const simulation = forceSimulation<SimNode>(simNodes)
    .force(
      "link",
      forceLink<SimNode, SimLink>(simLinks)
        .id((d) => d.id)
        .distance(config.linkDistance)
    )
    .force("charge", forceManyBody().strength(config.chargeStrength))
    .force(
      "center",
      forceCenter(centerX, centerY).strength(config.centerStrength)
    )
    .force("collision", forceCollide(config.collisionRadius))
    .stop();

  // Run simulation ticks
  for (let i = 0; i < config.iterations; i++) {
    simulation.tick();
  }

  // Create positioned nodes
  const positionedNodes = nodes.map((node) => {
    const simNode = simNodes.find((n) => n.id === node.id);
    return {
      ...node,
      position: {
        x: simNode?.x ?? node.position.x,
        y: simNode?.y ?? node.position.y,
      },
    };
  });

  return { nodes: positionedNodes, edges };
}
