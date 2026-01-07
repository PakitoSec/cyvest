/**
 * InvestigationGraph component - displays investigation structure with Dagre layout.
 * Shows root observable, checks, and containers in a hierarchical view.
 */

import React, { useMemo, useCallback } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type NodeTypes,
  BackgroundVariant,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import type { CyvestInvestigation, Check, Container } from "@cyvest/cyvest-js";

import type {
  InvestigationGraphProps,
  InvestigationNodeData,
  InvestigationNodeType,
} from "../types";
import { InvestigationNode } from "./InvestigationNode";
import { getLevelColor, truncateLabel } from "../utils/observables";
import { computeDagreLayout } from "../hooks/useDagreLayout";

/**
 * Custom node types for React Flow.
 */
const nodeTypes: NodeTypes = {
  investigation: InvestigationNode,
};

/**
 * Default edge style
 */
const defaultEdgeOptions = {
  type: "smoothstep",
  style: {
    stroke: "#94a3b8",
    strokeWidth: 1.5,
  },
  markerEnd: {
    type: MarkerType.ArrowClosed,
    width: 16,
    height: 16,
    color: "#94a3b8",
  },
};

/**
 * Flatten containers recursively to get all container keys.
 */
function flattenContainers(
  containers: Record<string, Container>
): Container[] {
  const result: Container[] = [];

  for (const container of Object.values(containers)) {
    result.push(container);
    if (container.sub_containers) {
      result.push(...flattenContainers(container.sub_containers));
    }
  }

  return result;
}

/**
 * Create investigation graph nodes and edges.
 */
function createInvestigationGraph(
  investigation: CyvestInvestigation
): { nodes: Node<InvestigationNodeData>[]; edges: Edge[] } {
  const nodes: Node<InvestigationNodeData>[] = [];
  const edges: Edge[] = [];

  const rootType = investigation.data_extraction.root_type;
  const normalizedRootType = rootType?.toLowerCase().trim();
  const rootsByType = normalizedRootType
    ? Object.values(investigation.observables).filter(
        (obs) => obs.type.toLowerCase() === normalizedRootType
      )
    : [];
  const primaryRoot = rootsByType[0] ?? null;

  // If no root found, use the first observable or create a placeholder
  const rootKey = primaryRoot?.key ?? investigation.investigation_id;
  const rootValue =
    primaryRoot?.value ??
    investigation.investigation_name ??
    investigation.investigation_id;
  const rootLevel = primaryRoot?.level ?? investigation.level;

  // Create root node
  const rootNodeData: InvestigationNodeData = {
    label: truncateLabel(rootValue, 24),
    nodeType: "root",
    level: rootLevel,
    score: primaryRoot?.score ?? investigation.score,
  };

  nodes.push({
    id: rootKey,
    type: "investigation",
    position: { x: 0, y: 0 },
    data: rootNodeData,
    selectable: true,
    draggable: true,
  });

  // Collect all check keys that belong to containers
  // These checks should NOT have a direct link to the root node
  const allContainers = flattenContainers(investigation.containers);
  const checksInContainers = new Set<string>();
  for (const container of allContainers) {
    for (const checkKey of container.checks) {
      checksInContainers.add(checkKey);
    }
  }

  // Add check nodes
  const allChecks = Object.values(investigation.checks);

  // Create unique check nodes (by key to avoid duplicates)
  const seenCheckIds = new Set<string>();
  for (const check of allChecks) {
    if (seenCheckIds.has(check.key)) continue;
    seenCheckIds.add(check.key);

    const checkNodeData: InvestigationNodeData = {
      label: truncateLabel(check.check_name, 20),
      nodeType: "check",
      level: check.level,
      score: check.score,
      description: truncateLabel(check.description, 30),
    };

    nodes.push({
      id: `check-${check.key}`,
      type: "investigation",
      position: { x: 0, y: 0 },
      data: checkNodeData,
      selectable: true,
      draggable: true,
    });

    // Only create edge from root to check if check is NOT in a container
    // Checks in containers will be linked through their container instead
    if (!checksInContainers.has(check.key)) {
      edges.push({
        id: `edge-root-${check.key}`,
        source: rootKey,
        target: `check-${check.key}`,
        type: "smoothstep",
        animated: false,
      });
    }
  }

  // Add container nodes
  for (const container of allContainers) {
    const containerNodeData: InvestigationNodeData = {
      label: truncateLabel(
        container.path.split("/").pop() ?? container.path,
        20
      ),
      nodeType: "container",
      level: container.aggregated_level,
      score: container.aggregated_score,
      path: container.path,
    };

    nodes.push({
      id: `container-${container.key}`,
      type: "investigation",
      position: { x: 0, y: 0 },
      data: containerNodeData,
      selectable: true,
      draggable: true,
    });

    // Edge from root to container
    edges.push({
      id: `edge-root-container-${container.key}`,
      source: rootKey,
      target: `container-${container.key}`,
      type: "smoothstep",
      animated: false,
    });

    // Edges from container to its checks
    for (const checkKey of container.checks) {
      if (seenCheckIds.has(checkKey)) {
        edges.push({
          id: `edge-container-check-${container.key}-${checkKey}`,
          source: `container-${container.key}`,
          target: `check-${checkKey}`,
          type: "smoothstep",
          animated: false,
        });
      }
    }
  }

  return { nodes, edges };
}

/**
 * InvestigationGraph component.
 * Displays investigation structure with horizontal Dagre layout.
 */
export const InvestigationGraph: React.FC<InvestigationGraphProps> = ({
  investigation,
  height = 500,
  width = "100%",
  onNodeClick,
  className,
}) => {
  // Create initial graph structure
  const { initialNodes, initialEdges } = useMemo(() => {
    const { nodes, edges } = createInvestigationGraph(investigation);
    return { initialNodes: nodes, initialEdges: edges };
  }, [investigation]);

  // Apply Dagre layout
  const { nodes: layoutNodes, edges: layoutEdges } = useMemo(() => {
    return computeDagreLayout(initialNodes, initialEdges, {
      direction: "LR",
      nodeSpacing: 40,
      rankSpacing: 140,
    });
  }, [initialNodes, initialEdges]);

  // React Flow state
  const [nodes, setNodes, onNodesChange] = useNodesState(layoutNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(layoutEdges);

  // Update nodes when layout changes
  React.useEffect(() => {
    setNodes(layoutNodes);
    setEdges(layoutEdges);
  }, [layoutNodes, layoutEdges, setNodes, setEdges]);

  // Handle node click
  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const data = node.data as unknown as InvestigationNodeData;
      onNodeClick?.(node.id, data.nodeType);
    },
    [onNodeClick]
  );

  // MiniMap node color based on level
  const miniMapNodeColor = useCallback((node: Node) => {
    const data = node.data as unknown as InvestigationNodeData;
    return getLevelColor(data.level);
  }, []);

  // Container styles
  const containerStyle = useMemo(
    () => ({
      width,
      height,
      position: "relative" as const,
      background: "linear-gradient(180deg, #fafbfc 0%, #f0f4f8 100%)",
    }),
    [width, height]
  );

  return (
    <div className={className} style={containerStyle}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        nodeTypes={nodeTypes}
        defaultEdgeOptions={defaultEdgeOptions}
        fitView
        fitViewOptions={{ padding: 0.3, maxZoom: 1.5 }}
        minZoom={0.1}
        maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
        // UX settings
        nodesDraggable={true}
        nodesConnectable={false}
        elementsSelectable={true}
        selectNodesOnDrag={false}
        panOnDrag={true}
        zoomOnScroll={true}
        zoomOnPinch={true}
        panOnScroll={false}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={24}
          size={1}
          color="#d1d5db"
        />
        <Controls
          showInteractive={false}
          style={{
            borderRadius: 10,
            boxShadow: "0 2px 12px rgba(0,0,0,0.1)",
            border: "1px solid rgba(0,0,0,0.06)",
          }}
        />
        <MiniMap
          nodeColor={miniMapNodeColor}
          zoomable
          pannable
          style={{
            borderRadius: 10,
            boxShadow: "0 2px 12px rgba(0,0,0,0.1)",
            border: "1px solid rgba(0,0,0,0.06)",
            background: "rgba(255,255,255,0.9)",
          }}
          maskColor="rgba(0,0,0,0.08)"
        />
      </ReactFlow>
    </div>
  );
};
