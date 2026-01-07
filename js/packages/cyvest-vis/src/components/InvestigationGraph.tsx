/**
 * InvestigationGraph component - displays investigation structure with Dagre layout.
 * Shows root observable, checks, and tags in a hierarchical view.
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

import type { CyvestInvestigation, Check, Tag } from "@cyvest/cyvest-js";
import { getTagAncestors } from "@cyvest/cyvest-js";

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
 * Get all tags as an array.
 */
function getAllTags(tags: Record<string, Tag>): Tag[] {
  return Object.values(tags);
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

  // Collect all check keys that belong to tags
  // These checks should NOT have a direct link to the root node
  const allTags = getAllTags(investigation.tags);
  const checksInTags = new Set<string>();
  for (const tag of allTags) {
    for (const checkKey of tag.checks) {
      checksInTags.add(checkKey);
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

    // Only create edge from root to check if check is NOT in a tag
    // Checks in tags will be linked through their tag instead
    if (!checksInTags.has(check.key)) {
      edges.push({
        id: `edge-root-${check.key}`,
        source: rootKey,
        target: `check-${check.key}`,
        type: "smoothstep",
        animated: false,
      });
    }
  }

  // Build hierarchical tag structure
  // First, collect all tag names and find/create ancestor tags
  const tagByName = new Map<string, Tag>();
  for (const tag of allTags) {
    tagByName.set(tag.name, tag);
  }

  // Collect all unique tag names including synthetic ancestors
  const allTagNames = new Set<string>();
  for (const tag of allTags) {
    allTagNames.add(tag.name);
    // Add ancestors (they may not exist as actual tags)
    for (const ancestor of getTagAncestors(tag.name)) {
      allTagNames.add(ancestor);
    }
  }

  // Create tag nodes (real and synthetic)
  for (const tagName of allTagNames) {
    const realTag = tagByName.get(tagName);

    const tagNodeData: InvestigationNodeData = {
      label: truncateLabel(tagName.split(":").pop() ?? tagName, 20),
      nodeType: "tag",
      level: realTag?.direct_level ?? "INFO",
      score: realTag?.direct_score ?? 0,
      name: tagName,
    };

    nodes.push({
      id: `tag-${tagName}`,
      type: "investigation",
      position: { x: 0, y: 0 },
      data: tagNodeData,
      selectable: true,
      draggable: true,
    });
  }

  // Create edges based on tag hierarchy
  for (const tagName of allTagNames) {
    const nodeId = `tag-${tagName}`;
    const parts = tagName.split(":");

    if (parts.length === 1) {
      // Top-level tag, connect to root
      edges.push({
        id: `edge-root-tag-${tagName}`,
        source: rootKey,
        target: nodeId,
        type: "smoothstep",
        animated: false,
      });
    } else {
      // Has a parent tag, connect to parent
      const parentName = parts.slice(0, -1).join(":");
      edges.push({
        id: `edge-tag-${parentName}-${tagName}`,
        source: `tag-${parentName}`,
        target: nodeId,
        type: "smoothstep",
        animated: false,
      });
    }
  }

  // Create edges from tags to their checks (only for real tags with checks)
  for (const tag of allTags) {
    for (const checkKey of tag.checks) {
      if (seenCheckIds.has(checkKey)) {
        edges.push({
          id: `edge-tag-check-${tag.name}-${checkKey}`,
          source: `tag-${tag.name}`,
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
