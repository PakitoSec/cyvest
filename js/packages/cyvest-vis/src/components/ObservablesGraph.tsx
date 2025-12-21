/**
 * ObservablesGraph component - displays observables as a force-directed graph.
 * Uses iterative d3-force simulation for smooth, interactive layout.
 */

import React, { useMemo, useCallback, useState } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type NodeTypes,
  type EdgeTypes,
  ConnectionMode,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import type { CyvestInvestigation } from "@cyvest/cyvest-js";
import { getObservableGraph } from "@cyvest/cyvest-js";

import type {
  ObservablesGraphProps,
  ObservableNodeData,
  ObservableEdgeData,
  ForceLayoutConfig,
} from "../types";
import { DEFAULT_FORCE_CONFIG } from "../types";
import { ObservableNode } from "./ObservableNode";
import { FloatingEdge } from "./FloatingEdge";
import {
  getObservableEmoji,
  getObservableShape,
  truncateLabel,
  getLevelColor,
} from "../utils/observables";
import { useForceLayout } from "../hooks/useForceLayout";

/**
 * Custom node types for React Flow.
 */
const nodeTypes: NodeTypes = {
  observable: ObservableNode,
};

/**
 * Custom edge types for React Flow.
 */
const edgeTypes: EdgeTypes = {
  floating: FloatingEdge,
};

/**
 * Convert investigation observables to React Flow nodes.
 */
function createObservableNodes(
  investigation: CyvestInvestigation,
  rootObservableIds: Set<string>
): Node<ObservableNodeData>[] {
  const graph = getObservableGraph(investigation);

  return graph.nodes.map((graphNode, index) => {
    const isRoot = rootObservableIds.has(graphNode.id);
    const shape = getObservableShape(graphNode.type, isRoot);

    const nodeData: ObservableNodeData = {
      label: truncateLabel(graphNode.value, 18),
      fullValue: graphNode.value,
      observableType: graphNode.type,
      level: graphNode.level,
      score: graphNode.score,
      emoji: getObservableEmoji(graphNode.type),
      shape,
      isRoot,
      whitelisted: graphNode.whitelisted,
      internal: graphNode.internal,
    };

    // Spread initial positions in a circle for better starting layout
    const angle = (index / graph.nodes.length) * 2 * Math.PI;
    const radius = isRoot ? 0 : 150;

    return {
      id: graphNode.id,
      type: "observable",
      position: {
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
      },
      data: nodeData,
    };
  });
}

/**
 * Convert investigation relationships to React Flow edges.
 */
function createObservableEdges(
  investigation: CyvestInvestigation
): Edge<ObservableEdgeData>[] {
  const graph = getObservableGraph(investigation);

  return graph.edges.map((graphEdge, index) => {
    const edgeData: ObservableEdgeData = {
      relationshipType: graphEdge.type,
      bidirectional: graphEdge.direction === "bidirectional",
    };

    return {
      id: `edge-${graphEdge.source}-${graphEdge.target}-${index}`,
      source: graphEdge.source,
      target: graphEdge.target,
      type: "floating",
      data: edgeData,
      style: { stroke: "#94a3b8", strokeWidth: 1.5 },
    };
  });
}

/**
 * Force controls panel component.
 */
const ForceControls: React.FC<{
  config: ForceLayoutConfig;
  onChange: (updates: Partial<ForceLayoutConfig>) => void;
  onRestart: () => void;
}> = ({ config, onChange, onRestart }) => {
  return (
    <div
      style={{
        position: "absolute",
        top: 10,
        right: 10,
        background: "white",
        padding: 12,
        borderRadius: 8,
        boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
        fontSize: 12,
        fontFamily: "system-ui, sans-serif",
        zIndex: 10,
        minWidth: 160,
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: 8 }}>Force Layout</div>

      <div style={{ marginBottom: 8 }}>
        <label style={{ display: "block", marginBottom: 2 }}>
          Repulsion: {config.chargeStrength}
        </label>
        <input
          type="range"
          min="-500"
          max="-50"
          value={config.chargeStrength}
          onChange={(e) =>
            onChange({ chargeStrength: Number(e.target.value) })
          }
          style={{ width: "100%" }}
        />
      </div>

      <div style={{ marginBottom: 8 }}>
        <label style={{ display: "block", marginBottom: 2 }}>
          Link Distance: {config.linkDistance}
        </label>
        <input
          type="range"
          min="30"
          max="200"
          value={config.linkDistance}
          onChange={(e) =>
            onChange({ linkDistance: Number(e.target.value) })
          }
          style={{ width: "100%" }}
        />
      </div>

      <div style={{ marginBottom: 8 }}>
        <label style={{ display: "block", marginBottom: 2 }}>
          Collision: {config.collisionRadius}
        </label>
        <input
          type="range"
          min="10"
          max="80"
          value={config.collisionRadius}
          onChange={(e) =>
            onChange({ collisionRadius: Number(e.target.value) })
          }
          style={{ width: "100%" }}
        />
      </div>

      <button
        onClick={onRestart}
        style={{
          width: "100%",
          padding: "6px 12px",
          border: "none",
          borderRadius: 4,
          background: "#3b82f6",
          color: "white",
          cursor: "pointer",
          fontSize: 12,
        }}
      >
        Restart Simulation
      </button>
    </div>
  );
};

/**
 * Inner component that uses the force layout hook.
 * Must be wrapped in ReactFlowProvider.
 */
const ObservablesGraphInner: React.FC<
  ObservablesGraphProps & {
    initialNodes: Node[];
    initialEdges: Edge[];
    primaryRootId?: string;
  }
> = ({
  initialNodes,
  initialEdges,
  primaryRootId,
  height,
  width,
  forceConfig: initialForceConfig = {},
  onNodeClick,
  onNodeDoubleClick,
  className,
  showControls = true,
}) => {
  // Force config state
  const [forceConfig, setForceConfig] = useState<ForceLayoutConfig>({
    ...DEFAULT_FORCE_CONFIG,
    ...initialForceConfig,
  });

  // React Flow state - initialized with initial nodes/edges
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Set initial nodes/edges when they change
  React.useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  // Use the iterative force layout hook
  const {
    onNodeDragStart,
    onNodeDrag,
    onNodeDragStop,
    updateForceConfig,
    restartSimulation,
  } = useForceLayout(forceConfig, primaryRootId);

  // Handle node click
  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      onNodeClick?.(node.id);
    },
    [onNodeClick]
  );

  // Handle node double click
  const handleNodeDoubleClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      onNodeDoubleClick?.(node.id);
    },
    [onNodeDoubleClick]
  );

  // Handle force config update
  const handleConfigChange = useCallback(
    (updates: Partial<ForceLayoutConfig>) => {
      setForceConfig((prev) => ({ ...prev, ...updates }));
      updateForceConfig(updates);
    },
    [updateForceConfig]
  );

  // MiniMap node color based on level
  const miniMapNodeColor = useCallback((node: Node) => {
    const data = node.data as unknown as ObservableNodeData;
    return getLevelColor(data.level);
  }, []);

  return (
    <div
      className={className}
      style={{
        width,
        height,
        position: "relative",
      }}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        onNodeDoubleClick={handleNodeDoubleClick}
        onNodeDragStart={onNodeDragStart}
        onNodeDrag={onNodeDrag}
        onNodeDragStop={onNodeDragStop}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        connectionMode={ConnectionMode.Loose}
        fitView
        fitViewOptions={{ padding: 0.3 }}
        minZoom={0.1}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
      >
        <Background />
        <Controls />
        <MiniMap nodeColor={miniMapNodeColor} zoomable pannable />
      </ReactFlow>

      {showControls && (
        <ForceControls
          config={forceConfig}
          onChange={handleConfigChange}
          onRestart={restartSimulation}
        />
      )}
    </div>
  );
};

/**
 * ObservablesGraph component.
 * Displays all observables from an investigation as a force-directed graph.
 * Wraps the inner component with ReactFlowProvider for hook access.
 */
export const ObservablesGraph: React.FC<ObservablesGraphProps> = (props) => {
  const { investigation } = props;

  const { rootKeys, primaryRootId } = useMemo(() => {
    const rootType = investigation.data_extraction.root_type;
    if (!rootType) {
      return { rootKeys: new Set<string>(), primaryRootId: undefined };
    }

    const normalizedRootType = rootType.toLowerCase().trim();
    const rootsByType = Object.values(investigation.observables).filter(
      (obs) => obs.type.toLowerCase() === normalizedRootType
    );

    return {
      rootKeys: new Set(rootsByType.map((obs) => obs.key)),
      primaryRootId: rootsByType[0]?.key,
    };
  }, [investigation]);

  // Create initial nodes and edges
  const { initialNodes, initialEdges } = useMemo(() => {
    const nodes = createObservableNodes(investigation, rootKeys);
    const edges = createObservableEdges(investigation);
    return { initialNodes: nodes, initialEdges: edges };
  }, [investigation, rootKeys]);

  return (
    <ReactFlowProvider>
      <ObservablesGraphInner
        {...props}
        initialNodes={initialNodes}
        initialEdges={initialEdges}
        primaryRootId={primaryRootId}
      />
    </ReactFlowProvider>
  );
};
