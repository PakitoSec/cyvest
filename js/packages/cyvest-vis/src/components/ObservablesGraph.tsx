/**
 * ObservablesGraph component - displays observables as a force-directed graph.
 * Uses iterative d3-force simulation for smooth, interactive layout.
 */

import React, { useMemo, useCallback, useState, useRef } from "react";
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
  BackgroundVariant,
  Panel,
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
import { truncateLabel, getLevelColor } from "../utils/observables";
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
 * Default edge style options
 */
const defaultEdgeOptions = {
  type: "floating",
  style: { stroke: "#94a3b8", strokeWidth: 1.5 },
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

    const nodeData: ObservableNodeData = {
      label: truncateLabel(graphNode.value, 16),
      fullValue: graphNode.value,
      observableType: graphNode.type,
      level: graphNode.level,
      score: graphNode.score,
      shape: "circle",
      isRoot,
      whitelisted: graphNode.whitelisted,
      internal: graphNode.internal,
    };

    // Spread initial positions in a circle for better starting layout
    const angle = (index / graph.nodes.length) * 2 * Math.PI;
    const radius = isRoot ? 0 : 180;

    return {
      id: graphNode.id,
      type: "observable",
      position: {
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
      },
      data: nodeData,
      // Enable selection for better UX
      selectable: true,
      draggable: true,
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
      // Animated edges for a modern feel
      animated: false,
      style: { stroke: "#94a3b8", strokeWidth: 1.5 },
    };
  });
}

/**
 * Force controls panel component with modern styling.
 */
const ForceControls: React.FC<{
  config: ForceLayoutConfig;
  onChange: (updates: Partial<ForceLayoutConfig>) => void;
  onRestart: () => void;
}> = ({ config, onChange, onRestart }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const panelStyle: React.CSSProperties = {
    background: "rgba(255, 255, 255, 0.95)",
    backdropFilter: "blur(8px)",
    padding: isExpanded ? 14 : 10,
    borderRadius: 12,
    boxShadow: "0 4px 16px rgba(0,0,0,0.12)",
    fontSize: 12,
    fontFamily:
      "'SF Pro Text', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
    minWidth: isExpanded ? 180 : "auto",
    transition: "all 0.2s ease",
    border: "1px solid rgba(0,0,0,0.06)",
  };

  const headerStyle: React.CSSProperties = {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 8,
    cursor: "pointer",
  };

  const titleStyle: React.CSSProperties = {
    fontWeight: 600,
    color: "#1f2937",
    fontSize: 12,
    letterSpacing: "-0.01em",
  };

  const toggleStyle: React.CSSProperties = {
    background: "none",
    border: "none",
    cursor: "pointer",
    padding: 4,
    borderRadius: 4,
    color: "#6b7280",
    display: "flex",
    alignItems: "center",
    transition: "transform 0.2s ease",
    transform: isExpanded ? "rotate(180deg)" : "rotate(0deg)",
  };

  const sliderContainerStyle: React.CSSProperties = {
    marginTop: 12,
    display: isExpanded ? "block" : "none",
  };

  const sliderLabelStyle: React.CSSProperties = {
    display: "flex",
    justifyContent: "space-between",
    marginBottom: 4,
    color: "#4b5563",
    fontSize: 11,
  };

  const sliderStyle: React.CSSProperties = {
    width: "100%",
    height: 4,
    appearance: "none",
    background: "#e5e7eb",
    borderRadius: 2,
    outline: "none",
    cursor: "pointer",
  };

  const buttonStyle: React.CSSProperties = {
    width: "100%",
    padding: "8px 12px",
    border: "none",
    borderRadius: 8,
    background: "linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)",
    color: "white",
    cursor: "pointer",
    fontSize: 12,
    fontWeight: 500,
    marginTop: 12,
    transition: "transform 0.1s ease, box-shadow 0.1s ease",
    boxShadow: "0 2px 4px rgba(59, 130, 246, 0.3)",
  };

  return (
    <div style={panelStyle}>
      <div style={headerStyle} onClick={() => setIsExpanded(!isExpanded)}>
        <span style={titleStyle}>⚡ Force Layout</span>
        <button style={toggleStyle}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <polyline points="6 9 12 15 18 9" />
          </svg>
        </button>
      </div>

      <div style={sliderContainerStyle}>
        <div style={{ marginBottom: 10 }}>
          <div style={sliderLabelStyle}>
            <span>Repulsion</span>
            <span>{config.chargeStrength}</span>
          </div>
          <input
            type="range"
            min="-500"
            max="-50"
            value={config.chargeStrength}
            onChange={(e) =>
              onChange({ chargeStrength: Number(e.target.value) })
            }
            style={sliderStyle}
          />
        </div>

        <div style={{ marginBottom: 10 }}>
          <div style={sliderLabelStyle}>
            <span>Link Distance</span>
            <span>{config.linkDistance}</span>
          </div>
          <input
            type="range"
            min="30"
            max="200"
            value={config.linkDistance}
            onChange={(e) =>
              onChange({ linkDistance: Number(e.target.value) })
            }
            style={sliderStyle}
          />
        </div>

        <div style={{ marginBottom: 6 }}>
          <div style={sliderLabelStyle}>
            <span>Collision</span>
            <span>{config.collisionRadius}</span>
          </div>
          <input
            type="range"
            min="10"
            max="80"
            value={config.collisionRadius}
            onChange={(e) =>
              onChange({ collisionRadius: Number(e.target.value) })
            }
            style={sliderStyle}
          />
        </div>

        <button
          onClick={onRestart}
          style={buttonStyle}
          onMouseEnter={(e) => {
            e.currentTarget.style.transform = "translateY(-1px)";
            e.currentTarget.style.boxShadow = "0 4px 8px rgba(59, 130, 246, 0.4)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = "translateY(0)";
            e.currentTarget.style.boxShadow = "0 2px 4px rgba(59, 130, 246, 0.3)";
          }}
        >
          Restart Simulation
        </button>
      </div>
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

  // Track if this is the first render for fitView
  const initialFitDone = useRef(false);

  // React Flow state - initialized with initial nodes/edges
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Set initial nodes/edges when they change
  React.useEffect(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
    initialFitDone.current = false;
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
        onNodeDoubleClick={handleNodeDoubleClick}
        onNodeDragStart={onNodeDragStart}
        onNodeDrag={onNodeDrag}
        onNodeDragStop={onNodeDragStop}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        defaultEdgeOptions={defaultEdgeOptions}
        connectionMode={ConnectionMode.Loose}
        fitView
        fitViewOptions={{ padding: 0.4, maxZoom: 1.5 }}
        minZoom={0.1}
        maxZoom={2.5}
        proOptions={{ hideAttribution: true }}
        // Better defaults for UX
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

        {showControls && (
          <Panel position="top-right">
            <ForceControls
              config={forceConfig}
              onChange={handleConfigChange}
              onRestart={restartSimulation}
            />
          </Panel>
        )}
      </ReactFlow>
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
