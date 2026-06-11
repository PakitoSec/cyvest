import React, { useCallback, useEffect, useMemo, useRef } from "react";
import type { Core, ElementDefinition, EventObjectEdge, EventObjectNode, LayoutOptions, Stylesheet } from "cytoscape";

import { createCyInstance } from "../core/createCyInstance";
import { createThemeStyle } from "../core/theme";
import {
  startForceSimulation,
  type ForceSimulationController,
} from "../layout/force";
import type {
  CyEdgeSelectEvent,
  CyNodeSelectEvent,
  CyvestForceOptions,
  CyvestThemeTokens,
} from "../types";

interface CytoscapeCanvasProps {
  elements: ElementDefinition[];
  stylesheet: Stylesheet[];
  layout: LayoutOptions;
  forceOptions?: CyvestForceOptions;
  physics?: boolean;
  width: number | string;
  height: number | string;
  className?: string;
  theme?: Partial<CyvestThemeTokens>;
  onCyReady?: (cy: Core) => void;
  onNodeSelect?: (event: CyNodeSelectEvent) => void;
  onEdgeSelect?: (event: CyEdgeSelectEvent) => void;
  showToolbar?: boolean;
}

function joinClassNames(...names: Array<string | undefined | false>): string {
  return names.filter(Boolean).join(" ");
}

export const CytoscapeCanvas: React.FC<CytoscapeCanvasProps> = ({
  elements,
  stylesheet,
  layout,
  forceOptions,
  physics = true,
  width,
  height,
  className,
  theme,
  onCyReady,
  onNodeSelect,
  onEdgeSelect,
  showToolbar = true,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const layoutRef = useRef(layout);
  const forceOptionsRef = useRef(forceOptions);
  const physicsRef = useRef(physics);
  const simulationRef = useRef<ForceSimulationController | null>(null);

  layoutRef.current = layout;
  forceOptionsRef.current = forceOptions;
  physicsRef.current = physics;

  useEffect(() => {
    if (!containerRef.current) {
      return;
    }

    const cy = createCyInstance(containerRef.current);
    cyRef.current = cy;
    onCyReady?.(cy);

    return () => {
      simulationRef.current?.stop();
      simulationRef.current = null;
      cy.destroy();
      cyRef.current = null;
    };
  }, [onCyReady]);

  const runLayout = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    simulationRef.current?.stop();
    simulationRef.current = null;

    const runner = cy.layout({
      ...layoutRef.current,
      animate: false,
    });
    runner.run();

    if (physicsRef.current) {
      simulationRef.current = startForceSimulation(
        cy,
        forceOptionsRef.current
      );
    }
  }, []);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    cy.batch(() => {
      cy.elements().remove();
      cy.add(elements);
      cy.style().fromJson(stylesheet).update();
    });

    runLayout();
  }, [elements, runLayout, stylesheet]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    const handleNodeTap = (event: EventObjectNode) => {
      if (!onNodeSelect) {
        return;
      }

      const node = event.target;
      const data = node.data() as Record<string, unknown>;
      const rawLabel = data.labelFull ?? data.labelShort ?? node.id();

      onNodeSelect({
        view: "observables",
        nodeId: node.id(),
        nodeType:
          typeof data.nodeType === "string" ? data.nodeType : "unknown",
        label: String(rawLabel),
        data,
        element: node,
      });
    };

    const handleEdgeTap = (event: EventObjectEdge) => {
      if (!onEdgeSelect) {
        return;
      }

      const edge = event.target;
      const data = edge.data() as Record<string, unknown>;

      onEdgeSelect({
        view: "observables",
        edgeId: edge.id(),
        sourceId: edge.source().id(),
        targetId: edge.target().id(),
        relationshipType:
          typeof data.relationshipType === "string"
            ? data.relationshipType
            : undefined,
        data,
        element: edge,
      });
    };

    const handleNodeMouseOver = (event: EventObjectNode) => {
      const node = event.target;
      const neighborhood = node.closedNeighborhood();
      cy.elements().addClass("cyvest-dimmed");
      neighborhood.removeClass("cyvest-dimmed");
      node.addClass("cyvest-focus");
      node.connectedEdges().addClass("cyvest-focus");
    };

    const clearFocus = () => {
      cy.elements().removeClass("cyvest-dimmed cyvest-focus");
    };

    const handleCanvasTap = (event: EventObjectNode | EventObjectEdge) => {
      if (event.target === cy) {
        cy.elements().unselect();
      }
    };

    cy.on("tap", "node", handleNodeTap);
    cy.on("tap", "edge", handleEdgeTap);
    cy.on("mouseover", "node", handleNodeMouseOver);
    cy.on("mouseout", "node", clearFocus);
    cy.on("tap", handleCanvasTap);

    return () => {
      cy.removeListener("tap", "node", handleNodeTap);
      cy.removeListener("tap", "edge", handleEdgeTap);
      cy.removeListener("mouseover", "node", handleNodeMouseOver);
      cy.removeListener("mouseout", "node", clearFocus);
      cy.removeListener("tap", handleCanvasTap);
    };
  }, [onEdgeSelect, onNodeSelect]);

  const handleFit = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    const padding =
      typeof layout.padding === "number" ? layout.padding : 56;
    cy.fit(undefined, padding);
  }, [layout.padding]);

  const handleCenter = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    cy.center();
  }, []);

  const wrapperStyle = useMemo(
    () => createThemeStyle(theme, width, height),
    [theme, width, height]
  );

  return (
    <div
      className={joinClassNames("cyvest-canvas", className)}
      style={wrapperStyle}
    >
      <div className="cyvest-canvas__surface" ref={containerRef} />

      {showToolbar && (
        <div className="cyvest-toolbar" role="toolbar" aria-label="Graph controls">
          <button
            type="button"
            className="cyvest-toolbar__button"
            onClick={handleFit}
            title="Fit graph"
            aria-label="Fit graph"
          >
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M8 3H3v5" />
              <path d="m3 3 7 7" />
              <path d="M16 3h5v5" />
              <path d="m21 3-7 7" />
              <path d="M8 21H3v-5" />
              <path d="m3 21 7-7" />
              <path d="M16 21h5v-5" />
              <path d="m21 21-7-7" />
            </svg>
          </button>
          <button
            type="button"
            className="cyvest-toolbar__button"
            onClick={runLayout}
            title="Reheat physics"
            aria-label="Reheat physics"
          >
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M21 12a9 9 0 1 1-2.64-6.36" />
              <path d="M21 3v6h-6" />
            </svg>
          </button>
          <button
            type="button"
            className="cyvest-toolbar__button"
            onClick={handleCenter}
            title="Center view"
            aria-label="Center view"
          >
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle cx="12" cy="12" r="3" />
              <circle cx="12" cy="12" r="9" />
            </svg>
          </button>
        </div>
      )}
    </div>
  );
};
