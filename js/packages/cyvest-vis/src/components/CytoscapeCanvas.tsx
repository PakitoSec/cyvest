import React, { useCallback, useEffect, useMemo, useRef } from "react";
import type {
  Core,
  ElementDefinition,
  EventObject,
  EventObjectEdge,
  EventObjectNode,
  LayoutOptions,
  StylesheetJson,
} from "cytoscape";

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
  stylesheet: StylesheetJson;
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

const COMPACT_LABELS_WIDTH = 640;
const COMPACT_FIT_PADDING = 32;

export function updateLabelDensity(cy: Core, containerWidth: number): boolean {
  const compact = containerWidth < COMPACT_LABELS_WIDTH;
  cy.nodes().toggleClass("cyvest-compact-label", compact);
  return compact;
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
  const onCyReadyRef = useRef(onCyReady);
  const compactLabelsRef = useRef<boolean | null>(null);
  const simulationRef = useRef<ForceSimulationController | null>(null);

  layoutRef.current = layout;
  forceOptionsRef.current = forceOptions;
  physicsRef.current = physics;
  onCyReadyRef.current = onCyReady;

  useEffect(() => {
    if (!containerRef.current) {
      return;
    }

    const cy = createCyInstance(containerRef.current);
    cyRef.current = cy;
    onCyReadyRef.current?.(cy);

    return () => {
      simulationRef.current?.stop();
      simulationRef.current = null;
      cy.destroy();
      cyRef.current = null;
    };
  }, []);

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
    } as LayoutOptions);
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
      compactLabelsRef.current = updateLabelDensity(
        cy,
        containerRef.current?.clientWidth ?? 0
      );
    });

    runLayout();
  }, [elements, physics, runLayout, stylesheet]);

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
        relationshipFamily:
          typeof data.relationshipFamily === "string"
            ? data.relationshipFamily as CyEdgeSelectEvent["relationshipFamily"]
            : undefined,
        direction:
          typeof data.direction === "string"
            ? data.direction as CyEdgeSelectEvent["direction"]
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

    const handleEdgeMouseOver = (event: EventObjectEdge) => {
      cy.elements().addClass("cyvest-dimmed");
      event.target.removeClass("cyvest-dimmed").addClass("cyvest-focus");
      event.target.connectedNodes().removeClass("cyvest-dimmed");
    };

    const handleCanvasTap = (event: EventObject) => {
      if (event.target === cy) {
        cy.elements().unselect();
      }
    };

    cy.on("tap", "node", handleNodeTap);
    cy.on("tap", "edge", handleEdgeTap);
    cy.on("mouseover", "node", handleNodeMouseOver);
    cy.on("mouseover", "edge", handleEdgeMouseOver);
    cy.on("mouseout", "node", clearFocus);
    cy.on("mouseout", "edge", clearFocus);
    cy.on("tap", handleCanvasTap);

    return () => {
      cy.removeListener("tap", "node", handleNodeTap);
      cy.removeListener("tap", "edge", handleEdgeTap);
      cy.removeListener("mouseover", "node", handleNodeMouseOver);
      cy.removeListener("mouseover", "edge", handleEdgeMouseOver);
      cy.removeListener("mouseout", "node", clearFocus);
      cy.removeListener("mouseout", "edge", clearFocus);
      cy.removeListener("tap", handleCanvasTap);
    };
  }, [onEdgeSelect, onNodeSelect]);

  useEffect(() => {
    const container = containerRef.current;
    const cy = cyRef.current;
    if (!container || !cy || typeof ResizeObserver === "undefined") {
      return;
    }

    let animationFrame: number | null = null;
    let settledFitTimer: ReturnType<typeof setTimeout> | null = null;
    const observer = new ResizeObserver(() => {
      if (animationFrame !== null) cancelAnimationFrame(animationFrame);
      animationFrame = requestAnimationFrame(() => {
        if (cy.destroyed()) return;
        cy.resize();
        const compact = updateLabelDensity(cy, container.clientWidth);
        if (compactLabelsRef.current !== compact) {
          compactLabelsRef.current = compact;
          runLayout();
        }
        const layoutPadding = (
          layoutRef.current as LayoutOptions & { padding?: number }
        ).padding;
        const padding = typeof layoutPadding === "number" ? layoutPadding : 56;
        const fitPadding = compact ? Math.min(padding, COMPACT_FIT_PADDING) : padding;
        const fit = () => {
          if (!cy.destroyed()) {
            cy.fit(undefined, fitPadding);
          }
        };
        fit();
        if (settledFitTimer !== null) clearTimeout(settledFitTimer);
        settledFitTimer = setTimeout(fit, 520);
      });
    });
    observer.observe(container);

    return () => {
      observer.disconnect();
      if (animationFrame !== null) cancelAnimationFrame(animationFrame);
      if (settledFitTimer !== null) clearTimeout(settledFitTimer);
    };
  }, [runLayout]);

  const handleFit = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    const layoutPadding = (layout as LayoutOptions & { padding?: number }).padding;
    const padding = typeof layoutPadding === "number" ? layoutPadding : 56;
    cy.fit(
      undefined,
      compactLabelsRef.current ? Math.min(padding, COMPACT_FIT_PADDING) : padding
    );
  }, [layout]);

  const handleCenter = useCallback(() => {
    const cy = cyRef.current;
    if (!cy) {
      return;
    }

    const root = cy.nodes().filter((node) => node.data("isRoot") === true).first();
    cy.animate(
      { center: { eles: root.empty() ? cy.nodes() : root } },
      { duration: 260 }
    );
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
