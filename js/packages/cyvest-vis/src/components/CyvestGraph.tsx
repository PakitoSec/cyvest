import React, { useCallback, useEffect, useMemo, useState } from "react";

import type { CyvestGraphProps, CyvestViewMode } from "../types";
import { CyvestInvestigationView } from "./CyvestInvestigationView";
import { CyvestObservablesView } from "./CyvestObservablesView";

function normalizeInitialView(view: CyvestViewMode | undefined): CyvestViewMode {
  return view === "investigation" ? "investigation" : "observables";
}

export const CyvestGraph: React.FC<CyvestGraphProps> = ({
  investigation,
  height = 500,
  width = "100%",
  className,
  theme,
  onCyReady,
  onNodeSelect,
  onEdgeSelect,
  initialView = "observables",
  showViewToggle = true,
  onViewChange,
  showToolbar = true,
  observablesLayout,
  investigationLayout,
  maxObservableLabelLength = 28,
  maxInvestigationLabelLength = 26,
}) => {
  const [activeView, setActiveView] = useState<CyvestViewMode>(() =>
    normalizeInitialView(initialView)
  );

  useEffect(() => {
    setActiveView(normalizeInitialView(initialView));
  }, [initialView]);

  useEffect(() => {
    onViewChange?.(activeView);
  }, [activeView, onViewChange]);

  const containerStyle = useMemo(
    () => ({
      width,
      height,
      position: "relative" as const,
    }),
    [width, height]
  );

  const handleViewChange = useCallback((view: CyvestViewMode) => {
    setActiveView(view);
  }, []);

  return (
    <div className={className} style={containerStyle}>
      {showViewToggle && (
        <div className="cyvest-view-toggle" role="tablist" aria-label="Graph view mode">
          <button
            type="button"
            className={
              activeView === "observables"
                ? "cyvest-view-toggle__button cyvest-view-toggle__button--active"
                : "cyvest-view-toggle__button"
            }
            onClick={() => handleViewChange("observables")}
            role="tab"
            aria-selected={activeView === "observables"}
          >
            Observables
          </button>
          <button
            type="button"
            className={
              activeView === "investigation"
                ? "cyvest-view-toggle__button cyvest-view-toggle__button--active"
                : "cyvest-view-toggle__button"
            }
            onClick={() => handleViewChange("investigation")}
            role="tab"
            aria-selected={activeView === "investigation"}
          >
            Investigation
          </button>
        </div>
      )}

      {activeView === "observables" ? (
        <CyvestObservablesView
          investigation={investigation}
          width="100%"
          height="100%"
          theme={theme}
          onCyReady={onCyReady}
          onNodeSelect={onNodeSelect}
          onEdgeSelect={onEdgeSelect}
          showToolbar={showToolbar}
          layout={observablesLayout}
          maxLabelLength={maxObservableLabelLength}
        />
      ) : (
        <CyvestInvestigationView
          investigation={investigation}
          width="100%"
          height="100%"
          theme={theme}
          onCyReady={onCyReady}
          onNodeSelect={onNodeSelect}
          onEdgeSelect={onEdgeSelect}
          showToolbar={showToolbar}
          layout={investigationLayout}
          maxLabelLength={maxInvestigationLabelLength}
        />
      )}
    </div>
  );
};
