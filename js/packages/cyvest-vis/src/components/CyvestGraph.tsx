import React from "react";

import type { CyvestGraphProps } from "../types";
import { CyvestObservablesView } from "./CyvestObservablesView";

/** Render the observable relationship graph for a Cyvest investigation. */
export const CyvestGraph: React.FC<CyvestGraphProps> = ({
  investigation,
  height = 500,
  width = "100%",
  className,
  theme,
  onCyReady,
  onNodeSelect,
  onEdgeSelect,
  physics = true,
  showToolbar = true,
  layout,
  maxLabelLength = 28,
}) => (
  <CyvestObservablesView
    investigation={investigation}
    width={width}
    height={height}
    className={className}
    theme={theme}
    onCyReady={onCyReady}
    onNodeSelect={onNodeSelect}
    onEdgeSelect={onEdgeSelect}
    physics={physics}
    showToolbar={showToolbar}
    layout={layout}
    maxLabelLength={maxLabelLength}
  />
);
