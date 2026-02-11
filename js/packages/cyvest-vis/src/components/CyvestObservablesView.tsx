import React, { useMemo } from "react";

import { buildObservablesElements } from "../adapters/observablesElements";
import { createObservablesStylesheet } from "../core/styles";
import { createElkLayout } from "../layout/elk";
import type { CyvestObservablesViewProps } from "../types";
import { CytoscapeCanvas } from "./CytoscapeCanvas";

export const CyvestObservablesView: React.FC<CyvestObservablesViewProps> = ({
  investigation,
  height = 500,
  width = "100%",
  className,
  theme,
  onCyReady,
  onNodeSelect,
  onEdgeSelect,
  showToolbar = true,
  layout,
  maxLabelLength = 28,
}) => {
  const elements = useMemo(
    () =>
      buildObservablesElements(investigation, {
        maxLabelLength,
        edgeColor: theme?.edgeColor,
      }),
    [investigation, maxLabelLength, theme?.edgeColor]
  );

  const stylesheet = useMemo(
    () => createObservablesStylesheet(theme),
    [theme]
  );

  const elkLayout = useMemo(
    () => createElkLayout("observables", layout),
    [layout]
  );

  return (
    <CytoscapeCanvas
      view="observables"
      elements={elements}
      stylesheet={stylesheet}
      layout={elkLayout}
      width={width}
      height={height}
      className={className}
      theme={theme}
      onCyReady={onCyReady}
      onNodeSelect={onNodeSelect}
      onEdgeSelect={onEdgeSelect}
      showToolbar={showToolbar}
    />
  );
};
