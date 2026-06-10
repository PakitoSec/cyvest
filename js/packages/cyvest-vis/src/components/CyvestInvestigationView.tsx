import React, { useMemo } from "react";

import { buildInvestigationElements } from "../adapters/investigationElements";
import { createInvestigationStylesheet } from "../core/styles";
import { createForceLayout } from "../layout/force";
import type { CyvestInvestigationViewProps } from "../types";
import { CytoscapeCanvas } from "./CytoscapeCanvas";

export const CyvestInvestigationView: React.FC<CyvestInvestigationViewProps> = ({
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
  maxLabelLength = 26,
}) => {
  const elements = useMemo(
    () =>
      buildInvestigationElements(investigation, {
        maxLabelLength,
        theme,
      }),
    [investigation, maxLabelLength, theme]
  );

  const stylesheet = useMemo(
    () => createInvestigationStylesheet(theme),
    [theme]
  );

  const forceLayout = useMemo(
    () => createForceLayout(elements, "investigation", layout),
    [elements, layout]
  );

  return (
    <CytoscapeCanvas
      view="investigation"
      elements={elements}
      stylesheet={stylesheet}
      layout={forceLayout}
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
