import React, { useMemo } from "react";

import { buildInvestigationElements } from "../adapters/investigationElements";
import { createInvestigationStylesheet } from "../core/styles";
import { createElkLayout } from "../layout/elk";
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
        edgeColor: theme?.edgeColor,
      }),
    [investigation, maxLabelLength, theme?.edgeColor]
  );

  const stylesheet = useMemo(
    () => createInvestigationStylesheet(theme),
    [theme]
  );

  const elkLayout = useMemo(
    () => createElkLayout("investigation", layout),
    [layout]
  );

  return (
    <CytoscapeCanvas
      view="investigation"
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
