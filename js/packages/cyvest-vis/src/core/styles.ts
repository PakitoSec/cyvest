import type { Stylesheet } from "cytoscape";

import type { CyvestThemeTokens } from "../types";
import { resolveTheme } from "../utils/colors";

export function createObservablesStylesheet(
  theme?: Partial<CyvestThemeTokens>
): Stylesheet[] {
  const resolved = resolveTheme(theme);

  return [
    {
      selector: "node",
      style: {
        shape: "data(shape)",
        width: "data(width)",
        height: "data(height)",
        label: "data(labelShort)",
        color: resolved.panelText,
        "font-size": 11,
        "font-family": resolved.fontFamily,
        "font-weight": 500,
        "text-wrap": "none",
        "text-max-width": 210,
        "text-halign": "center",
        "text-valign": "bottom",
        "text-margin-y": 10,
        "background-color": "data(fillColor)",
        "border-color": "data(borderColor)",
        "border-width": "data(borderWidth)",
        "background-image": "data(icon)",
        "background-fit": "none",
        "background-width": "13px",
        "background-height": "13px",
        "background-position-x": "50%",
        "background-position-y": "50%",
        "background-image-opacity": 1,
        "background-opacity": 1,
        opacity: "data(opacity)",
        "overlay-opacity": 0,
      },
    },
    {
      selector: "node:selected",
      style: {
        "border-color": resolved.accent,
        "border-width": 3,
      },
    },
    {
      selector: "edge",
      style: {
        width: "data(width)",
        "line-color": "data(color)",
        "target-arrow-color": "data(color)",
        "source-arrow-color": "data(color)",
        "target-arrow-shape": "data(targetArrowShape)",
        "source-arrow-shape": "data(sourceArrowShape)",
        "curve-style": "bezier",
        "arrow-scale": 1,
        opacity: 0.88,
        "overlay-opacity": 0,
      },
    },
    {
      selector: "edge:selected",
      style: {
        "line-color": resolved.edgeSelectedColor,
        "target-arrow-color": resolved.edgeSelectedColor,
        "source-arrow-color": resolved.edgeSelectedColor,
        label: "data(relationshipType)",
        color: resolved.panelTextMuted,
        "font-size": 10,
        "font-family": resolved.fontFamily,
        "text-background-color": resolved.panelBackground,
        "text-background-opacity": 0.98,
        "text-background-padding": 2,
      },
    },
  ];
}

export function createInvestigationStylesheet(
  theme?: Partial<CyvestThemeTokens>
): Stylesheet[] {
  const resolved = resolveTheme(theme);

  return [
    {
      selector: "node",
      style: {
        shape: "data(shape)",
        width: "data(width)",
        height: "data(height)",
        label: "data(labelShort)",
        color: resolved.panelText,
        "font-size": 10,
        "font-family": resolved.fontFamily,
        "font-weight": 500,
        "text-wrap": "none",
        "text-max-width": 190,
        "text-halign": "center",
        "text-valign": "center",
        "text-justification": "center",
        "background-color": "data(fillColor)",
        "border-color": "data(borderColor)",
        "border-width": "data(borderWidth)",
        "background-image": "data(icon)",
        "background-fit": "none",
        "background-width": "18px",
        "background-height": "18px",
        "background-position-x": "10px",
        "background-position-y": "50%",
        "background-image-opacity": 0.9,
        "text-margin-x": 0,
        "overlay-opacity": 0,
      },
    },
    {
      selector: "node[nodeType = 'finding']",
      style: {
        "text-halign": "center",
        "background-position-x": "10px",
      },
    },
    {
      selector: "node[nodeType = 'evidence']",
      style: {
        "text-halign": "center",
        "background-position-x": "10px",
        "border-style": "dashed",
      },
    },
    {
      selector: "node:selected",
      style: {
        "border-color": resolved.accent,
        "border-width": 3,
      },
    },
    {
      selector: "edge",
      style: {
        width: "data(width)",
        "line-color": "data(color)",
        "target-arrow-color": "data(color)",
        "source-arrow-color": "data(color)",
        "target-arrow-shape": "data(targetArrowShape)",
        "source-arrow-shape": "data(sourceArrowShape)",
        "curve-style": "taxi",
        "taxi-direction": "rightward",
        "taxi-turn": "26px",
        "arrow-scale": 0.95,
        opacity: 0.9,
        "overlay-opacity": 0,
      },
    },
    {
      selector: "edge:selected",
      style: {
        "line-color": resolved.edgeSelectedColor,
        "target-arrow-color": resolved.edgeSelectedColor,
        "source-arrow-color": resolved.edgeSelectedColor,
      },
    },
  ];
}
