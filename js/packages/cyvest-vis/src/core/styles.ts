import type { Stylesheet } from "cytoscape";

import type { CyvestThemeTokens } from "../types";
import { resolveTheme } from "../utils/colors";

function createSharedStylesheet(
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
        "font-size": 10.5,
        "font-family": resolved.fontFamily,
        "font-weight": 500,
        "min-zoomed-font-size": 8,
        "text-wrap": "none",
        "text-max-width": 190,
        "text-halign": "center",
        "text-valign": "bottom",
        "text-margin-y": 9,
        "text-background-color": resolved.panelBackground,
        "text-background-opacity": 0.86,
        "text-background-padding": 2,
        "text-background-shape": "roundrectangle",
        "background-color": "data(fillColor)",
        "border-color": "data(borderColor)",
        "border-width": "data(borderWidth)",
        "background-image": "data(icon)",
        "background-fit": "none",
        "background-width": "48%",
        "background-height": "48%",
        "background-position-x": "50%",
        "background-position-y": "50%",
        "background-image-opacity": 1,
        "background-opacity": 1,
        opacity: "data(opacity)",
        "overlay-opacity": 0,
        "transition-property":
          "opacity, border-width, border-color, underlay-opacity, underlay-padding",
        "transition-duration": 140,
      },
    },
    {
      selector: "node:selected",
      style: {
        "border-color": resolved.edgeSelectedColor,
        "border-width": 2.5,
        "underlay-color": resolved.accent,
        "underlay-opacity": 0.12,
        "underlay-padding": 7,
      },
    },
    {
      selector: "node.cyvest-focus",
      style: {
        "underlay-color": resolved.accent,
        "underlay-opacity": 0.08,
        "underlay-padding": 6,
      },
    },
    {
      selector: ".cyvest-dimmed",
      style: {
        opacity: 0.16,
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
        "arrow-scale": 0.62,
        opacity: 0.78,
        "overlay-opacity": 0,
        "transition-property": "opacity, line-color, width",
        "transition-duration": 140,
      },
    },
    {
      selector: "edge.cyvest-focus",
      style: {
        width: 1.7,
        "line-color": resolved.edgeSelectedColor,
        "target-arrow-color": resolved.edgeSelectedColor,
        "source-arrow-color": resolved.edgeSelectedColor,
        opacity: 0.9,
      },
    },
    {
      selector: "edge:selected",
      style: {
        width: 1.9,
        "line-color": resolved.edgeSelectedColor,
        "target-arrow-color": resolved.edgeSelectedColor,
        "source-arrow-color": resolved.edgeSelectedColor,
        label: "data(relationshipType)",
        color: resolved.panelTextMuted,
        "font-size": 9,
        "font-family": resolved.fontFamily,
        "text-background-color": resolved.panelBackground,
        "text-background-opacity": 0.94,
        "text-background-padding": 2,
      },
    },
  ];
}

export function createObservablesStylesheet(
  theme?: Partial<CyvestThemeTokens>
): Stylesheet[] {
  return [
    ...createSharedStylesheet(theme),
    {
      selector: "node[?isRoot]",
      style: {
        "font-weight": 700,
        "text-margin-y": 11,
      },
    },
  ];
}
