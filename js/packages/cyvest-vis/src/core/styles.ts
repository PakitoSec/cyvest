import type { StylesheetJson } from "cytoscape";

import type { CyvestThemeTokens } from "../types";
import { resolveTheme } from "../utils/colors";

function createSharedStylesheet(
  theme?: Partial<CyvestThemeTokens>
): StylesheetJson {
  const resolved = resolveTheme(theme);

  const stylesheet = [
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
        "min-zoomed-font-size": 0,
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
      selector: "node.cyvest-compact-label",
      style: {
        label: "data(displayLabel)",
      },
    },
    {
      selector: "node:selected",
      style: {
        label: "data(labelShort)",
        "min-zoomed-font-size": 0,
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
        label: "data(labelShort)",
        "min-zoomed-font-size": 0,
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
      selector: "node.cyvest-search-dimmed",
      style: {
        opacity: 0.24,
      },
    },
    {
      selector: "node.cyvest-search-match",
      style: {
        label: "data(labelShort)",
        "min-zoomed-font-size": 0,
        "underlay-color": resolved.accent,
        "underlay-opacity": 0.14,
        "underlay-padding": 9,
        "border-width": 2.5,
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
        "line-style": "data(lineStyle)",
        "line-dash-pattern": "data(dashPattern)",
        "curve-style": "unbundled-bezier",
        "control-point-distances": "data(curvature)",
        "control-point-weights": 0.5,
        "arrow-scale": 0.8,
        opacity: "data(opacity)",
        "overlay-opacity": 0,
        "transition-property": "opacity, line-color, width",
        "transition-duration": 140,
      },
    },
    {
      selector: "edge.cyvest-focus",
      style: {
        "line-color": "data(color)",
        "target-arrow-color": "data(color)",
        "source-arrow-color": "data(color)",
        opacity: 1,
        "overlay-color": resolved.accent,
        "overlay-opacity": 0.12,
        "overlay-padding": 5,
        label: "data(relationshipLabel)",
        color: resolved.panelTextMuted,
        "font-size": 9,
        "font-family": resolved.fontFamily,
        "text-background-color": resolved.panelBackground,
        "text-background-opacity": 0.94,
        "text-background-padding": 2,
      },
    },
    {
      selector: "edge:selected",
      style: {
        "line-color": "data(color)",
        "target-arrow-color": "data(color)",
        "source-arrow-color": "data(color)",
        opacity: 1,
        "overlay-color": resolved.accent,
        "overlay-opacity": 0.18,
        "overlay-padding": 6,
        label: "data(relationshipLabel)",
        color: resolved.panelTextMuted,
        "font-size": 9,
        "font-family": resolved.fontFamily,
        "text-background-color": resolved.panelBackground,
        "text-background-opacity": 0.94,
        "text-background-padding": 2,
      },
    },
  ];
  // Cytoscape accepts data-mapped values (for example `data(width)`) at
  // runtime, while its current TypeScript declarations only model literals.
  return stylesheet as unknown as StylesheetJson;
}

export function createObservablesStylesheet(
  theme?: Partial<CyvestThemeTokens>
): StylesheetJson {
  const stylesheet = [
    ...createSharedStylesheet(theme),
    {
      selector: "node[?isRoot]",
      style: {
        "font-weight": 700,
        "min-zoomed-font-size": 0,
        "text-valign": "top",
        "text-margin-y": -11,
      },
    },
    {
      selector: "node[?isRoot].cyvest-compact-label",
      style: {
        "text-halign": "left",
        "text-valign": "center",
        "text-margin-x": -10,
        "text-margin-y": 0,
      },
    },
  ];
  return stylesheet as unknown as StylesheetJson;
}
