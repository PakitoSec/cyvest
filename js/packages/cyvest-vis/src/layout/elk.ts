import type { LayoutOptions } from "cytoscape";

import type { CyvestElkOptions, CyvestViewMode } from "../types";

const DEFAULT_OBSERVABLES_LAYOUT: CyvestElkOptions = {
  algorithm: "stress",
  spacingNodeNode: 70,
  spacingEdgeNode: 40,
  padding: 56,
  fit: true,
  animate: false,
};

const DEFAULT_INVESTIGATION_LAYOUT: CyvestElkOptions = {
  algorithm: "dagre",
  direction: "RIGHT",
  spacingNodeNode: 50,
  spacingEdgeNode: 30,
  spacingBetweenLayers: 120,
  padding: 56,
  fit: true,
  animate: false,
};

export function getDefaultElkOptions(view: CyvestViewMode): CyvestElkOptions {
  return view === "observables"
    ? { ...DEFAULT_OBSERVABLES_LAYOUT }
    : { ...DEFAULT_INVESTIGATION_LAYOUT };
}

function mergeElkOptions(
  view: CyvestViewMode,
  overrides?: CyvestElkOptions
): CyvestElkOptions {
  return {
    ...getDefaultElkOptions(view),
    ...overrides,
    extra: {
      ...(getDefaultElkOptions(view).extra ?? {}),
      ...(overrides?.extra ?? {}),
    },
  };
}

export function createElkLayout(
  view: CyvestViewMode,
  overrides?: CyvestElkOptions
): LayoutOptions {
  const merged = mergeElkOptions(view, overrides);

  if (view === "investigation") {
    return {
      name: "dagre",
      fit: merged.fit ?? true,
      padding: merged.padding ?? 56,
      animate: merged.animate ?? false,
      // Force horizontal left-to-right investigation flow.
      rankDir: "LR",
      rankSep: merged.spacingBetweenLayers ?? 120,
      nodeSep: merged.spacingNodeNode ?? 50,
      edgeSep: merged.spacingEdgeNode ?? 30,
      ...(merged.extra ?? {}),
    } as LayoutOptions;
  }

  const elkOptions: Record<string, string | number | boolean> = {
    "elk.algorithm": merged.algorithm ?? "stress",
    "elk.spacing.nodeNode": merged.spacingNodeNode ?? 60,
    "elk.spacing.edgeNode": merged.spacingEdgeNode ?? 30,
    ...(merged.direction ? { "elk.direction": merged.direction } : {}),
    ...(merged.spacingBetweenLayers
      ? {
          "elk.layered.spacing.nodeNodeBetweenLayers":
            merged.spacingBetweenLayers,
        }
      : {}),
    ...(merged.extra ?? {}),
  };

  return {
    name: "elk",
    fit: merged.fit ?? true,
    padding: merged.padding ?? 56,
    animate: merged.animate ?? false,
    nodeDimensionsIncludeLabels: true,
    // cytoscape-elk reads these options and forwards them to elkjs
    elk: elkOptions,
  } as LayoutOptions;
}
