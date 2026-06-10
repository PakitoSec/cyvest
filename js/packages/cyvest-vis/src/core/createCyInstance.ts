import cytoscape, { type Core } from "cytoscape";

export function createCyInstance(container: HTMLDivElement): Core {
  return cytoscape({
    container,
    elements: [],
    style: [],
    autoungrabify: false,
    boxSelectionEnabled: false,
    selectionType: "single",
    wheelSensitivity: 0.16,
    minZoom: 0.16,
    maxZoom: 3,
  });
}
