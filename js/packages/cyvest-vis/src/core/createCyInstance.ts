import cytoscape, { type Core } from "cytoscape";
import dagre from "cytoscape-dagre";
import elk from "cytoscape-elk";

let pluginRegistered = false;

function ensurePluginsRegistered(): void {
  if (pluginRegistered) {
    return;
  }

  cytoscape.use(elk);
  cytoscape.use(dagre);
  pluginRegistered = true;
}

export function createCyInstance(container: HTMLDivElement): Core {
  ensurePluginsRegistered();

  return cytoscape({
    container,
    elements: [],
    style: [],
    autoungrabify: false,
    boxSelectionEnabled: false,
    selectionType: "single",
    wheelSensitivity: 0.2,
    minZoom: 0.1,
    maxZoom: 2.4,
  });
}
