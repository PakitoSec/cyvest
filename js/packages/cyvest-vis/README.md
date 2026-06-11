# @cyvest/cyvest-vis

React components for exploring the observable relationship graph of a Cyvest
investigation with Cytoscape and `d3-force`.

The default design uses a neutral canvas, compact nodes, thin edges, and a
restrained level palette. Color is limited to security-level contours.

## Usage

```tsx
import { CyvestGraph } from "@cyvest/cyvest-vis";
import "@cyvest/cyvest-vis/styles.css";

<CyvestGraph
  investigation={investigation}
  height={620}
  onNodeSelect={(event) => {
    console.log(event.nodeId, event.label);
  }}
/>
```

`CyvestGraph` and `CyvestObservablesView` render the same observable graph.
`CyvestGraph` is the concise public entry point.

Hovering a node isolates its immediate neighborhood. The initial placement is
deterministic; a live force simulation then settles the graph and is reheated
while nodes are dragged.

## Force layout

```tsx
<CyvestGraph
  investigation={investigation}
  layout={{
    linkDistance: 116,
    chargeStrength: -420,
    collisionPadding: 30,
    radialStep: 126,
  }}
/>
```

Set `physics={false}` to keep only the deterministic initial placement.

Available settings include `linkDistance`, `linkStrength`, `chargeStrength`,
`collisionPadding`, `radialStep`, `radialStrength`, `centerStrength`,
`iterations`, `padding`, and animation options.

## Theming

```tsx
<CyvestGraph
  investigation={investigation}
  theme={{
    background: "#ffffff",
    panelText: "#111827",
    accent: "#334155",
    edgeColor: "#d5dbe3",
  }}
/>
```

Use `DARK_CYVEST_THEME` for the built-in dark theme.

## Exports

- `CyvestGraph`
- `CyvestObservablesView`
- `computeForcePositions`
- `createForceLayout`
- `startForceSimulation`
- theme, event, icon, label, color, and observable graph data types

## Development

```bash
corepack pnpm -C js --filter @cyvest/cyvest-vis test:ci
corepack pnpm -C js --filter @cyvest/cyvest-vis build
corepack pnpm -C js --filter @cyvest/cyvest-app dev
```
