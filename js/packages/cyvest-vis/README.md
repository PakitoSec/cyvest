# @cyvest/cyvest-vis

React components for exploring Cyvest investigations with Cytoscape and a
deterministic `d3-force` layout.

The default design uses a neutral canvas, compact nodes, thin edges, and a
restrained level palette. Color is limited to security-level contours; node
shape communicates the object category.

## Views

`CyvestGraph` provides two related views:

- **Observables**: observables and their directed relationships.
- **Investigation**: root, tag hierarchy, Findings, and Evidence links.

Both views place the root at the center and use radial depth, link attraction,
repulsion, and collision forces. Hovering a node isolates its immediate
neighborhood. Clicking a node or edge emits a typed selection event.

## Install

```bash
pnpm add @cyvest/cyvest-vis
```

Import the package stylesheet once:

```tsx
import { CyvestGraph } from "@cyvest/cyvest-vis";
import "@cyvest/cyvest-vis/styles.css";

<CyvestGraph
  investigation={investigation}
  height={620}
  initialView="observables"
  onNodeSelect={(event) => {
    console.log(event.nodeId, event.label, event.nodeType);
  }}
/>
```

## Force layout

The force simulation runs to completion before Cytoscape renders the graph, so
the same investigation produces stable positions.

```tsx
<CyvestGraph
  investigation={investigation}
  observablesLayout={{
    linkDistance: 116,
    chargeStrength: -420,
    collisionPadding: 30,
    radialStep: 126,
  }}
  investigationLayout={{
    linkDistance: 132,
    radialStep: 142,
  }}
/>
```

Available layout settings include `linkDistance`, `linkStrength`,
`chargeStrength`, `collisionPadding`, `radialStep`, `radialStrength`,
`centerStrength`, `iterations`, `padding`, and animation options.

## Theming

Use the `theme` prop to override typed theme tokens:

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

The CSS controls use the same tokens through `--cyvest-*` custom properties.

## Exports

- `CyvestGraph`
- `CyvestObservablesView`
- `CyvestInvestigationView`
- `computeForcePositions`
- `createForceLayout`
- `getDefaultForceOptions`
- icon, label, color, event, theme, and graph data types

## Development

```bash
corepack pnpm -C js --filter @cyvest/cyvest-vis test:ci
corepack pnpm -C js --filter @cyvest/cyvest-vis build
corepack pnpm -C js --filter @cyvest/cyvest-app dev
```
