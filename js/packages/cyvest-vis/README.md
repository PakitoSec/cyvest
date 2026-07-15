# @cyvest/cyvest-vis

React components for exploring a Cyvest investigation as a typed,
community-aware observable graph with Cytoscape and `d3-force`.

The complete explorer includes search, semantic filters, an interactive
relationship legend, and a node/edge inspector. Security color stays on nodes;
line weight and rhythm distinguish edge families.

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

`CyvestGraph` is the complete public explorer. Use `controls="compact"` for the
canvas toolbar only, or `controls="none"` for an unadorned embedded view. The
low-level `CyvestObservablesView` remains available for custom shells.

Hovering a node isolates its immediate neighborhood. The initial placement is
deterministic. The investigation subject stays at the center while semantic
branches receive stable angular sectors on the first ring. Cross-linked
branches are placed next to each other, then directional infrastructure links
form small outward-facing trees inside each sector. Weak links can connect
sectors without collapsing them into one cloud.

## Force layout

```tsx
<CyvestGraph
  investigation={investigation}
  layout={{
    layerSpacing: 148,
    layerStrength: 0.9,
    siblingSpacing: 132,
    collisionPadding: 24,
  }}
/>
```

Set `physics={false}` to keep only the deterministic initial placement.

Available settings include `layerSpacing`, `layerStrength`, `siblingSpacing`,
`chargeStrength`, `collisionPadding`, `rootLinkDistance`, `rootLinkStrength`,
`iterations`, padding, and animation options. Legacy layout options remain
accepted for API compatibility.

## Relationship profiles

Custom relationship strings default to the weak `association` family. Override
them without adding visual metadata to the investigation JSON:

```tsx
<CyvestGraph
  investigation={investigation}
  relationshipProfiles={{
    "downloaded-from": {
      family: "behavioral",
      distance: 124,
      strength: 0.58,
      lineStyle: "dashed",
    },
  }}
/>
```

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
