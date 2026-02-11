# @cyvest/cyvest-vis

Cytoscape-based React components for rendering Cyvest investigations.

## Highlights

- Built on `@cyvest/cyvest-js` investigation and graph helpers
- Two views: observables graph and investigation hierarchy
- Layouts: ELK `stress` for observables, Dagre `LR` for investigation
- Professional built-in SVG icons for nodes
- Label truncation with full-value events
- Themeable with CSS variables and typed React props

## Install / Build

```bash
pnpm install
pnpm --filter @cyvest/cyvest-vis build
```

Run tests:

```bash
pnpm --filter @cyvest/cyvest-vis test
```

## Usage

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

## Main Exports

- `CyvestGraph`
- `CyvestObservablesView`
- `CyvestInvestigationView`
- `createElkLayout`
- `truncateLabel`
- `getObservableIconSvg`
- `getInvestigationIconSvg`

## Theming

Use the `theme` prop or override CSS variables.

```css
:root {
  --cyvest-background: #f4f7fb;
  --cyvest-grid-color: #d7dfeb;
  --cyvest-panel-bg: rgba(255, 255, 255, 0.96);
  --cyvest-panel-border: #d3dae6;
  --cyvest-panel-text: #172033;
  --cyvest-panel-muted: #556079;
  --cyvest-accent: #1f6feb;
  --cyvest-font-family: 'IBM Plex Sans', 'Segoe UI', sans-serif;
}
```

## Breaking Changes vs v1

- Rendering engine changed from React Flow to Cytoscape.
- Events moved to `onNodeSelect` / `onEdgeSelect`.
- Component names are now `CyvestObservablesView` and `CyvestInvestigationView`.
- Import stylesheet with `@cyvest/cyvest-vis/styles.css`.
