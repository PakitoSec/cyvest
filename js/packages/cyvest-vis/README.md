# @cyvest/cyvest-vis

React components for visualizing Cyvest investigations using XYFlow + D3 layouts.

## What it does

- Renders observables, relationships, checks, and containers as an interactive graph.
- Uses `@cyvest/cyvest-js` helpers for level colors, graph data, and schema-safe types.
- Ships CJS, ESM, and type definitions for React 18+ projects.

## Install & build

```bash
pnpm install          # from repo root
pnpm --filter @cyvest/cyvest-vis build
```

Run tests:

```bash
pnpm --filter @cyvest/cyvest-vis test
```

## Usage

```tsx
import { CyvestGraph } from "@cyvest/cyvest-vis";
import type { CyvestInvestigation } from "@cyvest/cyvest-js";

export function InvestigationView({ investigation }: { investigation: CyvestInvestigation }) {
  return (
    <CyvestGraph
      investigation={investigation}
      height={520}
      showViewToggle
      onNodeClick={(id) => console.log("Selected", id)}
    />
  );
}
```

Props include `height`, `width`, `showViewToggle`, `onNodeClick`, and optional control over zoom/pan behaviour. See `src/components` for more advanced hooks and utilities.
