# JavaScript Packages

Cyvest ships a small JavaScript/TypeScript workspace alongside the Python API. Use these packages to validate serialized investigations, power UI integrations, or explore the data model in a browser.

The JS packages follow the generated schema. A serialized investigation is a v7 document: facts
live under `facts.*` (`observables`, `relations`, `signals`, `evidences`, `findings`), decisions
and tags sit beside them, and **every derived value is read from `report`** — the SDK never
recomputes a score. `parseCyvest` reads any document of the same major up to its own minor: a
`7.1` SDK accepts a `7.0` document, a `7.0` SDK refuses a `7.1` one rather than dropping the
fields it does not know, and a 6.x document is pointed at `cyvest migrate`.

## Packages

- **@cyvest/cyvest-js** — Generated types, schema validation, graph builders, tag hierarchy utilities (including aggregated score and verdict), and helper functions for Cyvest investigation JSON. Ships ESM/CJS builds and `.d.ts` files.
- **@cyvest/cyvest-vis** — React 19+ visualization components using Cytoscape for interaction and a deterministic `d3-force` simulation for positioning. Depends on `@cyvest/cyvest-js`.
- **@cyvest/cyvest-app** — Private Vite demo that bundles sample investigations and renders them via `CyvestGraph`. Useful for tweaking visuals and testing UI flows.

## @cyvest/cyvest-vis

Interactive visualization of Cyvest observable relationships.

### Features

- **Observable Explorer**: community-aware force graph centered on the root, with typed edges, search, filters, legend, and node/edge inspection
- **Restrained visual language**: neutral surfaces, compact SVG nodes, thin edges, and verdict color used only as a contour
- **Interactive focus**: pan/zoom, fit, deterministic layout replay, selection, and neighborhood focus on hover

### Quick Start

```tsx
import { CyvestGraph } from "@cyvest/cyvest-vis";
import "@cyvest/cyvest-vis/styles.css";

<CyvestGraph
  investigation={investigation}
  height={600}
  onNodeSelect={(event) => console.log(event.nodeId, event.label)}
/>
```

### Available Components

| Component | Description |
|-----------|-------------|
| `CyvestGraph` | Main force-directed graph of observables and relationships |
| `CyvestObservablesView` | Force-directed graph of observables and relationships |

See `js/packages/cyvest-vis/README.md` for the full v6 API and theming details.

## Workspace commands

```bash
pnpm install                         # from repo root
pnpm --filter @cyvest/cyvest-js build
pnpm --filter @cyvest/cyvest-vis build
pnpm --filter @cyvest/cyvest-app dev # run the demo app
```

Run tests:

```bash
pnpm --filter @cyvest/cyvest-vis test
```

Regenerate TypeScript types from the Python schema when model changes land:

```bash
pnpm --filter @cyvest/cyvest-js run generate:types
```
