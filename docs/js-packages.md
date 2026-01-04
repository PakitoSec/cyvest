# JavaScript Packages

Cyvest ships a small JavaScript/TypeScript workspace alongside the Python API. Use these packages to validate serialized investigations, power UI integrations, or explore the data model in a browser.

The JS packages follow the generated schema. Serialized investigations should include the
schema-required fields such as `investigation_id`, `investigation_name`, `audit_log`,
`score_display`, `check_links`, and `observable_links`. The investigation start time is
recorded as an `INVESTIGATION_STARTED` event in the `audit_log`.

## Packages

- **@cyvest/cyvest-js** — Generated types, schema validation, graph builders, and helper functions for Cyvest investigation JSON. Ships ESM/CJS builds and `.d.ts` files.
- **@cyvest/cyvest-vis** — React 19+ visualization components (powered by React Flow + D3) to visualize investigations with level-aware styling. Depends on `@cyvest/cyvest-js`.
- **@cyvest/cyvest-app** — Private Vite demo that bundles sample investigations and renders them via `CyvestGraph`. Useful for tweaking visuals and testing UI flows.

## @cyvest/cyvest-vis

Interactive graph visualization for Cyvest investigations.

### Features

- **Observables Graph**: Force-directed layout showing all observables and relationships
- **Investigation Graph**: Hierarchical Dagre layout showing root → containers → checks
- **Professional icons**: SVG icons for all observable types (IPs, domains, emails, files, etc.)
- **Interactive controls**: Drag nodes, adjust force parameters, zoom/pan
- **Level-aware colors**: Nodes styled by security level (SAFE → MALICIOUS)

### Quick Start

```tsx
import { CyvestGraph } from "@cyvest/cyvest-vis";

<CyvestGraph
  investigation={investigation}
  height={600}
  showViewToggle
  onNodeClick={(id) => console.log(id)}
/>
```

### Available Components

| Component | Description |
|-----------|-------------|
| `CyvestGraph` | Combined view with toggle between Observables and Investigation |
| `ObservablesGraph` | Force-directed graph of observables and relationships |
| `InvestigationGraph` | Hierarchical graph of root, checks, and containers |

See `js/packages/cyvest-vis/src/components` for advanced hooks and utilities.

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
