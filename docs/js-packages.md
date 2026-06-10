# JavaScript Packages

Cyvest ships a small JavaScript/TypeScript workspace alongside the Python API. Use these packages to validate serialized investigations, power UI integrations, or explore the data model in a browser.

The JS packages follow the generated schema. Serialized investigations should include the
schema-required fields such as `investigation_id`, `investigation_name`, `audit_log`,
`score_display`, `finding_links`, and `observable_links`. The investigation start time is
recorded as an `INVESTIGATION_STARTED` event in the `audit_log`.

## Packages

- **@cyvest/cyvest-js** — Generated types, schema validation, graph builders, tag hierarchy utilities (including aggregated score/level), and helper functions for Cyvest investigation JSON. Ships ESM/CJS builds and `.d.ts` files.
- **@cyvest/cyvest-vis** — React 19+ visualization components (powered by Cytoscape) to visualize investigations with level-aware styling. Uses ELK for observables and Dagre for investigation hierarchy. Depends on `@cyvest/cyvest-js`.
- **@cyvest/cyvest-app** — Private Vite demo that bundles sample investigations and renders them via `CyvestGraph`. Useful for tweaking visuals and testing UI flows.

## @cyvest/cyvest-vis

Interactive graph visualization for Cyvest investigations with a clean v2 API.

### Features

- **Observables Graph**: ELK `stress` layout showing all observables and relationships
- **Investigation Graph**: Dagre `LR` layout showing root → tags → findings
- **Professional icons**: SVG icons for all observable types (IPs, domains, emails, files, etc.)
- **Interactive controls**: Pan/zoom, fit, and re-run layout
- **Level-aware colors**: Nodes styled by security level (SAFE → MALICIOUS)

### Quick Start

```tsx
import { CyvestGraph } from "@cyvest/cyvest-vis";
import "@cyvest/cyvest-vis/styles.css";

<CyvestGraph
  investigation={investigation}
  height={600}
  showViewToggle
  onNodeSelect={(event) => console.log(event.nodeId, event.label)}
/>
```

### Available Components

| Component | Description |
|-----------|-------------|
| `CyvestGraph` | Combined view with toggle between Observables and Investigation |
| `CyvestObservablesView` | ELK-based graph of observables and relationships |
| `CyvestInvestigationView` | Dagre-based graph of root, findings, and tags |

See `js/packages/cyvest-vis/README.md` for full v2 API and theming details.

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
