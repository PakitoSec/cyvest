# JavaScript Packages

Cyvest ships a small JavaScript/TypeScript workspace alongside the Python API. Use these packages to validate serialized investigations, power UI integrations, or explore the data model in a browser.

The JS packages follow the generated schema. Serialized investigations should include the
schema-required fields such as `investigation_id`, `investigation_name`, `started_at`,
`score_display`, `check_links`, and `observable_links`.

## Packages

- **@cyvest/cyvest-js** — Generated types, schema validation, graph builders, and helper functions for Cyvest investigation JSON. Ships ESM/CJS builds and `.d.ts` files.
- **@cyvest/cyvest-vis** — React 18+ components (powered by XYFlow + D3) to visualize investigations with level-aware styling. Depends on `@cyvest/cyvest-js`.
- **@cyvest/cyvest-app** — Private Vite demo that bundles sample investigations and renders them via `CyvestGraph`. Useful for tweaking visuals and testing UI flows.

## Workspace commands

```bash
pnpm install                         # from repo root
pnpm --filter @cyvest/cyvest-js build
pnpm --filter @cyvest/cyvest-vis build
pnpm --filter @cyvest/cyvest-app dev # run the demo app
```

Regenerate TypeScript types from the Python schema when model changes land:

```bash
pnpm --filter @cyvest/cyvest-js run generate:types
```
