# @cyvest/cyvest-js

TypeScript utilities and generated types for working with serialized Cyvest investigations in JavaScript/Node or browser contexts.

## What it does

- Validates Cyvest JSON payloads against the schema (AJV) and returns typed investigations.
- Ships generated TypeScript types plus helpers to query observables, findings, threat intel, tags, and relationships.
- Provides tag hierarchy utilities including aggregated score/level calculations.
- Builds lightweight graph representations for use in visualizers or custom tooling.

## Install & build

```bash
pnpm install          # from repo root
pnpm --filter @cyvest/cyvest-js build
```

Generate types from the latest Python schema if you change it:

```bash
pnpm --filter @cyvest/cyvest-js run generate:types
```

Run tests:

```bash
pnpm --filter @cyvest/cyvest-js test
```

## Usage

```ts
import {
  parseCyvest,
  findSourceObservables,
  getObservableGraph,
  type CyvestInvestigation,
} from "@cyvest/cyvest-js";
import raw from "./investigation.json";

const investigation: CyvestInvestigation = parseCyvest(raw);
const sources = findSourceObservables(investigation);
const graph = getObservableGraph(investigation);

console.log(`Sources: ${sources.length} • Nodes: ${graph.nodes.length}`);
```

## Publishing / consumers

- The package ships CJS, ESM, and type definitions in `dist/`.
- Peer projects in this repo (`@cyvest/cyvest-vis`, `@cyvest/cyvest-app`) depend on it; keep exports stable.
