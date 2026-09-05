# JavaScript Packages

Cyvest ships a small JavaScript/TypeScript workspace alongside the Python API. Use these packages to validate serialized investigations, power UI integrations, or explore the data model in a browser.

The JS packages follow the generated schema. A serialized investigation is a v7 document: facts
live under `facts.*` (`observables`, `relations`, `signals`, `evidences`, `findings`), decisions
and tags sit beside them, and **every derived value is read from `report`** — the SDK never
recomputes a score. `parseCyvest` reads any document of the same major up to its own minor: a
`7.1` SDK accepts a `7.0` document, a `7.0` SDK refuses a `7.1` one rather than dropping the
fields it does not know, and a 6.x document is pointed at `cyvest migrate`.

In 7.1, `ThreatIntel.taxonomies` contains `Taxonomy` objects (`name`, `value`, `verdict`), not
strings. `parseCyvest` normalizes legacy text entries without modifying the input or its report.
Their text becomes the name, their value is empty and their verdict is `INFO`; these entries
are descriptive only. `isCyvest` is a strict type guard and returns false for unnormalized
text entries: use the result of `parseCyvest` when loading older documents.

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

See `js/packages/cyvest-vis/README.md` for the full v7 API and theming details.

### Relationship semantics

A relation is not decoration: `RelationKind` records the pivot an analyst made, and the picture is
built from that. Direction is implied — `source_key` is the parent, `target_key` the child — so the
kind carries the whole meaning.

| Kind | Propagates score | Default attenuation | Visual family |
| --- | --- | --- | --- |
| `extraction` | yes | `1.0` | `extraction` |
| `pivot` | yes | `1.0` | `pivot` |
| `related-to` | no (symmetric) | `0.0` | `association` |

Any relationship string the SDK does not know falls back to `association`, the weakest family, so an
unrecognised kind can never pass itself off as evidence.

Each family carries a complete physical and visual profile:

| Family | Distance | Strength | Line | Width | Opacity |
| --- | --- | --- | --- | --- | --- |
| `extraction` | 84 | 0.90 | solid | 1.7 | 0.88 |
| `pivot` | 124 | 0.64 | dashed | 1.4 | 0.78 |
| `association` | 176 | 0.16 | dotted | 1.2 | 0.78 |

The progression is monotonic on purpose: the more causal the link, the shorter, stronger, thicker and
more solid it is drawn. A `related-to` sits twice as far and pulls five times less than an
`extraction`, which is what makes context read as context.

### How edge kind shapes the layout

The graph is not a free force simulation with per-edge lengths. The kind feeds three separate
channels, and the second one dominates.

**1. Link force.** The family's `distance` and `strength` are handed straight to `d3-force`'s
`forceLink`.

**2. The hierarchy.** Only `extraction` and `pivot` are treated as hierarchy links. The tree that
gives every node its parent, depth, branch and angular sector is a breadth-first walk over those
links alone, from the investigation root outward; `related-to` edges are excluded. An observable
reachable only through weak links is attached by fallback, and hangs off the root as a last resort.

That tree produces a radial target position per node (`depth × layerSpacing`, angle allocated by
subtree weight), and the forces pulling nodes toward those targets are stronger than any link force.
The result is a constrained radial tree that the simulation relaxes, not a cloud that happens to
settle. This is what keeps a handful of `related-to` edges from collapsing every branch into one
blob.

**3. Sibling promotion and branch ordering.** A `pivot` between two nodes that share a parent
re-parents the child under the source, so `domain → hosted url` becomes a real descent instead of a
chord across the ring. Cross-branch links are then weighted by their family strength to order the
sectors around the root and cut down crossings — an `extraction` bridging two branches weighs 0.9
against 0.16 for a `related-to`.

!!! note "The layout scale is not the policy"
    `association` keeps a residual strength of `0.16` where the default policy gives `related-to` an
    attenuation of `0.0`. A weak link still has to be visible and still has to hold its endpoints
    loosely together. The visual scale mirrors the *ordering* of the kinds, not the numbers in
    `Policy.attenuation`; a custom policy will not move the graph.

### What modulates an edge without moving it

- **`confidence`** scales opacity, `familyOpacity × (0.3 + 0.7 × confidence)`, so a tentative pivot
  looks tentative. It never changes geometry — unlike the engine, where confidence multiplies the
  propagated score.
- **A credited relation** — one the report lists as a retained contribution — is drawn 1.6× wider.
  An edge that actually carried score should stand out from one that merely exists.
- **Arrow heads** follow the kind: `related-to` gets none because it is symmetric, `extraction` and
  `pivot` get a head on the target.
- **Curvature** separates parallel edges, and bows a lone `related-to` so it reads as an aside.

Edges touching the root override their family with a longer, weaker profile so the subject has room
to breathe. Profiles you pass through `relationshipProfiles` still win over both.

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
