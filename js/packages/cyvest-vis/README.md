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

| Prop | Description |
| --- | --- |
| `controls` | `"full"` (default) for search, filters and legend, `"compact"` for the canvas toolbar only, `"none"` for an unadorned view |
| `showInspector` | Show the side panel describing the selected node or edge |
| `filterState` | Control the filters from the outside, as a partial `CyvestGraphFilterState` |
| `onFilterStateChange` | Called with the complete state whenever a filter changes |
| `relationshipProfiles` | Override the visual and physical profile of a relationship type |
| `theme` | Partial `CyvestThemeTokens`, see Theming |
| `physics` | Set to `false` to keep only the deterministic initial placement |
| `layout` | Force layout options, see Force layout |

Hovering a node isolates its immediate neighborhood. The initial placement is
deterministic. The investigation subject stays at the center while semantic
branches receive stable angular sectors on the first ring. Cross-linked
branches are placed next to each other, then directional pivot links
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

Edges are grouped into three families that mirror the analyst pivot recorded in
the investigation. Direction is implied by the relation itself — `source_key` is
the parent, `target_key` the child — so the kind carries the whole meaning.

| Kind | Family | Distance | Strength | Line | Width | Opacity |
| --- | --- | --- | --- | --- | --- | --- |
| `extraction` | `extraction` | 84 | 0.90 | solid | 1.7 | 0.88 |
| `pivot` | `pivot` | 124 | 0.64 | dashed | 1.4 | 0.78 |
| `related-to` | `association` | 176 | 0.16 | dotted | 1.2 | 0.78 |

Custom relationship strings default to the weak `association` family, so an
unrecognised kind can never pass itself off as evidence. The progression is
monotonic on purpose: the more causal the link, the shorter, stronger, thicker
and more solid it is drawn.

The kind also shapes the layout, and not only through link length. Only
`extraction` and `pivot` count as hierarchy links: the tree that gives every node
its parent, depth, branch and angular sector is walked over those alone, and the
forces pulling nodes toward their radial slot are stronger than any link force.
A node reachable only through `related-to` is attached by fallback. That is what
keeps weak context links from collapsing every branch into one cloud. A `pivot`
between two siblings additionally re-parents the child under the source, so
`domain → hosted url` becomes a real descent rather than a chord across the ring.

`confidence` scales edge opacity and a relation the report credits with a
retained contribution is drawn 1.6× wider; neither moves a node. Edges touching
the root override their family with a longer, weaker profile.

Override any of it without adding visual metadata to the investigation JSON:

```tsx
<CyvestGraph
  investigation={investigation}
  relationshipProfiles={{
    "downloaded-from": {
      family: "pivot",
      distance: 124,
      strength: 0.58,
      lineStyle: "dashed",
    },
  }}
/>
```

Profiles passed this way win over both the family defaults and the root
override.

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
- `BUILT_IN_RELATIONSHIP_TYPES`, `getRelationshipFamily`, `resolveRelationshipProfile`
- `EMPTY_GRAPH_FILTERS`, `normalizeGraphFilters`, `filterInvestigation`, `matchesGraphQuery`
- theme, event, icon, label, color, and observable graph data types

## Development

```bash
corepack pnpm -C js --filter @cyvest/cyvest-vis test:ci
corepack pnpm -C js --filter @cyvest/cyvest-vis build
corepack pnpm -C js --filter @cyvest/cyvest-app dev
```
