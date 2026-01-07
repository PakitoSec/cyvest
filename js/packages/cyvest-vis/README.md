# @cyvest/cyvest-vis

React components for visualizing Cyvest investigations using React Flow + D3 force layouts.

## Features

- **Two visualization modes**: Observables graph (force-directed) and Investigation graph (hierarchical Dagre layout)
- **Interactive force simulation**: Drag nodes, adjust forces in real-time
- **Professional SVG icons**: Clean icons for all observable types (IPs, domains, emails, files, threats, etc.)
- **Level-aware styling**: Nodes colored by security level (SAFE, INFORMATIVE, SUSPICIOUS, MALICIOUS)
- **Responsive design**: Works at any size with zoom, pan, and minimap controls
- Uses `@cyvest/cyvest-js` for types, colors, and graph data extraction

## Installation

```bash
pnpm install          # from repo root
pnpm --filter @cyvest/cyvest-vis build
```

Run tests:

```bash
pnpm --filter @cyvest/cyvest-vis test
```

## Usage

### Basic Usage

```tsx
import { CyvestGraph } from "@cyvest/cyvest-vis";
import type { CyvestInvestigation } from "@cyvest/cyvest-js";

function InvestigationView({ investigation }: { investigation: CyvestInvestigation }) {
  return (
    <CyvestGraph
      investigation={investigation}
      height={600}
      showViewToggle
      onNodeClick={(id) => console.log("Selected:", id)}
    />
  );
}
```

### Components

#### `CyvestGraph`

Main component with toggle between Observables and Investigation views.

```tsx
<CyvestGraph
  investigation={investigation}
  height={600}
  width="100%"
  initialView="observables"  // or "investigation"
  showViewToggle={true}
  onNodeClick={(nodeId) => {}}
/>
```

#### `ObservablesGraph`

Force-directed graph showing all observables and their relationships.

```tsx
import { ObservablesGraph } from "@cyvest/cyvest-vis";

<ObservablesGraph
  investigation={investigation}
  height={600}
  width="100%"
  showControls={true}  // Show force layout controls
  forceConfig={{
    chargeStrength: -200,
    linkDistance: 80,
    collisionRadius: 45,
  }}
  onNodeClick={(nodeId) => {}}
  onNodeDoubleClick={(nodeId) => {}}
/>
```

#### `InvestigationGraph`

Hierarchical graph showing root → tags → checks structure.

```tsx
import { InvestigationGraph } from "@cyvest/cyvest-vis";

<InvestigationGraph
  investigation={investigation}
  height={600}
  width="100%"
  onNodeClick={(nodeId, nodeType) => {
    // nodeType: "root" | "check" | "tag"
  }}
/>
```

### Custom Icons

Access icon components for custom UIs:

```tsx
import { getObservableIcon, getInvestigationIcon, GlobeIcon, MailIcon } from "@cyvest/cyvest-vis";

// Get icon by observable type
const Icon = getObservableIcon("ipv4-addr"); // Returns GlobeIcon
<Icon size={24} color="#3b82f6" />

// Or use icons directly
<GlobeIcon size={16} color="currentColor" />
<MailIcon size={16} color="#ef4444" />
```

Available icons: `GlobeIcon`, `DomainIcon`, `LinkIcon`, `MailIcon`, `EnvelopeIcon`, `FileIcon`, `HashIcon`, `UserIcon`, `IdCardIcon`, `GearIcon`, `AppIcon`, `RegistryIcon`, `ThreatActorIcon`, `BugIcon`, `SwordIcon`, `TargetIcon`, `AlertIcon`, `FlaskIcon`, `CertificateIcon`, `WifiIcon`, `WorldIcon`, `QuestionIcon`, `CheckIcon`, `TagIcon`, `CrosshairIcon`

## Types

```tsx
import type {
  CyvestGraphProps,
  ObservablesGraphProps,
  InvestigationGraphProps,
  ForceLayoutConfig,
  ObservableNodeData,
  InvestigationNodeData,
  InvestigationNodeType,
} from "@cyvest/cyvest-vis";
```

### Force Layout Configuration

```tsx
interface ForceLayoutConfig {
  chargeStrength: number;   // Repulsion strength (default: -200)
  linkDistance: number;     // Target link distance (default: 80)
  centerStrength: number;   // Center pull strength (default: 0.05)
  collisionRadius: number;  // Node collision radius (default: 45)
  iterations: number;       // Iterations for static layout (default: 300)
}
```

## Peer Dependencies

- React 19+
- React DOM 19+

## License

See repository root for license information.
