# @cyvest/cyvest-app

Vite-based demo app that ships with sample Cyvest investigations and renders them with `@cyvest/cyvest-vis`.

## What it does

- Loads bundled investigations (`src/investigations/*.json`) and validates them with `@cyvest/cyvest-js`.
- Visualizes the graph and levels via the `CyvestGraph` component.
- Serves as a quick playground for design tweaks to the visualization layer.

## Run locally

```bash
pnpm install                    # from repo root
pnpm --filter @cyvest/cyvest-app dev
```

Build for production:

```bash
pnpm --filter @cyvest/cyvest-app build
pnpm --filter @cyvest/cyvest-app preview
```

## Customize the demo

- Drop new investigations under `src/investigations/` and register them in `src/api.ts`.
- Adjust layout/controls in `src/App.tsx` to try new `CyvestGraph` props or styling.

Note: The app is marked `private` and intended for demos and development, not publishing.
