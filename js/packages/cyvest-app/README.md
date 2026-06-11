# @cyvest/cyvest-app

Vite demo application for the `@cyvest/cyvest-vis` force-directed observable graph.

## What it does

- Loads bundled investigations (`src/investigations/*.json`) and validates them with `@cyvest/cyvest-js`
- Renders the observable relationship graph with `CyvestGraph`
- Demonstrates node selection events and basic layout customization

## Run locally

```bash
pnpm install
pnpm --filter @cyvest/cyvest-app dev
```

Build for production:

```bash
pnpm --filter @cyvest/cyvest-app build
pnpm --filter @cyvest/cyvest-app preview
```

## Notes

- The app imports `@cyvest/cyvest-vis/styles.css` for default visual styling.
- The package is private and intended as a development/demo surface.
