
#! /bin/bash

uv run cyvest schema -o ./schema/cyvest.schema.json
pnpm -C js/packages/cyvest-js run generate:types
uv run examples/04_email.py -o ./js/packages/cyvest-app/src/investigations/cyvest_email.json
uv run examples/05_graph_dataset.py -o ./js/packages/cyvest-app/src/investigations/cyvest_visual.json
pnpm -C js run build
pnpm -C js run test:ci
