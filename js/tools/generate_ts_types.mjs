import { compile } from "json-schema-to-typescript";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

function stripRefSiblings(schema) {
  const s = JSON.parse(JSON.stringify(schema));

  const walk = (node) => {
    if (!node || typeof node !== "object") return;

    if (Array.isArray(node)) {
      for (const v of node) walk(v);
      return;
    }

    if (typeof node.$ref === "string") {
      for (const k of Object.keys(node)) {
        if (k !== "$ref") delete node[k];
      }
      return;
    }

    for (const v of Object.values(node)) walk(v);
  };

  walk(s);
  return s;
}

async function main() {
  const schemaPath = resolve(
    __dirname,
    "..",
    "..",
    "schema",
    "cyvest.schema.json"
  );

  const outPath = resolve(
    __dirname,
    "..",
    "packages",
    "cyvest-js",
    "src",
    "types.generated.ts"
  );

  const raw = await readFile(schemaPath, "utf8");
  const schema = JSON.parse(raw);

  const patched = stripRefSiblings(schema);

  const ts = await compile(patched, "CyvestSchema", {
    bannerComment: "// AUTO-GENERATED FROM cyvest.schema.json — DO NOT EDIT\n",
  });

  await writeFile(outPath, ts);
  console.log("Generated TypeScript types at", outPath);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
