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

/**
 * Remove "title" from primitive leaf schemas so json-schema-to-typescript
 * doesn't invent aliases like ScoreDisplay1/2/... for repeated primitives.
 */
function stripPrimitiveLeafTitles(schema) {
  const s = JSON.parse(JSON.stringify(schema));

  const primitiveTypes = new Set([
    "string",
    "number",
    "integer",
    "boolean",
    "null",
  ]);

  const isPrimitiveLeaf = (node) => {
    if (!node || typeof node !== "object") return false;
    if (typeof node.$ref === "string") return false;

    // If it’s explicitly object/array, not a leaf
    if (node.type === "object" || node.type === "array") return false;

    // Union types like { type: ["string","null"] }
    if (Array.isArray(node.type)) {
      return node.type.every((t) => primitiveTypes.has(t));
    }

    // Simple primitive
    if (typeof node.type === "string" && primitiveTypes.has(node.type)) {
      // If you want to keep titles for enums, uncomment:
      // if (Array.isArray(node.enum)) return false;
      return true;
    }

    return false;
  };

  const walk = (node) => {
    if (!node || typeof node !== "object") return;

    if (Array.isArray(node)) {
      for (const v of node) walk(v);
      return;
    }

    if (isPrimitiveLeaf(node) && typeof node.title === "string") {
      delete node.title;
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

  // 1) fix invalid $ref siblings
  let patched = stripRefSiblings(schema);

  // 2) strip titles from primitive leaves (fix ScoreDisplay1/2/etc.)
  patched = stripPrimitiveLeafTitles(patched);

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
