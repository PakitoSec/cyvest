import { compileFromFile } from "json-schema-to-typescript";
import { writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

async function main() {
  // schema is at repo root: /.../cyvest/schema/cyvest.schema.json
  const schemaPath = resolve(__dirname, "..", "..", "schema", "cyvest.schema.json");

  // output types into cyvest-js package:
  // /.../cyvest/js/packages/cyvest-js/src/types.generated.ts
  const outPath = resolve(
    __dirname,
    "..",
    "packages",
    "cyvest-js",
    "src",
    "types.generated.ts"
  );

  const ts = await compileFromFile(schemaPath, {
    bannerComment: "// AUTO-GENERATED FROM cyvest.schema.json — DO NOT EDIT\n"
  });

  await writeFile(outPath, ts);
  console.log("Generated TypeScript types at", outPath);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
