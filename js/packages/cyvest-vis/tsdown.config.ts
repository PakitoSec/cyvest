import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  // keep dist/index.js + dist/index.cjs as declared in package.json exports
  fixedExtension: false,
  deps: { neverBundle: ["react", "react-dom"] },
  // `to` is treated as a directory: pointing it at dist/styles.css nests the file.
  copy: [{ from: "src/styles.css", to: "dist" }],
});
