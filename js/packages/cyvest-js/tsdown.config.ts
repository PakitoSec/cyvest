import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  // keep dist/index.js + dist/index.cjs as declared in package.json exports
  fixedExtension: false,
});
