import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@cyvest/cyvest-js": resolve(import.meta.dirname, "../cyvest-js/src/index.ts"),
    },
  },
  test: {
    include: ["tests/**/*.{test,spec}.{ts,js,tsx,jsx}"],
    name: "cyvest-vis",
  },
});
