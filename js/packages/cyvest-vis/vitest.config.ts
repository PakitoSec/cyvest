import { resolve } from "node:path";
import { defineProject } from "vitest/config";

export default defineProject({
  resolve: {
    alias: {
      "@cyvest/cyvest-js": resolve(__dirname, "../cyvest-js/src/index.ts"),
    },
  },
  test: {
    include: ["tests/**/*.{test,spec}.{ts,js,tsx,jsx}"],
    name: "cyvest-vis",
  },
});
