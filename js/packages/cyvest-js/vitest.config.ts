import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.{test,spec}.{ts,js,tsx,jsx}"],
    name: "cyvest-js",
  },
});
