import { defineProject } from "vitest/config";

export default defineProject({
  test: {
    include: ["tests/**/*.{test,spec}.{ts,js,tsx,jsx}"],
    name: "cyvest-js",
  },
});
