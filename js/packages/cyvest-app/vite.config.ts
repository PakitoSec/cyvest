import { resolve } from "node:path";
import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@cyvest/cyvest-vis/styles.css": resolve(
        __dirname,
        "../cyvest-vis/src/styles.css"
      ),
      "@cyvest/cyvest-vis": resolve(__dirname, "../cyvest-vis/src/index.ts"),
      "@cyvest/cyvest-js": resolve(__dirname, "../cyvest-js/src/index.ts"),
    },
  },
  server: {
    port: 5173,
  },
});
