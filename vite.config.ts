import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  // Use root base '/' for development or Vercel, and '/scan-before-clone/' for GitHub Pages
  base: mode === 'development' || process.env.VERCEL ? '/' : '/scan-before-clone/',
  server: {
    host: "::",
    port: 8081,
  },
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}));
