import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    pool: "threads",
    hookTimeout: 60000,
    testTimeout: 60000,
    server: {
      deps: {
        // This tells Vitest to fix the missing extensions for this specific library on the fly
        inline: [/@majikah\/majik-key/, /@majikah\/majik-contact/],
      },
    },
  },
});
