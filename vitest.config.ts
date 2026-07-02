import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Resolve `obsigil-core` to its TypeScript source so the test suites run
// against source without a prior build. (obsigil-client source imports
// `obsigil-core`; this alias makes that resolve during tests.)
export default defineConfig({
  resolve: {
    alias: {
      "@obsigil/core": fileURLToPath(
        new URL("./packages/obsigil-core/src/index.ts", import.meta.url),
      ),
    },
  },
  test: {
    include: ["packages/*/test/**/*.test.ts"],
  },
});
