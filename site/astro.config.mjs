// @ts-check
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://mcpwatchman.com",
  build: {
    // 'auto' (the default) inlines a stylesheet when it is small enough, which
    // makes the CSP a function of how much CSS the page happens to have. Under
    // `style-src 'self'` an inlined stylesheet is blocked and the page renders
    // UNSTYLED — a trap that springs on a future commit that deletes some CSS,
    // not on this one. Pinned to 'never' so the policy and the build agree by
    // construction rather than by current file size.
    inlineStylesheets: "never",
  },
});
