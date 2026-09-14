# mcpwatchman — public site

Static Astro, deployed to Cloudflare Pages. No framework integrations, no
client-side router, one route.

```
npm install
npm run dev      # local dev server
npm run build    # → dist/
```

## Deploy

Cloudflare Pages, built from this subdirectory of the repo.

| setting | value |
|---|---|
| build command | `npm run build` |
| build output directory | `dist` |
| root directory | `site` |
| node version | 22 or later (`package.json` `engines`) |

`public/_headers` and `public/_redirects` are Pages-native and ship with the
build — the security headers and the www→apex redirect live there, not in any
dashboard field, so they are reviewable in git.

## What is here

One launch page. The full site `06-site-and-api.md` specifies — per-server
pages, search and filter, badges, RSS — needs scan data that does not exist
yet, so it is not built. This page exists because the domain was serving a
registrar parking lander, which is a worse answer than nothing for a product
whose subject is trust.

## Conventions worth keeping

- **Every number is monospaced.** If it is a measurement it is set in IBM Plex
  Mono. That is a rule, not a style preference — it is how the page signals
  which figures are claims about the world.
- **One colour means one thing.** `--deduct` only ever marks a subtraction;
  `--signal` is instrument amber for structure and emphasis. Do not reach for
  either decoratively.
- **Latin font subsets only.** The unscoped `@fontsource` imports pull Cyrillic,
  Greek and Vietnamese and take the build from 30 KB to 900 KB. Revisit at
  `06` §7 (internationalization), not before.
- **Figures on this page are real and dated.** The coverage number and the
  ledger arithmetic come from the shipped engine and a dated registry sample.
  When they go stale, change them or remove them.
