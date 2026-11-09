import type { APIRoute, GetStaticPaths } from "astro";
import scans from "../../lib/reports";
import { badgeFor, renderBadge } from "../../lib/badge";

/**
 * `/badge/<slug>.svg`, one per published server, rendered at build (`06` §2).
 *
 * The headers below document intent only: the site is a static asset store,
 * so what a browser actually receives is set by `public/_headers` →
 * `/badge/*`. Both say the same thing — one hour, `06` §2's cache window.
 */
export const getStaticPaths: GetStaticPaths = () =>
  scans.map((server) => ({ params: { slug: server.slug }, props: { server } }));

export const GET: APIRoute = ({ props }) =>
  new Response(renderBadge(badgeFor(props.server)), {
    headers: {
      "content-type": "image/svg+xml; charset=utf-8",
      "cache-control": "public, max-age=3600",
    },
  });
