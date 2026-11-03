/**
 * The reference pages, listed once for every generated index that names them
 * (`sitemap.xml`, `llms.txt`). A page added here reaches both; a page added to
 * `src/pages/` and not here reaches neither, which
 * `tests/test_site_methodology.py` catches by walking the built tree.
 */
import { AXES } from "./methodology";

export interface DocPage {
  path: string;
  title: string;
  summary: string;
}

export const DOC_PAGES: DocPage[] = [
  {
    path: "/methodology/",
    title: "Methodology",
    summary:
      "how a score is made: the five axes and their provisional weights, why the composite is withheld, what an unassessed axis and `fault` mean, and the stacking arithmetic.",
  },
  ...AXES.map((a) => ({
    path: `/methodology/${a.slug}/`,
    title: `Methodology: ${a.label}`,
    summary: `every sub-check, band or deduction the ${a.label} axis uses, and what is not scored yet.`,
  })),
  {
    path: "/disclosure/",
    title: "Disclosure and appeals",
    summary:
      "what is published at once and what is coordinated with a maintainer first, the embargo terms, and how to contest a finding.",
  },
  {
    path: "/api/",
    title: "API reference",
    summary: "every JSON endpoint, the fields of a server record, and the rules for reading a score.",
  },
  {
    path: "/cli/",
    title: "CLI reference",
    summary: "`mcpwatchman check`, its options and exit codes, and the commands arriving next.",
  },
  {
    path: "/about/",
    title: "About",
    summary: "who runs mcpwatchman, its independence, its relationship to the official registry, and the licence.",
  },
];
