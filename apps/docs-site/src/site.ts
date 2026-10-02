import { escapeHtml, renderMarkdown, type Heading } from "./markdown";
import { renderOpenApi } from "./openapi";

export interface SourcePage {
  /** Path relative to docs/, e.g. `spec/abl-v1.md`. */
  path: string;
  markdown: string;
}

export interface OutPage {
  /** Output path relative to the site root, e.g. `spec/abl-v1.html`. */
  path: string;
  title: string;
  html: string;
  section: string;
  headings: Heading[];
}

const SECTION_TITLES: Record<string, string> = {
  guides: "Guides",
  spec: "Specifications",
  runbooks: "Runbooks",
  adr: "Architecture decisions",
  plans: "Plans",
  security: "Security",
  compliance: "Compliance",
  reference: "API reference",
  root: "Overview",
};

const SKIP = new Set(["NEEDS.md"]);

export function sectionOf(path: string): string {
  const i = path.indexOf("/");
  return i < 0 ? "root" : path.slice(0, i);
}

export function outPath(mdPath: string): string {
  return mdPath.replace(/\.md$/, ".html");
}

export function relativeHref(from: string, to: string): string {
  const f = from.split("/").slice(0, -1);
  const t = to.split("/");
  let i = 0;
  while (i < f.length && i < t.length - 1 && f[i] === t[i]) i++;
  return [...f.slice(i).map(() => ".."), ...t.slice(i)].join("/") || to;
}

export function layout(
  page: { path: string; title: string; body: string },
  nav: Array<{ section: string; items: Array<{ path: string; title: string }> }>,
): string {
  const rel = (to: string) => relativeHref(page.path, to);
  const navHtml = nav
    .map(
      (s) =>
        `<h2 class="nav-h">${escapeHtml(SECTION_TITLES[s.section] ?? s.section)}</h2><ul>${s.items
          .map(
            (i) =>
              `<li><a href="${escapeHtml(rel(i.path))}"${i.path === page.path ? ' aria-current="page"' : ""}>${escapeHtml(i.title)}</a></li>`,
          )
          .join("")}</ul>`,
    )
    .join("");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(page.title)} - AXIS Docs</title>
<link rel="stylesheet" href="${escapeHtml(rel("assets/site.css"))}">
</head>
<body>
<a class="skip" href="#content">Skip to content</a>
<div class="wrap">
<nav aria-label="Documentation"><a class="brand" href="${escapeHtml(rel("index.html"))}">AXIS Docs</a>${navHtml}</nav>
<main id="content">
${page.body}
</main>
</div>
</body>
</html>
`;
}

export const SITE_CSS = `:root{--bg:#fff;--fg:#16181d;--muted:#4b5563;--border:#c9ced6;--accent:#1d4ed8;--code:#f1f3f5}
@media (prefers-color-scheme:dark){:root{--bg:#0e1116;--fg:#e6e8ec;--muted:#a3acb9;--border:#3a4150;--accent:#8db1ff;--code:#1d222b}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 system-ui,sans-serif}
.wrap{display:flex;flex-wrap:wrap;min-height:100vh}
nav{flex:0 0 18rem;padding:1rem;border-right:1px solid var(--border);overflow-wrap:anywhere}
main{flex:1 1 30rem;min-width:0;max-width:60rem;padding:1.5rem 2rem}
a{color:var(--accent)}
.brand{font-weight:700;font-size:1.2rem;display:block;margin-bottom:.5rem}
.nav-h{font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:1rem 0 .25rem}
nav ul{list-style:none;margin:0;padding:0}
nav [aria-current]{font-weight:700}
pre,code{background:var(--code);font-family:ui-monospace,Menlo,monospace;font-size:.9em}
pre{padding:.75rem;overflow-x:auto;border-radius:6px}
code{padding:.1em .3em;border-radius:4px}
pre code{padding:0;background:none}
table{border-collapse:collapse;display:block;overflow-x:auto;margin:1rem 0}
th,td{border:1px solid var(--border);padding:.35rem .6rem;text-align:left}
caption{caption-side:top;text-align:left;font-weight:600;padding:.25rem 0}
.method{font-weight:700;font-size:.8em;padding:.1em .4em;border:1px solid var(--border);border-radius:4px}
.skip{position:absolute;left:-999px}.skip:focus{left:.5rem;top:.5rem;background:var(--bg);padding:.5rem}
@media (max-width:48rem){nav{flex-basis:100%;border-right:0;border-bottom:1px solid var(--border)}main{padding:1rem}}
`;

/**
 * Build the whole site as an in-memory map of output path -> content. Pure and deterministic: sources are
 * sorted, nothing reads a clock or the network.
 */
export function buildSite(
  sources: SourcePage[],
  openapi: Record<string, unknown> | undefined,
): Map<string, string> {
  const pages: OutPage[] = [];
  for (const s of [...sources].sort((a, b) => a.path.localeCompare(b.path))) {
    if (SKIP.has(s.path)) continue;
    const r = renderMarkdown(s.markdown);
    pages.push({
      path: outPath(s.path),
      title: r.title,
      html: r.html,
      section: sectionOf(s.path),
      headings: r.headings,
    });
  }
  if (openapi) {
    const r = renderOpenApi(openapi);
    pages.push({
      path: "reference/openapi.html",
      title: "API reference",
      html: r.html,
      section: "reference",
      headings: [],
    });
  }

  // ADR index
  const adrs = pages
    .filter((p) => p.section === "adr")
    .sort((a, b) => a.path.localeCompare(b.path));
  const adrIndex = `<h1 id="architecture-decisions">Architecture decisions</h1><ul>${adrs
    .map(
      (a) =>
        `<li><a href="${escapeHtml(relativeHref("adr/index.html", a.path))}">${escapeHtml(a.title)}</a></li>`,
    )
    .join("")}</ul>`;
  pages.push({
    path: "adr/index.html",
    title: "Architecture decisions",
    html: adrIndex,
    section: "adr",
    headings: [],
  });

  const sections = [...new Set(pages.map((p) => p.section))].sort((a, b) =>
    a === "root" ? -1 : b === "root" ? 1 : a.localeCompare(b),
  );
  const nav = sections.map((section) => ({
    section,
    items: pages
      .filter((p) => p.section === section && !(section === "adr" && p.path !== "adr/index.html"))
      .map((p) => ({ path: p.path, title: p.title }))
      .sort((a, b) => a.path.localeCompare(b.path)),
  }));

  const homeBody = `<h1 id="axis-documentation">AXIS documentation</h1><p>Guides, specifications, runbooks and the API reference for the AXIS agentic OS.</p>${nav
    .filter((n) => n.section !== "root")
    .map(
      (n) =>
        `<h2 id="${n.section}">${escapeHtml(SECTION_TITLES[n.section] ?? n.section)}</h2><ul>${n.items.map((i) => `<li><a href="${escapeHtml(i.path)}">${escapeHtml(i.title)}</a></li>`).join("")}</ul>`,
    )
    .join("")}`;
  pages.push({
    path: "index.html",
    title: "AXIS documentation",
    html: homeBody,
    section: "root",
    headings: [],
  });

  const out = new Map<string, string>();
  for (const p of pages)
    out.set(p.path, layout({ path: p.path, title: p.title, body: p.html }, nav));
  out.set("assets/site.css", SITE_CSS);
  return out;
}
