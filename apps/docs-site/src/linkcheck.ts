export interface LinkProblem {
  page: string;
  href: string;
  problem: string;
}

const ATTR = /\b(?:href|src)="([^"]*)"/g;
const ID = /\bid="([^"]+)"/g;

function normalise(base: string, href: string): string {
  const parts = base.split("/").slice(0, -1);
  for (const seg of href.split("/")) {
    if (seg === "." || seg === "") continue;
    if (seg === "..") parts.pop();
    else parts.push(seg);
  }
  return parts.join("/");
}

/** Check every internal link and fragment in a built site (map of path -> content). */
export function checkLinks(site: ReadonlyMap<string, string>): LinkProblem[] {
  const ids = new Map<string, Set<string>>();
  for (const [p, c] of site) {
    if (!p.endsWith(".html")) continue;
    const s = new Set<string>();
    for (const m of c.matchAll(ID)) s.add(m[1]!);
    ids.set(p, s);
  }
  const problems: LinkProblem[] = [];
  for (const [page, content] of site) {
    if (!page.endsWith(".html")) continue;
    for (const m of content.matchAll(ATTR)) {
      const raw = m[1]!.replace(/&amp;/g, "&");
      if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith("//")) continue;
      const [pathPart, frag] = raw.split("#") as [string, string | undefined];
      const target = pathPart === "" ? page : normalise(page, pathPart.split("?")[0]!);
      if (!site.has(target)) {
        problems.push({ page, href: raw, problem: "missing target" });
        continue;
      }
      if (frag && target.endsWith(".html") && !ids.get(target)?.has(frag))
        problems.push({ page, href: raw, problem: "missing anchor" });
    }
  }
  return problems;
}
