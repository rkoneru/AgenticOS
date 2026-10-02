import { readFileSync, readdirSync, statSync, mkdtempSync, existsSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { escapeHtml, renderMarkdown, rewriteHref, slugify } from "../src/markdown";
import { extractOperations, renderOpenApi } from "../src/openapi";
import { buildSite, relativeHref, sectionOf, outPath } from "../src/site";
import { checkLinks } from "../src/linkcheck";

const repo = fileURLToPath(new URL("../../..", import.meta.url));

describe("markdown", () => {
  it("escapes raw html and drops unsafe links", () => {
    const r = renderMarkdown(
      '# T\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1)) [ok](https://a.example) ![i](x.png "t")\n\ninline <b onclick=x>b</b>',
    );
    expect(r.html).not.toContain("<script>");
    expect(r.html).toContain("&lt;script&gt;");
    expect(r.html).not.toContain("javascript:");
    expect(r.html).toContain('rel="noopener noreferrer"');
    expect(r.html).not.toContain("<img");
    expect(r.html).not.toContain("<b onclick");
  });
  it("gives headings unique ids and a title", () => {
    const r = renderMarkdown("# Hello World\n\n## A\n\n## A\n\n## \n\n### ***\n");
    expect(r.title).toBe("Hello World");
    expect(r.headings.map((h) => h.id).slice(0, 3)).toEqual(["hello-world", "a", "a-1"]);
    expect(renderMarkdown("no headings").title).toBe("Untitled");
    expect(renderMarkdown("## only h2").title).toBe("only h2");
  });
  it("rewrites relative .md links", () => {
    expect(rewriteHref("a/b.md#x")).toBe("a/b.html#x");
    expect(rewriteHref("b.md")).toBe("b.html");
    expect(rewriteHref("https://x.example/a.md")).toBe("https://x.example/a.md");
    expect(rewriteHref("#top")).toBe("#top");
    expect(rewriteHref("//cdn/x.md")).toBe("//cdn/x.md");
    expect(rewriteHref("../src/a.ts")).toBe("../src/a.ts");
    expect(renderMarkdown('[a](b.md "ti")').html).toContain('href="b.html" title="ti"');
  });
  it("utilities", () => {
    expect(slugify("Hello, <b>World</b>!")).toBe("hello-world");
    expect(escapeHtml(`<a href="x">'&`)).toBe("&lt;a href=&quot;x&quot;&gt;&#39;&amp;");
  });
});

describe("site", () => {
  it("builds nav, adr index, reference and is deterministic", () => {
    const sources = [
      { path: "adr/0002-b.md", markdown: "# 0002 B\n" },
      { path: "adr/0001-a.md", markdown: "# 0001 A\n\nsee [b](0002-b.md)\n" },
      { path: "spec/s.md", markdown: "# Spec\n\n[adr](../adr/0001-a.md#0001-a)\n" },
      { path: "NEEDS.md", markdown: "# Needs\n" },
      { path: "README.md", markdown: "# Root\n" },
    ];
    const spec = parse(
      "openapi: 3.1.0\ninfo: {title: T, version: '1', summary: s, description: d}\npaths: {}\n",
    ) as Record<string, unknown>;
    const a = buildSite(sources, spec);
    const b = buildSite([...sources].reverse(), spec);
    expect([...a.entries()]).toEqual([...b.entries()]);
    expect([...a.keys()].sort()).toEqual([
      "README.html",
      "adr/0001-a.html",
      "adr/0002-b.html",
      "adr/index.html",
      "assets/site.css",
      "index.html",
      "reference/openapi.html",
      "spec/s.html",
    ]);
    expect(a.get("adr/index.html")!.indexOf("0001 A")).toBeLessThan(
      a.get("adr/index.html")!.indexOf("0002 B"),
    );
    expect(a.get("spec/s.html")).toContain('href="../adr/0001-a.html#0001-a"');
    expect(a.get("spec/s.html")).toContain('aria-current="page"');
    expect(checkLinks(a)).toEqual([]);
    expect(buildSite(sources, undefined).has("reference/openapi.html")).toBe(false);
  });
  it("helpers", () => {
    expect(sectionOf("a/b.md")).toBe("a");
    expect(sectionOf("b.md")).toBe("root");
    expect(outPath("a/b.md")).toBe("a/b.html");
    expect(relativeHref("a/b.html", "a/c.html")).toBe("c.html");
    expect(relativeHref("a/b.html", "c/d.html")).toBe("../c/d.html");
    expect(relativeHref("index.html", "a/d.html")).toBe("a/d.html");
    expect(relativeHref("a/b.html", "a/b.html")).toBe("b.html");
  });
});

describe("link check", () => {
  it("flags missing pages and anchors, ignores externals", () => {
    const site = new Map([
      [
        "a.html",
        '<h1 id="x"></h1><a href="b.html">b</a><a href="#nope">n</a><a href="#x">x</a><a href="https://e.example/z">e</a><a href="gone.html">g</a><a href="b.html#missing">m</a><a href="./b.html?q=1&amp;r=2#top">q</a>',
      ],
      ["b.html", '<p id="top"></p><a href="../c.html">up</a>'],
      ["s/x.css", "body{}"],
    ]);
    const p = checkLinks(site);
    expect(p.map((x) => `${x.page}|${x.href}|${x.problem}`).sort()).toEqual([
      "a.html|#nope|missing anchor",
      "a.html|b.html#missing|missing anchor",
      "a.html|gone.html|missing target",
      "b.html|../c.html|missing target",
    ]);
  });
});

describe("openapi reference", () => {
  const spec = parse(
    readFileSync(join(repo, "packages/contracts/openapi/axis-v1.yaml"), "utf8"),
  ) as Record<string, unknown>;
  it("documents every operation of the frozen spec", () => {
    const ops = extractOperations(spec);
    const expected: string[] = [];
    for (const item of Object.values(
      spec["paths"] as Record<string, Record<string, { operationId?: string }>>,
    )) {
      for (const [m, op] of Object.entries(item))
        if (["get", "put", "post", "delete", "patch"].includes(m)) expected.push(op.operationId!);
    }
    expect(ops.map((o) => o.operationId).sort()).toEqual(expected.sort());
    const html = renderOpenApi(spec).html;
    for (const id of expected) expect(html).toContain(id);
    expect(html).toContain("/policies:test");
    expect(html).toContain("Idempotency-Key");
  });
  it("copes with odd shapes", () => {
    const html = renderOpenApi({
      openapi: "3",
      paths: {
        "/x": {
          parameters: [{ name: "p", in: "query", schema: { type: ["string", "null"] } }],
          get: {
            parameters: [
              { $ref: "#/nope" },
              { name: "e", in: "query", schema: { enum: ["a", "b"] } },
              { name: "r", in: "query", schema: { $ref: "#/c/R" } },
            ],
            responses: { "200": { $ref: "#/missing" } },
          },
        },
      },
    }).html;
    expect(html).toContain("a | b");
    expect(html).toContain("string | null");
  });
});

describe("real docs build", () => {
  it("builds offline and deterministically from docs/, every generated link resolves in curated sections", () => {
    const out1 = mkdtempSync(join(tmpdir(), "docs1-"));
    const out2 = mkdtempSync(join(tmpdir(), "docs2-"));
    const run = (o: string) =>
      spawnSync("pnpm", ["exec", "tsx", "src/build.ts"], {
        cwd: join(repo, "apps/docs-site"),
        env: {
          ...process.env,
          DOCS_OUT_DIR: o,
          HTTP_PROXY: "http://127.0.0.1:9",
          HTTPS_PROXY: "http://127.0.0.1:9",
          DOCS_STRICT_LINKS: "0",
        },
        encoding: "utf8",
      });
    const a = run(out1);
    expect(a.status, a.stderr).toBe(0);
    run(out2);
    const files = (d: string): string[] => {
      const r: string[] = [];
      const w = (p: string) => {
        for (const n of readdirSync(p).sort()) {
          const f = join(p, n);
          if (statSync(f).isDirectory()) w(f);
          else r.push(relative(d, f).split(sep).join("/"));
        }
      };
      w(d);
      return r;
    };
    const f1 = files(out1);
    expect(f1).toEqual(files(out2));
    for (const f of f1)
      expect(readFileSync(join(out1, f), "utf8")).toBe(readFileSync(join(out2, f), "utf8"));
    expect(existsSync(join(out1, "reference/openapi.html"))).toBe(true);
    expect(existsSync(join(out1, "adr/index.html"))).toBe(true);
    expect(f1.filter((f) => f.startsWith("runbooks/")).length).toBeGreaterThan(0);
    expect(f1.filter((f) => f.startsWith("spec/")).length).toBeGreaterThan(0);
    // No remote resources: nothing in the output references an http(s) src or stylesheet.
    for (const f of f1.filter((x) => x.endsWith(".html")))
      expect(readFileSync(join(out1, f), "utf8")).not.toMatch(
        /<(?:script|link|img)[^>]+(?:src|href)="https?:/,
      );
  }, 120_000);
});
