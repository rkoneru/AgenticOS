import { Marked, type Tokens } from "marked";

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/<[^>]*>/g, "")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .trim()
    .replace(/\s+/g, "-");
}

export interface Heading {
  depth: number;
  text: string;
  id: string;
}

export interface Rendered {
  html: string;
  title: string;
  headings: Heading[];
}

/** Rewrite a relative markdown link to its generated page (`x.md#a` -> `x.html#a`); leave others alone. */
export function rewriteHref(href: string): string {
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("#") || href.startsWith("//"))
    return href;
  return href.replace(/\.md(?=$|#|\?)/, ".html");
}

const SAFE_SCHEMES = /^(https?:|mailto:|#|\/|\.{1,2}\/|[^:]*$)/i;

/**
 * Render markdown to HTML. Raw HTML in the source is escaped (never passed through), unsafe link schemes are
 * dropped, and every heading gets a stable, de-duplicated id.
 */
export function renderMarkdown(src: string): Rendered {
  const headings: Heading[] = [];
  const seen = new Map<string, number>();
  const m = new Marked({ gfm: true });
  m.use({
    renderer: {
      html(token: Tokens.HTML | Tokens.Tag): string {
        return escapeHtml(token.text);
      },
      heading(
        this: { parser: { parseInline: (t: Tokens.Generic[]) => string } },
        token: Tokens.Heading,
      ): string {
        const inner = this.parser.parseInline(token.tokens as Tokens.Generic[]);
        let id = slugify(token.text) || "section";
        const n = seen.get(id) ?? 0;
        seen.set(id, n + 1);
        if (n > 0) id = `${id}-${n}`;
        headings.push({ depth: token.depth, text: token.text, id });
        return `<h${token.depth} id="${id}">${inner}</h${token.depth}>\n`;
      },
      link(
        this: { parser: { parseInline: (t: Tokens.Generic[]) => string } },
        token: Tokens.Link,
      ): string {
        const inner = this.parser.parseInline(token.tokens as Tokens.Generic[]);
        if (!SAFE_SCHEMES.test(token.href)) return inner;
        const external = /^https?:/i.test(token.href);
        const title = token.title ? ` title="${escapeHtml(token.title)}"` : "";
        return `<a href="${escapeHtml(rewriteHref(token.href))}"${title}${external ? ' rel="noopener noreferrer"' : ""}>${inner}</a>`;
      },
      image(token: Tokens.Image): string {
        return `<span class="img-alt">[image: ${escapeHtml(token.text)}]</span>`;
      },
    },
  });
  const html = m.parse(src, { async: false });
  const title = headings.find((h) => h.depth === 1)?.text ?? headings[0]?.text ?? "Untitled";
  return { html, title, headings };
}
