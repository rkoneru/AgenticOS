import { escapeHtml, slugify } from "./markdown";

type J = Record<string, unknown>;
const METHODS = ["get", "put", "post", "delete", "patch"] as const;

export interface Operation {
  method: string;
  path: string;
  id: string;
  summary: string;
  tag: string;
  operationId: string;
  parameters: Array<{ name: string; in: string; required: boolean; type: string }>;
  responses: Array<{ code: string; description: string }>;
  hasBody: boolean;
}

function resolveRef(spec: J, ref: string): J | undefined {
  if (!ref.startsWith("#/")) return undefined;
  let cur: unknown = spec;
  for (const part of ref.slice(2).split("/")) {
    if (typeof cur !== "object" || cur === null) return undefined;
    cur = (cur as J)[part.replace(/~1/g, "/").replace(/~0/g, "~")];
  }
  return cur as J | undefined;
}

function typeOf(schema: unknown): string {
  const s = (schema ?? {}) as J;
  if (typeof s["$ref"] === "string") return (s["$ref"] as string).split("/").pop() ?? "ref";
  if (Array.isArray(s["enum"])) return (s["enum"] as unknown[]).join(" | ");
  const t = s["type"];
  return Array.isArray(t) ? t.join(" | ") : typeof t === "string" ? t : "any";
}

export function extractOperations(spec: J): Operation[] {
  const paths = (spec["paths"] ?? {}) as Record<string, J>;
  const ops: Operation[] = [];
  for (const path of Object.keys(paths).sort()) {
    const item = paths[path]!;
    for (const method of METHODS) {
      const op = item[method] as J | undefined;
      if (!op) continue;
      const params = [
        ...((item["parameters"] as J[] | undefined) ?? []),
        ...((op["parameters"] as J[] | undefined) ?? []),
      ].map((p) => {
        const r = typeof p["$ref"] === "string" ? (resolveRef(spec, p["$ref"] as string) ?? {}) : p;
        return {
          name: String(r["name"] ?? "?"),
          in: String(r["in"] ?? "?"),
          required: r["required"] === true,
          type: typeOf(r["schema"]),
        };
      });
      const responses = Object.entries((op["responses"] ?? {}) as Record<string, J>).map(
        ([code, r]) => {
          const rr =
            typeof r["$ref"] === "string" ? (resolveRef(spec, r["$ref"] as string) ?? {}) : r;
          return { code, description: String(rr["description"] ?? "") };
        },
      );
      const operationId = String(op["operationId"] ?? `${method}-${path}`);
      ops.push({
        method: method.toUpperCase(),
        path,
        id: slugify(operationId),
        summary: String(op["summary"] ?? ""),
        tag: String(((op["tags"] as string[] | undefined) ?? ["Other"])[0]),
        operationId,
        parameters: params,
        responses,
        hasBody: op["requestBody"] !== undefined,
      });
    }
  }
  return ops;
}

export function renderOpenApi(spec: J): { html: string; operationIds: string[] } {
  const info = (spec["info"] ?? {}) as J;
  const ops = extractOperations(spec);
  const tags = [...new Set(ops.map((o) => o.tag))].sort();
  const out: string[] = [];
  out.push(
    `<h1 id="api-reference">${escapeHtml(String(info["title"] ?? "API"))} <small>v${escapeHtml(String(info["version"] ?? ""))}</small></h1>`,
  );
  out.push(`<p>${escapeHtml(String(info["summary"] ?? ""))}</p>`);
  const descr = String(info["description"] ?? "");
  out.push(`<pre class="desc">${escapeHtml(descr)}</pre>`);
  for (const tag of tags) {
    out.push(`<h2 id="tag-${slugify(tag)}">${escapeHtml(tag)}</h2>`);
    for (const o of ops.filter((x) => x.tag === tag)) {
      out.push(
        `<section class="op" id="${o.id}"><h3><span class="method m-${o.method.toLowerCase()}">${o.method}</span> <code>${escapeHtml(o.path)}</code></h3>`,
      );
      out.push(
        `<p>${escapeHtml(o.summary)} <small>(<code>${escapeHtml(o.operationId)}</code>)</small></p>`,
      );
      if (o.parameters.length) {
        out.push(
          "<table><caption>Parameters</caption><thead><tr><th>Name</th><th>In</th><th>Type</th><th>Required</th></tr></thead><tbody>",
        );
        for (const p of o.parameters)
          out.push(
            `<tr><td><code>${escapeHtml(p.name)}</code></td><td>${escapeHtml(p.in)}</td><td>${escapeHtml(p.type)}</td><td>${p.required ? "yes" : "no"}</td></tr>`,
          );
        out.push("</tbody></table>");
      }
      if (o.hasBody) out.push("<p>Request body: JSON (see the schema in the OpenAPI file).</p>");
      out.push(
        "<table><caption>Responses</caption><thead><tr><th>Status</th><th>Description</th></tr></thead><tbody>",
      );
      for (const r of o.responses)
        out.push(`<tr><td>${escapeHtml(r.code)}</td><td>${escapeHtml(r.description)}</td></tr>`);
      out.push("</tbody></table></section>");
    }
  }
  return { html: out.join("\n"), operationIds: ops.map((o) => o.operationId) };
}
