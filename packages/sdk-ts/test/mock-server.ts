/**
 * In-test mock AXIS server generated from the OpenAPI (via test/fixtures/mock-model.json, which the
 * generator derives from packages/contracts/openapi/axis-v1.yaml). It is an injected `fetch`, so no socket is
 * opened. For every request it:
 *   - authenticates (X-Axis-Api-Key or Bearer) and answers 401 problem+json otherwise,
 *   - validates path, query and header parameters and the JSON body against the operation's schemas,
 *   - records every violation in `violations` (tests assert it stays empty) and answers 422,
 *   - answers with a response synthesized from the operation's success schema.
 */
import { readFileSync } from "node:fs";
import { Ajv } from "ajv";
import addFormats from "ajv-formats";

interface Param {
  name: string;
  in: string;
  required?: boolean;
  schema: Record<string, unknown>;
}
interface ModelOp {
  operationId: string;
  method: string;
  path: string;
  idempotent: string;
  parameters: Param[];
  requestBody: {
    required?: boolean;
    content: Record<string, { schema: Record<string, unknown> }>;
  } | null;
  responses: Record<string, { content?: Record<string, { schema: Record<string, unknown> }> }>;
}
export interface MockModel {
  version: string;
  operations: ModelOp[];
}

export const model: MockModel = JSON.parse(
  readFileSync(new URL("./fixtures/mock-model.json", import.meta.url), "utf8"),
);

const ajv = new Ajv({ strict: false, allErrors: true });
(addFormats as unknown as (a: Ajv) => void)(ajv);

const PATTERN_SAMPLES: Record<string, string> = {
  "^axp_[0-9A-HJKMNP-TV-Z]{26}$": "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "^[0-9a-f]{64}$": "a".repeat(64),
  "^[0-9a-f]{32}$": "b".repeat(32),
};

export function synthesize(schema: Record<string, unknown>): unknown {
  const s = schema as {
    type?: string | string[];
    enum?: unknown[];
    const?: unknown;
    format?: string;
    pattern?: string;
    properties?: Record<string, Record<string, unknown>>;
    required?: string[];
    items?: Record<string, unknown>;
    minimum?: number;
    minLength?: number;
    "x-external"?: string;
  };
  if (s.const !== undefined) return s.const;
  if (s.enum) return s.enum[0];
  const types = Array.isArray(s.type) ? s.type : s.type ? [s.type] : [];
  if (types.includes("null")) return null;
  const t = types[0];
  if (t === "string") {
    if (s.format === "uuid") return "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f";
    if (s.format === "date-time") return "2026-01-01T00:00:00.000Z";
    if (s.pattern) {
      const sample =
        PATTERN_SAMPLES[s.pattern] ??
        (s.pattern.startsWith("^\\d{4}") ? "2026-01-01T00:00:00.000Z" : undefined);
      if (sample === undefined) throw new Error(`mock: no sample for pattern ${s.pattern}`);
      return sample;
    }
    return "x".repeat(Math.max(1, s.minLength ?? 1));
  }
  if (t === "integer") return Math.max(1, s.minimum ?? 1);
  if (t === "number") return 1;
  if (t === "boolean") return true;
  if (t === "array") return [synthesize(s.items ?? {})];
  if (t === "object" || s.properties) {
    if (s["x-external"]) return {};
    const o: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(s.properties ?? {})) o[k] = synthesize(v);
    return o;
  }
  return {};
}

export interface MockCall {
  operationId: string;
  method: string;
  url: URL;
  headers: Headers;
  body: unknown;
}

export type Override = (call: MockCall, n: number) => Response | Promise<Response> | undefined;

export interface MockOptions {
  /** Accepted credential; default: any non-empty one. */
  apiKey?: string;
  overrides?: Record<string, Override>;
  baseUrl?: string;
}

export function problem(
  status: number,
  code: string,
  extra: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Response {
  return new Response(
    JSON.stringify({
      type: `https://axis.example/problems/${code}`,
      title: code.replace(/_/g, " "),
      status,
      code,
      ...extra,
    }),
    {
      status,
      headers: { "content-type": "application/problem+json", ...headers },
    },
  );
}
export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function templateRegex(path: string): RegExp {
  return new RegExp(
    "^" + path.replace(/[.*+?^$()|[\]\\]/g, "\\$&").replace(/\{[^}]+\}/g, "([^/]+)") + "$",
  );
}

export function createMockServer(opts: MockOptions = {}) {
  const base = new URL(opts.baseUrl ?? "https://api.test.axis.example/v1/");
  const routes = model.operations.map((op) => ({
    op,
    re: templateRegex(op.path),
    names: [...op.path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1] as string),
  }));
  const calls: MockCall[] = [];
  const violations: string[] = [];
  const counts = new Map<string, number>();

  const fetchImpl = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = new URL(
      typeof input === "string" ? input : input instanceof URL ? input.href : input.url,
    );
    const headers = new Headers(init?.headers);
    const method = (init?.method ?? "GET").toUpperCase();
    if (url.origin !== base.origin) throw new TypeError(`mock: unexpected origin ${url.origin}`);
    const rel = url.pathname.slice(base.pathname.length - 1);
    const route = routes.find((r) => r.op.method === method && r.re.test(rel));
    if (!route) return problem(404, "not_found", { detail: `no route for ${method} ${rel}` });
    const op = route.op;
    const match = route.re.exec(rel) as RegExpExecArray;
    const bodyText = typeof init?.body === "string" ? init.body : undefined;
    const body = bodyText ? JSON.parse(bodyText) : undefined;
    const call: MockCall = { operationId: op.operationId, method, url, headers, body };
    calls.push(call);
    const n = (counts.get(op.operationId) ?? 0) + 1;
    counts.set(op.operationId, n);

    const bad = (msg: string) => {
      violations.push(`${op.operationId}: ${msg}`);
    };
    // authentication
    const key = headers.get("x-axis-api-key");
    const bearer = /^Bearer (.+)$/.exec(headers.get("authorization") ?? "")?.[1];
    const cred = key ?? bearer;
    const authed =
      cred !== undefined && cred !== "" && (opts.apiKey === undefined || cred === opts.apiKey);

    const override = opts.overrides?.[op.operationId]?.(call, n);
    if (override) return override;
    if (!authed) return problem(401, "unauthenticated");

    // parameters
    route.names.forEach((name, i) => {
      const p = op.parameters.find((x) => x.in === "path" && x.name === name);
      const rawV = decodeURIComponent(match[i + 1] as string);
      const pt = (p?.schema as { type?: string } | undefined)?.type;
      const v = pt === "integer" && /^\d+$/.test(rawV) ? Number(rawV) : rawV;
      if (!p || !ajv.validate(p.schema, v)) bad(`path param ${name}=${rawV} invalid`);
    });
    for (const p of op.parameters) {
      if (p.in === "query") {
        const raw = url.searchParams.get(p.name);
        if (raw === null) {
          if (p.required) bad(`missing required query ${p.name}`);
          continue;
        }
        const t = (p.schema as { type?: string }).type;
        const v = t === "integer" || t === "number" ? Number(raw) : raw;
        if (!ajv.validate(p.schema, v)) bad(`query ${p.name}=${raw} invalid: ${ajv.errorsText()}`);
      }
      if (p.in === "header") {
        const raw = headers.get(p.name.toLowerCase());
        if (raw === null) {
          if (p.required) bad(`missing header ${p.name}`);
        } else if (!ajv.validate(p.schema, raw)) bad(`header ${p.name} invalid`);
      }
    }
    for (const k of url.searchParams.keys())
      if (!op.parameters.some((p) => p.in === "query" && p.name === k)) bad(`unknown query ${k}`);
    // body
    if (op.requestBody) {
      const schema = op.requestBody.content["application/json"]?.schema;
      if (body === undefined) {
        if (op.requestBody.required) bad("missing required body");
      } else if (schema && !ajv.validate(schema, body)) bad(`body invalid: ${ajv.errorsText()}`);
    } else if (body !== undefined) bad("unexpected body");
    if (op.requestBody && body !== undefined && headers.get("content-type") !== "application/json")
      bad("content-type must be application/json");

    const status = Object.keys(op.responses).find((c) => /^2\d\d$/.test(c)) as string;
    const content = op.responses[status]?.content ?? {};
    if (headers.get("accept")?.includes("text/event-stream") && content["text/event-stream"]) {
      const ev = synthesize(
        model.operations.find((o) => o.operationId === "listRunEvents")!.responses["200"]!.content![
          "application/json"
        ]!.schema,
      ) as { items: unknown[] };
      const first = ev.items[0] as { sequence: number };
      return new Response(`id: ${first.sequence}\ndata: ${JSON.stringify(first)}\n\n`, {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      });
    }
    const schema = content["application/json"]?.schema;
    if (!schema) return new Response(null, { status: Number(status) });
    const value = synthesize(schema);
    if (!ajv.validate(schema, value))
      throw new Error(
        `mock: synthesized response invalid for ${op.operationId}: ${ajv.errorsText()}`,
      );
    return json(value, Number(status), { "x-request-id": `req-${calls.length}` });
  };

  return {
    fetch: fetchImpl as typeof fetch,
    calls,
    violations,
    baseUrl: base.href.replace(/\/$/, ""),
  };
}

/** Build sample params for an operation (path, query, body, per its schemas). */
export function sampleParams(operationId: string): Record<string, unknown> {
  const op = model.operations.find((o) => o.operationId === operationId) as ModelOp;
  const out: Record<string, unknown> = {};
  for (const p of op.parameters) {
    if (p.in === "path" || (p.in === "query" && p.required)) out[p.name] = synthesize(p.schema);
  }
  const bodySchema = op.requestBody?.content["application/json"]?.schema;
  if (bodySchema) out["body"] = synthesize(bodySchema);
  return out;
}

/** The error a promise rejects with (fails the test when it resolves). */
export async function rejected<E extends Error>(p: Promise<unknown>): Promise<E> {
  try {
    await p;
  } catch (e) {
    return e as E;
  }
  throw new Error("expected the promise to reject");
}
