import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse } from "yaml";
import type { ValidationIssue } from "./problem.js";

/**
 * The frozen OpenAPI document is the single source of truth: every validator below is compiled FROM it at start-up, so the gateway
 * cannot drift from the contract (a route table test also walks every operation in the file).
 */
const OPENAPI_ID = "https://axis.example/openapi/axis-v1";

type Json = Record<string, unknown>;

export interface ParamSpec {
  name: string;
  in: "path" | "query" | "header";
  required: boolean;
  /** JSON pointer (under OPENAPI_ID) of the parameter's schema. */
  ptr: string;
}

export interface OperationSpec {
  id: string;
  method: "get" | "post" | "put" | "delete";
  /** OpenAPI path template, without the `/v1` server prefix. */
  template: string;
  tags: string[];
  params: ParamSpec[];
  bodyPtr: string | undefined;
  bodyRequired: boolean;
  /** `status` or `default` -> media type -> schema pointer. */
  responses: Map<string, Map<string, string>>;
  idempotent: boolean;
}

const esc = (s: string): string => s.replaceAll("~", "~0").replaceAll("/", "~1");

export function openapiPath(): string {
  const req = createRequire(import.meta.url);
  return resolve(dirname(req.resolve("@axis/contracts/package.json")), "openapi", "axis-v1.yaml");
}

export class ApiSpec {
  readonly doc: Json;
  readonly operations: OperationSpec[] = [];
  private readonly strict: Ajv2020;
  private readonly coercing: Ajv2020;
  private readonly cache = new Map<string, ValidateFunction>();
  readonly version: string;

  constructor(path: string = openapiPath()) {
    const doc = parse(readFileSync(path, "utf8")) as Json;
    const dir = dirname(path);
    const external = new Map<string, Json>();
    const rewrite = (node: unknown): unknown => {
      if (Array.isArray(node)) return node.map(rewrite);
      if (typeof node !== "object" || node === null) return node;
      const out: Json = {};
      for (const [k, v] of Object.entries(node as Json)) {
        if (k === "$ref" && typeof v === "string" && v.startsWith("../")) {
          const file = resolve(dir, v);
          let schema = external.get(file);
          if (!schema) {
            schema = JSON.parse(readFileSync(file, "utf8")) as Json;
            external.set(file, schema);
          }
          out[k] = schema["$id"] as string;
        } else out[k] = rewrite(v);
      }
      return out;
    };
    this.doc = rewrite(doc) as Json;
    this.version = String((this.doc["info"] as Json)["version"]);
    const make = (coerceTypes: boolean): Ajv2020 => {
      const a = new Ajv2020({ allErrors: true, strict: false, coerceTypes, useDefaults: false });
      addFormats.default(a);
      for (const s of external.values()) a.addSchema(s);
      a.addSchema({ ...this.doc, $id: OPENAPI_ID });
      return a;
    };
    this.strict = make(false);
    this.coercing = make(true);
    this.collect();
  }

  private ref(node: unknown): Json {
    let cur = node as Json;
    for (let i = 0; i < 5 && typeof cur["$ref"] === "string"; i++) {
      const parts = (cur["$ref"] as string).replace(/^#\//, "").split("/").map((p) => p.replaceAll("~1", "/").replaceAll("~0", "~"));
      let n: unknown = this.doc;
      for (const p of parts) n = (n as Json)[p];
      cur = n as Json;
    }
    return cur;
  }

  private collect(): void {
    const paths = this.doc["paths"] as Record<string, Json>;
    for (const [template, item] of Object.entries(paths)) {
      for (const method of ["get", "post", "put", "delete"] as const) {
        const op = item[method] as Json | undefined;
        if (!op) continue;
        const params: ParamSpec[] = [];
        let idempotent = false;
        ((op["parameters"] as unknown[] | undefined) ?? []).forEach((raw, i) => {
          const r = raw as Json;
          const direct = typeof r["$ref"] !== "string";
          const p = this.ref(r);
          const base = direct
            ? `#/paths/${esc(template)}/${method}/parameters/${i}`
            : `#/${(r["$ref"] as string).replace(/^#\//, "")}`;
          if (p["in"] === "header" && String(p["name"]).toLowerCase() === "idempotency-key") idempotent = true;
          params.push({ name: String(p["name"]), in: p["in"] as ParamSpec["in"], required: p["required"] === true, ptr: `${base}/schema` });
        });
        const rb = op["requestBody"] as Json | undefined;
        const bodyPtr = rb
          ? `#/paths/${esc(template)}/${method}/requestBody/content/${esc("application/json")}/schema`
          : undefined;
        const responses = new Map<string, Map<string, string>>();
        for (const [status, rawResp] of Object.entries((op["responses"] as Json) ?? {})) {
          const isRef = typeof (rawResp as Json)["$ref"] === "string";
          const resp = this.ref(rawResp);
          const media = new Map<string, string>();
          for (const mt of Object.keys((resp["content"] as Json | undefined) ?? {})) {
            const base = isRef
              ? `#/${((rawResp as Json)["$ref"] as string).replace(/^#\//, "")}`
              : `#/paths/${esc(template)}/${method}/responses/${esc(status)}`;
            media.set(mt, `${base}/content/${esc(mt)}/schema`);
          }
          responses.set(status, media);
        }
        this.operations.push({
          id: String(op["operationId"]),
          method,
          template,
          tags: (op["tags"] as string[] | undefined) ?? [],
          params,
          bodyPtr,
          bodyRequired: rb?.["required"] === true,
          responses,
          idempotent,
        });
      }
    }
  }

  private validator(coerce: boolean, ptr: string): ValidateFunction {
    const key = `${coerce ? "c" : "s"}${ptr}`;
    let v = this.cache.get(key);
    if (!v) {
      const got = (coerce ? this.coercing : this.strict).getSchema(OPENAPI_ID + ptr);
      if (!got) throw new Error(`no schema at ${ptr}`);
      v = got;
      this.cache.set(key, v);
    }
    return v;
  }

  /** Validates a request body against the operation's JSON schema. */
  validateBody(op: OperationSpec, body: unknown): ValidationIssue[] {
    if (!op.bodyPtr) return [];
    const v = this.validator(false, op.bodyPtr);
    return v(body) ? [] : issues(v);
  }

  /**
   * Validates and COERCES (query strings -> integers, booleans) the parameters of one location against the operation's declared
   * parameter schemas. Unknown names are rejected (`additionalProperties: false`): a stray `tenant_id` is a client bug or an attack.
   */
  validateParams(
    op: OperationSpec,
    loc: "path" | "query" | "header",
    values: Record<string, string>,
  ): { value: Record<string, unknown>; issues: ValidationIssue[] } {
    const key = `params:${op.id}:${loc}`;
    let v = this.cache.get(key);
    const declared = op.params.filter((p) => p.in === loc);
    if (!v) {
      v = this.coercing.compile({
        type: "object",
        additionalProperties: loc === "header",
        properties: Object.fromEntries(declared.map((p) => [p.name, { $ref: OPENAPI_ID + p.ptr }])),
        required: declared.filter((p) => p.required).map((p) => p.name),
      });
      this.cache.set(key, v);
    }
    const value: Record<string, unknown> = { ...values };
    return v(value) ? { value, issues: [] } : { value, issues: issues(v) };
  }

  /** The response schema pointer for a status/media type (falls back to `default`). */
  responsePtr(op: OperationSpec, status: number, media: string): string | undefined {
    const m = op.responses.get(String(status)) ?? op.responses.get("default");
    return m?.get(media);
  }

  /** Issues for a response that does not match the contract; `undefined` when the contract declares nothing to check. */
  validateResponse(op: OperationSpec, status: number, media: string, body: unknown): ValidationIssue[] | undefined {
    const known = op.responses.get(String(status)) ?? op.responses.get("default");
    if (!known) return [{ path: "/", message: `status ${status} is not declared for ${op.id}` }];
    const ptr = known.get(media);
    if (!ptr) return [{ path: "/", message: `media type ${media} is not declared for ${op.id} ${status}` }];
    const v = this.validator(false, ptr);
    return v(body) ? [] : issues(v);
  }
}

function issues(v: ValidateFunction): ValidationIssue[] {
  return (v.errors ?? []).slice(0, 20).map((e) => {
    // "must NOT have additional properties" is reported at the parent; name the property so the caller can find it.
    const extra = e.keyword === "additionalProperties" ? String((e.params as { additionalProperty?: unknown }).additionalProperty) : undefined;
    const base = e.instancePath === "" ? "" : e.instancePath;
    return {
      path: extra !== undefined ? `${base}/${extra.replaceAll("~", "~0").replaceAll("/", "~1")}` : base === "" ? "/" : base,
      keyword: e.keyword,
      message: String(e.message),
    };
  });
}

/** Compiled path matcher for `/blueprints/{name}/versions/{version}` style templates. */
export function compileTemplate(template: string): { re: RegExp; names: string[] } {
  const names: string[] = [];
  const src = template
    .split("/")
    .map((seg) => {
      const m = /^\{(\w+)\}$/.exec(seg);
      if (m) {
        names.push(m[1] as string);
        return "([^/]+)";
      }
      return seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("/");
  return { re: new RegExp(`^${src}$`), names };
}
