#!/usr/bin/env node
/**
 * AXIS SDK generator (ADR 0040).
 *
 * Reads the frozen OpenAPI document and deterministically emits:
 *   - packages/sdk-ts/src/generated/{types,operations,client}.ts   typed TS client layer
 *   - sdk/python/src/axis_sdk/_generated/{models,operations,client}.py   typed Python layer (sync + async)
 *   - {packages/sdk-ts,sdk/python}/test(s)/fixtures/mock-model.json   spec model the mock servers are built from
 *
 * No network, no timestamps, no randomness: re-running on an unchanged spec yields a byte-identical tree.
 * `--check` writes nothing and exits 1 when the committed output differs (the drift tests call it).
 * To regenerate after the spec changes (for example the gateway adds AGIL/registry paths):  node scripts/generate-sdks.mjs
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SPEC_PATH = "packages/contracts/openapi/axis-v1.yaml";
const AUDIT_SCHEMA_PATH = "packages/contracts/schemas/audit-event-v1.schema.json";

/** External $refs whose full schema is owned elsewhere: typed as opaque documents in the SDKs. */
const EXTERNAL_OPAQUE = {
  "abl-v1.schema.json": "AblDocument",
  "policy-v1.schema.json": "PolicyDocument",
};
const EXTERNAL_CONVERTED = { "audit-event-v1.schema.json": "AuditEvent" };

/**
 * POST operations that are read-only in practice but cannot say so in OpenAPI 3.1 (no Idempotency-Key header
 * either). Safe to retry. Everything else that is a POST without an Idempotency-Key is NEVER retried.
 */
const SAFE_POST = new Set(["testPolicy", "verifyAuditChain"]);

const PY_KEYWORDS = new Set(
  "False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield".split(
    " ",
  ),
);

// ---------------------------------------------------------------------------------------------- helpers
const pascal = (s) =>
  s
    .replace(/[^A-Za-z0-9]+(.)?/g, (_, c) => (c ? c.toUpperCase() : ""))
    .replace(/^(.)/, (c) => c.toUpperCase());
const snake = (s) =>
  s
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[^A-Za-z0-9]+/g, "_")
    .toLowerCase();
const pyName = (s) => {
  const n = snake(s);
  return PY_KEYWORDS.has(n) ? `${n}_` : n;
};
const isIdent = (s) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(s);
const sha = (s) => createHash("sha256").update(s).digest("hex");
const readText = (p) => readFileSync(join(ROOT, p), "utf8");

// ---------------------------------------------------------------------------------------------- spec -> IR
function buildModel() {
  const specText = readText(SPEC_PATH);
  const spec = parse(specText);
  const auditText = readText(AUDIT_SCHEMA_PATH);
  const inputHash = sha(specText + "\0" + auditText);

  const types = []; // {name, ir}
  const names = new Set();
  const register = (name, ir) => {
    if (names.has(name)) throw new Error(`generator: duplicate type name ${name}`);
    names.add(name);
    types.push({ name, ir });
  };

  const pointer = (ref) => {
    if (!ref.startsWith("#/")) throw new Error(`generator: unsupported ref ${ref}`);
    return ref
      .slice(2)
      .split("/")
      .reduce((node, seg) => {
        const v = node?.[seg.replace(/~1/g, "/").replace(/~0/g, "~")];
        if (v === undefined) throw new Error(`generator: dangling ref ${ref}`);
        return v;
      }, spec);
  };

  function conv(s, hint, nested) {
    if (s.$ref) {
      if (s.$ref.startsWith("#/components/schemas/"))
        return { k: "ref", name: s.$ref.split("/").pop() };
      const file = s.$ref.split("/").pop();
      const opaque = EXTERNAL_OPAQUE[file] ?? EXTERNAL_CONVERTED[file];
      if (!opaque) throw new Error(`generator: unknown external ref ${s.$ref}`);
      return { k: "ref", name: opaque };
    }
    if (s.allOf) {
      const merged = { props: new Map(), required: new Set() };
      const fold = (part) => {
        if (part.$ref) return fold(pointer(part.$ref));
        if (part.allOf) return part.allOf.forEach(fold);
        for (const r of part.required ?? []) merged.required.add(r);
        for (const [k, v] of Object.entries(part.properties ?? {})) merged.props.set(k, v);
      };
      fold(s);
      return objectIr(Object.fromEntries(merged.props), [...merged.required], hint, nested);
    }
    if (s.enum) return { k: "enum", values: s.enum };
    if (s.const !== undefined) return { k: "enum", values: [s.const] };
    if (Array.isArray(s.type)) {
      return { k: "union", items: s.type.map((t) => conv({ ...s, type: t }, hint, nested)) };
    }
    switch (s.type) {
      case "string":
        return { k: "prim", t: "string" };
      case "integer":
      case "number":
        return { k: "prim", t: "number" };
      case "boolean":
        return { k: "prim", t: "boolean" };
      case "null":
        return { k: "prim", t: "null" };
      case "array":
        return {
          k: "array",
          item: s.items ? conv(s.items, `${hint}Item`, true) : { k: "prim", t: "unknown" },
        };
      case "object":
        return s.properties
          ? objectIr(s.properties, s.required ?? [], hint, nested)
          : { k: "record" };
      default:
        return s.properties
          ? objectIr(s.properties, s.required ?? [], hint, nested)
          : { k: "prim", t: "unknown" };
    }
  }

  function objectIr(properties, required, hint, nested) {
    const props = Object.entries(properties).map(([name, ps]) => ({
      name,
      required: required.includes(name),
      type: conv(ps, `${hint}${pascal(name)}`, true),
    }));
    const ir = { k: "object", props };
    if (!nested) return ir;
    register(hint, ir);
    return { k: "ref", name: hint };
  }

  // components
  for (const [name, schema] of Object.entries(spec.components.schemas)) {
    const ir = conv(schema, name, false);
    register(name, ir);
  }
  // external, converted
  const auditSchema = JSON.parse(auditText);
  register(
    "AuditEvent",
    conv({ ...auditSchema, if: undefined, then: undefined }, "AuditEvent", false),
  );
  register("AblDocument", { k: "record" });
  register("PolicyDocument", { k: "record" });

  // operations
  const ops = [];
  for (const [path, item] of Object.entries(spec.paths)) {
    for (const method of ["get", "put", "post", "delete", "patch"]) {
      const op = item[method];
      if (!op) continue;
      const id = op.operationId;
      if (!id) throw new Error(`generator: ${method} ${path} has no operationId`);
      const O = pascal(id);
      const params = (op.parameters ?? []).map((p) => (p.$ref ? pointer(p.$ref) : p));
      const pathParams = [];
      const queryParams = [];
      let idempotencyHeader = false;
      for (const p of params) {
        if (p.in === "path")
          pathParams.push({
            name: p.name,
            py: pyName(p.name),
            ir: conv(p.schema, `${O}${pascal(p.name)}`, false),
          });
        else if (p.in === "query")
          queryParams.push({
            name: p.name,
            py: pyName(p.name),
            required: !!p.required,
            ir: conv(p.schema, `${O}${pascal(p.name)}`, false),
          });
        else if (p.in === "header" && p.name.toLowerCase() === "idempotency-key")
          idempotencyHeader = true;
        else throw new Error(`generator: unsupported parameter ${p.in}:${p.name} on ${id}`);
      }
      const all = [...pathParams, ...queryParams].map((p) => p.name);
      if (
        new Set(all).size !== all.length ||
        all.includes("body") ||
        all.includes("idempotencyKey")
      )
        throw new Error(`generator: parameter name collision on ${id}`);

      let body = null;
      if (op.requestBody) {
        const media = op.requestBody.content?.["application/json"];
        if (!media) throw new Error(`generator: ${id} request body must be application/json`);
        body = { required: !!op.requestBody.required, ir: conv(media.schema, `${O}Request`, true) };
      }
      const okStatus = Object.keys(op.responses).find((c) => /^2\d\d$/.test(c));
      if (!okStatus) throw new Error(`generator: ${id} has no 2xx response`);
      const okContent = op.responses[okStatus].content ?? {};
      const jsonOk = okContent["application/json"];
      const response = jsonOk ? conv(jsonOk.schema, `${O}Response`, true) : null;
      const sse = "text/event-stream" in okContent;

      let idempotent;
      if (["get", "put", "delete"].includes(method)) idempotent = "always";
      else if (method === "post" && idempotencyHeader) idempotent = "with-key";
      else if (method === "post" && SAFE_POST.has(id)) idempotent = "always";
      else idempotent = "never";

      ops.push({
        id,
        method: method.toUpperCase(),
        path,
        tag: (op.tags ?? [])[0] ?? "",
        summary: op.summary ?? "",
        pathParams,
        queryParams,
        idempotencyHeader,
        body,
        response,
        successStatus: Number(okStatus),
        sse,
        idempotent,
      });
    }
  }

  const server = spec.servers?.[0];
  let baseUrl = server?.url ?? "";
  for (const [k, v] of Object.entries(server?.variables ?? {}))
    baseUrl = baseUrl.replace(`{${k}}`, v.default);

  return { spec, types, ops, inputHash, baseUrl, version: spec.info.version };
}

// ---------------------------------------------------------------------------------------------- TS rendering
const tsProp = (n) => (isIdent(n) ? n : JSON.stringify(n));
/** Optional members also accept an explicit undefined (the SDK is compiled with exactOptionalPropertyTypes). */
const tsField = (name, required, type) =>
  required ? `${tsProp(name)}: ${type}` : `${tsProp(name)}?: ${type} | undefined`;
function tsType(ir) {
  switch (ir.k) {
    case "ref":
      return ir.name;
    case "prim":
      return ir.t;
    case "enum":
      return ir.values.map((v) => JSON.stringify(v)).join(" | ");
    case "array":
      return `Array<${tsType(ir.item)}>`;
    case "record":
      return "Record<string, unknown>";
    case "union":
      return ir.items.map(tsType).join(" | ");
    case "object":
      return `{ ${ir.props.map((p) => tsField(p.name, p.required, tsType(p.type))).join("; ")} }`;
    default:
      throw new Error(`tsType ${ir.k}`);
  }
}
const lit = (v) => JSON.stringify(v);

function header(m, comment) {
  return `${comment} @generated by scripts/generate-sdks.mjs from ${SPEC_PATH} (input sha256 ${m.inputHash.slice(0, 16)}). DO NOT EDIT.\n${comment} Regenerate with: node scripts/generate-sdks.mjs\n`;
}

function tsTypes(m) {
  let out = header(m, "//") + "\n";
  for (const { name, ir } of m.types) {
    if (ir.k === "object") {
      out += `export interface ${name} {\n${ir.props
        .map((p) => `  ${tsField(p.name, p.required, tsType(p.type))};`)
        .join("\n")}\n}\n\n`;
    } else out += `export type ${name} = ${tsType(ir)};\n\n`;
  }
  // per-operation parameter bags
  for (const op of m.ops) {
    const fields = tsParamFields(op);
    if (fields.length)
      out += `export interface ${pascal(op.id)}Params {\n${fields.join("\n")}\n}\n\n`;
  }
  return out;
}

function tsParamFields(op) {
  const f = [];
  for (const p of op.pathParams) f.push(`  ${tsProp(p.name)}: ${tsType(p.ir)};`);
  for (const p of op.queryParams) f.push(`  ${tsField(p.name, p.required, tsType(p.ir))};`);
  if (op.body) f.push(`  ${tsField("body", op.body.required, tsType(op.body.ir))};`);
  if (op.idempotencyHeader)
    f.push(
      "  /** Reused across retries; generated automatically when omitted. */\n  idempotencyKey?: string | undefined;",
    );
  return f;
}

function tsOperations(m) {
  let out = header(m, "//") + "\n";
  out += `export type IdempotencyMode = "always" | "with-key" | "never";

export interface OperationSpec {
  readonly id: string;
  readonly method: "GET" | "PUT" | "POST" | "DELETE" | "PATCH";
  readonly path: string;
  readonly tag: string;
  readonly summary: string;
  readonly pathParams: readonly string[];
  readonly queryParams: readonly string[];
  readonly hasBody: boolean;
  readonly bodyRequired: boolean;
  /** The operation accepts an Idempotency-Key header. */
  readonly idempotencyKey: boolean;
  /** always: safe to retry; with-key: retry only with an Idempotency-Key; never: never retried. */
  readonly idempotent: IdempotencyMode;
  readonly successStatus: number;
  readonly sse: boolean;
}

export const API_VERSION = ${lit(m.version)};
export const DEFAULT_BASE_URL = ${lit(m.baseUrl)};

export const OPERATIONS = {
`;
  for (const op of m.ops) {
    out += `  ${op.id}: {
    id: ${lit(op.id)},
    method: ${lit(op.method)},
    path: ${lit(op.path)},
    tag: ${lit(op.tag)},
    summary: ${lit(op.summary)},
    pathParams: ${lit(op.pathParams.map((p) => p.name))},
    queryParams: ${lit(op.queryParams.map((p) => p.name))},
    hasBody: ${!!op.body},
    bodyRequired: ${!!op.body?.required},
    idempotencyKey: ${op.idempotencyHeader},
    idempotent: ${lit(op.idempotent)},
    successStatus: ${op.successStatus},
    sse: ${op.sse},
  },\n`;
  }
  out += `} as const satisfies Record<string, OperationSpec>;

export type OperationId = keyof typeof OPERATIONS;
export const OPERATION_IDS = Object.keys(OPERATIONS) as OperationId[];
`;
  return out;
}

function tsClient(m) {
  const imports = new Set();
  let body = "";
  for (const op of m.ops) {
    const P = `${pascal(op.id)}Params`;
    const hasParams = tsParamFields(op).length > 0;
    const allOptional =
      !op.pathParams.length && !op.queryParams.some((p) => p.required) && !op.body?.required;
    const ret = op.response ? tsType(op.response) : "void";
    for (const n of [...(ret.match(/[A-Z][A-Za-z0-9]*/g) ?? [])])
      if (m.types.some((t) => t.name === n)) imports.add(n);
    if (hasParams) imports.add(P);
    const sig = hasParams
      ? `params: ${P}${allOptional ? " = {}" : ""}, options?: RequestOptions`
      : "options?: RequestOptions";
    body += `  /** ${op.method} ${op.path} - ${op.summary} */
  ${op.id}(${sig}): Promise<${ret}> {
    return this.transport.call<${ret}>(OPERATIONS.${op.id}, ${hasParams ? "params" : "{}"}, options);
  }\n\n`;
  }
  return (
    header(m, "//") +
    `
import type { RequestOptions, Transport } from "../transport.js";
import { OPERATIONS } from "./operations.js";
import type {
${[...imports]
  .sort()
  .map((n) => `  ${n},`)
  .join("\n")}
} from "./types.js";

/** One method per operationId. The ergonomic layer (../client.ts) is built on top of this. */
export class GeneratedApi {
  constructor(protected readonly transport: Transport) {}

${body.trimEnd()}
}
`
  );
}

// ---------------------------------------------------------------------------------------------- Python rendering
function pyType(ir) {
  switch (ir.k) {
    case "ref":
      return ir.name;
    case "prim":
      return { string: "str", number: "float", boolean: "bool", null: "None", unknown: "Any" }[
        ir.t
      ];
    case "enum":
      return `Literal[${ir.values.map((v) => JSON.stringify(v)).join(", ")}]`;
    case "array":
      return `list[${pyType(ir.item)}]`;
    case "record":
      return "dict[str, Any]";
    case "union":
      return ir.items.map(pyType).join(" | ");
    default:
      throw new Error(`pyType ${ir.k}`);
  }
}
function pyModels(m) {
  let out =
    header(m, "#") +
    `\nfrom __future__ import annotations\n\nfrom typing import Any, Literal, NotRequired, TypedDict\n\n`;
  for (const { name, ir } of m.types) {
    if (ir.k === "object") {
      const field = (p) => {
        const t = pyType(p.type);
        return p.required ? t : `NotRequired[${t}]`;
      };
      if (ir.props.every((p) => isIdent(p.name) && !PY_KEYWORDS.has(p.name))) {
        out += `\nclass ${name}(TypedDict):\n${ir.props.length ? ir.props.map((p) => `    ${p.name}: ${field(p)}`).join("\n") : "    pass"}\n\n`;
      } else {
        out += `\n${name} = TypedDict(\n    ${JSON.stringify(name)},\n    {${ir.props.map((p) => `${JSON.stringify(p.name)}: ${JSON.stringify(field(p))}`).join(", ")}},\n)\n\n`;
      }
    } else out += `\ntype ${name} = ${pyType(ir)}\n\n`;
  }
  return out.replace(/\n{3,}/g, "\n\n\n").trimEnd() + "\n";
}

function pyOperations(m) {
  const b = (v) => (v ? "True" : "False");
  const tup = (a) => (a.length === 0 ? "()" : `(${a.map((x) => JSON.stringify(x)).join(", ")},)`);
  let out =
    header(m, "#") +
    `
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

IdempotencyMode = Literal["always", "with-key", "never"]


@dataclass(frozen=True, slots=True)
class OperationSpec:
    id: str
    method: str
    path: str
    tag: str
    summary: str
    path_params: tuple[str, ...]
    query_params: tuple[str, ...]
    has_body: bool
    body_required: bool
    # The operation accepts an Idempotency-Key header.
    idempotency_key: bool
    # always: safe to retry; with-key: retry only with an Idempotency-Key; never: never retried.
    idempotent: IdempotencyMode
    success_status: int
    sse: bool


API_VERSION = ${JSON.stringify(m.version)}
DEFAULT_BASE_URL = ${JSON.stringify(m.baseUrl)}

OPERATIONS: dict[str, OperationSpec] = {
`;
  for (const op of m.ops) {
    out += `    ${JSON.stringify(op.id)}: OperationSpec(
        id=${JSON.stringify(op.id)},
        method=${JSON.stringify(op.method)},
        path=${JSON.stringify(op.path)},
        tag=${JSON.stringify(op.tag)},
        summary=${JSON.stringify(op.summary)},
        path_params=${tup(op.pathParams.map((p) => p.name))},
        query_params=${tup(op.queryParams.map((p) => p.name))},
        has_body=${b(!!op.body)},
        body_required=${b(!!op.body?.required)},
        idempotency_key=${b(op.idempotencyHeader)},
        idempotent=${JSON.stringify(op.idempotent)},
        success_status=${op.successStatus},
        sse=${b(op.sse)},
    ),\n`;
  }
  return out + "}\n";
}

function pyClient(m) {
  const modelNames = new Set(m.types.map((t) => t.name));
  const used = new Set();
  const methods = (isAsync) => {
    let out = "";
    for (const op of m.ops) {
      const args = [];
      for (const p of op.pathParams) args.push(`${p.py}: ${pyType(p.ir)}`);
      if (op.body)
        args.push(
          op.body.required
            ? `body: ${pyType(op.body.ir)}`
            : `body: ${pyType(op.body.ir)} | None = None`,
        );
      for (const p of op.queryParams)
        args.push(
          p.required ? `${p.py}: ${pyType(p.ir)}` : `${p.py}: ${pyType(p.ir)} | None = None`,
        );
      if (op.idempotencyHeader) args.push("idempotency_key: str | None = None");
      args.push("options: RequestOptions | None = None");
      const ret = op.response ? pyType(op.response) : "None";
      for (const n of ret.match(/[A-Z][A-Za-z0-9]*/g) ?? []) if (modelNames.has(n)) used.add(n);
      for (const a of [...op.pathParams, ...op.queryParams, ...(op.body ? [op.body] : [])])
        for (const n of pyType(a.ir).match(/[A-Z][A-Za-z0-9]*/g) ?? [])
          if (modelNames.has(n)) used.add(n);
      const pathDict = `{${op.pathParams.map((p) => `${JSON.stringify(p.name)}: ${p.py}`).join(", ")}}`;
      const queryDict = `{${op.queryParams.map((p) => `${JSON.stringify(p.name)}: ${p.py}`).join(", ")}}`;
      const call = `self._t.call(
            OPERATIONS[${JSON.stringify(op.id)}],
            path=${pathDict},
            query=${queryDict},
            body=${op.body ? "body" : "None"},
            idempotency_key=${op.idempotencyHeader ? "idempotency_key" : "None"},
            options=options,
        )`;
      const aw = isAsync ? "await " : "";
      out += `    ${isAsync ? "async " : ""}def ${snake(op.id)}(
        self,
        *,
        ${args.join(",\n        ")},
    ) -> ${ret}:
        """${op.method} ${op.path}: ${op.summary}"""
        ${op.response ? `return cast("${ret}", ${aw}${call})` : `${aw}${call}`}

`;
    }
    return out.trimEnd() + "\n";
  };
  const sync = methods(false);
  const asyn = methods(true);
  return (
    header(m, "#") +
    `
from __future__ import annotations

from typing import cast

from ..transport_types import AsyncTransport, RequestOptions, SyncTransport
from .models import (
${[...used]
  .sort()
  .map((n) => `    ${n},`)
  .join("\n")}
)
from .operations import OPERATIONS

__all__ = ["AsyncGeneratedApi", "GeneratedApi"]


class GeneratedApi:
    """One method per operationId (synchronous)."""

    def __init__(self, transport: SyncTransport) -> None:
        self._t = transport

${sync}

class AsyncGeneratedApi:
    """One method per operationId (asynchronous)."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._t = transport

${asyn}`
  );
}

// ---------------------------------------------------------------------------------------------- mock model
/** Fully dereferenced view of every operation: what the in-test mock servers are generated from. */
function mockModel(m) {
  const { spec } = m;
  const seen = [];
  const deref = (node) => {
    if (Array.isArray(node)) return node.map(deref);
    if (node && typeof node === "object") {
      if (node.$ref) {
        const ref = node.$ref;
        if (!ref.startsWith("#/")) {
          const file = ref.split("/").pop();
          return { type: "object", "x-external": file };
        }
        if (seen.includes(ref)) throw new Error(`generator: cyclic ref ${ref}`);
        seen.push(ref);
        const target = ref
          .slice(2)
          .split("/")
          .reduce((n, s) => n[s], spec);
        const { $ref: _r, ...siblings } = node;
        const out = { ...deref(target), ...deref(siblings) };
        seen.pop();
        return out;
      }
      return Object.fromEntries(Object.entries(node).map(([k, v]) => [k, deref(v)]));
    }
    return node;
  };
  const operations = [];
  for (const [path, item] of Object.entries(spec.paths)) {
    for (const method of ["get", "put", "post", "delete", "patch"]) {
      const op = item[method];
      if (!op) continue;
      operations.push({
        operationId: op.operationId,
        method: method.toUpperCase(),
        path,
        idempotent: m.ops.find((o) => o.id === op.operationId).idempotent,
        parameters: (op.parameters ?? []).map(deref),
        requestBody: op.requestBody ? deref(op.requestBody) : null,
        responses: deref(op.responses),
      });
    }
  }
  return {
    openapi: spec.openapi,
    version: spec.info.version,
    inputHash: m.inputHash,
    security: spec.security,
    securitySchemes: deref(spec.components.securitySchemes),
    operations,
  };
}

// ---------------------------------------------------------------------------------------------- entry
export function generate() {
  const m = buildModel();
  const files = new Map();
  files.set("packages/sdk-ts/src/generated/types.ts", tsTypes(m));
  files.set("packages/sdk-ts/src/generated/operations.ts", tsOperations(m));
  files.set("packages/sdk-ts/src/generated/client.ts", tsClient(m));
  files.set("sdk/python/src/axis_sdk/_generated/__init__.py", header(m, "#") + "\n");
  files.set("sdk/python/src/axis_sdk/_generated/models.py", pyModels(m));
  files.set("sdk/python/src/axis_sdk/_generated/operations.py", pyOperations(m));
  files.set("sdk/python/src/axis_sdk/_generated/client.py", pyClient(m));
  const model = JSON.stringify(mockModel(m), null, 2) + "\n";
  files.set("packages/sdk-ts/test/fixtures/mock-model.json", model);
  files.set("sdk/python/tests/fixtures/mock-model.json", model);
  return files;
}

/** Paths whose on-disk content differs from a fresh generation. */
export function drift() {
  const bad = [];
  for (const [p, content] of generate()) {
    const abs = join(ROOT, p);
    if (!existsSync(abs) || readFileSync(abs, "utf8") !== content) bad.push(p);
  }
  return bad;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--check")) {
    const bad = drift();
    if (bad.length) {
      console.error(
        `generated SDK files are stale (run: node scripts/generate-sdks.mjs):\n  ${bad.join("\n  ")}`,
      );
      process.exit(1);
    }
    console.log("generated SDK files are up to date");
  } else {
    for (const [p, content] of generate()) {
      const abs = join(ROOT, p);
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, content);
    }
    console.log("generated SDK files written");
  }
}
