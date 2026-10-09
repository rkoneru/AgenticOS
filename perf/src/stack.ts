/** Client side of the real stack (e2e/interfaces_stack.py): provisioning through the harness ops and a minimal HTTP/gRPC toolkit. */
import { execFileSync } from "node:child_process";
import { readFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { parse } from "yaml";

export const ROOT = fileURLToPath(new URL("../../", import.meta.url));

export interface StackInfo {
  gateway: string;
  gateway_origin: string;
  cp: string;
  ops_url: string;
  ops_token: string;
  run_service: string;
  kernel_target: string;
  db_url: string;
  byo_key: string;
}

export function readStack(path: string): StackInfo {
  return JSON.parse(readFileSync(path, "utf8")) as StackInfo;
}

export async function ops<T = Record<string, unknown>>(
  info: StackInfo,
  op: string,
  body: Record<string, unknown>,
): Promise<T> {
  const r = await fetch(`${info.ops_url}/ops/${op}`, {
    method: "POST",
    headers: { authorization: `Bearer ${info.ops_token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`ops ${op}: ${r.status} ${await r.text()}`);
  return (await r.json()) as T;
}

export const yamlFile = (rel: string): Record<string, unknown> =>
  parse(readFileSync(join(ROOT, rel), "utf8")) as Record<string, unknown>;

export interface Tenant {
  tenantId: string;
  slug: string;
  kernelToken: string;
  apiKey: string;
  ownerSession: string;
}

/** A tenant with the Phase 7 policy pack ACTIVE, a BYO model key and an owner API key; the claims blueprint is published. */
export async function setupTenant(info: StackInfo, slug: string): Promise<Tenant> {
  const t = await ops<{
    tenant_id: string;
    kernel_token: string;
    owner_member_id: string;
    owner_session: string;
  }>(info, "provision-tenant", {
    slug,
    byo_key: info.byo_key,
    pack: yamlFile("e2e/policies/phase7-interfaces/pack.yaml"),
  });
  const k = await ops<{ secret: string }>(info, "api-key", {
    tenant_id: t.tenant_id,
    member_id: t.owner_member_id,
  });
  const tenant: Tenant = {
    tenantId: t.tenant_id,
    slug,
    kernelToken: t.kernel_token,
    apiKey: k.secret,
    ownerSession: t.owner_session,
  };
  const r = await http(info, tenant, "POST", "/blueprints", {
    abl: yamlFile("e2e/agents/claims7.abl.yaml"),
  });
  if (r.status !== 201 && r.status !== 200)
    throw new Error(`blueprint publish: ${r.status} ${r.text}`);
  return tenant;
}

export interface HttpResult {
  status: number;
  text: string;
  json: () => unknown;
}

export async function http(
  info: StackInfo,
  t: Pick<Tenant, "apiKey">,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
): Promise<HttpResult> {
  const r = await fetch(`${info.gateway}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${t.apiKey}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...headers,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await r.text();
  return { status: r.status, text, json: () => JSON.parse(text) as unknown };
}

/** Signed registry publish through the `axis` CLI (as the publisher would), so `registry resolve` has real, verified content. */
export async function seedRegistry(info: StackInfo, t: Tenant, ns: string): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "axis-perf-"));
  const cli = (...argv: string[]): string =>
    execFileSync("node", [join(ROOT, "apps/cli/dist/bin.js"), "--json", ...argv], {
      env: {
        ...process.env,
        AXIS_API_KEY: t.apiKey,
        AXIS_BASE_URL: info.gateway,
        XDG_CONFIG_HOME: join(dir, "cfg"),
        NO_COLOR: "1",
      },
      encoding: "utf8",
    });
  const pem = join(dir, "publisher.pem");
  const kg = JSON.parse(cli("registry", "keygen", "--out", pem)) as { public_key: string };
  cli("registry", "claim", ns);
  cli("registry", "add-key", ns, `--public-key=${kg.public_key}`);
  await new Promise((r) => setTimeout(r, 1200)); // a signature is only trusted from the moment its key became valid
  const abl = join(dir, "helper.json");
  writeFileSync(abl, JSON.stringify(yamlFile("e2e/agents/helper7.abl.yaml")));
  const signed = JSON.parse(
    execFileSync(
      "node",
      [
        join(ROOT, "apps/cli/dist/bin.js"),
        "registry",
        "sign",
        abl,
        "--namespace",
        ns,
        "--key",
        pem,
      ],
      {
        env: { ...process.env, XDG_CONFIG_HOME: join(dir, "cfg"), NO_COLOR: "1" },
        encoding: "utf8",
      },
    ),
  ) as Record<string, unknown>;
  const bundle = join(dir, "bundle.json");
  writeFileSync(bundle, JSON.stringify({ namespace: ns, ...signed }));
  cli("registry", "publish", bundle);
  return `${ns}/helper-agent@^1`;
}

// ---- gRPC gate client ---------------------------------------------------------------------------------------------------

type GateClient = grpc.Client & {
  Evaluate: (
    req: Record<string, unknown>,
    md: grpc.Metadata,
    opts: grpc.CallOptions,
    cb: (
      err: grpc.ServiceError | null,
      res: { decision: string; audit_event_id: string; reason: string },
    ) => void,
  ) => void;
};

export function gateClient(target: string): GateClient {
  const def = protoLoader.loadSync("axis/runtime/v1/gate.proto", {
    includeDirs: [join(ROOT, "proto")],
    keepCase: true,
    longs: String,
    enums: String,
    defaults: false,
    oneofs: true,
  });
  const pkg = grpc.loadPackageDefinition(def) as unknown as {
    axis: {
      runtime: { v1: { GateService: new (t: string, c: grpc.ChannelCredentials) => GateClient } };
    };
  };
  return new pkg.axis.runtime.v1.GateService(target, grpc.credentials.createInsecure());
}

/** Plain JSON -> google.protobuf.Value in the shape @grpc/proto-loader expects (it does not convert JS objects for us). */
export function pbValue(v: unknown): Record<string, unknown> {
  if (v === null || v === undefined) return { nullValue: 0 };
  if (typeof v === "number") return { numberValue: v };
  if (typeof v === "string") return { stringValue: v };
  if (typeof v === "boolean") return { boolValue: v };
  if (Array.isArray(v)) return { listValue: { values: v.map(pbValue) } };
  return { structValue: pbStruct(v as Record<string, unknown>) };
}
export function pbStruct(o: Record<string, unknown>): { fields: Record<string, unknown> } {
  return { fields: Object.fromEntries(Object.entries(o).map(([k, x]) => [k, pbValue(x)])) };
}

export function gateRequest(
  tenantId: string,
  tool = "lookup-claim",
  traceId?: string,
  agent = "load-agent",
): Record<string, unknown> {
  const hex = (n: number): string =>
    Array.from({ length: n }, () => Math.floor(Math.random() * 16).toString(16)).join("");
  return {
    tenant_id: tenantId,
    trace: { trace_id: traceId ?? hex(32), span_id: hex(16) },
    actor: { type: "TYPE_AGENT", id: agent, pid: "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV" },
    blueprint: { name: agent === "load-agent" ? "claims-agent" : agent, version: "1.0.0" },
    enforcement_point: "ENFORCEMENT_POINT_TOOL_CALL",
    action: tool,
    context: pbStruct({
      tool: { name: tool, kind: "function", side_effects: "read" },
      args: { claim_id: "c-1" },
    }),
  };
}

export function evaluate(
  c: GateClient,
  token: string,
  req: Record<string, unknown>,
  deadlineMs = 5000,
): Promise<{ decision: string; audit_event_id: string; reason: string }> {
  const md = new grpc.Metadata();
  md.set("authorization", `Bearer ${token}`);
  return new Promise((resolve, reject) =>
    c.Evaluate(req, md, { deadline: Date.now() + deadlineMs }, (err, res) =>
      err ? reject(err) : resolve(res),
    ),
  );
}
