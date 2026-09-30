import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  PROTO_ROOT,
  createGateServer,
  fromValue,
  listen,
  staticTokenAuthenticator,
  type GateServerDeps,
  type Principal,
} from "../src/index.js";
import { PID, T1, T2, harness, type Harness } from "./helpers.js";

const tokens: Record<string, Principal> = {
  "t1-token": { tenantId: T1, subject: "svc-runtime-1", platformOperator: false },
  "t2-token": { tenantId: T2, subject: "svc-runtime-2", platformOperator: false },
  "ops-token": { tenantId: null, subject: "platform-oncall", platformOperator: true },
};

type Client = grpc.Client &
  Record<
    string,
    (
      req: unknown,
      md: grpc.Metadata,
      cb: (e: grpc.ServiceError | null, r: Record<string, unknown>) => void,
    ) => void
  >;

function toValue(v: unknown): unknown {
  if (v === null) return { kind: "nullValue", nullValue: 0 };
  if (typeof v === "number") return { kind: "numberValue", numberValue: v };
  if (typeof v === "string") return { kind: "stringValue", stringValue: v };
  if (typeof v === "boolean") return { kind: "boolValue", boolValue: v };
  if (Array.isArray(v)) return { kind: "listValue", listValue: { values: v.map(toValue) } };
  return { kind: "structValue", structValue: toStruct(v as Record<string, unknown>) };
}
const toStruct = (o: Record<string, unknown>) => ({
  fields: Object.fromEntries(Object.entries(o).map(([k, v]) => [k, toValue(v)])),
});

let h: Harness;
let server: grpc.Server;
let client: Client;
let auditDown = false;
let setThrows = false;

beforeAll(async () => {
  h = await harness();
  const realAppend = h.audit.append.bind(h.audit);
  const audit: GateServerDeps["audit"] = {
    append: (e) => (auditDown ? Promise.reject(new Error("down")) : realAppend(e)),
  };
  const realSet = h.kill.set.bind(h.kill);
  const killSwitches: GateServerDeps["killSwitches"] = {
    isEngaged: (s, t) => h.kill.isEngaged(s, t),
    set: (s, t, e) => (setThrows ? Promise.reject(new Error("redis down")) : realSet(s, t, e)),
  };
  server = createGateServer({
    kernel: h.kernel,
    audit,
    killSwitches,
    authenticate: staticTokenAuthenticator(tokens),
  });
  const port = await listen(server, "127.0.0.1:0");
  const def = protoLoader.loadSync("axis/runtime/v1/gate.proto", {
    includeDirs: [PROTO_ROOT],
    keepCase: true,
    longs: String,
    enums: String,
    defaults: false,
    oneofs: true,
  });
  const pkg = grpc.loadPackageDefinition(def) as unknown as {
    axis: {
      runtime: { v1: { GateService: new (a: string, c: grpc.ChannelCredentials) => Client } };
    };
  };
  client = new pkg.axis.runtime.v1.GateService(
    `127.0.0.1:${port}`,
    grpc.credentials.createInsecure(),
  );
});
afterAll(() => {
  client.close();
  server.forceShutdown();
});

const call = (method: string, req: unknown, token?: string) =>
  new Promise<{ err: grpc.ServiceError | null; res: Record<string, unknown> }>((resolve) => {
    const md = new grpc.Metadata();
    if (token) md.set("authorization", `Bearer ${token}`);
    (client[method] as Client[string]).call(client, req, md, (err, res) => resolve({ err, res }));
  });

const evalReq = (
  over: Record<string, unknown> = {},
  context: Record<string, unknown> = { tool: { name: "lookup", side_effects: "read" }, args: {} },
) => ({
  tenant_id: T1,
  trace: { trace_id: "a".repeat(32), span_id: "b".repeat(16) },
  actor: { type: "TYPE_AGENT", id: "claims-triage", pid: PID },
  blueprint: { name: "claims-triage", version: "1.0.0" },
  enforcement_point: "ENFORCEMENT_POINT_TOOL_CALL",
  action: "lookup",
  context: toStruct(context),
  ...over,
});

describe("Evaluate", () => {
  it("round-trips an allowed request over a real socket", async () => {
    const { err, res } = await call("Evaluate", evalReq(), "t1-token");
    expect(err).toBeNull();
    expect(res).toMatchObject({
      decision: "DECISION_ALLOW",
      policy_version: "baseline-deny@1.0.0,phi-redaction@1.1.0",
    });
    expect(res["audit_event_id"]).toMatch(/^[0-9a-f-]{36}$/);
    expect(res["matched_rule_ids"]).toEqual(["baseline-deny/allow-read-tools"]);
  });

  it("converts every Struct value kind (numbers, floats, nested, lists, null, bools)", async () => {
    const ctx = {
      tool: { name: "payments", side_effects: "external" },
      args: { amount: 5000.5, list: [1, "a", null, true], nested: { ok: true } },
    };
    const { res } = await call("Evaluate", evalReq({ action: "payments" }, ctx), "t1-token");
    expect(res["decision"]).toBe("DECISION_REQUIRE_APPROVAL");
    expect(fromValue(undefined)).toBeNull();
    expect(fromValue({ kind: "nullValue" })).toBeNull();
    expect(fromValue({ kind: "listValue" })).toEqual([]);
    expect(fromValue({ kind: "structValue" })).toEqual({});
  });

  it("returns DECISION_ALLOW_WITH_REDACTION fields", async () => {
    const { res } = await call(
      "Evaluate",
      evalReq({ enforcement_point: "ENFORCEMENT_POINT_MODEL_CALL" }, { data: { phi: true } }),
      "t1-token",
    );
    expect(res).toMatchObject({
      decision: "DECISION_ALLOW_WITH_REDACTION",
      redact_fields: ["phi.mrn", "phi.ssn", "pii.email"],
    });
  });

  it("missing or unknown credentials are UNAUTHENTICATED", async () => {
    expect((await call("Evaluate", evalReq())).err?.code).toBe(grpc.status.UNAUTHENTICATED);
    expect((await call("Evaluate", evalReq(), "nope")).err?.code).toBe(grpc.status.UNAUTHENTICATED);
    expect((await call("Evaluate", evalReq(), "__proto__")).err?.code).toBe(
      grpc.status.UNAUTHENTICATED,
    );
  });

  it("a tenant cannot evaluate on behalf of another tenant: DENY, not audited in the victim's chain", async () => {
    const before = h.audit.events.get(T2)?.length ?? 0;
    const { res } = await call("Evaluate", evalReq({ tenant_id: T2 }), "t1-token");
    expect(res).toMatchObject({
      decision: "DECISION_DENY",
      reason: "tenant does not match credential",
      audit_event_id: "",
    });
    expect(h.audit.events.get(T2)?.length ?? 0).toBe(before);
  });

  it("platform operator credentials (no tenant) cannot evaluate tenant requests", async () => {
    const { res } = await call("Evaluate", evalReq(), "ops-token");
    expect(res["decision"]).toBe("DECISION_DENY");
  });

  it.each([
    ["unspecified enforcement point", { enforcement_point: "ENFORCEMENT_POINT_UNSPECIFIED" }],
    ["missing enforcement point", { enforcement_point: undefined }],
    ["unspecified actor type", { actor: { type: "TYPE_UNSPECIFIED", id: "x" } }],
    ["bad trace", { trace: { trace_id: "zz" } }],
    ["empty action", { action: "" }],
  ])("%s is DENY", async (_n, over) => {
    const { res } = await call("Evaluate", evalReq(over), "t1-token");
    expect(res["decision"]).toBe("DECISION_DENY");
    expect(res["audit_event_id"]).toBe("");
  });

  it("an authenticator that throws means UNAUTHENTICATED", async () => {
    const s = createGateServer({
      kernel: h.kernel,
      audit: h.audit,
      killSwitches: h.kill,
      authenticate: () => Promise.reject(new Error("idp down")),
    });
    const port = await listen(s, "127.0.0.1:0");
    const def = protoLoader.loadSync("axis/runtime/v1/gate.proto", {
      includeDirs: [PROTO_ROOT],
      keepCase: true,
      enums: String,
      defaults: false,
      oneofs: true,
    });
    const pkg = grpc.loadPackageDefinition(def) as unknown as {
      axis: {
        runtime: { v1: { GateService: new (a: string, c: grpc.ChannelCredentials) => Client } };
      };
    };
    const c = new pkg.axis.runtime.v1.GateService(
      `127.0.0.1:${port}`,
      grpc.credentials.createInsecure(),
    );
    const err = await new Promise<grpc.ServiceError | null>((resolve) =>
      c["Evaluate"]?.call(c, evalReq(), new grpc.Metadata(), (e) => resolve(e)),
    );
    expect(err?.code).toBe(grpc.status.UNAUTHENTICATED);
    c.close();
    s.forceShutdown();
  });
});

describe("SetKillSwitch", () => {
  const ks = (over: Record<string, unknown>) => ({
    tenant_id: T1,
    scope: "SCOPE_TENANT",
    engaged: true,
    reason: "incident 42",
    ...over,
  });

  it("engage denies subsequent evaluations immediately (audited); release restores them", async () => {
    const t0 = performance.now();
    const on = await call("SetKillSwitch", ks({}), "t1-token");
    expect(on.res).toMatchObject({ engaged: true });
    expect(on.res["audit_event_id"]).not.toBe("");
    expect((await call("Evaluate", evalReq(), "t1-token")).res).toMatchObject({
      decision: "DECISION_DENY",
      reason: "kill-switch engaged (tenant)",
    });
    expect(performance.now() - t0).toBeLessThan(1000);
    const off = await call("SetKillSwitch", ks({ engaged: false }), "t1-token");
    expect(off.res["engaged"]).toBe(false);
    expect((await call("Evaluate", evalReq(), "t1-token")).res["decision"]).toBe("DECISION_ALLOW");
    const adminEvents = (h.audit.events.get(T1) ?? []).filter(
      (e) => e.enforcement_point === "admin",
    );
    expect(adminEvents.map((e) => e.action)).toEqual([
      "kill_switch:tenant:engage",
      "kill_switch:tenant:release",
    ]);
    expect(adminEvents[0]).toMatchObject({
      actor: { type: "human", id: "svc-runtime-1" },
      reason: "incident 42",
    });
  });

  it("agent and tool scopes need a target", async () => {
    expect((await call("SetKillSwitch", ks({ scope: "SCOPE_AGENT" }), "t1-token")).err?.code).toBe(
      grpc.status.INVALID_ARGUMENT,
    );
    const ok = await call(
      "SetKillSwitch",
      ks({ scope: "SCOPE_TOOL", target: "lookup" }),
      "t1-token",
    );
    expect(ok.err).toBeNull();
    expect((await call("Evaluate", evalReq(), "t1-token")).res["reason"]).toBe(
      "kill-switch engaged (tool)",
    );
    await call(
      "SetKillSwitch",
      ks({ scope: "SCOPE_TOOL", target: "lookup", engaged: false }),
      "t1-token",
    );
  });

  it("rejects unknown scope, cross-tenant, and global from a non-operator", async () => {
    expect(
      (await call("SetKillSwitch", ks({ scope: "SCOPE_UNSPECIFIED" }), "t1-token")).err?.code,
    ).toBe(grpc.status.INVALID_ARGUMENT);
    expect((await call("SetKillSwitch", ks({ tenant_id: T2 }), "t1-token")).err?.code).toBe(
      grpc.status.PERMISSION_DENIED,
    );
    expect(
      (await call("SetKillSwitch", ks({ scope: "SCOPE_GLOBAL", tenant_id: "" }), "t1-token")).err
        ?.code,
    ).toBe(grpc.status.PERMISSION_DENIED);
    expect((await call("SetKillSwitch", ks({}))).err?.code).toBe(grpc.status.UNAUTHENTICATED);
    expect((await call("Evaluate", evalReq(), "t1-token")).res["decision"]).toBe("DECISION_ALLOW");
  });

  it("a platform operator can engage and release the global switch (no tenant chain to audit)", async () => {
    const on = await call("SetKillSwitch", { scope: "SCOPE_GLOBAL", engaged: true }, "ops-token");
    expect(on.err).toBeNull();
    expect(on.res["audit_event_id"]).toBe("");
    expect((await call("Evaluate", evalReq({ tenant_id: T2 }), "t2-token")).res["decision"]).toBe(
      "DECISION_DENY",
    );
    const off = await call("SetKillSwitch", { scope: "SCOPE_GLOBAL", engaged: false }, "ops-token");
    expect(off.err).toBeNull();
    expect((await call("Evaluate", evalReq({ tenant_id: T2 }), "t2-token")).res["decision"]).toBe(
      "DECISION_ALLOW",
    );
  });

  it("engaging still applies when audit is down; releasing is refused when audit is down", async () => {
    auditDown = true;
    try {
      const on = await call("SetKillSwitch", ks({}), "t1-token");
      expect(on.err).toBeNull();
      expect(on.res["audit_event_id"]).toBe("");
      const off = await call("SetKillSwitch", ks({ engaged: false }), "t1-token");
      expect(off.err?.code).toBe(grpc.status.INTERNAL);
      auditDown = false;
      // still engaged: the failed release changed nothing
      expect(await h.kill.isEngaged("tenant", { tenantId: T1, agent: "claims-triage" })).toBe(true);
    } finally {
      auditDown = false;
    }
    expect((await call("SetKillSwitch", ks({ engaged: false }), "t1-token")).err).toBeNull();
  });

  it("store failure is INTERNAL, not success", async () => {
    setThrows = true;
    try {
      expect((await call("SetKillSwitch", ks({}), "t1-token")).err?.code).toBe(
        grpc.status.INTERNAL,
      );
    } finally {
      setThrows = false;
    }
  });
});
