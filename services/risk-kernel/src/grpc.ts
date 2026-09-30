import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { hashJson, type AuditSink, type UnsealedEvent } from "@axis/contracts";
import type { RiskKernel } from "./kernel.js";
import type { KillScope, KillSwitchStore } from "./stores.js";
import type { GateRequest, GateResponse } from "./types.js";

export const PROTO_ROOT = fileURLToPath(new URL("../../../proto/", import.meta.url));

export interface Principal {
  /** Tenant the credential belongs to; null for platform operators. */
  tenantId: string | null;
  subject: string;
  platformOperator: boolean;
}

/** Derives the caller from credentials. The request's `tenant_id` is never trusted on its own. */
export type Authenticator = (md: grpc.Metadata) => Promise<Principal | undefined>;

/** Bearer-token authenticator backed by a static table. Dev/test only: production uses mTLS + short-lived tokens (Phase 6). */
export function staticTokenAuthenticator(tokens: Record<string, Principal>): Authenticator {
  return (md) => {
    const h = md.get("authorization")[0];
    const token = typeof h === "string" && h.startsWith("Bearer ") ? h.slice(7) : undefined;
    return Promise.resolve(
      token !== undefined && Object.prototype.hasOwnProperty.call(tokens, token)
        ? tokens[token]
        : undefined,
    );
  };
}

const EP: Record<string, GateRequest["enforcement_point"]> = {
  ENFORCEMENT_POINT_TOOL_CALL: "tool_call",
  ENFORCEMENT_POINT_MCP_CALL: "mcp_call",
  ENFORCEMENT_POINT_MODEL_CALL: "model_call",
  ENFORCEMENT_POINT_MEMORY_WRITE: "memory_write",
  ENFORCEMENT_POINT_MESSAGE_SEND: "message_send",
  ENFORCEMENT_POINT_CODE_EXEC: "code_exec",
  ENFORCEMENT_POINT_BROWSER_EXEC: "browser_exec",
};
const ACTOR: Record<string, GateRequest["actor"]["type"]> = {
  TYPE_HUMAN: "human",
  TYPE_AGENT: "agent",
  TYPE_SYSTEM: "system",
};
const DECISION_ENUM: Record<GateResponse["decision"], string> = {
  ALLOW: "DECISION_ALLOW",
  DENY: "DECISION_DENY",
  REQUIRE_APPROVAL: "DECISION_REQUIRE_APPROVAL",
  ALLOW_WITH_REDACTION: "DECISION_ALLOW_WITH_REDACTION",
};
const SCOPE: Record<string, KillScope> = {
  SCOPE_GLOBAL: "global",
  SCOPE_TENANT: "tenant",
  SCOPE_AGENT: "agent",
  SCOPE_TOOL: "tool",
};

type PbValue = {
  kind?: string;
  nullValue?: unknown;
  numberValue?: number;
  stringValue?: string;
  boolValue?: boolean;
  structValue?: PbStruct;
  listValue?: { values?: PbValue[] };
};
type PbStruct = { fields?: Record<string, PbValue> };

export function fromValue(v: PbValue | undefined): unknown {
  switch (v?.kind) {
    case "numberValue":
      return v.numberValue;
    case "stringValue":
      return v.stringValue;
    case "boolValue":
      return v.boolValue;
    case "structValue":
      return fromStruct(v.structValue);
    case "listValue":
      return (v.listValue?.values ?? []).map(fromValue);
    default:
      return null;
  }
}

export function fromStruct(s: PbStruct | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(s?.fields ?? {})) out[k] = fromValue(v);
  return out;
}

export function toRequest(m: Record<string, unknown>): unknown {
  const a = (m["actor"] ?? {}) as Record<string, unknown>;
  const b = (m["blueprint"] ?? {}) as Record<string, unknown>;
  const t = (m["trace"] ?? {}) as Record<string, unknown>;
  const pid = a["pid"];
  return {
    tenant_id: m["tenant_id"],
    trace_id: t["trace_id"],
    actor: { type: ACTOR[a["type"] as string], id: a["id"], ...(pid ? { pid } : {}) },
    blueprint: { name: b["name"], version: b["version"] },
    enforcement_point: EP[m["enforcement_point"] as string],
    action: m["action"],
    context: fromStruct(m["context"] as PbStruct | undefined),
  };
}

export function toWire(r: GateResponse): Record<string, unknown> {
  return {
    decision: DECISION_ENUM[r.decision],
    policy_version: r.policy_version,
    reason: r.reason,
    matched_rule_ids: r.matched_rule_ids,
    redact_fields: r.redact_fields,
    approval_id: r.approval_id,
    audit_event_id: r.audit_event_id,
  };
}

export interface GateServerDeps {
  kernel: RiskKernel;
  audit: AuditSink;
  killSwitches: KillSwitchStore;
  authenticate: Authenticator;
  clock?: () => number;
}

type Call<Req> = grpc.ServerUnaryCall<Req, unknown>;

function loadService(): grpc.ServiceDefinition {
  const def = protoLoader.loadSync("axis/runtime/v1/gate.proto", {
    includeDirs: [PROTO_ROOT],
    keepCase: true,
    longs: String,
    enums: String,
    defaults: false,
    oneofs: true,
  });
  const pkg = grpc.loadPackageDefinition(def) as unknown as {
    axis: { runtime: { v1: { GateService: { service: grpc.ServiceDefinition } } } };
  };
  return pkg.axis.runtime.v1.GateService.service;
}

/**
 * gRPC GateService. Authentication failures are gRPC errors (UNAUTHENTICATED); a tenant mismatch between the credential and the
 * request is answered with a DENY. Clients must treat transport errors, deadlines and DECISION_UNSPECIFIED as DENY.
 */
export function createGateServer(deps: GateServerDeps): grpc.Server {
  const clock = deps.clock ?? Date.now;
  const server = new grpc.Server();

  server.addService(loadService(), {
    Evaluate: (call: Call<Record<string, unknown>>, cb: grpc.sendUnaryData<unknown>) => {
      void (async () => {
        const principal = await deps.authenticate(call.metadata).catch(() => undefined);
        if (!principal)
          return cb({ code: grpc.status.UNAUTHENTICATED, message: "unauthenticated" });
        const raw = toRequest(call.request) as { tenant_id?: unknown };
        if (principal.tenantId === null || raw.tenant_id !== principal.tenantId) {
          const denied: GateResponse = {
            decision: "DENY",
            policy_version: "",
            reason: "tenant does not match credential",
            matched_rule_ids: [],
            redact_fields: [],
            approval: null,
            approval_id: "",
            audit_event_id: "",
          };
          return cb(null, toWire(denied));
        }
        cb(null, toWire(await deps.kernel.evaluate(raw)));
      })().catch(() => cb({ code: grpc.status.INTERNAL, message: "internal" }));
    },

    SetKillSwitch: (call: Call<Record<string, unknown>>, cb: grpc.sendUnaryData<unknown>) => {
      void (async () => {
        const principal = await deps.authenticate(call.metadata).catch(() => undefined);
        if (!principal)
          return cb({ code: grpc.status.UNAUTHENTICATED, message: "unauthenticated" });
        const m = call.request;
        const scope = SCOPE[m["scope"] as string];
        const engaged = m["engaged"] === true;
        const tenantId = (m["tenant_id"] as string | undefined) || undefined;
        const target = (m["target"] as string | undefined) || undefined;
        if (!scope) return cb({ code: grpc.status.INVALID_ARGUMENT, message: "scope required" });
        if (scope === "global" ? !principal.platformOperator : principal.tenantId !== tenantId) {
          return cb({ code: grpc.status.PERMISSION_DENIED, message: "not permitted" });
        }
        if ((scope === "agent" || scope === "tool") && !target) {
          return cb({ code: grpc.status.INVALID_ARGUMENT, message: "target required" });
        }
        const auditTenant = scope === "global" ? principal.tenantId : tenantId;
        const audit = async (): Promise<string> => {
          if (!auditTenant) return ""; // platform-wide switch by an operator with no tenant: recorded in platform logs, not a tenant chain
          const event: UnsealedEvent = {
            schema_version: 1,
            id: randomUUID(),
            tenant_id: auditTenant,
            ts: new Date(clock()).toISOString(),
            trace_id: randomUUID().replace(/-/g, ""),
            actor: { type: "human", id: principal.subject },
            blueprint: { name: "platform", version: "0" },
            policy_version: "none",
            enforcement_point: "admin",
            action: `kill_switch:${scope}:${engaged ? "engage" : "release"}`,
            decision: "ALLOW",
            ...(m["reason"] ? { reason: String(m["reason"]).slice(0, 1000) } : {}),
            inputs_hash: hashJson({
              scope,
              tenantId: tenantId ?? null,
              target: target ?? null,
              engaged,
            }),
            outputs_hash: hashJson({ engaged }),
          };
          return (await deps.audit.append(event)).id;
        };
        let auditId = "";
        if (engaged) {
          // Engaging must never be blocked by an audit outage: apply first, audit best-effort.
          await deps.killSwitches.set(scope, { tenantId, target }, true);
          auditId = await audit().catch(() => "");
        } else {
          // Releasing is the risky direction: require the audit record first.
          auditId = await audit();
          await deps.killSwitches.set(scope, { tenantId, target }, false);
        }
        cb(null, { engaged, audit_event_id: auditId });
      })().catch(() => cb({ code: grpc.status.INTERNAL, message: "internal" }));
    },
  });
  return server;
}

export function listen(server: grpc.Server, address: string): Promise<number> {
  return new Promise((resolve, reject) => {
    server.bindAsync(address, grpc.ServerCredentials.createInsecure(), (err, port) =>
      err ? reject(err) : resolve(port),
    );
  });
}
