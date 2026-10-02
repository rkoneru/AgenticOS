/**
 * Mock control-plane API for console development and Playwright tests. It implements the frozen
 * /v1 surface (packages/contracts/openapi/axis-v1.yaml) plus the additive endpoints the console uses
 * (see docs/spec/console.md). It is NOT the real control plane: state is in memory and `POST /__reset`
 * restores the seed. It does enforce what the console relies on the server for: cookie session, CSRF
 * double-submit, role checks, self-approval refusal, one-time API-key secrets, write-only model keys.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import * as abl from "@axis/abl";
import { sealEvent, verifyChain, type AuditEvent, type UnsealedEvent } from "@axis/contracts";

type J = Record<string, unknown>;
const TENANT = "11111111-1111-4111-8111-111111111111";
export const SEED_RUN = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const SEED_APPROVAL = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const SELF_APPROVAL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const PID = "axp_0000000000000000000000000A";
const XSS = '<img src=x onerror="window.__xss=1"><script>window.__xss=2</script>';
const ROLE_RANK: Record<string, number> = {
  owner: 100,
  admin: 80,
  builder: 50,
  operator: 50,
  auditor: 40,
  billing: 40,
  viewer: 10,
};

interface RunRec {
  run: J;
  events: J[];
  subs: Set<(e: J) => void>;
}

interface State {
  blueprints: J[];
  runs: Map<string, RunRec>;
  approvals: J[];
  policies: J[];
  audit: AuditEvent[];
  members: J[];
  apiKeys: J[];
  modelKeys: J[];
  budgets: J[];
  sso: J;
  killSwitches: J[];
  listings: J[];
  installed: Map<string, J>;
  idempotency: Map<string, { status: number; body: unknown }>;
  timers: NodeJS.Timeout[];
}

const iso = (offsetMs = 0) => new Date(Date.now() + offsetMs).toISOString();

function ablDoc(name: string, version: string): J {
  return {
    apiVersion: "abl.axis.dev/v1",
    kind: "Agent",
    metadata: { name, version },
    spec: {
      riskClassification: { level: "minimal", rationale: "Answers general questions." },
      model: { primary: { provider: "anthropic", model: "claude-sonnet-5-5" } },
      instructions: { system: "You are a helpful assistant." },
    },
  };
}

function seedAudit(): AuditEvent[] {
  const out: AuditEvent[] = [];
  const mk = (i: number, decision: UnsealedEvent["decision"], action: string, reason?: string) => {
    const e: UnsealedEvent = {
      schema_version: 1,
      id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
      tenant_id: TENANT,
      ts: new Date(Date.parse("2026-01-01T00:00:00.000Z") + i * 1000).toISOString(),
      trace_id: "ab".repeat(16),
      actor: { type: "agent", id: "hello-agent", pid: PID },
      blueprint: { name: "hello-agent", version: "1.0.0" },
      policy_version: "baseline-deny@1",
      enforcement_point: "tool_call",
      action,
      decision,
      ...(reason ? { reason } : {}),
      inputs_hash: "b".repeat(64),
      outputs_hash: "c".repeat(64),
    };
    out.push(sealEvent(e, out[out.length - 1]));
  };
  mk(1, "ALLOW", "kb.search");
  mk(2, "REQUIRE_APPROVAL", "email.send", "external write needs approval");
  mk(3, "DENY", "shell.exec", XSS);
  mk(4, "ALLOW", "kb.search");
  mk(5, "ALLOW_WITH_REDACTION", "memory.write", "phi redacted");
  return out;
}

function seedEvents(): J[] {
  const at = (n: number) => iso(-60_000 + n * 1000);
  return [
    {
      sequence: 1,
      type: "state_transition",
      pid: PID,
      at: at(1),
      data: { from: "spawn", to: "running" },
    },
    {
      sequence: 2,
      type: "model_call",
      pid: PID,
      at: at(2),
      data: { model: "claude-sonnet-5-5", tokens: 1200, cost_usd: 0.012 },
    },
    {
      sequence: 3,
      type: "gate_decision",
      pid: PID,
      at: at(3),
      audit_event_id: "00000000-0000-4000-8000-000000000002",
      data: { decision: "REQUIRE_APPROVAL", reason: "external write needs approval" },
    },
    { sequence: 4, type: "tool_call", pid: PID, at: at(4), data: { tool: XSS } },
    {
      sequence: 5,
      type: "gate_decision",
      pid: PID,
      at: at(5),
      audit_event_id: "00000000-0000-4000-8000-000000000003",
      data: { decision: "DENY", reason: XSS },
    },
    {
      sequence: 6,
      type: "model_call",
      pid: PID,
      at: at(6),
      data: { model: "claude-sonnet-5-5", tokens: 800, cost_usd: 0.008 },
    },
    {
      sequence: 7,
      type: "state_transition",
      pid: PID,
      at: at(7),
      data: { from: "running", to: "terminated" },
    },
  ];
}

function fresh(): State {
  const runs = new Map<string, RunRec>();
  runs.set(SEED_RUN, {
    run: {
      id: SEED_RUN,
      init_pid: PID,
      blueprint: { name: "hello-agent", version: "1.0.0" },
      state: "terminated",
      exit_reason: "completed",
      trace_id: "ab".repeat(16),
      created_at: iso(-61_000),
      finished_at: iso(-53_000),
    },
    events: seedEvents(),
    subs: new Set(),
  });
  return {
    blueprints: [
      {
        name: "hello-agent",
        version: "1.0.0",
        risk_level: "minimal",
        content_hash: "d".repeat(64),
        signature: null,
        created_at: iso(-86_400_000),
        abl: ablDoc("hello-agent", "1.0.0"),
      },
    ],
    runs,
    approvals: [
      {
        id: SEED_APPROVAL,
        status: "pending",
        run_id: SEED_RUN,
        pid: PID,
        action: "email.send",
        roles: ["admin", "builder"],
        requested_at: iso(-300_000),
        sla_deadline: iso(3_600_000),
        requested_by: "m-other",
        args_hash: "e".repeat(64),
        policy_reason: "external write needs approval",
        matched_rule_ids: ["R-ext-write"],
      },
      {
        id: SELF_APPROVAL,
        status: "pending",
        run_id: SEED_RUN,
        pid: PID,
        action: "crm.update",
        roles: ["admin"],
        requested_at: iso(-200_000),
        sla_deadline: iso(600_000),
        requested_by: "m-admin",
        args_hash: "f".repeat(64),
        policy_reason: "write to production CRM",
      },
    ],
    policies: [
      {
        name: "baseline-deny",
        version: "1",
        version_id: "pv-1",
        content_hash: "1".repeat(64),
        created_at: iso(-86_400_000),
        active: true,
        policy: {
          apiVersion: "policy.axis.dev/v1",
          metadata: { name: "baseline-deny" },
          spec: { rules: [{ id: "deny-all", effect: "deny" }] },
        },
      },
      {
        name: "baseline-deny",
        version: "2",
        version_id: "pv-2",
        content_hash: "2".repeat(64),
        created_at: iso(-3_600_000),
        active: false,
        policy: {
          apiVersion: "policy.axis.dev/v1",
          metadata: { name: "baseline-deny" },
          spec: {
            rules: [
              { id: "deny-all", effect: "deny" },
              { id: "allow-read", effect: "allow", when: "tool.side_effects == read" },
            ],
          },
        },
      },
    ],
    audit: seedAudit(),
    members: [
      { id: "m-admin", email: "admin@acme.test", role: "admin", status: "active" },
      { id: "m-other", email: "other@acme.test", role: "builder", status: "active" },
    ],
    apiKeys: [
      {
        id: "k1",
        name: "ci",
        prefix: "axk_0123456789abcdef",
        scopes: ["runs:read"],
        environment: "dev",
        created_at: iso(-86_400_000),
        expires_at: iso(86_400_000 * 80),
        revoked_at: null,
      },
    ],
    modelKeys: [{ provider: "anthropic", label: "default", updated_at: iso(-86_400_000) }],
    budgets: [
      { id: "b1", scope: "run", metric: "tokens", period: "run", soft: 1500, hard: 2000 },
      { id: "b2", scope: "run", metric: "cost_usd", period: "run", soft: 0.05, hard: 0.1 },
    ],
    sso: {
      connection_type: "oidc",
      organization_id: "org_acme",
      jit_enabled: true,
      jit_default_role: "viewer",
    },
    killSwitches: [],
    listings: [
      {
        id: "crm-agent",
        name: "CRM Agent",
        publisher: "Acme Labs",
        version: "2.0.0",
        summary: "Keeps your CRM tidy.",
        permissions: {
          tools: ["crm.read", "crm.update"],
          data_classes: ["pii"],
          egress_hosts: ["api.crm.example"],
          max_risk_level: "limited",
        },
      },
      {
        id: "faq-bot",
        name: "FAQ Bot",
        publisher: "Acme Labs",
        version: "1.1.0",
        summary: "Answers questions from your KB.",
        permissions: {
          tools: ["kb.search"],
          data_classes: [],
          egress_hosts: [],
          max_risk_level: "minimal",
        },
      },
    ],
    installed: new Map(),
    idempotency: new Map(),
    timers: [],
  };
}

let S = fresh();

function problem(
  res: ServerResponse,
  status: number,
  code: string,
  title: string,
  extra: J = {},
): void {
  res.writeHead(status, { "content-type": "application/problem+json" });
  res.end(
    JSON.stringify({
      type: `https://axis.example/problems/${code}`,
      title,
      status,
      code,
      ...extra,
    }),
  );
}
function send(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(body === undefined ? "" : JSON.stringify(body));
}
async function readJson(req: IncomingMessage): Promise<J> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const t = Buffer.concat(chunks).toString("utf8");
  if (!t) return {};
  return JSON.parse(t) as J;
}
function cookies(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const p of (req.headers.cookie ?? "").split(";")) {
    const i = p.indexOf("=");
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  }
  return out;
}

function emit(rec: RunRec, e: J): void {
  rec.events.push(e);
  for (const s of rec.subs) s(e);
}

function scriptRun(id: string): void {
  const rec = S.runs.get(id)!;
  const seqBase = () => rec.events.length + 1;
  const steps: Array<(r: RunRec) => void> = [
    (r) =>
      emit(r, {
        sequence: seqBase(),
        type: "state_transition",
        pid: PID,
        at: iso(),
        data: { from: "spawn", to: "running" },
      }),
    (r) =>
      emit(r, {
        sequence: seqBase(),
        type: "model_call",
        pid: PID,
        at: iso(),
        data: { model: "claude-sonnet-5-5", tokens: 900, cost_usd: 0.009 },
      }),
    (r) =>
      emit(r, {
        sequence: seqBase(),
        type: "gate_decision",
        pid: PID,
        at: iso(),
        audit_event_id: "00000000-0000-4000-8000-000000000001",
        data: { decision: "ALLOW", reason: "read tool" },
      }),
    (r) =>
      emit(r, {
        sequence: seqBase(),
        type: "tool_call",
        pid: PID,
        at: iso(),
        data: { tool: "kb.search" },
      }),
    (r) =>
      emit(r, {
        sequence: seqBase(),
        type: "model_call",
        pid: PID,
        at: iso(),
        data: { model: "claude-sonnet-5-5", tokens: 400, cost_usd: 0.004 },
      }),
    (r) => {
      emit(r, {
        sequence: seqBase(),
        type: "state_transition",
        pid: PID,
        at: iso(),
        data: { from: "running", to: "terminated" },
      });
      r.run["state"] = "terminated";
      r.run["exit_reason"] = "completed";
      r.run["finished_at"] = iso();
      for (const s of r.subs) s({ __end: true });
    },
  ];
  steps.forEach((fn, i) => S.timers.push(setTimeout(() => fn(rec), 250 * (i + 1))));
}

const need = (role: string, min: number) => (ROLE_RANK[role] ?? 0) >= min;

function page<T>(items: T[]): { items: T[]; next_cursor: null } {
  return { items, next_cursor: null };
}

function usageRows(groupBy: string): J[] {
  if (groupBy === "day") {
    const rows: J[] = [];
    for (let d = 13; d >= 0; d--) {
      const day = new Date(Date.now() - d * 86_400_000).toISOString().slice(0, 10);
      rows.push({
        meter: "tokens",
        quantity: 1000 + ((d * 733) % 4000),
        unit: "tokens",
        group: day,
      });
      rows.push({ meter: "tool_executions", quantity: 5 + (d % 7), unit: "calls", group: day });
    }
    return rows;
  }
  return [
    { meter: "tokens", quantity: 52_300, unit: "tokens" },
    { meter: "runtime_seconds", quantity: 3_600, unit: "s" },
    { meter: "tool_executions", quantity: 120, unit: "calls" },
    { meter: "voice_minutes", quantity: 12, unit: "min" },
  ];
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://mock");
  const path = url.pathname;
  const method = req.method ?? "GET";
  const ck = cookies(req);

  if (path === "/__reset" && method === "POST") {
    for (const t of S.timers) clearTimeout(t);
    S = fresh();
    return send(res, 200, { ok: true });
  }
  if (path === "/__tamper" && method === "POST") {
    // Corrupt one stored event without re-sealing (simulates tampering the console must surface).
    S.audit[2] = { ...S.audit[2]!, action: "shell.exec.tampered" };
    return send(res, 200, { ok: true });
  }
  if (path === "/__health") return send(res, 200, { ok: true });

  // --- SSO (fake IdP: start redirects straight to the callback) ---
  if (path === "/auth/sso/start") {
    const role = url.searchParams.get("role") ?? "admin";
    const rt = url.searchParams.get("return_to") ?? "/";
    res.writeHead(302, {
      location: `/auth/sso/callback?code=fake&role=${encodeURIComponent(role)}&return_to=${encodeURIComponent(rt)}`,
    });
    return void res.end();
  }
  if (path === "/auth/sso/callback") {
    const role = ROLE_RANK[url.searchParams.get("role") ?? ""]
      ? url.searchParams.get("role")!
      : "viewer";
    const rt = url.searchParams.get("return_to") ?? "/";
    const safe = rt.startsWith("/") && !rt.startsWith("//") && !rt.startsWith("/\\") ? rt : "/";
    const csrf = randomBytes(16).toString("hex");
    res.writeHead(302, {
      location: safe,
      "set-cookie": [
        `__Host-axis_at=${role}; Path=/; HttpOnly; Secure; SameSite=Strict`,
        `__Host-axis_csrf=${csrf}; Path=/; Secure; SameSite=Strict`,
      ],
    });
    return void res.end();
  }

  // --- everything else needs a session ---
  const role = ck["__Host-axis_at"];
  if (!role || !(role in ROLE_RANK))
    return problem(res, 401, "unauthenticated", "Sign in required");
  const me = `m-${role}`;

  if (method !== "GET" && method !== "HEAD") {
    const header = req.headers["x-axis-csrf"];
    if (!ck["__Host-axis_csrf"] || header !== ck["__Host-axis_csrf"])
      return problem(res, 403, "forbidden", "CSRF token missing or wrong");
  }

  let body: J = {};
  if (method !== "GET" && method !== "HEAD" && method !== "DELETE") {
    try {
      body = await readJson(req);
    } catch {
      return problem(res, 400, "validation_failed", "Invalid JSON");
    }
  }

  if (path === "/auth/me" && method === "GET") {
    return send(res, 200, {
      member: { id: me, email: `${role}@acme.test`, role },
      tenant: { id: TENANT, name: "Acme", region: "us-east-1" },
    });
  }
  if (path === "/auth/logout" && method === "POST") {
    return send(res, 204, undefined, {
      "set-cookie": "__Host-axis_at=; Path=/; Max-Age=0; HttpOnly; Secure",
    });
  }

  const idem = req.headers["idempotency-key"];
  if (method === "POST" && typeof idem === "string") {
    const hit = S.idempotency.get(`${path}|${idem}`);
    if (hit) return send(res, hit.status, hit.body);
  }
  const reply = (status: number, b: unknown): void => {
    if (method === "POST" && typeof idem === "string")
      S.idempotency.set(`${path}|${idem}`, { status, body: b });
    send(res, status, b);
  };

  const deny = (min: number): boolean => {
    if (need(role, min)) return false;
    problem(res, 403, "forbidden", "Your role cannot do that");
    return true;
  };

  // ------------------------------------------------------------------ /v1
  if (path.startsWith("/v1/")) {
    const p = path.slice(3);
    if (p === "/blueprints" && method === "GET") return send(res, 200, page(S.blueprints));
    if (p === "/blueprints" && method === "POST") {
      if (deny(50)) return;
      const doc = body["abl"];
      const c = abl.compileAbl(doc);
      if (!c.ok) {
        return problem(res, 422, "validation_failed", "Blueprint failed validation", {
          errors: [
            ...c.issues.map((i) => ({ path: i.path, keyword: i.keyword, message: i.message })),
            ...c.findings.map((f) => ({ path: f.path, keyword: f.code, message: f.message })),
          ],
        });
      }
      const meta = (doc as { metadata: { name: string; version: string } }).metadata;
      if (
        S.blueprints.some((b) => b["name"] === meta.name && b["version"] === String(meta.version))
      )
        return problem(res, 409, "conflict", "That version is already published and immutable");
      const bv = {
        name: meta.name,
        version: String(meta.version),
        risk_level: c.manifest.risk.level,
        content_hash: c.manifest.blueprint.content_hash,
        signature: null,
        created_at: iso(),
        abl: doc,
      };
      S.blueprints.push(bv);
      return reply(201, bv);
    }
    let m = /^\/blueprints\/([^/]+)\/versions\/([^/]+)$/.exec(p);
    if (m && method === "GET") {
      const b = S.blueprints.find(
        (x) =>
          x["name"] === decodeURIComponent(m![1]!) && x["version"] === decodeURIComponent(m![2]!),
      );
      return b ? send(res, 200, b) : problem(res, 404, "not_found", "Blueprint version not found");
    }
    if (p === "/runs" && method === "GET") {
      const st = url.searchParams.get("state");
      return send(
        res,
        200,
        page(
          [...S.runs.values()]
            .map((r) => r.run)
            .filter((r) => !st || r["state"] === st)
            .reverse(),
        ),
      );
    }
    if (p === "/runs" && method === "POST") {
      if (deny(50)) return;
      const bp = body["blueprint"] as { name?: string; version?: string } | undefined;
      if (
        !bp?.name ||
        !bp.version ||
        !S.blueprints.some((b) => b["name"] === bp.name && b["version"] === bp.version)
      )
        return problem(res, 422, "validation_failed", "Unknown blueprint version");
      const id = randomUUID();
      const run = {
        id,
        init_pid: PID,
        blueprint: bp,
        state: "running",
        trace_id: randomBytes(16).toString("hex"),
        created_at: iso(),
        finished_at: null,
      };
      S.runs.set(id, { run, events: [], subs: new Set() });
      scriptRun(id);
      return reply(202, run);
    }
    m = /^\/runs\/([^/]+)(\/events|\/signals|\/explanation)?$/.exec(p);
    if (m) {
      const rec = S.runs.get(m[1]!);
      if (!rec) return problem(res, 404, "not_found", "Run not found");
      if (!m[2] && method === "GET") return send(res, 200, rec.run);
      if (m[2] === "/signals" && method === "POST") {
        if (deny(50)) return;
        if (rec.run["state"] === "terminated")
          return problem(res, 409, "conflict", "The run has already finished");
        const sig = body["signal"];
        rec.run["state"] =
          sig === "PAUSE"
            ? "suspended"
            : sig === "TERM" || sig === "KILL"
              ? "terminated"
              : "running";
        return send(res, 200, { pid: PID, state: rec.run["state"] });
      }
      if (m[2] === "/explanation" && method === "GET") {
        return send(res, 200, {
          summary:
            m[1] === SEED_RUN
              ? `The agent paused for approval, then a tool call was denied. ${XSS}`
              : "The agent completed its work within budget.",
          steps: [
            "Started with the published blueprint.",
            "Asked to send an email; policy required approval.",
            `A shell command was denied. ${XSS}`,
          ],
          decision_refs: [
            { audit_event_id: "00000000-0000-4000-8000-000000000002", seq: 2 },
            { audit_event_id: "00000000-0000-4000-8000-000000000003", seq: 3 },
          ],
          remediation: [
            "Ask an approver to review the pending email.",
            "Add an allow rule for the tool if it is safe.",
          ],
        });
      }
      if (m[2] === "/events" && method === "GET") {
        const after = Number(url.searchParams.get("after_sequence") ?? 0);
        if ((req.headers.accept ?? "").includes("text/event-stream")) {
          res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
          const write = (e: J) => res.write(`data: ${JSON.stringify(e)}\n\n`);
          for (const e of rec.events) if ((e["sequence"] as number) > after) write(e);
          if (rec.run["state"] === "terminated") return void res.end();
          const sub = (e: J) => {
            if (e["__end"]) return void res.end();
            write(e);
          };
          rec.subs.add(sub);
          req.on("close", () => rec.subs.delete(sub));
          return;
        }
        return send(res, 200, {
          items: rec.events.filter((e) => (e["sequence"] as number) > after),
          next_cursor: null,
        });
      }
    }
    if (p === "/approvals" && method === "GET") {
      const st = url.searchParams.get("status");
      return send(res, 200, page(S.approvals.filter((a) => !st || a["status"] === st)));
    }
    m = /^\/approvals\/([^/]+)\/(decision|explanation)$/.exec(p);
    if (m) {
      const a = S.approvals.find((x) => x["id"] === m![1]);
      if (!a) return problem(res, 404, "not_found", "Approval not found");
      if (m[2] === "explanation" && method === "GET") {
        return send(res, 200, {
          summary: "An external write needs a human decision before it can run.",
          steps: ["The agent requested email.send.", "Policy rule R-ext-write requires approval."],
          decision_refs: [{ audit_event_id: "00000000-0000-4000-8000-000000000002", seq: 2 }],
          remediation: ["Approve or deny before the SLA deadline."],
        });
      }
      if (m[2] === "decision" && method === "POST") {
        if (deny(40)) return;
        if (a["requested_by"] === me)
          return problem(res, 403, "policy_denied", "Self-approval is not allowed");
        if (a["status"] !== "pending") return problem(res, 409, "conflict", "Already decided");
        a["status"] = body["decision"] === "approve" ? "approved" : "rejected";
        a["decided_by"] = me;
        a["decided_at"] = iso();
        a["comment"] = (body["comment"] as string | undefined) ?? null;
        return reply(200, a);
      }
    }
    if (p === "/policies" && method === "GET") return send(res, 200, page(S.policies));
    if (p === "/policies" && method === "POST") {
      if (deny(80)) return;
      const pol = body["policy"] as J | undefined;
      if (!pol || pol["apiVersion"] !== "policy.axis.dev/v1")
        return problem(res, 422, "validation_failed", "Policy failed validation", {
          errors: [{ path: "/apiVersion", message: "must be policy.axis.dev/v1" }],
        });
      const name = ((pol["metadata"] as J | undefined)?.["name"] as string) ?? "pack";
      const version = String(S.policies.filter((x) => x["name"] === name).length + 1);
      const rec = {
        name,
        version,
        version_id: `pv-${S.policies.length + 1}`,
        content_hash: randomBytes(32).toString("hex"),
        created_at: iso(),
        active: false,
        policy: pol,
      };
      S.policies.push(rec);
      return reply(201, rec);
    }
    if (p === "/policies:test" && method === "POST") {
      const pol = body["policy"] as J | undefined;
      const rq = body["request"] as
        { context?: { tool?: { side_effects?: string; name?: string } } } | undefined;
      if (!pol || pol["apiVersion"] !== "policy.axis.dev/v1" || !rq)
        return problem(res, 422, "validation_failed", "Policy failed validation", {
          errors: [{ path: "/apiVersion", message: "must be policy.axis.dev/v1" }],
        });
      const fx = rq.context?.tool?.side_effects;
      const d = fx === "read" ? "ALLOW" : fx === "external" ? "REQUIRE_APPROVAL" : "DENY";
      return send(res, 200, {
        decision: d,
        policy_version: "test",
        reason:
          d === "ALLOW"
            ? "read tools are allowed"
            : d === "DENY"
              ? "no rule allows this (fail closed)"
              : "external side effects need approval",
        matched_rule_ids: d === "DENY" ? [] : ["R-" + fx],
      });
    }
    if (p === "/audit/events" && method === "GET") {
      if (deny(40)) return;
      const tr = url.searchParams.get("trace_id");
      const dec = url.searchParams.get("decision");
      const from = Number(url.searchParams.get("from_seq") ?? 0);
      const limit = Number(url.searchParams.get("limit") ?? 100);
      return send(
        res,
        200,
        page(
          S.audit
            .filter(
              (e) => (!tr || e.trace_id === tr) && (!dec || e.decision === dec) && e.seq >= from,
            )
            .slice(0, limit),
        ),
      );
    }
    m = /^\/audit\/events\/([^/]+)\/explanation$/.exec(p);
    if (m && method === "GET") {
      const e = S.audit.find((x) => x.id === m![1]);
      return e
        ? send(res, 200, {
            summary: `${e.action} was ${e.decision.toLowerCase()} by policy ${e.policy_version}.`,
            steps: [
              `Enforcement point: ${e.enforcement_point}`,
              `Reason: ${e.reason ?? "none recorded"}`,
            ],
            decision_refs: [{ audit_event_id: e.id, seq: e.seq }],
            remediation: ["Review the policy rule that matched."],
          })
        : problem(res, 404, "not_found", "Event not found");
    }
    if (p === "/audit/verify" && method === "POST") {
      if (deny(40)) return;
      const from = (body["from_seq"] as number | undefined) ?? 1;
      const to = (body["to_seq"] as number | undefined) ?? S.audit.length;
      const slice = S.audit.filter((e) => e.seq >= from && e.seq <= to);
      const prev = S.audit.find((e) => e.seq === from - 1);
      const v = verifyChain(slice, prev);
      return send(
        res,
        200,
        v.ok
          ? { ok: true, verified: v.length }
          : { ok: false, verified: 0, broken_at_seq: v.brokenAtSeq, reason: v.reason },
      );
    }
    if (p === "/kill-switches" && method === "GET")
      return send(res, 200, { items: S.killSwitches });
    if (p === "/kill-switches" && method === "PUT") {
      if (deny(80)) return;
      const ks = {
        scope: body["scope"],
        target: body["target"] ?? null,
        engaged: body["engaged"],
        reason: body["reason"] ?? null,
        updated_at: iso(),
      };
      S.killSwitches = [
        ...S.killSwitches.filter((k) => k["scope"] !== ks.scope || k["target"] !== ks.target),
        ks,
      ];
      return send(res, 200, ks);
    }
    if (p === "/usage" && method === "GET") {
      if (deny(40)) return;
      return send(res, 200, { items: usageRows(url.searchParams.get("group_by") ?? "meter") });
    }
    if (p === "/evals/runs") return problem(res, 501, "internal", "Eval Hub is not implemented");
    if (p === "/marketplace/listings" && method === "GET") {
      const q = (url.searchParams.get("q") ?? "").toLowerCase();
      return send(
        res,
        200,
        page(
          S.listings
            .filter((l) => String(l["name"]).toLowerCase().includes(q))
            .map((l) => ({
              ...l,
              installed: S.installed.has(l["id"] as string),
            })),
        ),
      );
    }
    m = /^\/marketplace\/listings\/([^/]+)(\/install)?$/.exec(p);
    if (m) {
      const l = S.listings.find((x) => x["id"] === m![1]);
      if (!l) return problem(res, 404, "not_found", "Listing not found");
      if (!m[2] && method === "GET")
        return send(res, 200, {
          ...l,
          installed: S.installed.has(l["id"] as string),
          installed_permissions: S.installed.get(l["id"] as string) ?? null,
        });
      if (m[2] && method === "POST") {
        if (deny(80)) return;
        if (JSON.stringify(body["accepted_permissions"]) !== JSON.stringify(l["permissions"]))
          return problem(
            res,
            409,
            "conflict",
            "Accepted permissions do not match the listing's current permissions",
          );
        S.installed.set(l["id"] as string, l["permissions"] as J);
        return reply(200, { installed: true });
      }
    }
    return problem(res, 404, "not_found", "Not found");
  }

  // ------------------------------------------------------------------ /admin/v1
  if (path.startsWith("/admin/v1/")) {
    const segs = path.slice("/admin/v1/".length).split("/").filter(Boolean);
    const [r0, r1, r2] = segs;
    if (r0 === "tenant" && method === "GET")
      return send(res, 200, { id: TENANT, name: "Acme", region: "us-east-1" });
    if (r0 === "members") {
      if (deny(80)) return;
      if (!r1 && method === "GET") return send(res, 200, page(S.members));
      if (!r1 && method === "POST") {
        const mem = {
          id: `m-${randomBytes(3).toString("hex")}`,
          email: body["email"],
          role: body["role"],
          status: "active",
        };
        S.members.push(mem);
        return send(res, 201, mem);
      }
      const mem = S.members.find((x) => x["id"] === r1);
      if (!mem) return problem(res, 404, "not_found", "Member not found");
      if (method === "PATCH") {
        mem["role"] = body["role"];
        return send(res, 200, mem);
      }
      if (method === "DELETE") {
        S.members = S.members.filter((x) => x !== mem);
        return send(res, 204, undefined);
      }
    }
    if (r0 === "api-keys") {
      if (deny(50)) return;
      if (!r1 && method === "GET") return send(res, 200, page(S.apiKeys));
      const mk = (name: string, env: string): J => {
        const prefix = `axk_${randomBytes(8).toString("hex")}`;
        const rec = {
          id: randomUUID(),
          name,
          prefix,
          scopes: body["scopes"] ?? [],
          environment: env,
          created_at: iso(),
          expires_at: iso(86_400_000 * 90),
          revoked_at: null,
        };
        S.apiKeys.push(rec);
        return { ...rec, secret: `${prefix}_${randomBytes(32).toString("base64url")}` };
      };
      if (!r1 && method === "POST")
        return send(res, 201, mk(String(body["name"]), String(body["environment"] ?? "dev")));
      const k = S.apiKeys.find((x) => x["id"] === r1);
      if (!k) return problem(res, 404, "not_found", "Key not found");
      if (r2 === "rotate" && method === "POST") {
        k["revoked_at"] = iso();
        return send(res, 201, mk(String(k["name"]), String(k["environment"])));
      }
      if (!r2 && method === "DELETE") {
        k["revoked_at"] = iso();
        return send(res, 200, k);
      }
    }
    if (r0 === "model-keys") {
      if (deny(50)) return;
      if (!r1 && method === "GET") return send(res, 200, { items: S.modelKeys });
      if (r1 && r2 && method === "PUT") {
        S.modelKeys = [
          ...S.modelKeys.filter((k) => !(k["provider"] === r1 && k["label"] === r2)),
          { provider: r1, label: r2, updated_at: iso() },
        ];
        return send(res, 200, { provider: r1, label: r2, updated_at: iso() }); // value is never echoed
      }
      if (r1 && r2 && method === "DELETE") {
        S.modelKeys = S.modelKeys.filter((k) => !(k["provider"] === r1 && k["label"] === r2));
        return send(res, 204, undefined);
      }
    }
    if (r0 === "budgets") {
      if (!r1 && method === "GET") return send(res, 200, { items: S.budgets });
      if (deny(80)) return;
      if (!r1 && method === "PUT") {
        const items = (body["items"] as J[]) ?? [];
        S.budgets = items.map((b, i) => ({ id: `b${Date.now()}-${i}`, ...b }));
        return send(res, 200, { items: S.budgets });
      }
      if (r1 && method === "DELETE") {
        S.budgets = S.budgets.filter((b) => b["id"] !== r1);
        return send(res, 204, undefined);
      }
    }
    if (r0 === "sso" && r1 === "connection") {
      if (method === "GET") return send(res, 200, S.sso);
      if (deny(100)) return;
      S.sso = { ...S.sso, ...body };
      return send(res, 200, S.sso);
    }
    if (r0 === "directories" && method === "GET")
      return send(res, 200, {
        items: [
          {
            id: "d1",
            name: "Okta",
            status: "active",
            default_role: "viewer",
            token_prefix: "axs_0123456789abcdef",
          },
        ],
      });
    if (r0 === "policies" && r2 === "activate" && method === "POST") {
      if (deny(80)) return;
      const target = S.policies.find((x) => x["version_id"] === r1);
      if (!target) return problem(res, 404, "not_found", "Version not found");
      for (const x of S.policies) if (x["name"] === target["name"]) x["active"] = x === target;
      return send(res, 200, { activated: true });
    }
    return problem(res, 404, "not_found", "Not found");
  }
  return problem(res, 404, "not_found", "Not found");
}

export function startMockApi(port: number): Promise<{ close: () => void }> {
  const server = createServer((req, res) => {
    handle(req, res).catch((e: unknown) => {
      if (!res.headersSent) problem(res, 500, "internal", e instanceof Error ? e.message : "error");
    });
  });
  return new Promise((resolve) =>
    server.listen(port, "127.0.0.1", () => resolve({ close: () => server.close() })),
  );
}
