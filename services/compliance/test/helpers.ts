import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { MemoryAuditLog } from "@axis/audit";
import { validateAblYaml, type AblDocument } from "@axis/abl";
import pg from "pg";
import { inject } from "vitest";
import {
  ComplianceAudit,
  Ed25519Sealer,
  MemoryDocStore,
  createCompliance,
  missing,
  sourced,
  type AuditStats,
  type BlueprintSnapshot,
  type Compliance,
  type ComplianceActor,
  type DocStore,
  type EvalEvidence,
  type SourcePorts,
} from "../src/index.js";

export const hex = (n: number): string => randomBytes(n / 2).toString("hex");
export const newPool = (max = 10): pg.Pool =>
  new pg.Pool({ connectionString: inject("dbUrl"), max });

export class Clock {
  constructor(public t: Date) {}
  now = (): Date => new Date(this.t.getTime());
  advance(ms: number): void {
    this.t = new Date(this.t.getTime() + ms);
  }
}
export const DAY = 86_400_000;

export async function adminClient(): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: inject("dbUrl") });
  await c.connect();
  return c;
}
export async function newTenantRow(admin: pg.Client): Promise<string> {
  const id = randomUUID();
  await admin.query(
    "INSERT INTO tenants (id, slug, name, region) VALUES ($1, $2, $2, 'us-east-1')",
    [id, `t-${hex(10)}`],
  );
  return id;
}

export const T1 = "11111111-1111-4111-8111-111111111111";
export const T2 = "22222222-2222-4222-8222-222222222222";

export const user = (tenantId: string, role = "admin", subject = `user-${role}`): ComplianceActor => ({
  tenantId,
  subject,
  role,
});

const ABL_PATH = fileURLToPath(
  new URL("../../../packages/abl/examples/valid/claims-triage.yaml", import.meta.url),
);
export function ablDoc(over?: (d: AblDocument) => void): AblDocument {
  const r = validateAblYaml(readFileSync(ABL_PATH, "utf8"));
  if (!r.ok) throw new Error("fixture invalid");
  const d = structuredClone(r.doc) as AblDocument;
  over?.(d);
  return d;
}

export const HASH_A = "a".repeat(64);

export function snapshot(over: Partial<BlueprintSnapshot> = {}): BlueprintSnapshot {
  return {
    abl: ablDoc(),
    content_hash: HASH_A,
    origin: "registry",
    registry: {
      namespace: "acme",
      signature_key_id: "key-1",
      signed_at: "2026-01-01T00:00:00.000Z",
      published_at: "2026-01-01T00:00:01.000Z",
      verification: { ok: true, checks: ["hash", "provenance", "signature"] },
      provenance_attached: true,
    },
    versions: [
      { version: "2.3.1", content_hash: HASH_A, published_at: "2026-01-01T00:00:01.000Z", state: "active" },
      { version: "2.3.0", content_hash: "b".repeat(64), published_at: "2025-12-01T00:00:00.000Z", state: "deprecated" },
    ],
    ...over,
  };
}

export const EVIDENCE: EvalEvidence = {
  runs: [
    {
      run_id: "run-1",
      suite_ref: "claims-regression@1.0.0",
      declared_ref: "claims-regression@^1.0.0",
      status: "passed",
      overall: 0.95,
      threshold: 0.92,
      mode: "offline",
      content_hash: HASH_A,
      finished_at: "2026-01-02T00:00:00.000Z",
    },
  ],
  attestations: [{ run_id: "run-1", suite_ref: "claims-regression@1.0.0", overall: 0.95, verified: true }],
  gate: [{ suite_ref: "claims-regression@1.0.0", threshold: 0.92, pass: true, reasons: [] }],
  online: [{ id: "prod", suite_ref: "claims-regression@1.0.0", rate: 0.1, enabled: true }],
};

export const STATS: AuditStats = {
  event_count: 120,
  head_seq: 120,
  head_hash: "c".repeat(64),
  first_ts: "2026-01-01T00:00:00.000Z",
  last_ts: "2026-01-03T00:00:00.000Z",
  by_decision: { ALLOW: 100, DENY: 15, REQUIRE_APPROVAL: 5 },
  by_enforcement_point: { tool_call: 100, admin: 20 },
  chain: { verified: true, checked_through_seq: 120, reason: null },
};

/** Sources that answer per tenant; individual ports can be replaced to make them fail. */
export function fakeSources(over: Partial<SourcePorts> = {}, calls: string[] = []): SourcePorts {
  return {
    blueprints: {
      get: (t, ref) => {
        calls.push(`blueprints:${t}`);
        return Promise.resolve(
          ref.name === "claims-triage" && ref.version === "2.3.1"
            ? sourced(snapshot())
            : missing("blueprint not found"),
        );
      },
    },
    evals: {
      evidence: (t) => {
        calls.push(`evals:${t}`);
        return Promise.resolve(sourced(EVIDENCE));
      },
    },
    policies: {
      activePacks: (t) => {
        calls.push(`policies:${t}`);
        return Promise.resolve(
          sourced([
            { id: "baseline-deny", version: "1.0.0", hash: "d".repeat(64), active_since: "2026-01-01T00:00:00.000Z" },
          ]),
        );
      },
    },
    audit: {
      statistics: (t) => {
        calls.push(`audit:${t}`);
        return Promise.resolve(sourced(STATS));
      },
    },
    limitations: {
      list: (t) => {
        calls.push(`limitations:${t}`);
        return Promise.resolve(
          sourced([{ id: "NEEDS-1", title: "single instance", detail: null, evidence: null }]),
        );
      },
    },
    ...over,
  };
}

export interface World {
  svc: Compliance;
  docs: DocStore;
  log: MemoryAuditLog;
  clock: Clock;
  sealer: Ed25519Sealer;
  calls: string[];
}

export function world(o: { docs?: DocStore; sources?: Partial<SourcePorts>; sealer?: Ed25519Sealer } = {}): World {
  const log = new MemoryAuditLog();
  const clock = new Clock(new Date("2026-03-01T10:00:00.000Z"));
  const docs = o.docs ?? new MemoryDocStore();
  const sealer = o.sealer ?? Ed25519Sealer.generate("test-seal");
  const calls: string[] = [];
  let n = 0;
  const svc = createCompliance({
    docs,
    audit: new ComplianceAudit(log, clock.now),
    now: clock.now,
    newId: () => `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`,
    sources: fakeSources(o.sources, calls),
    sealer,
  });
  return { svc, docs, log, clock, sealer, calls };
}

export const input = {
  system: (over: Record<string, unknown> = {}) => ({
    name: "Claims triage",
    purpose: "Routes inbound insurance claims to adjusters",
    owner: "claims-platform@example.com",
    risk_level: "high" as const,
    blueprints: [{ name: "claims-triage", version: "2.3.1" }],
    data_categories: ["claims", "phi"],
    stakeholders: [{ role: "owner", name: "Claims platform" }],
    ...over,
  }),
  assessment: (systemId: string, over: Record<string, unknown> = {}) => ({
    system_id: systemId,
    title: "Claims triage impact assessment",
    risk_rating: "high" as const,
    intended_use: "Recommend a routing queue; an adjuster decides",
    blueprints: [{ name: "claims-triage", version: "2.3.1" }],
    affected_groups: [{ group: "claimants", impact: "delay or misrouting of a claim" }],
    risks: [
      {
        id: "R1",
        description: "Misrouting of urgent claims",
        likelihood: "medium" as const,
        severity: "high" as const,
        mitigation: "Adjuster reviews every routing",
        residual: "low" as const,
      },
    ],
    stakeholders: [{ role: "reviewer", name: "Compliance office" }],
    review_due: "2026-09-01",
    ...over,
  }),
};
