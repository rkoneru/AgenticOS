import type { AblDocument } from "@axis/abl";
import {
  missing,
  sourced,
  type AuditSourcePort,
  type AuditStats,
  type BlueprintSnapshot,
  type BlueprintSourcePort,
  type BlueprintVersionInfo,
  type ComplianceActor,
  type EvalEvidence,
  type EvalSourcePort,
  type LimitationsSourcePort,
  type PolicySourcePort,
  type SourcePorts,
} from "@axis/compliance";
import { maxSatisfying, parseRange } from "@axis/registry";
import {
  PortInvalid,
  PortNotFound,
  type AuditPort,
  type BlueprintStore,
  type EvalsPort,
  type PolicyPort,
  type Principal,
  type RegistryPort,
  type Role,
} from "../ports.js";

/** The sources ask the other components on behalf of the CALLER: same tenant, same member, same role. */
const principalOf = (a: ComplianceActor): Principal => ({
  tenantId: a.tenantId,
  memberId: a.subject,
  role: a.role as Role,
  credential: "session",
});

export interface ComplianceSourceDeps {
  blueprints: BlueprintStore;
  registry: RegistryPort;
  evals: EvalsPort;
  policies: PolicyPort;
  auditLog: AuditPort;
  limitations: LimitationsSourcePort;
  /** Most recent audit events counted and verified for the statistics (default 10 000). */
  maxAuditEvents?: number;
}

const PAGES = 20;

/** Does a run of suite `name@1.2.3` count toward the declared `name@^1.0.0`? */
export function suiteMatches(declared: string, suiteRef: string): boolean {
  const d = declared.lastIndexOf("@");
  const s = suiteRef.lastIndexOf("@");
  if (d < 1 || s < 1 || declared.slice(0, d) !== suiteRef.slice(0, s)) return false;
  try {
    return maxSatisfying([suiteRef.slice(s + 1)], parseRange(declared.slice(d + 1))) !== undefined;
  } catch {
    return declared === suiteRef;
  }
}

interface RegistryHit {
  namespace: string;
  row: { version: string; content_hash: string; published_at: string; state?: string };
  all: { version: string; content_hash: string; published_at: string; state?: string }[];
}

/** The tenant's registry namespaces that hold `name@version`. */
async function findInRegistry(
  registry: RegistryPort,
  p: Principal,
  name: string,
  version: string,
): Promise<RegistryHit | undefined> {
  for (const ns of await registry.listNamespaces(p)) {
    let rows;
    try {
      rows = await registry.listVersions(p, ns.namespace, name);
    } catch (e) {
      if (e instanceof PortNotFound) continue;
      throw e;
    }
    const row = rows.find((v) => v.version === version);
    if (row) return { namespace: ns.namespace, row, all: rows };
  }
  return undefined;
}

export class GatewayBlueprintSource implements BlueprintSourcePort {
  constructor(private readonly d: ComplianceSourceDeps) {}

  async get(actor: ComplianceActor, ref: { name: string; version: string }) {
    const local = await this.d.blueprints.get(actor.tenantId, ref.name, ref.version);
    if (local) {
      const versions: BlueprintVersionInfo[] = [];
      let after: string | undefined;
      for (let i = 0; i < PAGES; i++) {
        const page = await this.d.blueprints.list(actor.tenantId, {
          limit: 200,
          ...(after ? { after } : {}),
        });
        for (const v of page.items)
          if (v.name === ref.name)
            versions.push({
              version: v.version,
              content_hash: v.content_hash,
              published_at: v.created_at,
              state: "active",
            });
        if (!page.next) break;
        after = page.next;
      }
      const snap: BlueprintSnapshot = {
        abl: local.abl as AblDocument,
        content_hash: local.content_hash,
        origin: "tenant",
        registry: null,
        versions,
      };
      return sourced(snap);
    }
    const p = principalOf(actor);
    const hit = await findInRegistry(this.d.registry, p, ref.name, ref.version);
    if (!hit)
      return missing<BlueprintSnapshot>(
        "blueprint not found in this tenant's blueprints or registry namespaces",
      );
    try {
      const r = await this.d.registry.resolve(p, `${hit.namespace}/${ref.name}@${ref.version}`);
      const snap: BlueprintSnapshot = {
        abl: r.abl as AblDocument,
        content_hash: r.content_hash,
        origin: "registry",
        registry: {
          namespace: hit.namespace,
          signature_key_id: r.signature.key_id,
          signed_at: r.signature.signed_at,
          published_at: r.published_at,
          verification: { ok: true, checks: ["content_hash", "provenance", "signature"] },
          provenance_attached: r.provenance !== null && r.provenance !== undefined,
        },
        versions: hit.all.map((v) => ({
          version: v.version,
          content_hash: v.content_hash,
          published_at: v.published_at,
          state: v.state ?? "active",
        })),
      };
      return sourced(snap);
    } catch (e) {
      if (e instanceof PortInvalid)
        return missing<BlueprintSnapshot>(
          `registry verification failed: ${e.issues
            .map((i) => i.keyword ?? "failed")
            .sort()
            .join(",")}`,
        );
      throw e;
    }
  }
}

export class GatewayEvalSource implements EvalSourcePort {
  constructor(private readonly d: ComplianceSourceDeps) {}

  async evidence(
    actor: ComplianceActor,
    bp: { name: string; version: string; content_hash: string },
    declared: { ref: string; threshold: number }[],
  ) {
    const p = principalOf(actor);
    const runs: EvalEvidence["runs"] = [];
    let cursor: string | undefined;
    for (let i = 0; i < PAGES; i++) {
      const page = await this.d.evals.listRuns(p, {
        limit: 200,
        blueprint: bp.name,
        content_hash: bp.content_hash,
        ...(cursor ? { cursor } : {}),
      });
      for (const r of page.items) {
        const b = r["blueprint"] as { version?: string } | undefined;
        if (b?.version !== undefined && b.version !== bp.version) continue;
        const suite = String(r["suite"]);
        runs.push({
          run_id: r.id,
          suite_ref: suite,
          declared_ref: declared.find((x) => suiteMatches(x.ref, suite))?.ref ?? suite,
          status: r.status,
          overall: typeof r["score"] === "number" ? r["score"] : null,
          threshold: typeof r["threshold"] === "number" ? r["threshold"] : 0,
          mode: String(r["mode"] ?? "unknown"),
          content_hash: bp.content_hash,
          finished_at: typeof r["finished_at"] === "string" ? r["finished_at"] : null,
        });
      }
      if (!page.next) break;
      cursor = page.next;
    }
    const hit = await findInRegistry(this.d.registry, p, bp.name, bp.version);
    const attestations: EvalEvidence["attestations"] = hit
      ? (await this.d.registry.evalAttestations(p, hit.namespace, bp.name, bp.version)).map(
          (a) => ({
            run_id: a.run_id,
            suite_ref: a.suite_ref,
            overall: a.overall,
            verified: a.verified,
          }),
        )
      : [];
    const gate: EvalEvidence["gate"] = [];
    if (declared.length > 0) {
      const g = await this.d.evals.gate(p, {
        blueprint: {
          ...(hit ? { namespace: hit.namespace } : {}),
          name: bp.name,
          version: bp.version,
          content_hash: bp.content_hash,
        },
        suites: declared,
      });
      const reasons = (g["reasons"] as { code: string; suite_ref?: string }[] | undefined) ?? [];
      const rows =
        (g["runs"] as { suite_ref: string; required_threshold: number }[] | undefined) ?? [];
      for (const r of rows) {
        const mine = reasons.filter((x) => x.suite_ref === r.suite_ref).map((x) => x.code);
        gate.push({
          suite_ref: r.suite_ref,
          threshold: r.required_threshold,
          pass: g["allowed"] === true || mine.length === 0,
          reasons: mine,
        });
      }
      const general = reasons.filter((x) => x.suite_ref === undefined).map((x) => x.code);
      if (general.length > 0)
        gate.push({
          suite_ref: "(release)",
          threshold: 0,
          pass: g["allowed"] === true,
          reasons: general,
        });
    }
    const sampling = await this.d.evals.listSampling(p);
    const online = sampling
      .filter((s) => s["blueprint_name"] === bp.name)
      .map((s) => ({
        id: String(s["id"]),
        suite_ref: String(s["suite_ref"]),
        rate: Number(s["rate"]),
        enabled: s["enabled"] === true,
      }));
    return sourced<EvalEvidence>({ runs, attestations, gate, online });
  }
}

export class GatewayPolicySource implements PolicySourcePort {
  constructor(private readonly d: ComplianceSourceDeps) {}
  async activePacks(actor: ComplianceActor) {
    const p = principalOf(actor);
    const out = [];
    let after: string | undefined;
    for (let i = 0; i < PAGES; i++) {
      const page = await this.d.policies.list(p, { limit: 200, ...(after ? { after } : {}) });
      for (const x of page.items)
        if (x.active === true)
          out.push({
            id: x.name,
            version: x.version,
            hash: x.content_hash ?? null,
            active_since: null,
          });
      if (!page.next) break;
      after = page.next;
    }
    return sourced(out);
  }
}

/**
 * The documentation activity itself (`compliance.*` events, and the gateway's `api.<operation>Compliance...` records of those calls) is not counted: generating a document appends events,
 * and a count that included them would make every regeneration differ from the one before even when nothing else happened.
 */
export const isDocumentationEvent = (action: string): boolean =>
  action.startsWith("compliance.") || /^api\.[A-Za-z]*Compliance[A-Za-z]*$/.test(action);

export class GatewayAuditSource implements AuditSourcePort {
  constructor(private readonly d: ComplianceSourceDeps) {}
  async statistics(actor: ComplianceActor) {
    const t = actor.tenantId;
    const head = await this.d.auditLog.head(t);
    const cap = this.d.maxAuditEvents ?? 10_000;
    const from = Math.max(1, head - cap + 1);
    const byDecision: Record<string, number> = {};
    const byPoint: Record<string, number> = {};
    let count = 0;
    let first: string | null = null;
    let last: string | null = null;
    let lastHash: string | null = null;
    let lastSeq = 0; // the chain was verified through the head; the figure reported is the last COUNTED event, so it does not move when only documentation events are appended
    for (let seq = from; head > 0 && seq <= head;) {
      const page = await this.d.auditLog.list(t, { fromSeq: seq, limit: 1000 });
      const tail = page[page.length - 1];
      if (!tail) break;
      for (const e of page) {
        if (e.seq > head || isDocumentationEvent(e.action)) continue;
        count++;
        byDecision[e.decision] = (byDecision[e.decision] ?? 0) + 1;
        byPoint[e.enforcement_point] = (byPoint[e.enforcement_point] ?? 0) + 1;
        first ??= e.ts;
        last = e.ts;
        lastHash = e.hash;
        lastSeq = e.seq;
      }
      seq = tail.seq + 1;
    }
    const verdict =
      head === 0
        ? ({ ok: true, length: 0 } as const)
        : await this.d.auditLog.verify(t, { fromSeq: from, toSeq: head });
    return sourced<AuditStats>({
      event_count: count,
      head_seq: lastSeq,
      head_hash: lastHash,
      window_from_seq: from,
      first_ts: first,
      last_ts: last,
      by_decision: byDecision,
      by_enforcement_point: byPoint,
      chain: verdict.ok
        ? { verified: true, checked_through_seq: lastSeq, reason: null }
        : {
            verified: false,
            checked_through_seq: Math.max(0, verdict.brokenAtSeq - 1),
            reason: `${verdict.reason} at seq ${verdict.brokenAtSeq}`,
          },
    });
  }
}

/** The document generator's sources, built from the gateway's own ports (so the SAME tenant scoping and role checks apply). */
export function gatewayComplianceSources(d: ComplianceSourceDeps): SourcePorts {
  return {
    blueprints: new GatewayBlueprintSource(d),
    evals: new GatewayEvalSource(d),
    policies: new GatewayPolicySource(d),
    audit: new GatewayAuditSource(d),
    limitations: d.limitations,
  };
}
