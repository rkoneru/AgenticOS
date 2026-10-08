import { randomUUID } from "node:crypto";
import { hashJson } from "@axis/contracts";
import type { GovernanceAudit } from "./audit.js";
import { requireOfficer } from "./authz.js";
import { ManifestSigner, type ExportBundle, type ExportManifest } from "./bundle.js";
import { classWideHold, overlaps, subjectScopedHolds } from "./holds.js";
import type { Pseudonymiser, Sealer } from "./keys.js";
import { HoldRegistry } from "./registry.js";
import type { ResidencyPolicy } from "./residency.js";
import type {
  DsarRequest,
  GovernanceStore,
  Hold,
  RequestKind,
  RequestStatus,
  StepRecord,
} from "./store.js";
import { OPEN_STATUSES } from "./store.js";
import { resolveSubject } from "./subjects.js";
import {
  GovernanceError,
  normalizeIds,
  type CountResult,
  type EraseResult,
  type Identifier,
  type Principal,
  type ProviderContext,
  type SubjectDataProvider,
} from "./types.js";

export const DAY_MS = 86_400_000;
export const SLA_DAYS = 30; // GDPR Art. 12(3): one month
export const EXTENSION_DAYS = 60; // further two months where necessary
export const AT_RISK_DAYS = 7;

export interface RequesterVerifier {
  verify(
    req: { tenantId: string; requestId: string; subjectRef: string; kind: RequestKind },
    evidence: unknown,
  ): Promise<{ ok: boolean; method: string }>;
}

export const REJECT_REASONS = [
  "identity_not_verified",
  "manifestly_unfounded",
  "excessive",
  "other",
] as const;
export type RejectReason = (typeof REJECT_REASONS)[number];

export interface DsarDeps {
  store: GovernanceStore;
  pseudo: Pseudonymiser;
  sealer: Sealer;
  providers: readonly SubjectDataProvider[];
  audit: GovernanceAudit;
  verifier: RequesterVerifier;
  residency: ResidencyPolicy;
  holds: HoldRegistry;
  signer: ManifestSigner;
  /** Region this instance serves; the default bundle destination. */
  serviceRegion?: string;
  now?: () => Date;
  /** Test seam: called at named points of an erase so a test can crash there. */
  checkpoint?: (name: string) => void | Promise<void>;
}

export interface OpenInput {
  kind: RequestKind;
  identifiers: readonly Identifier[];
  destinationRegion?: string;
  receivedAt?: Date;
}

export interface ProviderOutcome {
  provider: string;
  held: boolean;
  erase?: EraseResult;
  verify?: CountResult;
}
export interface EraseOutcome {
  request: DsarRequest;
  status: "completed" | "held";
  providers: ProviderOutcome[];
}

export type SlaState = "ok" | "at_risk" | "breached" | "closed";
export function slaState(r: DsarRequest, now: Date): SlaState {
  if (!OPEN_STATUSES.includes(r.status)) return "closed";
  const due = (r.extendedUntil ?? r.dueAt).getTime();
  if (now.getTime() > due) return "breached";
  return due - now.getTime() <= AT_RISK_DAYS * DAY_MS ? "at_risk" : "ok";
}

export class ResidualDataError extends GovernanceError {
  constructor(readonly residual: { provider: string; residual: number }[]) {
    super(
      "residual_data",
      `verification found residual subject data in: ${residual.map((r) => r.provider).join(", ")}`,
    );
  }
}

export class DsarEngine {
  private readonly now: () => Date;
  constructor(private readonly d: DsarDeps) {
    this.now = d.now ?? (() => new Date());
  }

  // ---- lifecycle -------------------------------------------------------------------------------------------------------------

  async open(p: Principal, i: OpenInput): Promise<DsarRequest> {
    const t = p.tenantId;
    requireOfficer(p, t);
    const ids = normalizeIds(i.identifiers);
    if (ids.length === 0)
      throw new GovernanceError("invalid", "at least one identifier is required");
    const { subjectId } = await resolveSubject(this.d.store, this.d.pseudo, t, ids);
    const subjectRef = await this.d.pseudo.subjectRef(t, subjectId);
    const receivedAt = i.receivedAt ?? this.now();
    const id = randomUUID();
    await this.d.audit.emit({
      tenantId: t,
      action: "dsar.received",
      actorId: p.id,
      reason: `kind=${i.kind}`,
      input: { request_id: id, kind: i.kind, subject_ref: subjectRef },
      output: { due_at: new Date(receivedAt.getTime() + SLA_DAYS * DAY_MS).toISOString() },
      raw: ids.map((x) => x.value),
    });
    const req: DsarRequest = {
      tenantId: t,
      id,
      kind: i.kind,
      subjectId,
      subjectRef,
      status: "received",
      receivedAt,
      dueAt: new Date(receivedAt.getTime() + SLA_DAYS * DAY_MS),
      extendedUntil: null,
      extensionReason: null,
      verifiedAt: null,
      verifiedMethod: null,
      requestedBy: p.id,
      destinationRegion: i.destinationRegion ?? null,
      sealedIdentifiers: await this.d.sealer.seal(t, { identifiers: ids }),
      result: {},
      rev: 1,
    };
    await this.d.store.insertRequest(req);
    return req;
  }

  private async load(p: Principal, id: string): Promise<DsarRequest> {
    requireOfficer(p, p.tenantId);
    const r = await this.d.store.getRequest(p.tenantId, id);
    if (!r) throw new GovernanceError("not_found", "request not found");
    return r;
  }

  async get(p: Principal, id: string): Promise<DsarRequest> {
    return this.load(p, id);
  }
  async list(p: Principal, statuses?: readonly RequestStatus[]): Promise<DsarRequest[]> {
    requireOfficer(p, p.tenantId);
    return this.d.store.listRequests(p.tenantId, statuses);
  }

  private async identifiers(r: DsarRequest): Promise<Identifier[]> {
    if (!r.sealedIdentifiers)
      throw new GovernanceError("invalid", "identifiers were shredded after completion");
    return (
      await this.d.sealer.open<{ identifiers: Identifier[] }>(r.tenantId, r.sealedIdentifiers)
    ).identifiers;
  }

  async verify(p: Principal, id: string, evidence: unknown): Promise<DsarRequest> {
    const r = await this.load(p, id);
    if (r.status !== "received") return r; // idempotent: already verified or closed
    const v = await this.d.verifier.verify(
      { tenantId: r.tenantId, requestId: r.id, subjectRef: r.subjectRef, kind: r.kind },
      evidence,
    );
    if (!v.ok) {
      await this.d.audit.emit({
        tenantId: r.tenantId,
        action: "dsar.verification.failed",
        actorId: p.id,
        decision: "DENY",
        input: { request_id: r.id, subject_ref: r.subjectRef },
      });
      return r;
    }
    await this.d.audit.emit({
      tenantId: r.tenantId,
      action: "dsar.verified",
      actorId: p.id,
      reason: `method=${v.method}`,
      input: { request_id: r.id, subject_ref: r.subjectRef },
    });
    return this.d.store.updateRequest(
      { ...r, status: "verified", verifiedAt: this.now(), verifiedMethod: v.method },
      r.rev,
    );
  }

  async extend(p: Principal, id: string, reason: string): Promise<DsarRequest> {
    const r = await this.load(p, id);
    if (!OPEN_STATUSES.includes(r.status))
      throw new GovernanceError("invalid", "request is closed");
    if (r.extendedUntil !== null)
      throw new GovernanceError("conflict", "a request can be extended once");
    if (reason.trim().length < 3)
      throw new GovernanceError("invalid", "an extension needs a reason");
    if (this.now().getTime() > r.dueAt.getTime())
      throw new GovernanceError(
        "invalid",
        "the deadline has already passed; an extension must be notified within it",
      );
    const until = new Date(r.dueAt.getTime() + EXTENSION_DAYS * DAY_MS);
    await this.d.audit.emit({
      tenantId: r.tenantId,
      action: "dsar.extended",
      actorId: p.id,
      input: { request_id: r.id, subject_ref: r.subjectRef },
      output: { extended_until: until.toISOString() },
    });
    return this.d.store.updateRequest(
      { ...r, extendedUntil: until, extensionReason: reason },
      r.rev,
    );
  }

  async reject(p: Principal, id: string, reason: RejectReason): Promise<DsarRequest> {
    const r = await this.load(p, id);
    if (!(REJECT_REASONS as readonly string[]).includes(reason))
      throw new GovernanceError("invalid", "unknown reject reason");
    if (!OPEN_STATUSES.includes(r.status))
      throw new GovernanceError("invalid", "request is closed");
    await this.d.audit.emit({
      tenantId: r.tenantId,
      action: "dsar.rejected",
      actorId: p.id,
      reason,
      input: { request_id: r.id, subject_ref: r.subjectRef },
    });
    return this.d.store.updateRequest({ ...r, status: "rejected", sealedIdentifiers: null }, r.rev);
  }

  // ---- context ---------------------------------------------------------------------------------------------------------------

  private async ctx(r: DsarRequest): Promise<ProviderContext> {
    const subj = await this.d.store.getSubject(r.tenantId, r.subjectId);
    const salt = subj?.salt ?? null;
    return {
      tenantId: r.tenantId,
      now: this.now(),
      pseudonym: async (kind, value) => {
        if (salt === null) throw new GovernanceError("invalid", "subject already shredded");
        return this.d.pseudo.tokenFor(r.tenantId, salt, {
          kind: kind as Identifier["kind"],
          value,
        });
      },
    };
  }

  /** Fixed-point of the identifiers every store knows about the same person (bounded). */
  private async closure(
    r: DsarRequest,
    ctx: ProviderContext,
    start: Identifier[],
  ): Promise<Identifier[]> {
    let ids = normalizeIds(start);
    for (let round = 0; round < 3; round++) {
      const next = new Set(ids.map((x) => `${x.kind}\u0000${x.value}`));
      const extra: Identifier[] = [];
      for (const p of this.d.providers) {
        for (const f of (await p.find(ctx, ids)).discovered ?? []) {
          const [n] = normalizeIds([f]);
          if (n && !next.has(`${n.kind}\u0000${n.value}`)) {
            next.add(`${n.kind}\u0000${n.value}`);
            extra.push(n);
          }
        }
      }
      if (extra.length === 0) break;
      ids = normalizeIds([...ids, ...extra]);
    }
    void r;
    return ids;
  }

  // ---- export ----------------------------------------------------------------------------------------------------------------

  async export(p: Principal, id: string): Promise<ExportBundle> {
    const r = await this.load(p, id);
    if (r.kind !== "export" && r.kind !== "erase")
      throw new GovernanceError("invalid", "request kind has no export");
    if (r.status === "received")
      throw new GovernanceError("not_verified", "requester is not verified");
    if (!(["verified", "processing", "completed"] as RequestStatus[]).includes(r.status))
      throw new GovernanceError("invalid", `request is ${r.status}`);
    const dest = r.destinationRegion ?? this.d.serviceRegion;
    try {
      await this.d.residency.assertEgress(r.tenantId, dest);
    } catch (e) {
      await this.d.audit.emit({
        tenantId: r.tenantId,
        action: "dsar.export.refused",
        actorId: p.id,
        decision: "DENY",
        reason: "residency",
        input: { request_id: r.id, subject_ref: r.subjectRef, destination: dest ?? null },
      });
      throw new GovernanceError("residency", (e as Error).message);
    }
    const ctx = await this.ctx(r);
    const ids = await this.closure(r, ctx, await this.identifiers(r));
    const records: ExportBundle["records"] = {};
    const stores: ExportManifest["stores"] = [];
    let total = 0;
    for (const prov of this.d.providers) {
      const cols = await prov.export(ctx, ids);
      const m: ExportManifest["stores"][number]["collections"] = [];
      records[prov.id] = {};
      for (const c of cols) {
        const recs = JSON.parse(JSON.stringify(c.records)) as unknown[];
        (records[prov.id] as Record<string, unknown[]>)[c.name] = recs;
        m.push({ name: c.name, count: recs.length, sha256: hashJson(recs) });
        total += recs.length;
      }
      stores.push({ provider: prov.id, declaration: prov.declaration, collections: m });
      await this.d.store.putStep({
        tenantId: r.tenantId,
        requestId: r.id,
        provider: prov.id,
        phase: "export",
        status: "done",
        result: { collections: m },
      });
    }
    const manifest: ExportManifest = {
      version: 1,
      request_id: r.id,
      tenant_id: r.tenantId,
      subject_ref: r.subjectRef,
      generated_at: this.now().toISOString(),
      stores,
      total_records: total,
      records_sha256: hashJson(records),
    };
    const bundle: ExportBundle = { manifest, records, signature: this.d.signer.sign(manifest) };
    await this.d.audit.emit({
      tenantId: r.tenantId,
      action: "dsar.export.completed",
      actorId: p.id,
      input: { request_id: r.id, subject_ref: r.subjectRef },
      output: { total_records: total, records_sha256: manifest.records_sha256 },
      raw: ids.map((x) => x.value),
    });
    if (r.kind === "export" && r.status !== "completed")
      await this.d.store.updateRequest(
        {
          ...r,
          status: "completed",
          sealedIdentifiers: null,
          result: {
            ...r.result,
            export: { total_records: total, records_sha256: manifest.records_sha256 },
          },
        },
        r.rev,
      );
    return bundle;
  }

  // ---- erase -----------------------------------------------------------------------------------------------------------------

  private async heldProviders(
    r: DsarRequest,
    holds: Hold[],
    ids: Identifier[],
  ): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    const groups = await this.d.holds.activeGroups(r.tenantId, holds);
    for (const prov of this.d.providers)
      for (const cls of prov.declaration.dataClasses) {
        const wide = classWideHold(holds, cls);
        if (wide) {
          out.set(prov.id, wide.id);
          break;
        }
        const sub = subjectScopedHolds(holds, cls).find(
          (h) =>
            (groups.get(h.id) ?? []).some((g) => overlaps(g, ids)) || h.subjectId === r.subjectId,
        );
        if (sub) {
          out.set(prov.id, sub.id);
          break;
        }
      }
    return out;
  }

  private async cp(name: string): Promise<void> {
    await this.d.checkpoint?.(name);
  }

  /** Idempotent and resumable: call again after a crash or after a hold is released. */
  async erase(p: Principal, id: string): Promise<EraseOutcome> {
    let r = await this.load(p, id);
    if (r.kind !== "erase") throw new GovernanceError("invalid", "not an erasure request");
    if (r.status === "completed")
      return {
        request: r,
        status: "completed",
        providers: (r.result["providers"] as ProviderOutcome[] | undefined) ?? [],
      };
    if (r.status === "received")
      throw new GovernanceError("not_verified", "requester is not verified");
    if (r.status !== "verified" && r.status !== "processing")
      throw new GovernanceError("invalid", `request is ${r.status}`);

    const first = r.status === "verified";
    await this.d.audit.emit({
      tenantId: r.tenantId,
      action: first ? "dsar.erase.started" : "dsar.erase.resumed",
      actorId: p.id,
      input: { request_id: r.id, subject_ref: r.subjectRef },
    });
    if (first) r = await this.d.store.updateRequest({ ...r, status: "processing" }, r.rev);
    await this.cp("erase:start");

    const ctx = await this.ctx(r);
    const start = await this.identifiers(r);
    const ids = await this.closure(r, ctx, start);
    if (ids.length !== start.length) {
      // Newly discovered identifiers are attached to the subject (future requests resolve to it) and re-sealed for resume.
      const lookups = await Promise.all(
        ids.map(async (i) => ({ hmac: await this.d.pseudo.lookup(r.tenantId, i), kind: i.kind })),
      );
      await this.d.store.addLookups(r.tenantId, r.subjectId, lookups);
      r = await this.d.store.updateRequest(
        { ...r, sealedIdentifiers: await this.d.sealer.seal(r.tenantId, { identifiers: ids }) },
        r.rev,
      );
    }

    const holds = await this.d.store.listHolds(r.tenantId, true);
    const held = await this.heldProviders(r, holds, ids);
    const outcomes: ProviderOutcome[] = [];

    for (const prov of this.d.providers) {
      if (held.has(prov.id)) {
        outcomes.push({ provider: prov.id, held: true });
        continue;
      }
      await this.cp(`before:${prov.id}`);
      const res = await prov.erase(ctx, ids);
      await this.cp(`after:${prov.id}`);
      const prev = await this.d.store.getStep(r.tenantId, r.id, prov.id, "erase");
      const pr = (prev?.result ?? {}) as Partial<EraseResult>;
      const cum: EraseResult = {
        erased: (pr.erased ?? 0) + res.erased,
        pseudonymised: (pr.pseudonymised ?? 0) + res.pseudonymised,
        retained: res.retained,
      };
      await this.d.store.putStep({
        tenantId: r.tenantId,
        requestId: r.id,
        provider: prov.id,
        phase: "erase",
        status: "done",
        result: { ...cum },
      } satisfies StepRecord);
      outcomes.push({ provider: prov.id, held: false, erase: cum });
    }

    // Verification pass: ALWAYS re-queries every (non-held) provider, whatever the steps say.
    await this.cp("verify:start");
    const residual: { provider: string; residual: number }[] = [];
    for (const o of outcomes) {
      if (o.held) continue;
      const prov = this.d.providers.find((x) => x.id === o.provider) as SubjectDataProvider;
      const c = await prov.count(ctx, ids);
      o.verify = c;
      await this.d.store.putStep({
        tenantId: r.tenantId,
        requestId: r.id,
        provider: prov.id,
        phase: "verify",
        status: c.residual === 0 ? "done" : "failed",
        result: { ...c },
      });
      if (c.residual > 0) residual.push({ provider: prov.id, residual: c.residual });
    }
    if (residual.length > 0) {
      await this.d.audit.emit({
        tenantId: r.tenantId,
        action: "dsar.erase.verification_failed",
        actorId: p.id,
        decision: "DENY",
        input: { request_id: r.id, subject_ref: r.subjectRef },
        output: { residual },
      });
      await this.d.store.updateRequest(
        { ...r, result: { ...r.result, verification: { ok: false, residual } } },
        r.rev,
      );
      throw new ResidualDataError(residual);
    }

    if (held.size > 0) {
      const blocked = [...held].map(([provider, hold]) => ({ provider, hold }));
      await this.d.audit.emit({
        tenantId: r.tenantId,
        action: "dsar.erase.held",
        actorId: p.id,
        reason: "legal_hold",
        input: { request_id: r.id, subject_ref: r.subjectRef },
        output: { blocked },
      });
      const request = await this.d.store.updateRequest(
        {
          ...r,
          result: { ...r.result, blocked, verification: { ok: false, held: blocked.length } },
        },
        r.rev,
      );
      return { request, status: "held", providers: outcomes };
    }

    const proof = {
      ok: true,
      verified_at: this.now().toISOString(),
      providers: outcomes.map((o) => ({
        provider: o.provider,
        erased: o.erase?.erased ?? 0,
        pseudonymised: o.erase?.pseudonymised ?? 0,
        retained: o.verify?.retained ?? 0,
        residual: o.verify?.residual ?? 0,
      })),
    };
    await this.cp("before-complete");
    await this.d.audit.emit({
      tenantId: r.tenantId,
      action: "dsar.erase.completed",
      actorId: p.id,
      input: { request_id: r.id, subject_ref: r.subjectRef },
      output: { proof_sha256: hashJson(proof) },
      raw: ids.map((x) => x.value),
    });
    await this.cp("before-shred");
    await this.d.store.shredSubject(r.tenantId, r.subjectId, this.now());
    const request = await this.d.store.updateRequest(
      {
        ...r,
        status: "completed",
        sealedIdentifiers: null,
        result: { verification: proof, providers: outcomes },
      },
      r.rev,
    );
    return { request, status: "completed", providers: outcomes };
  }

  // ---- restriction request ---------------------------------------------------------------------------------------------------

  async applyRestriction(p: Principal, id: string, reason: string): Promise<DsarRequest> {
    const r = await this.load(p, id);
    if (r.kind !== "restrict") throw new GovernanceError("invalid", "not a restriction request");
    if (r.status === "received")
      throw new GovernanceError("not_verified", "requester is not verified");
    if (r.status === "completed") return r;
    const ids = await this.identifiers(r);
    await this.d.holds.restrict(p, ids, reason);
    return this.d.store.updateRequest(
      { ...r, status: "completed", sealedIdentifiers: null },
      r.rev,
    );
  }

  // ---- SLA -------------------------------------------------------------------------------------------------------------------

  /** Emit (once per level) the at-risk / breached audit events for open requests. */
  async sweepSla(p: Principal): Promise<{ id: string; state: SlaState }[]> {
    requireOfficer(p, p.tenantId);
    const out: { id: string; state: SlaState }[] = [];
    for (const r of await this.d.store.listRequests(p.tenantId, OPEN_STATUSES)) {
      const state = slaState(r, this.now());
      if (state === "ok" || state === "closed") continue;
      out.push({ id: r.id, state });
      const flagged = (r.result["sla_flags"] as string[] | undefined) ?? [];
      if (flagged.includes(state)) continue;
      await this.d.audit.emit({
        tenantId: r.tenantId,
        action: state === "breached" ? "dsar.sla.breached" : "dsar.sla.at_risk",
        actorId: p.id,
        actorType: "human",
        input: { request_id: r.id, subject_ref: r.subjectRef },
        output: { due_at: (r.extendedUntil ?? r.dueAt).toISOString() },
      });
      await this.d.store.updateRequest(
        { ...r, result: { ...r.result, sla_flags: [...flagged, state] } },
        r.rev,
      );
    }
    return out;
  }
}
