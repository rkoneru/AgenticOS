import { canonicalize, sha256Hex } from "@axis/contracts";
import { compilePolicySet, opaBuildWasm, opaCheck, type PolicyIssue } from "@axis/policy";
import { randomUUID } from "node:crypto";
import { conflict, CpError, invalid, notFound } from "./errors.js";
import type { Principal } from "./authz.js";
import { StoreConflict, type ControlPlaneStore, type PackVersionRecord } from "./types.js";

export type ValidationResult = { ok: true; policyVersion: string; rego: string } | { ok: false; issues: PolicyIssue[] };

/** Validates a SET of policy documents the way the Risk Kernel will load it: DSL schema + compile + `opa check --strict` + Wasm build. */
export type PackValidator = (docs: unknown[]) => ValidationResult;

export const compileValidator: PackValidator = (docs) => {
  const c = compilePolicySet(docs);
  if (!c.ok) return c;
  try {
    opaCheck(c.rego);
    opaBuildWasm(c.rego);
  } catch (err) {
    return { ok: false, issues: [{ doc: -1, path: "/", code: "OPA_REJECTED", message: (err as Error).message.slice(0, 300) }] };
  }
  return { ok: true, policyVersion: c.policyVersion, rego: c.rego };
};

export const BASELINE_PACK = "baseline-deny";

export interface PublicPackVersion {
  versionId: string;
  pack: string;
  version: string;
  contentHash: string;
  createdAt: Date;
  active: boolean;
}

const issuesToError = (issues: PolicyIssue[]): CpError =>
  invalid(`policy does not validate: ${issues.slice(0, 5).map((i) => `${i.code} ${i.path}`).join("; ")}`);

/**
 * Versioned policy packs per tenant. A version is immutable once published (validated by compiling it). Activation compiles the
 * whole prospective active SET again (packs compose), so a set that does not compile can never become active, and is audited by the
 * admin layer. The baseline-deny pack cannot be deactivated (a tenant is never left without its default DENY floor).
 */
export class PolicyPackService {
  private readonly newId: () => string;
  constructor(
    private readonly o: { store: ControlPlaneStore; validator?: PackValidator; now?: () => Date; newId?: () => string },
  ) {
    this.newId = o.newId ?? randomUUID;
  }
  private get validate(): PackValidator {
    return this.o.validator ?? compileValidator;
  }

  async publish(p: Principal, doc: unknown): Promise<PublicPackVersion> {
    const v = this.validate([doc]);
    if (!v.ok) throw issuesToError(v.issues);
    const meta = (doc as { metadata: { name: string; version: string } }).metadata;
    try {
      const rec = await this.o.store.insertPackVersion({
        tenantId: p.tenantId,
        packId: this.newId(),
        packName: meta.name,
        versionId: this.newId(),
        version: meta.version,
        source: doc,
        rego: v.rego,
        contentHash: sha256Hex(canonicalize(doc)),
      });
      return this.pub(rec, false);
    } catch (err) {
      if (err instanceof StoreConflict) throw conflict(`${meta.name}@${meta.version} already exists (versions are immutable)`);
      throw err;
    }
  }

  private pub(r: PackVersionRecord, active: boolean): PublicPackVersion {
    return { versionId: r.versionId, pack: r.packName, version: r.version, contentHash: r.contentHash, createdAt: r.createdAt, active };
  }

  async list(p: Principal): Promise<PublicPackVersion[]> {
    const [versions, active] = await Promise.all([this.o.store.listPackVersions(p.tenantId), this.o.store.listActiveAssignments(p.tenantId)]);
    const on = new Set(active.map((a) => a.versionId));
    return versions.map((v) => this.pub(v, on.has(v.versionId)));
  }

  async getVersion(p: Principal, versionId: string): Promise<PackVersionRecord> {
    const v = await this.o.store.getPackVersion(p.tenantId, versionId);
    if (!v) throw notFound("policy version not found");
    return v;
  }

  /** The documents that would be active if `replace` became active (same pack name replaced). */
  private async prospective(tenantId: string, replace?: PackVersionRecord): Promise<{ docs: unknown[]; names: string[] }> {
    const active = await this.o.store.listActiveAssignments(tenantId);
    const docs: unknown[] = [];
    const names: string[] = [];
    for (const a of active) {
      const v = await this.o.store.getPackVersion(tenantId, a.versionId);
      if (!v || (replace && v.packName === replace.packName)) continue;
      docs.push(v.source);
      names.push(v.packName);
    }
    if (replace) {
      docs.push(replace.source);
      names.push(replace.packName);
    }
    return { docs, names };
  }

  async activate(p: Principal, versionId: string): Promise<{ policyVersion: string; pack: string; version: string }> {
    const v = await this.getVersion(p, versionId);
    const { docs } = await this.prospective(p.tenantId, v);
    const r = this.validate(docs);
    if (!r.ok) throw issuesToError(r.issues);
    await this.o.store.activatePackVersion(p.tenantId, versionId, p.memberId, this.o.now ? this.o.now() : new Date());
    return { policyVersion: r.policyVersion, pack: v.packName, version: v.version };
  }

  async deactivate(p: Principal, packName: string): Promise<void> {
    if (packName === BASELINE_PACK) throw conflict("the baseline-deny pack cannot be deactivated; activate a newer version instead");
    const active = await this.o.store.listActiveAssignments(p.tenantId);
    for (const a of active) {
      const v = await this.o.store.getPackVersion(p.tenantId, a.versionId);
      if (v?.packName === packName) {
        await this.o.store.deactivatePack(p.tenantId, a.packId, this.o.now ? this.o.now() : new Date());
        return;
      }
    }
    throw notFound("pack is not active");
  }

  /** What the Risk Kernel should load for this tenant. */
  async effective(tenantId: string): Promise<{ policyVersion: string; rego: string; packs: string[] }> {
    const { docs, names } = await this.prospective(tenantId);
    const r = this.validate(docs);
    if (!r.ok) throw issuesToError(r.issues);
    return { policyVersion: r.policyVersion, rego: r.rego, packs: names };
  }
}
