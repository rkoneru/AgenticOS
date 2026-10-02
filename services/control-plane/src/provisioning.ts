import { canonicalize, sha256Hex } from "@axis/contracts";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parse } from "yaml";
import type { AdminAudit } from "./audit.js";
import { conflict, CpError, invalid } from "./errors.js";
import { BASELINE_PACK, compileValidator, type PackValidator } from "./policies.js";
import {
  StoreConflict,
  type Budget,
  type ControlPlaneStore,
  type TenantSettings,
} from "./types.js";

export const DEFAULT_BASELINE_PACK = fileURLToPath(
  new URL("../../../policies/baseline-deny/pack.yaml", import.meta.url),
);

export const DEFAULT_BUDGETS: Omit<Budget, "tenantId" | "id">[] = [
  {
    scope: "tenant",
    target: "",
    metric: "tokens",
    period: "day",
    soft: 4_000_000,
    hard: 5_000_000,
  },
  { scope: "tenant", target: "", metric: "cost_usd", period: "day", soft: 80, hard: 100 },
  { scope: "run", target: "", metric: "tokens", period: "run", soft: 200_000, hard: 250_000 },
  { scope: "run", target: "", metric: "tool_calls", period: "run", soft: 40, hard: 50 },
];

export const DEFAULT_SETTINGS: Omit<TenantSettings, "tenantId"> = {
  retentionAuditDays: 2555,
  retentionTranscriptDays: 30,
  retentionMemoryDays: 365,
};

export interface SignupInput {
  slug: string;
  name: string;
  ownerEmail: string;
  ownerName?: string;
  region: string;
  phiMode?: boolean;
}

export interface ProvisionerOptions {
  store: ControlPlaneStore;
  audit: AdminAudit;
  /** The region THIS control plane instance serves. Tenants are homed here or refused. */
  region: string;
  /** Regions the platform offers (signup rejects others). */
  regions: readonly string[];
  /** Default policy pack documents installed and activated for every tenant (baseline-deny). */
  defaultPacks?: unknown[];
  validator?: PackValidator;
  newId?: () => string;
  /** Runs after the tenant exists and is audited (dev: publishes the tenant's baseline-deny bundle for the kernel). */
  afterProvision?: (tenantId: string) => Promise<void>;
}

export function loadDefaultPacks(path: string = DEFAULT_BASELINE_PACK): unknown[] {
  return [parse(readFileSync(path, "utf8")) as unknown];
}

const SLUG = /^[a-z][a-z0-9-]{1,62}$/;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/;

/**
 * Tenant signup: tenant + owner + default policy packs (baseline-deny, active) + default budgets + settings + shared-RLS placement,
 * in ONE transaction, then the genesis audit event of the tenant's chain. Self-service e-mail verification is NOT built (NEEDS #185):
 * the HTTP layer exposes this behind a platform credential only.
 */
export class Provisioner {
  private readonly newId: () => string;
  constructor(private readonly o: ProvisionerOptions) {
    this.newId = o.newId ?? randomUUID;
  }

  async signup(
    i: SignupInput,
  ): Promise<{ tenantId: string; ownerMemberId: string; policyVersion: string }> {
    if (!SLUG.test(i.slug)) throw invalid("slug must match ^[a-z][a-z0-9-]{1,62}$");
    if (typeof i.name !== "string" || i.name.length < 1 || i.name.length > 120)
      throw invalid("name must be 1-120 characters");
    if (!EMAIL.test(i.ownerEmail)) throw invalid("a valid owner e-mail is required");
    if (!this.o.regions.includes(i.region))
      throw invalid(`unknown region; offered: ${this.o.regions.join(", ")}`);
    if (i.region !== this.o.region)
      throw new CpError(
        "region_mismatch",
        `this control plane serves ${this.o.region}; sign up against the ${i.region} endpoint`,
      );
    const docs = this.o.defaultPacks ?? loadDefaultPacks();
    const validate = this.o.validator ?? compileValidator;
    const v = validate(docs);
    if (!v.ok) throw new CpError("unavailable", "default policy packs do not validate");
    const packs = docs.map((d) => {
      const meta = (d as { metadata: { name: string; version: string } }).metadata;
      const one = validate([d]);
      if (!one.ok) throw new CpError("unavailable", "default policy pack does not validate");
      return {
        packId: this.newId(),
        versionId: this.newId(),
        name: meta.name,
        version: meta.version,
        source: d,
        rego: one.rego,
        contentHash: sha256Hex(canonicalize(d)),
      };
    });
    if (!packs.some((p) => p.name === BASELINE_PACK))
      throw new CpError("unavailable", "the baseline-deny pack is required");
    const tenantId = this.newId();
    const ownerId = this.newId();
    try {
      await this.o.store.provisionTenant({
        tenantId,
        slug: i.slug,
        name: i.name,
        region: i.region,
        phiMode: i.phiMode ?? false,
        owner: {
          id: ownerId,
          userRef: `signup:${ownerId}`,
          email: i.ownerEmail.toLowerCase(),
          ...(i.ownerName ? { displayName: i.ownerName } : {}),
        },
        packs,
        budgets: DEFAULT_BUDGETS,
        settings: DEFAULT_SETTINGS,
        placement: { isolationTier: "shared_rls" },
      });
    } catch (err) {
      if (err instanceof StoreConflict) throw conflict("slug already in use");
      throw err;
    }
    await this.o.audit.record({
      tenantId,
      actor: { type: "system", id: "signup" },
      action: "tenant.provision",
      decision: "ALLOW",
      policyVersion: v.policyVersion,
      reason: `region=${i.region} tier=shared_rls owner=${ownerId} packs=${packs.map((p) => `${p.name}@${p.version}`).join(",")}`,
      inputs: { slug: i.slug, region: i.region },
      outputs: { tenant: tenantId, owner: ownerId },
    });
    await this.o.afterProvision?.(tenantId);
    return { tenantId, ownerMemberId: ownerId, policyVersion: v.policyVersion };
  }
}
