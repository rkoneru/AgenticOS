import type { AblDocument } from "@axis/abl";
import type { UsageSink } from "@axis/billing";
import { RegistryError, compareVersionStrings, conflict, invalid, notFound } from "@axis/registry";
import { createHash } from "node:crypto";
import {
  DEFAULT_BASELINE,
  consentDigest,
  diffCapabilities,
  isCapability,
  type Baseline,
  type Capability,
  type PermissionDiff,
} from "./capabilities.js";
import { guarded, iso, mutate, requireRole, type Ctx } from "./ctx.js";
import { tenantScope, type Doc } from "./docstore.js";
import type { ListingService } from "./listings.js";
import { recommendedPolicyPack } from "./policy-stub.js";
import { scanBlueprint, type ScanFinding, type Severity } from "./scan.js";
import type { InstallRecord, TenantPrincipal } from "./types.js";

export interface Preview {
  namespace: string;
  name: string;
  version: string;
  contentHash: string;
  riskLevel: string;
  maxSeverity: Severity;
  findings: ScanFinding[];
  capabilities: Capability[];
  diff: PermissionDiff;
  /** What `install` must echo to prove the admin saw THIS diff of THIS blueprint. */
  consentDigest: string;
}

export const installKey = (ns: string, name: string): string => `${ns}/${name}`;

export class InstallService {
  constructor(
    private readonly c: Ctx,
    private readonly listings: ListingService,
    private readonly metering?: UsageSink,
  ) {}

  // ------------------------------------------------------------------ baseline
  async baseline(p: TenantPrincipal): Promise<Baseline> {
    requireRole(p, "read");
    return this.baselineOf(p.tenantId);
  }
  private async baselineOf(tenantId: string): Promise<Baseline> {
    const d = await this.c.docs.get<Baseline>(tenantScope(tenantId), tenantId, "baselines", "self");
    return d ? d.data : DEFAULT_BASELINE;
  }
  async setBaseline(p: TenantPrincipal, granted: Capability[]): Promise<Baseline> {
    requireRole(p, "admin");
    if (!Array.isArray(granted) || granted.length > 500 || !granted.every(isCapability))
      throw invalid("granted must be a list of {key, level}");
    const b: Baseline = { granted: granted.map((g) => ({ key: g.key, level: g.level })) };
    const scope = tenantScope(p.tenantId);
    const cur = await this.c.docs.get(scope, p.tenantId, "baselines", "self");
    return mutate(
      this.c,
      p.tenantId,
      { type: "human", id: p.subject },
      "marketplace.baseline.set",
      { count: b.granted.length },
      async () => {
        await guarded(
          () =>
            cur
              ? this.c.docs.update(scope, p.tenantId, "baselines", "self", cur.rev, b)
              : this.c.docs.insert(scope, p.tenantId, "baselines", "self", b),
          "baseline",
        );
        return b;
      },
    );
  }

  // ------------------------------------------------------------------ preview
  /** Everything fresh: listing status, approval pin, registry verification, scan and diff. Used by preview AND by install/update. */
  private async evaluate(
    p: TenantPrincipal,
    ns: string,
    name: string,
    range: string,
    against: readonly Capability[],
  ): Promise<Preview> {
    const { version, contentHash } = await this.listings.installable(ns, name, range);
    // Verified against the registry NOW (signature, provenance, hash); yanked versions are refused.
    const bp = await this.c.registry.getVersion({ tenantId: p.tenantId }, ns, name, version);
    if (bp.contentHash !== contentHash)
      throw new RegistryError(
        "verification_failed",
        "the registry content no longer matches the reviewed hash",
        ["approval_hash_mismatch"],
      );
    const scan = scanBlueprint(bp.abl as AblDocument, DEFAULT_BASELINE);
    const diff = diffCapabilities(against, scan.capabilities);
    return {
      namespace: ns,
      name,
      version,
      contentHash,
      riskLevel: bp.riskLevel,
      maxSeverity: scan.maxSeverity,
      findings: scan.findings,
      capabilities: scan.capabilities,
      diff,
      consentDigest: consentDigest({ namespace: ns, name, version, contentHash }, diff),
    };
  }

  async preview(p: TenantPrincipal, ns: string, name: string, range: string): Promise<Preview> {
    requireRole(p, "admin");
    return this.evaluate(p, ns, name, range, (await this.baselineOf(p.tenantId)).granted);
  }

  // ------------------------------------------------------------------ install / update / uninstall
  async install(
    p: TenantPrincipal,
    input: {
      namespace: string;
      name: string;
      version: string;
      contentHash: string;
      consentDigest: string;
    },
  ): Promise<InstallRecord> {
    requireRole(p, "admin");
    const scope = tenantScope(p.tenantId);
    const key = installKey(input.namespace, input.name);
    const cur = await this.c.docs.get<InstallRecord>(scope, p.tenantId, "installs", key);
    if (cur && cur.data.state !== "uninstalled") throw conflict("already installed (use update)");
    const pv = await this.evaluate(
      p,
      input.namespace,
      input.name,
      input.version,
      (await this.baselineOf(p.tenantId)).granted,
    );
    if (pv.version !== input.version) throw invalid("version must be an exact version");
    this.checkConsent(pv, input.contentHash, input.consentDigest);
    const listing = await this.listings.listed(input.namespace, input.name);
    const rec: InstallRecord = {
      id: this.c.newId(),
      namespace: pv.namespace,
      name: pv.name,
      version: pv.version,
      contentHash: pv.contentHash,
      publisherTenantId: listing.publisherTenantId,
      state: "active",
      granted: pv.capabilities,
      consentedBy: p.subject,
      consentedAt: iso(this.c.now()),
      flagReason: null,
      policyPack: recommendedPolicyPack(pv, pv.capabilities),
      meteredAt: null,
      installCount: (cur?.data.installCount ?? 0) + 1,
    };
    const saved = await mutate(
      this.c,
      p.tenantId,
      { type: "human", id: p.subject },
      "marketplace.install",
      {
        key,
        version: pv.version,
        contentHash: pv.contentHash,
        added: pv.diff.added.map((a) => a.key),
      },
      async () => {
        const doc = await guarded(
          () =>
            cur
              ? this.c.docs.update(scope, p.tenantId, "installs", key, cur.rev, rec)
              : this.c.docs.insert(scope, p.tenantId, "installs", key, rec),
          "install",
        );
        await this.stillInstallable(p.tenantId, doc, rec);
        return rec;
      },
    );
    return this.meter(p.tenantId, saved);
  }

  private checkConsent(pv: Preview, contentHash: string, digest: string): void {
    if (contentHash !== pv.contentHash)
      throw new RegistryError("conflict", "content hash differs from the reviewed blueprint", [
        "content_hash_mismatch",
      ]);
    if (digest !== pv.consentDigest)
      throw new RegistryError(
        "conflict",
        "consent does not match the current permission diff: preview again and re-consent",
        ["consent_required"],
      );
  }

  /** The diff an UPDATE would be consented against: the new version vs what this install was granted (not vs the baseline). */
  async updatePreview(
    p: TenantPrincipal,
    ns: string,
    name: string,
    version: string,
  ): Promise<Preview> {
    requireRole(p, "admin");
    const cur = await this.c.docs.get<InstallRecord>(
      tenantScope(p.tenantId),
      p.tenantId,
      "installs",
      installKey(ns, name),
    );
    if (!cur || cur.data.state === "uninstalled") throw notFound("not installed");
    return this.evaluate(p, ns, name, version, cur.data.granted);
  }

  /** Update to another approved version. WIDENING permissions requires fresh consent; downgrades are refused (rollback defence). */
  async update(
    p: TenantPrincipal,
    ns: string,
    name: string,
    input: { version: string; consentDigest?: string; allowDowngrade?: boolean },
  ): Promise<InstallRecord> {
    requireRole(p, "admin");
    const scope = tenantScope(p.tenantId);
    const key = installKey(ns, name);
    const cur = await this.c.docs.get<InstallRecord>(scope, p.tenantId, "installs", key);
    if (!cur || cur.data.state === "uninstalled") throw notFound("not installed");
    const pv = await this.evaluate(p, ns, name, input.version, cur.data.granted);
    if (pv.version !== input.version) throw invalid("version must be an exact version");
    if (compareVersionStrings(pv.version, cur.data.version) < 0 && input.allowDowngrade !== true)
      throw new RegistryError(
        "conflict",
        "refusing to move to an older version without allowDowngrade",
        ["rollback"],
      );
    if (pv.diff.widening) {
      if (input.consentDigest !== pv.consentDigest)
        throw new RegistryError(
          "conflict",
          "the new version asks for more permissions: re-consent required",
          ["consent_required"],
        );
    }
    const listing = await this.listings.listed(ns, name);
    const rec: InstallRecord = {
      ...cur.data,
      version: pv.version,
      contentHash: pv.contentHash,
      publisherTenantId: listing.publisherTenantId,
      state: "active",
      flagReason: null,
      granted: pv.capabilities, // least privilege: exactly what the new version needs, which the admin has seen
      consentedBy: pv.diff.widening ? p.subject : cur.data.consentedBy,
      consentedAt: pv.diff.widening ? iso(this.c.now()) : cur.data.consentedAt,
      policyPack: recommendedPolicyPack(pv, pv.capabilities),
    };
    return mutate(
      this.c,
      p.tenantId,
      { type: "human", id: p.subject },
      "marketplace.install.update",
      { key, from: cur.data.version, to: pv.version, widening: pv.diff.widening },
      async () => {
        const doc = await guarded(
          () => this.c.docs.update(scope, p.tenantId, "installs", key, cur.rev, rec),
          "install",
        );
        await this.stillInstallable(p.tenantId, doc, rec);
        return rec;
      },
    );
  }

  /**
   * A takedown flags the installs it can SEE. One that ran between this request's evaluation and its write found nothing to flag, so the
   * write would leave an active install of a taken-down version. Re-check AFTER the write (order: write, then read the listing; the
   * takedown does: block the listing, then look for installs): whichever of the two comes second sees the other, so the install is either
   * flagged by the takedown or refused and flagged here.
   */
  private async stillInstallable(
    tenantId: string,
    doc: Doc<InstallRecord>,
    rec: InstallRecord,
  ): Promise<void> {
    try {
      await this.listings.installable(rec.namespace, rec.name, rec.version);
      return;
    } catch {
      // fall through: not installable any more (or not provably so)
    }
    const reason = "taken down while this install was in progress";
    await this.c.docs
      .update(tenantScope(tenantId), tenantId, "installs", doc.key, doc.rev, {
        ...doc.data,
        state: "flagged",
        flagReason: reason,
      })
      .catch(() => undefined);
    throw conflict(
      `${rec.namespace}/${rec.name}@${rec.version} was taken down; the install was flagged`,
    );
  }

  async uninstall(p: TenantPrincipal, ns: string, name: string): Promise<void> {
    requireRole(p, "admin");
    const scope = tenantScope(p.tenantId);
    const key = installKey(ns, name);
    const cur = await this.c.docs.get<InstallRecord>(scope, p.tenantId, "installs", key);
    if (!cur || cur.data.state === "uninstalled") throw notFound("not installed");
    await mutate(
      this.c,
      p.tenantId,
      { type: "human", id: p.subject },
      "marketplace.uninstall",
      { key, version: cur.data.version },
      () =>
        guarded(
          () =>
            this.c.docs.update(scope, p.tenantId, "installs", key, cur.rev, {
              ...cur.data,
              state: "uninstalled",
              policyPack: null,
            }),
          "install",
        ),
    );
  }

  async list(p: TenantPrincipal): Promise<InstallRecord[]> {
    requireRole(p, "read");
    return (await this.c.docs.find<InstallRecord>(tenantScope(p.tenantId), "installs")).map(
      (d) => d.data,
    );
  }

  async get(p: TenantPrincipal, ns: string, name: string): Promise<InstallRecord> {
    requireRole(p, "read");
    const d = await this.c.docs.get<InstallRecord>(
      tenantScope(p.tenantId),
      p.tenantId,
      "installs",
      installKey(ns, name),
    );
    if (!d) throw notFound("not installed");
    return d.data;
  }

  // ------------------------------------------------------------------ metering
  /**
   * Publisher usage hook: one `marketplace_installs` record for the PUBLISHER's tenant per install, idempotent per install id. Failure
   * never fails or undoes the install: `meteredAt` stays null and `flushMetering` retries. Payouts are NOT implemented (NEEDS).
   */
  private async meter(installer: string, rec: InstallRecord): Promise<InstallRecord> {
    if (!this.metering) return rec;
    const who = createHash("sha256").update(installer).digest("hex").slice(0, 16);
    try {
      await this.metering.append({
        tenantId: rec.publisherTenantId,
        // One billable install per (installing tenant, listing): install -> uninstall -> install again must not run up the publisher's meter.
        idempotencyKey: `marketplace-install:${who}:${installKey(rec.namespace, rec.name)}`,
        meter: "marketplace_installs",
        quantity: 1n,
        eventTime: new Date(rec.consentedAt),
        dimensions: {
          listing: installKey(rec.namespace, rec.name),
          version: rec.version,
          installer: who,
        },
        source: "marketplace",
      });
    } catch {
      return rec;
    }
    const scope = tenantScope(installer);
    const cur = await this.c.docs.get<InstallRecord>(
      scope,
      installer,
      "installs",
      installKey(rec.namespace, rec.name),
    );
    if (!cur || cur.data.id !== rec.id || cur.data.meteredAt) return rec;
    const next = { ...cur.data, meteredAt: iso(this.c.now()) };
    await this.c.docs
      .update(scope, installer, "installs", cur.key, cur.rev, next)
      .catch(() => undefined);
    return next;
  }

  /** Retries every install of the tenant whose usage record has not been accepted yet. Safe to call repeatedly (idempotency keys). */
  async flushMetering(p: TenantPrincipal): Promise<number> {
    requireRole(p, "admin");
    let n = 0;
    for (const i of await this.list(p))
      if (
        i.meteredAt === null &&
        i.state !== "uninstalled" &&
        (await this.meter(p.tenantId, i)).meteredAt
      )
        n++;
    return n;
  }
}
