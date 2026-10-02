import { randomUUID } from "node:crypto";
import type { AuditEvent } from "@axis/contracts";
import {
  ApiKeyService,
  type CreateKeyInput,
  type CreatedKey,
  type PublicApiKey,
} from "./apikeys.js";
import type { AdminAudit } from "./audit.js";
import {
  isRead,
  type Action,
  type Authorizer,
  type AuthzDecision,
  type AuthzRequest,
  type Principal,
} from "./authz.js";
import type { DirectoryService } from "./directory.js";
import type { DomainService } from "./domains.js";
import { CpError, conflict, forbidden, invalid, notFound } from "./errors.js";
import type { IdentityProvider } from "./idp.js";
import type { ModelKeyService, PublicModelKey } from "./modelkeys.js";
import type { PolicyBundlePublisher } from "./bundles.js";
import type { PackValidator, PolicyPackService, PublicPackVersion } from "./policies.js";
import { isExternalRole, isRole, ROLE_RANK, type Role } from "./roles.js";
import type { SessionService } from "./sessions.js";
import type { RegionGuard } from "./tenancy.js";
import {
  LastOwnerError,
  StoreConflict,
  type Budget,
  type BudgetMetric,
  type BudgetPeriod,
  type BudgetScope,
  type ControlPlaneStore,
  type DirectoryRecord,
  type IdentityConnection,
  type Member,
  type TenantSettings,
} from "./types.js";

export interface AuditReaderLike {
  listEvents(tenantId: string, q: { fromSeq?: number; limit: number }): Promise<AuditEvent[]>;
}

export interface AdminDeps {
  store: ControlPlaneStore;
  authorizer: Authorizer;
  audit: AdminAudit;
  sessions: SessionService;
  apiKeys: ApiKeyService;
  modelKeys: ModelKeyService;
  policies: PolicyPackService;
  directories: DirectoryService;
  domains: DomainService;
  idp: IdentityProvider;
  region: RegionGuard;
  auditReader?: AuditReaderLike;
  /** Publishes the tenant's compiled active policy for the Risk Kernel after every activation/deactivation (dev: files). */
  bundles?: PolicyBundlePublisher;
  newId?: () => string;
  now?: () => Date;
  validator?: PackValidator;
}

export interface PublicMember {
  id: string;
  email: string;
  role: Role;
  status: Member["status"];
  displayName?: string;
  directoryManaged: boolean;
  createdAt: Date;
}

const pubMember = (m: Member): PublicMember => ({
  id: m.id,
  email: m.email,
  role: m.role,
  status: m.status,
  ...(m.displayName ? { displayName: m.displayName } : {}),
  directoryManaged: m.directoryId !== undefined,
  createdAt: m.createdAt,
});

/** Audit detail is hashed canonically, which rejects NaN/Infinity: record them as text so validation (not the audit) refuses them. */
const num = (v: unknown): unknown =>
  typeof v === "number" && !Number.isFinite(v) ? String(v) : (v ?? null);

const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Ids from the path or body are untrusted: anything that is not a UUID is "not found", never passed to a store. */
const idOf = (v: unknown): string => {
  if (typeof v !== "string" || !UUID.test(v)) throw notFound();
  return v.toLowerCase();
};

type Resource = AuthzRequest["resource"];

/**
 * Tenant admin operations. Every method takes the authenticated `Principal` as its first argument and uses `principal.tenantId` for
 * ALL data access: no method accepts a tenant id. Order of every operation:
 *   1. region pin (mutations)   2. authorization (OPA, fail-closed)   3. audit the decision (mutations: allow and deny; reads: deny)
 *   4. perform   5. audit the outcome (mutations).
 * A mutation whose decision cannot be written to the tenant's audit chain is not performed.
 */
export class AdminService {
  private readonly newId: () => string;
  private readonly now: () => Date;
  constructor(private readonly d: AdminDeps) {
    this.newId = d.newId ?? randomUUID;
    this.now = d.now ?? (() => new Date());
  }

  // ------------------------------------------------------------------ guard
  private async decide(p: Principal, req: Omit<AuthzRequest, "principal">): Promise<AuthzDecision> {
    return this.d.authorizer.decide({ principal: p, ...req });
  }

  private async deniedAudit(
    p: Principal,
    action: string,
    dec: AuthzDecision,
    detail: Record<string, unknown>,
  ): Promise<never> {
    // A failed audit write must not turn a DENY into anything else.
    await this.d.audit
      .record({
        tenantId: p.tenantId,
        actor: { type: "human", id: p.memberId },
        action: `admin.${action}`,
        decision: "DENY",
        policyVersion: dec.policyVersion,
        reason: `credential=${p.credential} why=${dec.reason}`,
        inputs: detail,
        outputs: {},
      })
      .catch(() => undefined);
    throw forbidden();
  }

  /** Authorize + audit + run. `load` resolves the resource BEFORE the decision so attribute-based rules see its owner/environment. */
  private async guarded<T>(
    p: Principal,
    action: Action,
    opts: {
      resource?: Resource;
      targetRole?: Role;
      currentTargetRole?: Role;
      detail?: Record<string, unknown>;
      /** Called when `load` found nothing: re-decides without resource attributes so an unauthorized caller gets 403, not 404. */
      missing?: boolean;
    },
    fn: () => Promise<{ result: T; outputs?: Record<string, unknown> }>,
  ): Promise<T> {
    const detail = opts.detail ?? {};
    const mutation = !isRead(action);
    if (mutation) await this.d.region.assertWritable(p.tenantId);
    const dec = await this.decide(p, {
      action,
      ...(opts.resource ? { resource: opts.resource } : {}),
      ...(opts.targetRole ? { targetRole: opts.targetRole } : {}),
      ...(opts.currentTargetRole ? { currentTargetRole: opts.currentTargetRole } : {}),
    });
    if (!dec.allowed) return this.deniedAudit(p, action, dec, detail);
    if (opts.missing) throw notFound();
    if (mutation) {
      await this.d.audit.record({
        tenantId: p.tenantId,
        actor: { type: "human", id: p.memberId },
        action: `admin.${action}`,
        decision: "ALLOW",
        policyVersion: dec.policyVersion,
        reason: `credential=${p.credential} rules=${dec.winners.join(",")}`.slice(0, 900),
        inputs: detail,
        outputs: {},
      });
    }
    let out: { result: T; outputs?: Record<string, unknown> };
    try {
      out = await fn();
    } catch (err) {
      if (mutation) {
        const code =
          err instanceof CpError
            ? err.code
            : err instanceof LastOwnerError
              ? "last_owner"
              : "error";
        await this.d.audit
          .record({
            tenantId: p.tenantId,
            actor: { type: "human", id: p.memberId },
            action: `admin.${action}.result`,
            decision: "ALLOW",
            policyVersion: dec.policyVersion,
            reason: `failed code=${code}`,
            inputs: detail,
            outputs: { error: code },
          })
          .catch(() => undefined);
      }
      throw this.translate(err);
    }
    if (mutation)
      await this.d.audit
        .record({
          tenantId: p.tenantId,
          actor: { type: "human", id: p.memberId },
          action: `admin.${action}.result`,
          decision: "ALLOW",
          policyVersion: dec.policyVersion,
          reason: "ok",
          inputs: detail,
          outputs: out.outputs ?? {},
        })
        .catch(() => undefined);
    return out.result;
  }

  private translate(err: unknown): unknown {
    if (err instanceof LastOwnerError) return conflict(err.message);
    if (err instanceof StoreConflict) return conflict(err.message);
    return err;
  }

  // ------------------------------------------------------------------ tenant
  tenant(p: Principal): Promise<{
    id: string;
    slug: string;
    name: string;
    region: string;
    status: string;
    isolationTier: string;
  }> {
    return this.guarded(p, "tenant.read", {}, async () => {
      const t = await this.d.store.getTenant(p.tenantId);
      if (!t) throw notFound();
      const pl = await this.d.store.getPlacement(p.tenantId);
      return {
        result: {
          id: t.id,
          slug: t.slug,
          name: t.name,
          region: t.region,
          status: t.status,
          isolationTier: pl?.isolationTier ?? "shared_rls",
        },
      };
    });
  }

  // ------------------------------------------------------------------ members
  listMembers(
    p: Principal,
    limit = 50,
    after?: string,
  ): Promise<{ items: PublicMember[]; nextCursor?: string }> {
    return this.guarded(p, "members.read", {}, async () => {
      const r = await this.d.store.listMembers(
        p.tenantId,
        Math.min(Math.max(limit, 1), 200),
        after === undefined ? undefined : idOf(after),
      );
      return {
        result: {
          items: r.items.map(pubMember),
          ...(r.nextCursor ? { nextCursor: r.nextCursor } : {}),
        },
      };
    });
  }

  async getMember(p: Principal, id: string): Promise<PublicMember> {
    const mid = idOf(id);
    const m = await this.d.store.getMember(p.tenantId, mid);
    return this.guarded(p, "members.read", { ...(m ? {} : { missing: true }) }, () =>
      Promise.resolve({ result: pubMember(m as Member) }),
    );
  }

  /** Pre-provision a member (they sign in through the tenant's SSO connection with this verified e-mail). */
  async inviteMember(p: Principal, input: { email: string; role: Role }): Promise<PublicMember> {
    if (!isRole(input.role)) throw invalid("unknown role");
    return this.guarded(
      p,
      "members.invite",
      { targetRole: input.role, detail: { role: input.role } },
      async () => {
        if (typeof input.email !== "string" || !EMAIL.test(input.email))
          throw invalid("a valid e-mail is required");
        const id = this.newId();
        const m = await this.d.store.insertMember({
          tenantId: p.tenantId,
          id,
          userRef: `invite:${id}`,
          email: input.email.toLowerCase(),
          role: input.role,
          status: "active",
        });
        return { result: pubMember(m), outputs: { member: m.id, role: m.role } };
      },
    );
  }

  async updateMemberRole(p: Principal, id: string, role: Role): Promise<PublicMember> {
    const mid = idOf(id);
    if (!isRole(role)) throw invalid("unknown role");
    const m = await this.d.store.getMember(p.tenantId, mid);
    return this.guarded(
      p,
      "members.update_role",
      {
        ...(m ? { resource: { tenantId: m.tenantId } } : { missing: true }),
        targetRole: role,
        ...(m ? { currentTargetRole: m.role } : {}),
        detail: { member: mid, role },
      },
      async () => {
        const cur = m as Member;
        if (cur.status !== "active") throw conflict("member is not active");
        if (cur.directoryId !== undefined && !isExternalRole(role))
          throw invalid("a directory-managed member cannot be made owner");
        if (cur.role === "owner" && role !== "owner")
          await this.assertNotLastOwner(p.tenantId, cur.id);
        const next = await this.d.store.updateMember(p.tenantId, mid, { role }, this.now());
        if (!next) throw notFound();
        return { result: pubMember(next), outputs: { member: mid, from: cur.role, to: role } };
      },
    );
  }

  async removeMember(p: Principal, id: string): Promise<void> {
    const mid = idOf(id);
    const m = await this.d.store.getMember(p.tenantId, mid);
    return this.guarded(
      p,
      "members.remove",
      {
        ...(m
          ? { resource: { tenantId: m.tenantId }, currentTargetRole: m.role }
          : { missing: true }),
        detail: { member: mid },
      },
      async () => {
        const cur = m as Member;
        if (cur.role === "owner") await this.assertNotLastOwner(p.tenantId, cur.id);
        await this.d.store.updateMember(p.tenantId, mid, { status: "deprovisioned" }, this.now());
        // Immediate: no session or API key of the removed member survives this call.
        const sessions = await this.d.sessions.revokeAllOfMember(p.tenantId, mid, "member_removed");
        const keys = await this.d.store.revokeApiKeysOfMember(p.tenantId, mid, this.now());
        return { result: undefined, outputs: { member: mid, sessions, keys } };
      },
    );
  }

  private async assertNotLastOwner(tenantId: string, except: string): Promise<void> {
    let after: string | undefined;
    for (;;) {
      const page = await this.d.store.listMembers(tenantId, 200, after);
      if (page.items.some((x) => x.id !== except && x.role === "owner" && x.status === "active"))
        return;
      if (!page.nextCursor) throw new LastOwnerError();
      after = page.nextCursor;
    }
  }

  // ------------------------------------------------------------------ API keys
  listApiKeys(
    p: Principal,
    limit?: number,
    after?: string,
  ): Promise<{ items: PublicApiKey[]; nextCursor?: string }> {
    return this.guarded(p, "apikeys.read", {}, async () => ({
      result: await this.d.apiKeys.list(p, limit, after === undefined ? undefined : idOf(after)),
    }));
  }

  createApiKey(p: Principal, input: CreateKeyInput): Promise<CreatedKey> {
    return this.guarded(
      p,
      "apikeys.create",
      {
        resource: {
          ownerMemberId: p.memberId,
          ...(input.environment ? { environment: input.environment } : {}),
        },
        detail: { name: input.name, scopes: input.scopes, environment: input.environment ?? "dev" },
      },
      async () => {
        const r = await this.d.apiKeys.create(p, input);
        return { result: r, outputs: { key: r.key.id, prefix: r.key.prefix } };
      },
    );
  }

  async rotateApiKey(p: Principal, id: string): Promise<CreatedKey> {
    const kid = idOf(id);
    const k = await this.d.store.getApiKey(p.tenantId, kid);
    return this.guarded(
      p,
      "apikeys.rotate",
      {
        ...(k
          ? {
              resource: {
                tenantId: k.tenantId,
                ownerMemberId: k.ownerMemberId,
                environment: k.environment,
              },
            }
          : { missing: true }),
        detail: { key: kid },
      },
      async () => {
        const r = await this.d.apiKeys.rotate(p, kid);
        return { result: r, outputs: { old: kid, key: r.key.id } };
      },
    );
  }

  async revokeApiKey(p: Principal, id: string): Promise<PublicApiKey> {
    const kid = idOf(id);
    const k = await this.d.store.getApiKey(p.tenantId, kid);
    return this.guarded(
      p,
      "apikeys.revoke",
      {
        ...(k
          ? {
              resource: {
                tenantId: k.tenantId,
                ownerMemberId: k.ownerMemberId,
                environment: k.environment,
              },
            }
          : { missing: true }),
        detail: { key: kid },
      },
      async () => ({ result: await this.d.apiKeys.revoke(p, kid), outputs: { key: kid } }),
    );
  }

  // ------------------------------------------------------------------ BYO model keys
  listModelKeys(p: Principal): Promise<PublicModelKey[]> {
    return this.guarded(p, "modelkeys.read", {}, async () => ({
      result: await this.d.modelKeys.list(p),
    }));
  }
  /** The ABAC owner of an existing BYO key is whoever last wrote it; a key that does not exist yet has no owner to protect. */
  private async modelKeyResource(p: Principal, provider: string, label: string): Promise<Resource> {
    const existing = await this.d.store.getModelCredential(p.tenantId, provider, label);
    return existing ? { tenantId: existing.tenantId, ownerMemberId: existing.createdBy } : {};
  }

  /** `value` is never logged, audited or returned. */
  async putModelKey(
    p: Principal,
    provider: string,
    label: string,
    value: string,
  ): Promise<PublicModelKey> {
    const resource = await this.modelKeyResource(p, provider, label);
    return this.guarded(
      p,
      "modelkeys.write",
      { resource, detail: { provider, label } },
      async () => {
        const r = await this.d.modelKeys.put(p, provider, label, value);
        return { result: r, outputs: { provider, label } };
      },
    );
  }
  async deleteModelKey(p: Principal, provider: string, label: string): Promise<void> {
    const resource = await this.modelKeyResource(p, provider, label);
    return this.guarded(
      p,
      "modelkeys.delete",
      { resource, detail: { provider, label } },
      async () => {
        await this.d.modelKeys.delete(p, provider, label);
        return { result: undefined };
      },
    );
  }

  // ------------------------------------------------------------------ policy packs
  listPolicies(p: Principal): Promise<PublicPackVersion[]> {
    return this.guarded(p, "policies.read", {}, async () => ({
      result: await this.d.policies.list(p),
    }));
  }
  publishPolicy(p: Principal, doc: unknown): Promise<PublicPackVersion> {
    return this.guarded(
      p,
      "policies.publish",
      {
        detail: { pack: (doc as { metadata?: { name?: unknown } } | null)?.metadata?.name ?? null },
      },
      async () => {
        const r = await this.d.policies.publish(p, doc);
        return { result: r, outputs: { version: r.versionId, hash: r.contentHash } };
      },
    );
  }
  async activatePolicy(
    p: Principal,
    versionId: string,
  ): Promise<{ policyVersion: string; pack: string; version: string }> {
    const vid = idOf(versionId);
    return this.guarded(p, "policies.activate", { detail: { version: vid } }, async () => {
      const r = await this.d.policies.activate(p, vid);
      await this.d.bundles?.publish(p.tenantId);
      return { result: r, outputs: { policy_version: r.policyVersion } };
    });
  }
  deactivatePolicy(p: Principal, pack: string): Promise<void> {
    return this.guarded(
      p,
      "policies.activate",
      { detail: { pack, op: "deactivate" } },
      async () => {
        await this.d.policies.deactivate(p, pack);
        await this.d.bundles?.publish(p.tenantId);
        return { result: undefined };
      },
    );
  }

  // ------------------------------------------------------------------ budgets
  listBudgets(p: Principal): Promise<Budget[]> {
    return this.guarded(p, "budgets.read", {}, async () => ({
      result: await this.d.store.listBudgets(p.tenantId),
    }));
  }

  putBudget(
    p: Principal,
    b: {
      scope: BudgetScope;
      target?: string;
      metric: BudgetMetric;
      period: BudgetPeriod;
      soft?: number;
      hard?: number;
    },
  ): Promise<Budget> {
    return this.guarded(
      p,
      "budgets.write",
      {
        detail: {
          scope: b.scope,
          target: b.target ?? "",
          metric: b.metric,
          period: b.period,
          soft: num(b.soft),
          hard: num(b.hard),
        },
      },
      async () => {
        const target = b.target ?? "";
        if (!["tenant", "agent", "run"].includes(b.scope)) throw invalid("unknown scope");
        if (!["tokens", "cost_usd", "tool_calls", "runtime_seconds"].includes(b.metric))
          throw invalid("unknown metric");
        if (!["run", "hour", "day", "month"].includes(b.period)) throw invalid("unknown period");
        if (b.scope === "agent" ? !/^[a-z][a-z0-9-]{1,62}$/.test(target) : target !== "")
          throw invalid("target must be an agent name for agent budgets and empty otherwise");
        for (const v of [b.soft, b.hard])
          if (
            v !== undefined &&
            (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 1e12)
          )
            throw invalid("limits must be finite numbers in [0, 1e12]");
        if (b.soft === undefined && b.hard === undefined)
          throw invalid("soft or hard limit required");
        if (b.soft !== undefined && b.hard !== undefined && b.soft > b.hard)
          throw invalid("soft must not exceed hard");
        const row = await this.d.store.upsertBudget({
          tenantId: p.tenantId,
          id: this.newId(),
          scope: b.scope,
          target,
          metric: b.metric,
          period: b.period,
          ...(b.soft !== undefined ? { soft: b.soft } : {}),
          ...(b.hard !== undefined ? { hard: b.hard } : {}),
        });
        return { result: row, outputs: { budget: row.id } };
      },
    );
  }

  async deleteBudget(p: Principal, id: string): Promise<void> {
    const bid = idOf(id);
    return this.guarded(p, "budgets.write", { detail: { budget: bid, op: "delete" } }, async () => {
      if (!(await this.d.store.deleteBudget(p.tenantId, bid))) throw notFound();
      return { result: undefined };
    });
  }

  /** The budget configuration the runtime (TKI) and the Risk Kernel's budget gate are started with. */
  async budgetConfig(tenantId: string): Promise<BudgetConfig> {
    const rows = await this.d.store.listBudgets(tenantId);
    const cfg: BudgetConfig = { tenant: [], agents: {}, run: [] };
    for (const r of rows) {
      const e = {
        metric: r.metric,
        period: r.period,
        ...(r.soft !== undefined ? { soft: r.soft } : {}),
        ...(r.hard !== undefined ? { hard: r.hard } : {}),
      };
      if (r.scope === "tenant") cfg.tenant.push(e);
      else if (r.scope === "run") cfg.run.push(e);
      else (cfg.agents[r.target] ??= []).push(e);
    }
    return cfg;
  }

  // ------------------------------------------------------------------ settings (retention)
  getSettings(p: Principal): Promise<TenantSettings> {
    return this.guarded(p, "settings.read", {}, async () => {
      const s = await this.d.store.getSettings(p.tenantId);
      if (!s) throw notFound();
      return { result: s };
    });
  }

  updateRetention(
    p: Principal,
    patch: { auditDays?: number; transcriptDays?: number; memoryDays?: number },
  ): Promise<TenantSettings> {
    return this.guarded(p, "settings.write", { detail: { ...patch } }, async () => {
      const cur = await this.d.store.getSettings(p.tenantId);
      if (!cur) throw notFound();
      const chk = (
        v: number | undefined,
        lo: number,
        hi: number,
        n: string,
      ): number | undefined => {
        if (v === undefined) return undefined;
        if (!Number.isInteger(v) || v < lo || v > hi)
          throw invalid(`${n} must be an integer in [${lo}, ${hi}]`);
        return v;
      };
      const audit = chk(patch.auditDays, 365, 3650, "auditDays");
      // The audit chain may only get LONGER retention than the platform floor and never shorter than it already was (evidence).
      if (audit !== undefined && audit < cur.retentionAuditDays)
        throw conflict("audit retention cannot be shortened");
      const next: TenantSettings = {
        tenantId: p.tenantId,
        retentionAuditDays: audit ?? cur.retentionAuditDays,
        retentionTranscriptDays:
          chk(patch.transcriptDays, 1, 3650, "transcriptDays") ?? cur.retentionTranscriptDays,
        retentionMemoryDays:
          chk(patch.memoryDays, 1, 3650, "memoryDays") ?? cur.retentionMemoryDays,
        updatedBy: p.memberId,
      };
      await this.d.store.putSettings(next);
      return { result: next, outputs: { ...next } };
    });
  }

  // ------------------------------------------------------------------ directories / SSO / domains
  listDirectories(p: Principal): Promise<Omit<DirectoryRecord, "tokenHash" | "tokenPrefix">[]> {
    return this.guarded(p, "directories.read", {}, async () => {
      const ds = await this.d.store.listDirectories(p.tenantId);
      return {
        result: ds.map(({ tokenHash: _h, tokenPrefix: _p, ...rest }) => (void _h, void _p, rest)),
      };
    });
  }

  createDirectory(
    p: Principal,
    name: string,
    defaultRole: Role = "viewer",
  ): Promise<{ id: string; token: string }> {
    return this.guarded(
      p,
      "directories.manage",
      { targetRole: defaultRole, detail: { name, defaultRole } },
      async () => {
        const r = await this.d.directories.createDirectory(p.tenantId, name, defaultRole);
        return {
          result: { id: r.directory.id, token: r.token },
          outputs: { directory: r.directory.id },
        };
      },
    );
  }

  async rotateDirectoryToken(p: Principal, id: string): Promise<{ token: string }> {
    const did = idOf(id);
    return this.guarded(
      p,
      "directories.manage",
      { detail: { directory: did, op: "rotate" } },
      async () => ({
        result: { token: await this.d.directories.rotateToken(p.tenantId, did) },
        outputs: { directory: did },
      }),
    );
  }

  async revokeDirectory(p: Principal, id: string): Promise<void> {
    const did = idOf(id);
    return this.guarded(
      p,
      "directories.manage",
      { detail: { directory: did, op: "revoke" } },
      async () => {
        await this.d.directories.revokeDirectory(p.tenantId, did);
        return { result: undefined };
      },
    );
  }

  async setGroupRole(
    p: Principal,
    directoryId: string,
    group: string,
    role: Role | undefined,
  ): Promise<void> {
    const did = idOf(directoryId);
    return this.guarded(
      p,
      "directories.manage",
      {
        ...(role ? { targetRole: role } : {}),
        detail: { directory: did, group, role: role ?? null },
      },
      async () => {
        await this.d.directories.setRoleMapping(p.tenantId, did, group, role);
        return { result: undefined };
      },
    );
  }

  setSsoConnection(
    p: Principal,
    c: {
      idpOrgId: string;
      idpConnectionId?: string;
      connectionType: "saml" | "oidc";
      jitEnabled?: boolean;
      jitDefaultRole?: Role;
    },
  ): Promise<IdentityConnection> {
    return this.guarded(
      p,
      "sso.manage",
      {
        targetRole: c.jitDefaultRole ?? "viewer",
        detail: {
          org: c.idpOrgId,
          type: c.connectionType,
          jit: c.jitEnabled ?? false,
          role: c.jitDefaultRole ?? "viewer",
        },
      },
      async () => {
        if (!/^[\w.-]{1,128}$/.test(c.idpOrgId)) throw invalid("invalid organization id");
        if (!["saml", "oidc"].includes(c.connectionType)) throw invalid("unknown connection type");
        const role = c.jitDefaultRole ?? "viewer";
        if (!isExternalRole(role)) throw invalid("JIT can never create an owner");
        const existing = (await this.d.store.listConnections(p.tenantId)).find(
          (x) => x.idpOrgId === c.idpOrgId,
        );
        const row: IdentityConnection = {
          tenantId: p.tenantId,
          id: existing?.id ?? this.newId(),
          idpOrgId: c.idpOrgId,
          ...(c.idpConnectionId ? { idpConnectionId: c.idpConnectionId } : {}),
          connectionType: c.connectionType,
          jitEnabled: c.jitEnabled ?? false,
          jitDefaultRole: role,
        };
        try {
          await this.d.store.upsertConnection(row);
        } catch (err) {
          if (err instanceof StoreConflict)
            throw conflict("this IdP organization is already linked to a tenant");
          throw err;
        }
        return { result: row, outputs: { connection: row.id } };
      },
    );
  }

  adminPortalLink(
    p: Principal,
    intent: "sso" | "dsync",
    returnUrl: string,
  ): Promise<{ url: string }> {
    return this.guarded(p, "sso.manage", { detail: { intent } }, async () => {
      const conn = (await this.d.store.listConnections(p.tenantId))[0];
      if (!conn) throw conflict("no IdP organization is linked yet");
      return {
        result: {
          url: await this.d.idp.adminPortalLink({
            organizationId: conn.idpOrgId,
            intent,
            returnUrl,
          }),
        },
      };
    });
  }

  beginDomain(
    p: Principal,
    domain: string,
  ): Promise<{ domain: string; recordName: string; recordValue: string }> {
    return this.guarded(p, "domains.manage", { detail: { domain, op: "begin" } }, async () => ({
      result: await this.d.domains.begin(p.tenantId, domain),
    }));
  }
  verifyDomain(p: Principal, domain: string): Promise<{ domain: string; status: string }> {
    return this.guarded(p, "domains.manage", { detail: { domain, op: "verify" } }, async () => {
      const r = await this.d.domains.verify(p.tenantId, domain);
      return { result: { domain: r.domain, status: r.status }, outputs: { domain: r.domain } };
    });
  }
  listDomains(p: Principal): Promise<{ domain: string; status: string }[]> {
    return this.guarded(p, "directories.read", {}, async () => ({
      result: (await this.d.domains.list(p.tenantId)).map((x) => ({
        domain: x.domain,
        status: x.status,
      })),
    }));
  }

  // ------------------------------------------------------------------ sessions / audit
  async revokeMemberSessions(p: Principal, memberId: string): Promise<{ revoked: number }> {
    const mid = idOf(memberId);
    const m = await this.d.store.getMember(p.tenantId, mid);
    return this.guarded(
      p,
      "sessions.revoke",
      {
        ...(m
          ? { resource: { tenantId: m.tenantId }, currentTargetRole: m.role }
          : { missing: true }),
        detail: { member: mid },
      },
      async () => {
        const n = await this.d.sessions.revokeAllOfMember(p.tenantId, mid, "admin_revoked");
        return { result: { revoked: n }, outputs: { sessions: n } };
      },
    );
  }

  listAudit(p: Principal, q: { fromSeq?: number; limit?: number }): Promise<AuditEvent[]> {
    return this.guarded(
      p,
      "audit.read",
      { resource: { classification: "restricted" } },
      async () => {
        if (!this.d.auditReader) throw new CpError("unavailable", "audit reader not configured");
        return {
          result: await this.d.auditReader.listEvents(p.tenantId, {
            ...(q.fromSeq !== undefined ? { fromSeq: q.fromSeq } : {}),
            limit: Math.min(Math.max(q.limit ?? 100, 1), 1000),
          }),
        };
      },
    );
  }
}

export interface BudgetEntry {
  metric: BudgetMetric;
  period: BudgetPeriod;
  soft?: number;
  hard?: number;
}
export interface BudgetConfig {
  tenant: BudgetEntry[];
  run: BudgetEntry[];
  agents: Record<string, BudgetEntry[]>;
}

/** Highest-privilege role a principal may hand out (documentation and tests). */
export const grantableRoles = (role: Role): Role[] =>
  (Object.keys(ROLE_RANK) as Role[]).filter((r) => ROLE_RANK[r] <= ROLE_RANK[role]);
