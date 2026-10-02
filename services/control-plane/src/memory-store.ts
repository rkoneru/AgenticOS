import { safeEqual } from "./crypto.js";
import type { Role } from "./roles.js";
import {
  LastOwnerError,
  StoreConflict,
  type ApiKeyRecord,
  type Budget,
  type ControlPlaneStore,
  type DirectoryRecord,
  type IdentityConnection,
  type Member,
  type ModelCredentialRecord,
  type Page,
  type PackVersionRecord,
  type Placement,
  type PolicyAssignment,
  type ProvisionSpec,
  type ScimGroup,
  type SessionRecord,
  type TenantKeyRecord,
  type TenantRecord,
  type TenantSettings,
  type VerifiedDomain,
} from "./types.js";

const k = (...p: string[]): string => p.join("\u0000");

function page<T extends { id: string }>(rows: T[], limit: number, after?: string): Page<T> {
  const sorted = [...rows].sort((a, b) => (a.id < b.id ? -1 : 1));
  const start = after === undefined ? 0 : sorted.findIndex((r) => r.id > after);
  const slice = start < 0 ? [] : sorted.slice(start, start + limit);
  const last = slice[slice.length - 1];
  const more = start >= 0 && start + limit < sorted.length;
  return more && last ? { items: slice, nextCursor: last.id } : { items: slice };
}

/** Reference implementation of the port (unit tests, dev). The same contract suite runs against the Postgres store. */
export class MemoryControlPlaneStore implements ControlPlaneStore {
  private tenants = new Map<string, TenantRecord>();
  private members = new Map<string, Member>();
  private keys = new Map<string, ApiKeyRecord>();
  private sessions = new Map<string, SessionRecord>();
  private dirs = new Map<string, DirectoryRecord>();
  private mappings = new Map<string, Role>();
  private groups = new Map<string, ScimGroup>();
  private gmembers = new Map<string, Set<string>>();
  private conns = new Map<string, IdentityConnection>();
  private domains = new Map<string, VerifiedDomain>();
  private tkeys = new Map<string, TenantKeyRecord>();
  private creds = new Map<string, ModelCredentialRecord>();
  private versions = new Map<string, PackVersionRecord>();
  private assigns = new Map<string, PolicyAssignment>();
  private budgets = new Map<string, Budget>();
  private settings = new Map<string, TenantSettings>();
  private placements = new Map<string, Placement>();
  private seq = 0;
  private id(): string {
    this.seq++;
    return `00000000-0000-4000-8000-${this.seq.toString(16).padStart(12, "0")}`;
  }

  provisionTenant(spec: ProvisionSpec): Promise<void> {
    if (
      [...this.tenants.values()].some((t) => t.slug === spec.slug) ||
      this.tenants.has(spec.tenantId)
    )
      return Promise.reject(new StoreConflict("slug already in use"));
    const now = new Date();
    this.tenants.set(spec.tenantId, {
      id: spec.tenantId,
      slug: spec.slug,
      name: spec.name,
      region: spec.region,
      phiMode: spec.phiMode,
      status: "active",
    });
    this.members.set(k(spec.tenantId, spec.owner.id), {
      tenantId: spec.tenantId,
      id: spec.owner.id,
      userRef: spec.owner.userRef,
      email: spec.owner.email,
      role: "owner",
      status: "active",
      ...(spec.owner.displayName ? { displayName: spec.owner.displayName } : {}),
      createdAt: now,
      updatedAt: now,
    });
    for (const p of spec.packs) {
      this.versions.set(k(spec.tenantId, p.versionId), {
        tenantId: spec.tenantId,
        packId: p.packId,
        packName: p.name,
        versionId: p.versionId,
        version: p.version,
        source: p.source,
        rego: p.rego,
        contentHash: p.contentHash,
        createdAt: now,
      });
      const id = this.id();
      this.assigns.set(k(spec.tenantId, id), {
        tenantId: spec.tenantId,
        id,
        packId: p.packId,
        versionId: p.versionId,
        active: true,
        activatedBy: spec.owner.id,
        activatedAt: now,
      });
    }
    for (const b of spec.budgets) {
      const id = this.id();
      this.budgets.set(k(spec.tenantId, id), { ...b, tenantId: spec.tenantId, id });
    }
    this.settings.set(spec.tenantId, { tenantId: spec.tenantId, ...spec.settings });
    this.placements.set(spec.tenantId, { tenantId: spec.tenantId, ...spec.placement });
    return Promise.resolve();
  }

  getTenant(t: string): Promise<TenantRecord | undefined> {
    return Promise.resolve(this.tenants.get(t));
  }

  // members
  insertMember(m: Omit<Member, "createdAt" | "updatedAt">): Promise<Member> {
    const dup = [...this.members.values()].some(
      (x) =>
        x.tenantId === m.tenantId &&
        (x.userRef === m.userRef ||
          x.email.toLowerCase() === m.email.toLowerCase() ||
          (m.externalId !== undefined &&
            x.externalId === m.externalId &&
            x.directoryId === m.directoryId)),
    );
    if (dup) return Promise.reject(new StoreConflict("member exists"));
    const now = new Date();
    const row: Member = { ...m, createdAt: now, updatedAt: now };
    this.members.set(k(m.tenantId, m.id), row);
    return Promise.resolve({ ...row });
  }
  getMember(t: string, id: string): Promise<Member | undefined> {
    const m = this.members.get(k(t, id));
    return Promise.resolve(m && { ...m });
  }
  private findMember(t: string, f: (m: Member) => boolean): Member | undefined {
    for (const m of this.members.values()) if (m.tenantId === t && f(m)) return { ...m };
    return undefined;
  }
  findMemberByUserRef(t: string, userRef: string): Promise<Member | undefined> {
    return Promise.resolve(this.findMember(t, (m) => m.userRef === userRef));
  }
  findMemberByEmail(t: string, email: string): Promise<Member | undefined> {
    return Promise.resolve(
      this.findMember(t, (m) => m.email.toLowerCase() === email.toLowerCase()),
    );
  }
  findMemberByExternalId(t: string, d: string, e: string): Promise<Member | undefined> {
    return Promise.resolve(this.findMember(t, (m) => m.directoryId === d && m.externalId === e));
  }
  listMembers(t: string, limit: number, after?: string): Promise<Page<Member>> {
    return Promise.resolve(
      page(
        [...this.members.values()].filter((m) => m.tenantId === t).map((m) => ({ ...m })),
        limit,
        after,
      ),
    );
  }
  updateMember(
    t: string,
    id: string,
    patch: Partial<Pick<Member, "role" | "status" | "displayName" | "email" | "userRef">>,
    now: Date,
  ): Promise<Member | undefined> {
    const m = this.members.get(k(t, id));
    if (!m) return Promise.resolve(undefined);
    const next: Member = { ...m, ...patch, updatedAt: now };
    if (patch.status === "deprovisioned") next.deprovisionedAt = now;
    const losesOwner =
      m.role === "owner" &&
      m.status === "active" &&
      (next.role !== "owner" || next.status !== "active");
    if (losesOwner) {
      const others = [...this.members.values()].filter(
        (x) => x.tenantId === t && x.id !== id && x.role === "owner" && x.status === "active",
      );
      if (others.length === 0) return Promise.reject(new LastOwnerError());
    }
    if (patch.email !== undefined) {
      const dup = [...this.members.values()].some(
        (x) =>
          x.tenantId === t && x.id !== id && x.email.toLowerCase() === patch.email?.toLowerCase(),
      );
      if (dup) return Promise.reject(new StoreConflict("email in use"));
    }
    this.members.set(k(t, id), next);
    return Promise.resolve({ ...next });
  }

  // api keys
  insertApiKey(key: ApiKeyRecord): Promise<ApiKeyRecord> {
    if ([...this.keys.values()].some((x) => x.tenantId === key.tenantId && x.prefix === key.prefix))
      return Promise.reject(new StoreConflict("prefix in use"));
    this.keys.set(k(key.tenantId, key.id), { ...key });
    return Promise.resolve({ ...key });
  }
  getApiKey(t: string, id: string): Promise<ApiKeyRecord | undefined> {
    const x = this.keys.get(k(t, id));
    return Promise.resolve(x && { ...x });
  }
  listApiKeys(t: string, limit: number, after?: string): Promise<Page<ApiKeyRecord>> {
    return Promise.resolve(
      page(
        [...this.keys.values()].filter((x) => x.tenantId === t).map((x) => ({ ...x })),
        limit,
        after,
      ),
    );
  }
  findApiKeyByLookup(prefix: string, hash: Buffer): Promise<ApiKeyRecord | undefined> {
    for (const x of this.keys.values())
      if (x.prefix === prefix && safeEqual(x.keyHash, hash)) return Promise.resolve({ ...x });
    return Promise.resolve(undefined);
  }
  updateApiKey(
    t: string,
    id: string,
    patch: { revokedAt?: Date; lastUsedAt?: Date },
  ): Promise<ApiKeyRecord | undefined> {
    const x = this.keys.get(k(t, id));
    if (!x) return Promise.resolve(undefined);
    if (patch.revokedAt && !x.revokedAt) x.revokedAt = patch.revokedAt;
    if (patch.lastUsedAt) x.lastUsedAt = patch.lastUsedAt;
    return Promise.resolve({ ...x });
  }
  revokeApiKeysOfMember(t: string, memberId: string, at: Date): Promise<number> {
    let n = 0;
    for (const x of this.keys.values())
      if (x.tenantId === t && x.ownerMemberId === memberId && !x.revokedAt) {
        x.revokedAt = at;
        n++;
      }
    return Promise.resolve(n);
  }

  // sessions
  insertSession(s: SessionRecord): Promise<void> {
    this.sessions.set(k(s.tenantId, s.id), { ...s });
    return Promise.resolve();
  }
  getSession(t: string, id: string): Promise<SessionRecord | undefined> {
    const s = this.sessions.get(k(t, id));
    return Promise.resolve(s && { ...s });
  }
  rotateRefresh(
    t: string,
    id: string,
    expected: Buffer,
    next: Buffer,
    now: Date,
  ): Promise<boolean> {
    const s = this.sessions.get(k(t, id));
    if (!s || s.revokedAt || !safeEqual(s.refreshHash, expected)) return Promise.resolve(false);
    s.prevRefreshHash = s.refreshHash;
    s.refreshHash = next;
    s.counter++;
    s.refreshedAt = now;
    return Promise.resolve(true);
  }
  revokeSession(t: string, id: string, at: Date, reason: string): Promise<boolean> {
    const s = this.sessions.get(k(t, id));
    if (!s || s.revokedAt) return Promise.resolve(false);
    s.revokedAt = at;
    s.revokedReason = reason;
    return Promise.resolve(true);
  }
  revokeSessionsOfMember(t: string, memberId: string, at: Date, reason: string): Promise<number> {
    let n = 0;
    for (const s of this.sessions.values())
      if (s.tenantId === t && s.memberId === memberId && !s.revokedAt) {
        s.revokedAt = at;
        s.revokedReason = reason;
        n++;
      }
    return Promise.resolve(n);
  }

  // directories
  insertDirectory(d: DirectoryRecord): Promise<void> {
    this.dirs.set(k(d.tenantId, d.id), { ...d });
    return Promise.resolve();
  }
  getDirectory(t: string, id: string): Promise<DirectoryRecord | undefined> {
    const d = this.dirs.get(k(t, id));
    return Promise.resolve(d && { ...d });
  }
  listDirectories(t: string): Promise<DirectoryRecord[]> {
    return Promise.resolve(
      [...this.dirs.values()].filter((d) => d.tenantId === t).map((d) => ({ ...d })),
    );
  }
  findDirectoryByLookup(prefix: string, hash: Buffer): Promise<DirectoryRecord | undefined> {
    for (const d of this.dirs.values())
      if (d.tokenPrefix === prefix && safeEqual(d.tokenHash, hash))
        return Promise.resolve({ ...d });
    return Promise.resolve(undefined);
  }
  updateDirectory(
    t: string,
    id: string,
    patch: { revokedAt?: Date; lastUsedAt?: Date; tokenPrefix?: string; tokenHash?: Buffer },
  ): Promise<void> {
    const d = this.dirs.get(k(t, id));
    if (d) {
      if (patch.revokedAt) {
        d.revokedAt = patch.revokedAt;
        d.status = "revoked";
      }
      if (patch.lastUsedAt) d.lastUsedAt = patch.lastUsedAt;
      if (patch.tokenPrefix) d.tokenPrefix = patch.tokenPrefix;
      if (patch.tokenHash) d.tokenHash = patch.tokenHash;
    }
    return Promise.resolve();
  }
  setRoleMapping(t: string, d: string, name: string, role: Role | undefined): Promise<void> {
    if (role === undefined) this.mappings.delete(k(t, d, name));
    else this.mappings.set(k(t, d, name), role);
    return Promise.resolve();
  }
  listRoleMappings(t: string, d: string): Promise<Record<string, Role>> {
    const out: Record<string, Role> = {};
    for (const [key, role] of this.mappings) {
      const [kt, kd, name] = key.split("\u0000") as [string, string, string];
      if (kt === t && kd === d) out[name] = role;
    }
    return Promise.resolve(out);
  }
  insertGroup(g: Omit<ScimGroup, "createdAt">): Promise<ScimGroup> {
    if (
      [...this.groups.values()].some(
        (x) =>
          x.tenantId === g.tenantId &&
          x.directoryId === g.directoryId &&
          x.displayName === g.displayName,
      )
    )
      return Promise.reject(new StoreConflict("group exists"));
    const row = { ...g, createdAt: new Date() };
    this.groups.set(k(g.tenantId, g.id), row);
    return Promise.resolve({ ...row });
  }
  getGroup(t: string, d: string, id: string): Promise<ScimGroup | undefined> {
    const g = this.groups.get(k(t, id));
    return Promise.resolve(g && g.directoryId === d ? { ...g } : undefined);
  }
  listGroups(t: string, d: string): Promise<ScimGroup[]> {
    return Promise.resolve(
      [...this.groups.values()]
        .filter((g) => g.tenantId === t && g.directoryId === d)
        .map((g) => ({ ...g })),
    );
  }
  updateGroup(
    t: string,
    d: string,
    id: string,
    patch: { displayName?: string; externalId?: string },
  ): Promise<ScimGroup | undefined> {
    const g = this.groups.get(k(t, id));
    if (!g || g.directoryId !== d) return Promise.resolve(undefined);
    if (patch.displayName !== undefined) g.displayName = patch.displayName;
    if (patch.externalId !== undefined) g.externalId = patch.externalId;
    return Promise.resolve({ ...g });
  }
  deleteGroup(t: string, d: string, id: string): Promise<boolean> {
    const g = this.groups.get(k(t, id));
    if (!g || g.directoryId !== d) return Promise.resolve(false);
    this.groups.delete(k(t, id));
    this.gmembers.delete(k(t, id));
    return Promise.resolve(true);
  }
  groupMembers(t: string, groupId: string): Promise<string[]> {
    return Promise.resolve([...(this.gmembers.get(k(t, groupId)) ?? [])]);
  }
  setGroupMembers(t: string, groupId: string, ids: string[]): Promise<void> {
    if (!this.groups.has(k(t, groupId))) return Promise.resolve();
    this.gmembers.set(k(t, groupId), new Set(ids.filter((i) => this.members.has(k(t, i)))));
    return Promise.resolve();
  }
  groupsOfMember(t: string, d: string, memberId: string): Promise<ScimGroup[]> {
    return Promise.resolve(
      [...this.groups.values()]
        .filter(
          (g) =>
            g.tenantId === t && g.directoryId === d && this.gmembers.get(k(t, g.id))?.has(memberId),
        )
        .map((g) => ({ ...g })),
    );
  }

  // identity
  upsertConnection(c: IdentityConnection): Promise<void> {
    if (
      [...this.conns.values()].some((x) => x.idpOrgId === c.idpOrgId && x.tenantId !== c.tenantId)
    )
      return Promise.reject(new StoreConflict("organization already linked"));
    this.conns.set(k(c.tenantId, c.id), { ...c });
    return Promise.resolve();
  }
  findConnectionByOrg(org: string): Promise<IdentityConnection | undefined> {
    for (const c of this.conns.values()) if (c.idpOrgId === org) return Promise.resolve({ ...c });
    return Promise.resolve(undefined);
  }
  listConnections(t: string): Promise<IdentityConnection[]> {
    return Promise.resolve(
      [...this.conns.values()].filter((c) => c.tenantId === t).map((c) => ({ ...c })),
    );
  }
  upsertDomain(d: VerifiedDomain): Promise<void> {
    if (
      d.status === "verified" &&
      [...this.domains.values()].some(
        (x) => x.domain === d.domain && x.status === "verified" && x.tenantId !== d.tenantId,
      )
    )
      return Promise.reject(new StoreConflict("domain verified by another tenant"));
    this.domains.set(k(d.tenantId, d.domain), { ...d });
    return Promise.resolve();
  }
  getDomain(t: string, domain: string): Promise<VerifiedDomain | undefined> {
    const d = this.domains.get(k(t, domain));
    return Promise.resolve(d && { ...d });
  }
  listDomains(t: string): Promise<VerifiedDomain[]> {
    return Promise.resolve(
      [...this.domains.values()].filter((d) => d.tenantId === t).map((d) => ({ ...d })),
    );
  }

  // BYO
  getActiveTenantKey(t: string): Promise<TenantKeyRecord | undefined> {
    const all = [...this.tkeys.values()]
      .filter((x) => x.tenantId === t && !x.retiredAt)
      .sort((a, b) => b.version - a.version);
    return Promise.resolve(all[0] && { ...all[0] });
  }
  getTenantKey(t: string, version: number): Promise<TenantKeyRecord | undefined> {
    const x = this.tkeys.get(k(t, String(version)));
    return Promise.resolve(x && { ...x });
  }
  insertTenantKey(key: TenantKeyRecord): Promise<void> {
    if (this.tkeys.has(k(key.tenantId, String(key.version))))
      return Promise.reject(new StoreConflict("key version exists"));
    this.tkeys.set(k(key.tenantId, String(key.version)), { ...key });
    return Promise.resolve();
  }
  putModelCredential(c: ModelCredentialRecord): Promise<ModelCredentialRecord> {
    const key = k(c.tenantId, c.provider, c.label);
    const prev = this.creds.get(key);
    const row = prev
      ? { ...c, id: prev.id, createdAt: prev.createdAt, rotatedAt: c.createdAt }
      : { ...c };
    this.creds.set(key, row);
    return Promise.resolve({ ...row });
  }
  getModelCredential(
    t: string,
    provider: string,
    label: string,
  ): Promise<ModelCredentialRecord | undefined> {
    const c = this.creds.get(k(t, provider, label));
    return Promise.resolve(c && { ...c });
  }
  listModelCredentials(t: string): Promise<ModelCredentialRecord[]> {
    return Promise.resolve(
      [...this.creds.values()].filter((c) => c.tenantId === t).map((c) => ({ ...c })),
    );
  }
  deleteModelCredential(t: string, provider: string, label: string): Promise<boolean> {
    return Promise.resolve(this.creds.delete(k(t, provider, label)));
  }

  // policies
  insertPackVersion(v: Omit<PackVersionRecord, "createdAt">): Promise<PackVersionRecord> {
    if (
      [...this.versions.values()].some(
        (x) => x.tenantId === v.tenantId && x.packName === v.packName && x.version === v.version,
      )
    )
      return Promise.reject(new StoreConflict("version exists (versions are immutable)"));
    const existing = [...this.versions.values()].find(
      (x) => x.tenantId === v.tenantId && x.packName === v.packName,
    );
    const row: PackVersionRecord = {
      ...v,
      packId: existing?.packId ?? v.packId,
      createdAt: new Date(),
    };
    this.versions.set(k(v.tenantId, v.versionId), row);
    return Promise.resolve({ ...row });
  }
  getPackVersion(t: string, id: string): Promise<PackVersionRecord | undefined> {
    const v = this.versions.get(k(t, id));
    return Promise.resolve(v && { ...v });
  }
  listPackVersions(t: string): Promise<PackVersionRecord[]> {
    return Promise.resolve(
      [...this.versions.values()].filter((v) => v.tenantId === t).map((v) => ({ ...v })),
    );
  }
  activatePackVersion(
    t: string,
    versionId: string,
    by: string,
    now: Date,
  ): Promise<PolicyAssignment> {
    const v = this.versions.get(k(t, versionId));
    if (!v) return Promise.reject(new StoreConflict("unknown version"));
    for (const a of this.assigns.values())
      if (a.tenantId === t && a.packId === v.packId && a.active) {
        a.active = false;
        a.deactivatedAt = now;
      }
    const id = this.id();
    const row: PolicyAssignment = {
      tenantId: t,
      id,
      packId: v.packId,
      versionId,
      active: true,
      activatedBy: by,
      activatedAt: now,
    };
    this.assigns.set(k(t, id), row);
    return Promise.resolve({ ...row });
  }
  deactivatePack(t: string, packId: string, now: Date): Promise<boolean> {
    let hit = false;
    for (const a of this.assigns.values())
      if (a.tenantId === t && a.packId === packId && a.active) {
        a.active = false;
        a.deactivatedAt = now;
        hit = true;
      }
    return Promise.resolve(hit);
  }
  listActiveAssignments(t: string): Promise<PolicyAssignment[]> {
    return Promise.resolve(
      [...this.assigns.values()].filter((a) => a.tenantId === t && a.active).map((a) => ({ ...a })),
    );
  }

  // budgets etc
  upsertBudget(b: Budget): Promise<Budget> {
    const dup = [...this.budgets.values()].find(
      (x) =>
        x.tenantId === b.tenantId &&
        x.scope === b.scope &&
        x.target === b.target &&
        x.metric === b.metric &&
        x.period === b.period,
    );
    const id = dup?.id ?? b.id;
    const row = { ...b, id };
    this.budgets.set(k(b.tenantId, id), row);
    return Promise.resolve({ ...row });
  }
  listBudgets(t: string): Promise<Budget[]> {
    return Promise.resolve(
      [...this.budgets.values()].filter((b) => b.tenantId === t).map((b) => ({ ...b })),
    );
  }
  deleteBudget(t: string, id: string): Promise<boolean> {
    return Promise.resolve(this.budgets.delete(k(t, id)));
  }
  getSettings(t: string): Promise<TenantSettings | undefined> {
    const s = this.settings.get(t);
    return Promise.resolve(s && { ...s });
  }
  putSettings(s: TenantSettings): Promise<void> {
    this.settings.set(s.tenantId, { ...s });
    return Promise.resolve();
  }
  getPlacement(t: string): Promise<Placement | undefined> {
    const p = this.placements.get(t);
    return Promise.resolve(p && { ...p });
  }
  putPlacement(p: Placement): Promise<void> {
    this.placements.set(p.tenantId, { ...p });
    return Promise.resolve();
  }
}
