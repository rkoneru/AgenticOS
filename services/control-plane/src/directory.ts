import { randomUUID } from "node:crypto";
import { hmac, randomHex, randomToken } from "./crypto.js";
import { CpError, conflict, invalid, notFound } from "./errors.js";
import type { AdminAudit } from "./audit.js";
import type { DirectoryEvent } from "./idp.js";
import { isExternalRole, maxRole, type Role } from "./roles.js";
import type { SessionService } from "./sessions.js";
import {
  LastOwnerError,
  StoreConflict,
  type ControlPlaneStore,
  type DirectoryRecord,
  type Member,
  type ScimGroup,
} from "./types.js";

export interface DirectoryContext {
  tenantId: string;
  directory: DirectoryRecord;
}

export interface DirectoryUserInput {
  externalId?: string;
  userName: string;
  email: string;
  displayName?: string;
  active: boolean;
}

export interface DirectoryOptions {
  store: ControlPlaneStore;
  sessions: SessionService;
  audit: AdminAudit;
  pepper: Uint8Array;
  now?: () => Date;
  newId?: () => string;
}

const TOKEN_RE = /^axs_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Directory provisioning core shared by the SCIM 2.0 endpoints and IdP directory-sync events.
 * Rules: the tenant comes from the directory token only; a directory sees and changes only members IT provisioned (`directory_id`);
 * roles come from the tenant-configured group mapping and are capped below `owner`; deprovisioning revokes every session and API
 * key of the member immediately.
 */
export class DirectoryService {
  private readonly now: () => Date;
  private readonly newId: () => string;
  constructor(private readonly o: DirectoryOptions) {
    if (o.pepper.length < 32) throw new Error("pepper must be >= 32 bytes");
    this.now = o.now ?? (() => new Date());
    this.newId = o.newId ?? randomUUID;
  }

  private tokenHash(token: string): Buffer {
    return hmac(this.o.pepper, "scim\0", token);
  }

  // ---- directory credential lifecycle (admin API calls these after authorization)
  async createDirectory(
    tenantId: string,
    name: string,
    defaultRole: Role,
  ): Promise<{ directory: DirectoryRecord; token: string }> {
    if (!/^[\w .-]{1,80}$/.test(name)) throw invalid("invalid directory name");
    if (!isExternalRole(defaultRole))
      throw invalid("defaultRole must be an external role (never owner)");
    const prefix = randomHex(8);
    const token = `axs_${prefix}_${randomToken(32)}`;
    const directory: DirectoryRecord = {
      tenantId,
      id: this.newId(),
      name,
      tokenPrefix: prefix,
      tokenHash: this.tokenHash(token),
      defaultRole,
      status: "active",
      createdAt: this.now(),
    };
    await this.o.store.insertDirectory(directory);
    return { directory, token };
  }

  async rotateToken(tenantId: string, directoryId: string): Promise<string> {
    const d = await this.o.store.getDirectory(tenantId, directoryId);
    if (!d || d.status !== "active") throw notFound("directory not found");
    const prefix = randomHex(8);
    const token = `axs_${prefix}_${randomToken(32)}`;
    await this.o.store.updateDirectory(tenantId, directoryId, {
      tokenPrefix: prefix,
      tokenHash: this.tokenHash(token),
    });
    return token;
  }

  async revokeDirectory(tenantId: string, directoryId: string): Promise<void> {
    if (!(await this.o.store.getDirectory(tenantId, directoryId)))
      throw notFound("directory not found");
    await this.o.store.updateDirectory(tenantId, directoryId, { revokedAt: this.now() });
  }

  async setRoleMapping(
    tenantId: string,
    directoryId: string,
    groupName: string,
    role: Role | undefined,
  ): Promise<void> {
    if (!(await this.o.store.getDirectory(tenantId, directoryId)))
      throw notFound("directory not found");
    if (role !== undefined && !isExternalRole(role))
      throw invalid("a directory group can never map to owner");
    if (groupName.length === 0 || groupName.length > 200) throw invalid("invalid group name");
    await this.o.store.setRoleMapping(tenantId, directoryId, groupName, role);
  }

  /** Bearer token -> context. Revoked directory or malformed/unknown token: undefined. */
  async authenticate(authorization: string | undefined): Promise<DirectoryContext | undefined> {
    const m = /^Bearer (\S+)$/.exec(authorization ?? "");
    const tm = m ? TOKEN_RE.exec(m[1] as string) : null;
    if (!m || !tm) return undefined;
    const d = await this.o.store.findDirectoryByLookup(
      tm[1] as string,
      this.tokenHash(m[1] as string),
    );
    if (!d || d.status !== "active") return undefined;
    await this.o.store.updateDirectory(d.tenantId, d.id, { lastUsedAt: this.now() });
    return { tenantId: d.tenantId, directory: d };
  }

  // ---- audit
  private async audit(
    ctx: DirectoryContext,
    action: string,
    decision: "ALLOW" | "DENY",
    detail: Record<string, unknown>,
  ): Promise<void> {
    await this.o.audit.record({
      tenantId: ctx.tenantId,
      actor: { type: "system", id: `scim:${ctx.directory.id}` },
      action,
      decision,
      policyVersion: "scim-directory-token",
      reason: Object.entries(detail)
        .map(([k, v]) => `${k}=${String(v)}`)
        .join(" "),
      inputs: { directory: ctx.directory.id, ...detail },
      outputs: {},
    });
  }

  // ---- users
  private owned(ctx: DirectoryContext, m: Member | undefined): Member | undefined {
    return m && m.directoryId === ctx.directory.id ? m : undefined;
  }

  async getUser(ctx: DirectoryContext, id: string): Promise<Member | undefined> {
    if (!UUID.test(id)) return undefined;
    return this.owned(ctx, await this.o.store.getMember(ctx.tenantId, id));
  }

  async listUsers(ctx: DirectoryContext): Promise<Member[]> {
    const out: Member[] = [];
    let after: string | undefined;
    for (;;) {
      const page = await this.o.store.listMembers(ctx.tenantId, 200, after);
      out.push(...page.items.filter((m) => m.directoryId === ctx.directory.id));
      if (!page.nextCursor) return out;
      after = page.nextCursor;
    }
  }

  async createUser(ctx: DirectoryContext, u: DirectoryUserInput): Promise<Member> {
    this.validateUser(u);
    const id = this.newId();
    try {
      const m = await this.o.store.insertMember({
        tenantId: ctx.tenantId,
        id,
        userRef: `scim:${ctx.directory.id}:${u.externalId ?? id}`,
        email: u.email.toLowerCase(),
        role: ctx.directory.defaultRole,
        status: u.active ? "active" : "deprovisioned",
        ...(u.displayName ? { displayName: u.displayName } : {}),
        ...(u.externalId ? { externalId: u.externalId } : {}),
        directoryId: ctx.directory.id,
      });
      await this.audit(ctx, "scim.user.create", "ALLOW", { member: m.id, active: u.active });
      return m;
    } catch (err) {
      if (err instanceof StoreConflict)
        throw conflict("a user with this userName, email or externalId already exists");
      throw err;
    }
  }

  private validateUser(u: DirectoryUserInput): void {
    if (typeof u.email !== "string" || !EMAIL.test(u.email))
      throw invalid("a valid email (userName or emails[].value) is required");
    if (
      u.externalId !== undefined &&
      (typeof u.externalId !== "string" || u.externalId.length === 0 || u.externalId.length > 256)
    )
      throw invalid("invalid externalId");
    if (
      u.displayName !== undefined &&
      (typeof u.displayName !== "string" || u.displayName.length > 256)
    )
      throw invalid("invalid displayName");
  }

  /** Apply a change to a directory-provisioned member. Owners are never modified except by deprovisioning. */
  async updateUser(
    ctx: DirectoryContext,
    id: string,
    change: Partial<DirectoryUserInput>,
  ): Promise<Member> {
    const m = await this.getUser(ctx, id);
    if (!m) throw notFound("user not found");
    let cur = m;
    if (
      change.userName !== undefined ||
      change.email !== undefined ||
      change.displayName !== undefined
    ) {
      if (change.email !== undefined && !EMAIL.test(change.email)) throw invalid("invalid email");
      try {
        cur =
          (await this.o.store.updateMember(
            ctx.tenantId,
            id,
            {
              ...(change.email ? { email: change.email.toLowerCase() } : {}),
              ...(change.displayName !== undefined ? { displayName: change.displayName } : {}),
            },
            this.now(),
          )) ?? cur;
      } catch (err) {
        if (err instanceof StoreConflict) throw conflict("email already in use");
        throw err;
      }
    }
    if (change.active === false && cur.status === "active")
      cur = await this.deprovision(ctx, cur, "scim.user.deprovision");
    else if (change.active === true && cur.status === "deprovisioned") {
      cur = (await this.o.store.updateMember(
        ctx.tenantId,
        id,
        { status: "active" },
        this.now(),
      )) as Member;
      await this.audit(ctx, "scim.user.reactivate", "ALLOW", { member: id });
      cur = await this.recomputeRole(ctx, cur);
    }
    return cur;
  }

  /** Immediate revocation: member inactive, every session and API key dead before this returns. */
  async deprovision(ctx: DirectoryContext, m: Member, action: string): Promise<Member> {
    let out = m;
    let lastOwner = false;
    try {
      out =
        (await this.o.store.updateMember(
          ctx.tenantId,
          m.id,
          { status: "deprovisioned" },
          this.now(),
        )) ?? m;
    } catch (err) {
      if (!(err instanceof LastOwnerError)) throw err;
      lastOwner = true;
    }
    const sessions = await this.o.sessions.revokeAllOfMember(ctx.tenantId, m.id, "deprovisioned");
    const keys = await this.o.store.revokeApiKeysOfMember(ctx.tenantId, m.id, this.now());
    await this.audit(ctx, lastOwner ? `${action}.last_owner_locked_out` : action, "ALLOW", {
      member: m.id,
      sessions,
      keys,
    });
    if (lastOwner)
      throw new CpError(
        "conflict",
        "the last owner cannot be deprovisioned; its sessions and API keys were revoked, an owner must be appointed",
      );
    return out;
  }

  async deleteUser(ctx: DirectoryContext, id: string): Promise<boolean> {
    const m = await this.getUser(ctx, id);
    if (!m) return false;
    if (m.status === "active") await this.deprovision(ctx, m, "scim.user.delete");
    return true;
  }

  // ---- roles and groups
  async recomputeRole(ctx: DirectoryContext, m: Member): Promise<Member> {
    if (m.role === "owner" || m.directoryId !== ctx.directory.id) return m;
    const mappings = await this.o.store.listRoleMappings(ctx.tenantId, ctx.directory.id);
    const groups = await this.o.store.groupsOfMember(ctx.tenantId, ctx.directory.id, m.id);
    const mapped = groups
      .map((g) => mappings[g.displayName])
      .filter((r): r is Role => r !== undefined && isExternalRole(r));
    const role = maxRole([ctx.directory.defaultRole, ...mapped]) as Role;
    if (role === m.role) return m;
    const next = (await this.o.store.updateMember(
      ctx.tenantId,
      m.id,
      { role },
      this.now(),
    )) as Member;
    await this.audit(ctx, "scim.user.role_change", "ALLOW", {
      member: m.id,
      from: m.role,
      to: role,
    });
    return next;
  }

  async createGroup(
    ctx: DirectoryContext,
    g: { displayName: string; externalId?: string; memberIds: string[] },
  ): Promise<ScimGroup> {
    if (
      typeof g.displayName !== "string" ||
      g.displayName.length === 0 ||
      g.displayName.length > 200
    )
      throw invalid("displayName is required");
    try {
      const grp = await this.o.store.insertGroup({
        tenantId: ctx.tenantId,
        id: this.newId(),
        directoryId: ctx.directory.id,
        displayName: g.displayName,
        ...(g.externalId ? { externalId: g.externalId } : {}),
      });
      await this.setMembers(ctx, grp.id, g.memberIds);
      await this.audit(ctx, "scim.group.create", "ALLOW", { group: grp.id });
      return grp;
    } catch (err) {
      if (err instanceof StoreConflict)
        throw conflict("a group with this displayName already exists");
      throw err;
    }
  }

  getGroup(ctx: DirectoryContext, id: string): Promise<ScimGroup | undefined> {
    if (!UUID.test(id)) return Promise.resolve(undefined);
    return this.o.store.getGroup(ctx.tenantId, ctx.directory.id, id);
  }
  listGroups(ctx: DirectoryContext): Promise<ScimGroup[]> {
    return this.o.store.listGroups(ctx.tenantId, ctx.directory.id);
  }
  groupMembers(ctx: DirectoryContext, id: string): Promise<string[]> {
    return this.o.store.groupMembers(ctx.tenantId, id);
  }

  /** Replaces the member list; only members of THIS directory can be added (IDOR: foreign ids are ignored as unknown). */
  async setMembers(ctx: DirectoryContext, groupId: string, memberIds: string[]): Promise<void> {
    const grp = await this.getGroup(ctx, groupId);
    if (!grp) throw notFound("group not found");
    const valid: Member[] = [];
    for (const id of new Set(memberIds)) {
      const m = await this.getUser(ctx, id);
      if (!m) throw invalid(`unknown member ${id}`);
      valid.push(m);
    }
    const before = await this.o.store.groupMembers(ctx.tenantId, groupId);
    await this.o.store.setGroupMembers(
      ctx.tenantId,
      groupId,
      valid.map((m) => m.id),
    );
    const affected = new Set([...before, ...valid.map((m) => m.id)]);
    for (const id of affected) {
      const m = await this.o.store.getMember(ctx.tenantId, id);
      if (m) await this.recomputeRole(ctx, m);
    }
  }

  async updateGroup(
    ctx: DirectoryContext,
    id: string,
    patch: { displayName?: string; externalId?: string },
  ): Promise<ScimGroup> {
    try {
      const g = await this.o.store.updateGroup(ctx.tenantId, ctx.directory.id, id, patch);
      if (!g) throw notFound("group not found");
      if (patch.displayName !== undefined)
        for (const mid of await this.o.store.groupMembers(ctx.tenantId, id)) {
          const m = await this.o.store.getMember(ctx.tenantId, mid);
          if (m) await this.recomputeRole(ctx, m);
        }
      return g;
    } catch (err) {
      if (err instanceof StoreConflict)
        throw conflict("a group with this displayName already exists");
      throw err;
    }
  }

  async deleteGroup(ctx: DirectoryContext, id: string): Promise<boolean> {
    const members = await this.o.store.groupMembers(ctx.tenantId, id);
    const ok = await this.o.store.deleteGroup(ctx.tenantId, ctx.directory.id, id);
    if (ok) {
      for (const mid of members) {
        const m = await this.o.store.getMember(ctx.tenantId, mid);
        if (m) await this.recomputeRole(ctx, m);
      }
      await this.audit(ctx, "scim.group.delete", "ALLOW", { group: id });
    }
    return ok;
  }

  // ---- IdP directory-sync events (WorkOS-shaped), same core
  async applyEvent(ctx: DirectoryContext, ev: DirectoryEvent): Promise<void> {
    switch (ev.type) {
      case "user.created":
      case "user.updated": {
        const existing = await this.o.store.findMemberByExternalId(
          ctx.tenantId,
          ctx.directory.id,
          ev.user.externalId,
        );
        if (existing)
          await this.updateUser(ctx, existing.id, {
            userName: ev.user.userName,
            email: ev.user.email,
            active: ev.user.active,
            ...(ev.user.displayName ? { displayName: ev.user.displayName } : {}),
          });
        else await this.createUser(ctx, ev.user);
        return;
      }
      case "user.deleted": {
        const m = await this.o.store.findMemberByExternalId(
          ctx.tenantId,
          ctx.directory.id,
          ev.externalId,
        );
        if (m) await this.deleteUser(ctx, m.id);
        return;
      }
      case "group.created":
      case "group.updated": {
        const groups = await this.listGroups(ctx);
        const ids: string[] = [];
        for (const ext of ev.group.memberExternalIds) {
          const m = await this.o.store.findMemberByExternalId(ctx.tenantId, ctx.directory.id, ext);
          if (m) ids.push(m.id);
        }
        const g = groups.find(
          (x) => x.externalId === ev.group.externalId || x.displayName === ev.group.name,
        );
        if (!g)
          await this.createGroup(ctx, {
            displayName: ev.group.name,
            externalId: ev.group.externalId,
            memberIds: ids,
          });
        else {
          await this.updateGroup(ctx, g.id, { displayName: ev.group.name });
          await this.setMembers(ctx, g.id, ids);
        }
        return;
      }
      case "group.deleted": {
        const g = (await this.listGroups(ctx)).find((x) => x.externalId === ev.externalId);
        if (g) await this.deleteGroup(ctx, g.id);
        return;
      }
    }
  }
}
