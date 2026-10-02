import type { Role } from "./roles.js";

export type Environment = "dev" | "staging" | "prod";
export type Classification = "public" | "internal" | "confidential" | "restricted";
export type IsolationTier = "shared_rls" | "dedicated_db" | "single_tenant_vpc";

export interface TenantRecord {
  id: string;
  slug: string;
  name: string;
  region: string;
  phiMode: boolean;
  status: "active" | "suspended" | "deleted";
}

export interface Member {
  tenantId: string;
  id: string;
  userRef: string;
  email: string;
  role: Role;
  status: "active" | "deprovisioned";
  displayName?: string;
  externalId?: string;
  directoryId?: string;
  deprovisionedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface ApiKeyRecord {
  tenantId: string;
  id: string;
  name: string;
  prefix: string;
  keyHash: Buffer;
  scopes: string[];
  environment: Environment;
  ownerMemberId: string;
  createdBy: string;
  createdAt: Date;
  expiresAt?: Date;
  revokedAt?: Date;
  lastUsedAt?: Date;
  rotatedFrom?: string;
}

export interface SessionRecord {
  tenantId: string;
  id: string;
  memberId: string;
  refreshHash: Buffer;
  prevRefreshHash?: Buffer;
  counter: number;
  authMethod: "sso" | "dev";
  createdAt: Date;
  expiresAt: Date;
  refreshedAt: Date;
  revokedAt?: Date;
  revokedReason?: string;
}

export interface DirectoryRecord {
  tenantId: string;
  id: string;
  name: string;
  idpDirectoryId?: string;
  tokenPrefix: string;
  tokenHash: Buffer;
  defaultRole: Role;
  status: "active" | "revoked";
  createdAt: Date;
  revokedAt?: Date;
  lastUsedAt?: Date;
}

export interface ScimGroup {
  tenantId: string;
  id: string;
  directoryId: string;
  displayName: string;
  externalId?: string;
  createdAt: Date;
}

export interface IdentityConnection {
  tenantId: string;
  id: string;
  idpOrgId: string;
  idpConnectionId?: string;
  connectionType: "saml" | "oidc";
  jitEnabled: boolean;
  jitDefaultRole: Role;
}

export interface VerifiedDomain {
  tenantId: string;
  domain: string;
  status: "pending" | "verified";
  challengeHash?: Buffer;
  verifiedAt?: Date;
}

export interface TenantKeyRecord {
  tenantId: string;
  version: number;
  kmsKeyId: string;
  wrappedDek: Buffer;
  retiredAt?: Date;
}

export interface ModelCredentialRecord {
  tenantId: string;
  id: string;
  provider: string;
  label: string;
  keyVersion: number;
  nonceAndCiphertext: Buffer;
  createdBy: string;
  createdAt: Date;
  rotatedAt?: Date;
}

export interface PackVersionRecord {
  tenantId: string;
  packId: string;
  packName: string;
  versionId: string;
  version: string;
  source: unknown;
  rego: string;
  contentHash: string;
  createdAt: Date;
}

export interface PolicyAssignment {
  tenantId: string;
  id: string;
  packId: string;
  versionId: string;
  active: boolean;
  activatedBy: string;
  activatedAt: Date;
  deactivatedAt?: Date;
}

export type BudgetScope = "tenant" | "agent" | "run";
export type BudgetMetric = "tokens" | "cost_usd" | "tool_calls" | "runtime_seconds";
export type BudgetPeriod = "run" | "hour" | "day" | "month";
export interface Budget {
  tenantId: string;
  id: string;
  scope: BudgetScope;
  target: string;
  metric: BudgetMetric;
  period: BudgetPeriod;
  soft?: number;
  hard?: number;
}

export interface TenantSettings {
  tenantId: string;
  retentionAuditDays: number;
  retentionTranscriptDays: number;
  retentionMemoryDays: number;
  updatedBy?: string;
}

export interface Placement {
  tenantId: string;
  isolationTier: IsolationTier;
  poolKey?: string;
}

/** Everything written atomically at signup. */
export interface ProvisionSpec {
  tenantId: string;
  slug: string;
  name: string;
  region: string;
  phiMode: boolean;
  owner: { id: string; userRef: string; email: string; displayName?: string };
  packs: {
    packId: string;
    versionId: string;
    name: string;
    version: string;
    source: unknown;
    rego: string;
    contentHash: string;
  }[];
  budgets: Omit<Budget, "tenantId" | "id">[];
  settings: Omit<TenantSettings, "tenantId">;
  placement: Omit<Placement, "tenantId">;
}

export type Page<T> = { items: T[]; nextCursor?: string };

/** Thrown by stores; the services translate it. */
export class StoreConflict extends Error {}
export class LastOwnerError extends Error {
  constructor() {
    super("the last owner of a tenant cannot be demoted or removed");
  }
}

/**
 * Persistence port of the control plane. EVERY method takes the tenant explicitly; the services obtain it only from an authenticated
 * principal. The Postgres implementation additionally runs each call under FORCED row-level security for that tenant. The only
 * methods that work without a known tenant are the three `authenticate*`/`find*ByLookup` lookups, which require a secret hash.
 */
export interface ControlPlaneStore {
  // tenants
  provisionTenant(spec: ProvisionSpec): Promise<void>;
  getTenant(tenantId: string): Promise<TenantRecord | undefined>;

  // members
  insertMember(m: Omit<Member, "createdAt" | "updatedAt">): Promise<Member>;
  getMember(tenantId: string, id: string): Promise<Member | undefined>;
  findMemberByUserRef(tenantId: string, userRef: string): Promise<Member | undefined>;
  findMemberByEmail(tenantId: string, email: string): Promise<Member | undefined>;
  findMemberByExternalId(
    tenantId: string,
    directoryId: string,
    externalId: string,
  ): Promise<Member | undefined>;
  listMembers(tenantId: string, limit: number, after?: string): Promise<Page<Member>>;
  /** Atomic w.r.t. the last-owner rule (throws LastOwnerError). */
  updateMember(
    tenantId: string,
    id: string,
    patch: Partial<Pick<Member, "role" | "status" | "displayName" | "email">>,
    now: Date,
  ): Promise<Member | undefined>;

  // api keys
  insertApiKey(k: ApiKeyRecord): Promise<ApiKeyRecord>;
  getApiKey(tenantId: string, id: string): Promise<ApiKeyRecord | undefined>;
  listApiKeys(tenantId: string, limit: number, after?: string): Promise<Page<ApiKeyRecord>>;
  /** Pre-tenant lookup: a row only for the exact (prefix, hash). */
  findApiKeyByLookup(prefix: string, keyHash: Buffer): Promise<ApiKeyRecord | undefined>;
  updateApiKey(
    tenantId: string,
    id: string,
    patch: { revokedAt?: Date; lastUsedAt?: Date },
  ): Promise<ApiKeyRecord | undefined>;
  revokeApiKeysOfMember(tenantId: string, memberId: string, at: Date): Promise<number>;

  // sessions
  insertSession(s: SessionRecord): Promise<void>;
  getSession(tenantId: string, id: string): Promise<SessionRecord | undefined>;
  /** Compare-and-set rotation: succeeds only when `expectedHash` is the current refresh hash and the session is live. */
  rotateRefresh(
    tenantId: string,
    id: string,
    expectedHash: Buffer,
    newHash: Buffer,
    now: Date,
  ): Promise<boolean>;
  revokeSession(tenantId: string, id: string, at: Date, reason: string): Promise<boolean>;
  revokeSessionsOfMember(
    tenantId: string,
    memberId: string,
    at: Date,
    reason: string,
  ): Promise<number>;

  // directories / SCIM
  insertDirectory(d: DirectoryRecord): Promise<void>;
  getDirectory(tenantId: string, id: string): Promise<DirectoryRecord | undefined>;
  listDirectories(tenantId: string): Promise<DirectoryRecord[]>;
  findDirectoryByLookup(prefix: string, tokenHash: Buffer): Promise<DirectoryRecord | undefined>;
  updateDirectory(
    tenantId: string,
    id: string,
    patch: { revokedAt?: Date; lastUsedAt?: Date; tokenPrefix?: string; tokenHash?: Buffer },
  ): Promise<void>;
  setRoleMapping(
    tenantId: string,
    directoryId: string,
    groupName: string,
    role: Role | undefined,
  ): Promise<void>;
  listRoleMappings(tenantId: string, directoryId: string): Promise<Record<string, Role>>;
  insertGroup(g: Omit<ScimGroup, "createdAt">): Promise<ScimGroup>;
  getGroup(tenantId: string, directoryId: string, id: string): Promise<ScimGroup | undefined>;
  listGroups(tenantId: string, directoryId: string): Promise<ScimGroup[]>;
  updateGroup(
    tenantId: string,
    directoryId: string,
    id: string,
    patch: { displayName?: string; externalId?: string },
  ): Promise<ScimGroup | undefined>;
  deleteGroup(tenantId: string, directoryId: string, id: string): Promise<boolean>;
  groupMembers(tenantId: string, groupId: string): Promise<string[]>;
  setGroupMembers(tenantId: string, groupId: string, memberIds: string[]): Promise<void>;
  groupsOfMember(tenantId: string, directoryId: string, memberId: string): Promise<ScimGroup[]>;

  // identity
  upsertConnection(c: Omit<IdentityConnection, "id"> & { id: string }): Promise<void>;
  /** Pre-tenant lookup by the IdP organization id. */
  findConnectionByOrg(idpOrgId: string): Promise<IdentityConnection | undefined>;
  listConnections(tenantId: string): Promise<IdentityConnection[]>;
  upsertDomain(d: VerifiedDomain): Promise<void>;
  getDomain(tenantId: string, domain: string): Promise<VerifiedDomain | undefined>;
  listDomains(tenantId: string): Promise<VerifiedDomain[]>;

  // BYO keys
  getActiveTenantKey(tenantId: string): Promise<TenantKeyRecord | undefined>;
  getTenantKey(tenantId: string, version: number): Promise<TenantKeyRecord | undefined>;
  insertTenantKey(k: TenantKeyRecord): Promise<void>;
  putModelCredential(c: ModelCredentialRecord): Promise<ModelCredentialRecord>;
  getModelCredential(
    tenantId: string,
    provider: string,
    label: string,
  ): Promise<ModelCredentialRecord | undefined>;
  listModelCredentials(tenantId: string): Promise<ModelCredentialRecord[]>;
  deleteModelCredential(tenantId: string, provider: string, label: string): Promise<boolean>;

  // policy packs
  insertPackVersion(v: Omit<PackVersionRecord, "createdAt">): Promise<PackVersionRecord>;
  getPackVersion(tenantId: string, versionId: string): Promise<PackVersionRecord | undefined>;
  listPackVersions(tenantId: string): Promise<PackVersionRecord[]>;
  /** Deactivates any active assignment of the same pack and activates `versionId`, atomically. */
  activatePackVersion(
    tenantId: string,
    versionId: string,
    by: string,
    now: Date,
  ): Promise<PolicyAssignment>;
  deactivatePack(tenantId: string, packId: string, now: Date): Promise<boolean>;
  listActiveAssignments(tenantId: string): Promise<PolicyAssignment[]>;

  // budgets / settings / placement
  upsertBudget(b: Omit<Budget, "id"> & { id: string }): Promise<Budget>;
  listBudgets(tenantId: string): Promise<Budget[]>;
  deleteBudget(tenantId: string, id: string): Promise<boolean>;
  getSettings(tenantId: string): Promise<TenantSettings | undefined>;
  putSettings(s: TenantSettings): Promise<void>;
  getPlacement(tenantId: string): Promise<Placement | undefined>;
  putPlacement(p: Placement): Promise<void>;
}
