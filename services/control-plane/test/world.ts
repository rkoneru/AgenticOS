import { MemoryAuditLog, PgAuditLog } from "@axis/audit";
import type { AuditStore } from "@axis/audit";
import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { inject } from "vitest";
import {
  Authorizer,
  FakeDnsResolver,
  FakeIdentityProvider,
  LocalKms,
  MemoryControlPlaneStore,
  PgControlPlaneStore,
  compileValidator,
  wireControlPlane,
  type ControlPlane,
  type ControlPlaneStore,
  type PackValidator,
  type Principal,
  type Role,
  type WireConfig,
} from "../src/index.js";

export const ROLE = "axis_app";
export type Kind = "memory" | "pg";
export const KINDS: Kind[] = ["memory", "pg"];

export class Clock {
  constructor(public ms = Date.UTC(2026, 9, 1, 12, 0, 0)) {}
  now = (): Date => new Date(this.ms);
  advance(sec: number): void {
    this.ms += sec * 1000;
  }
}

let authz: Promise<Authorizer> | undefined;
export const sharedAuthorizer = (): Promise<Authorizer> => (authz ??= Authorizer.fromPackFile());

const cache = new Map<string, ReturnType<PackValidator>>();
/** The REAL validator (compile + opa check + wasm build), memoized so the suite stays fast. */
export const cachedValidator: PackValidator = (docs) => {
  const k = JSON.stringify(docs);
  let r = cache.get(k);
  if (!r) {
    r = compileValidator(docs);
    cache.set(k, r);
  }
  return r;
};

export const secrets = (): WireConfig["secrets"] => ({
  pepper: randomBytes(32),
  cookieKey: randomBytes(32),
  signingKeys: [{ kid: "k1", key: randomBytes(32) }],
});

export interface World {
  kind: Kind;
  store: ControlPlaneStore;
  auditStore: AuditStore;
  cp: ControlPlane;
  idp: FakeIdentityProvider;
  dns: FakeDnsResolver;
  kms: LocalKms;
  clock: Clock;
  pool?: pg.Pool;
  region: string;
  /** Provision a tenant with an owner; returns ids and the owner's authenticated principal. */
  tenant(slug?: string): Promise<{ tenantId: string; owner: Principal; ownerId: string; slug: string }>;
  /** Insert a member directly through the store and log them in (real session, real token). */
  member(tenantId: string, role: Role, email?: string): Promise<{ principal: Principal; memberId: string; email: string }>;
  login(tenantId: string, memberId: string): Promise<Principal>;
  close(): Promise<void>;
}

export async function makeWorld(kind: Kind, over: Partial<WireConfig> = {}): Promise<World> {
  const clock = new Clock();
  let store: ControlPlaneStore;
  let auditStore: AuditStore;
  let pool: pg.Pool | undefined;
  if (kind === "pg") {
    pool = new pg.Pool({ connectionString: inject("dbUrl"), max: 8 });
    store = new PgControlPlaneStore({ pool, role: ROLE });
    auditStore = new PgAuditLog({ pool, role: ROLE, now: clock.now });
  } else {
    store = new MemoryControlPlaneStore();
    auditStore = new MemoryAuditLog({ now: clock.now });
  }
  const idp = new FakeIdentityProvider();
  const dns = new FakeDnsResolver();
  const kms = new LocalKms({ "kms-1": randomBytes(32) }, "kms-1");
  const region = "us-east-1";
  const cp = wireControlPlane({
    store,
    auditSink: auditStore,
    auditReader: auditStore,
    authorizer: await sharedAuthorizer(),
    idp,
    kms,
    dns,
    region,
    regions: ["us-east-1", "eu-west-1"],
    secrets: secrets(),
    redirectUri: "https://cp.example.test/auth/sso/callback",
    allowedReturnOrigins: ["https://console.example.test"],
    validator: cachedValidator,
    now: clock.now,
    secureCookies: true,
    ...over,
  });
  const w: World = {
    kind,
    store,
    auditStore,
    cp,
    idp,
    dns,
    kms,
    clock,
    ...(pool ? { pool } : {}),
    region,
    async login(tenantId, memberId) {
      const m = await store.getMember(tenantId, memberId);
      if (!m) throw new Error("no such member");
      const s = await cp.sessions.issue(m, "dev");
      const p = await cp.sessions.authenticate(s.accessToken);
      if (!p) throw new Error("login failed");
      return p;
    },
    async tenant(slug = `t-${randomUUID().slice(0, 12)}`) {
      const r = await cp.provisioner.signup({ slug, name: `Tenant ${slug}`, ownerEmail: `owner@${slug}.test`, region });
      const owner = await w.login(r.tenantId, r.ownerMemberId);
      return { tenantId: r.tenantId, owner, ownerId: r.ownerMemberId, slug };
    },
    async member(tenantId, role, email = `${role}-${randomUUID().slice(0, 8)}@x.test`) {
      const id = randomUUID();
      await store.insertMember({ tenantId, id, userRef: `test:${id}`, email, role, status: "active" });
      return { principal: await w.login(tenantId, id), memberId: id, email };
    },
    async close() {
      await pool?.end();
    },
  };
  return w;
}

export const eventsOf = (w: World, tenantId: string) => w.auditStore.listEvents(tenantId, { limit: 1000 });
