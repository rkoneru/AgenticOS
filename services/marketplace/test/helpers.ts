import { randomBytes, randomUUID } from "node:crypto";
import { MemoryAuditLog } from "@axis/audit";
import { HmacSealSigner, MemoryUsageLedger } from "@axis/billing";
import {
  MemoryRegistryStore,
  PgRegistryStore,
  RegistryService,
  ServiceAudit,
  ablContentHash,
  buildStatement,
  generatePublisherKey,
  signBlueprint,
  signStatement,
  type EvalGatePort,
  type PublisherKeyPair,
  type RegistryStore,
} from "@axis/registry";
import pg from "pg";
import { inject } from "vitest";
import {
  FakeDomainProver,
  FakeIdentityProver,
  MemoryDocStore,
  PgDocStore,
  createMarketplace,
  type DocStore,
  type Marketplace,
  type ReviewOptions,
  type StaffPrincipal,
  type TenantPrincipal,
} from "../src/index.js";

export const ROLE = "axis_app";
/** Letters that the registry's confusable-name fold leaves alone. */
export const rid = (n = 6): string =>
  Array.from(randomBytes(n), (b) => "cdfghjkpquxyz"[b % 13]).join("");

export class Clock {
  constructor(public t: Date) {}
  now = (): Date => new Date(this.t.getTime());
  advance(ms: number): void {
    this.t = new Date(this.t.getTime() + ms);
  }
}

export const newPool = (max = 10): pg.Pool =>
  new pg.Pool({ connectionString: inject("dbUrl"), max });
export async function adminClient(): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: inject("dbUrl") });
  await c.connect();
  return c;
}
export async function newTenant(admin: pg.Client): Promise<string> {
  const id = randomUUID();
  await admin.query(
    "INSERT INTO tenants (id, slug, name, region) VALUES ($1, $2, $2, 'us-east-1')",
    [id, `t-${randomBytes(5).toString("hex")}`],
  );
  return id;
}

export const tenantP = (
  tenantId: string,
  role: TenantPrincipal["role"] = "admin",
  subject = `u-${tenantId.slice(0, 6)}-${role}`,
): TenantPrincipal => ({ kind: "tenant", tenantId, subject, role });
export const reviewer = (subject = "rev-1", tenantId?: string): StaffPrincipal => ({
  kind: "reviewer",
  subject,
  ...(tenantId ? { tenantId } : {}),
});
export const moderator = (subject = "mod-1"): StaffPrincipal => ({ kind: "moderator", subject });

export const ablDoc = (
  name: string,
  version: string,
  spec: Record<string, unknown> = {},
): Record<string, unknown> => ({
  apiVersion: "abl.axis.dev/v1",
  kind: "Agent",
  metadata: { name, version },
  spec: {
    riskClassification: {
      level: "minimal",
      rationale: "Answers general product questions; no decisions about people.",
    },
    model: { primary: { provider: "anthropic", model: "claude-sonnet-5-5" } },
    instructions: { system: "You are a helpful assistant." },
    budgets: { costUsd: { hard: 5 }, toolCalls: { hard: 20 } },
    policy: { packs: ["baseline-deny@^1.0.0"] },
    ...spec,
  },
});

export interface Env {
  docs: DocStore;
  registryStore: RegistryStore;
  audit: MemoryAuditLog;
  clock: Clock;
  registry: RegistryService;
  mp: Marketplace;
  domain: FakeDomainProver;
  identity: FakeIdentityProver;
  ledger: MemoryUsageLedger;
  meterFail: { on: boolean };
  tenant: () => Promise<string>;
}

export interface EnvOptions {
  docs?: DocStore;
  registryStore?: RegistryStore;
  tenant?: () => Promise<string>;
  review?: ReviewOptions;
  evalGate?: EvalGatePort;
}

export function makeEnv(o: EnvOptions = {}): Env {
  const clock = new Clock(new Date("2026-10-02T12:00:00Z"));
  const audit = new MemoryAuditLog({ now: clock.now });
  const registryStore = o.registryStore ?? new MemoryRegistryStore();
  const docs = o.docs ?? new MemoryDocStore();
  const registry = new RegistryService({
    store: registryStore,
    audit: new ServiceAudit(audit, "registry", clock.now),
    now: clock.now,
    ...(o.evalGate ? { evalGate: o.evalGate } : {}),
  });
  const domain = new FakeDomainProver();
  const identity = new FakeIdentityProver();
  const ledger = new MemoryUsageLedger({
    signer: new HmacSealSigner(Buffer.alloc(32, 7)),
    now: clock.now,
  });
  const meterFail = { on: false };
  const metering = {
    append: (i: Parameters<MemoryUsageLedger["append"]>[0]) =>
      meterFail.on ? Promise.reject(new Error("billing down")) : ledger.append(i),
  };
  let n = 0;
  const mp = createMarketplace({
    docs,
    registry,
    audit: new ServiceAudit(audit, "marketplace", clock.now),
    domain,
    identity,
    metering,
    ...(o.review ? { review: o.review } : {}),
    now: clock.now,
    newId: () => `00000000-0000-4000-8000-${(++n).toString(16).padStart(12, "0")}`,
  });
  return {
    docs,
    registryStore,
    audit,
    clock,
    registry,
    mp,
    domain,
    identity,
    ledger,
    meterFail,
    tenant: o.tenant ?? (() => Promise.resolve(randomUUID())),
  };
}

export function pgEnv(pool: pg.Pool, admin: pg.Client): Env {
  return makeEnv({
    docs: new PgDocStore({ pool, role: ROLE }),
    registryStore: new PgRegistryStore({ pool, role: ROLE }),
    tenant: () => newTenant(admin),
  });
}

/** A tenant that publishes: verified publisher, registry namespace, signing key. */
export class Pub {
  key!: PublisherKeyPair;
  readonly p: TenantPrincipal;
  readonly b: TenantPrincipal;
  constructor(
    readonly env: Env,
    readonly tenantId: string,
    readonly namespace: string,
  ) {
    this.p = tenantP(tenantId, "admin", `admin-${namespace}`);
    this.b = tenantP(tenantId, "builder", `builder-${namespace}`);
  }

  static async create(env: Env, opts: { verified?: boolean } = {}): Promise<Pub> {
    const tenantId = await env.tenant();
    const pub = new Pub(env, tenantId, `pub-${rid(6)}`);
    await env.registry.claimNamespace(pub.p, pub.namespace);
    pub.key = generatePublisherKey();
    await env.registry.addKey(pub.p, pub.namespace, {
      publicKey: pub.key.publicKey,
      validFrom: new Date(env.clock.t.getTime() - 1000),
    });
    if (opts.verified !== false) await pub.verify();
    return pub;
  }

  async verify(reviewerSubject = "rev-verify"): Promise<void> {
    const domain = `${this.namespace}.example.com`;
    const rec = await this.env.mp.publishers.start(this.p, {
      legalName: `${this.namespace} Inc`,
      domain,
      contactEmail: `ops@${domain}`,
    });
    this.env.domain.records.set(domain, [`axis-verify=${rec.challenge}`]);
    await this.env.mp.publishers.submitEvidence(this.p);
    await this.env.mp.publishers.decide(reviewer(reviewerSubject), this.tenantId, {
      decision: "approve",
      reason: "evidence checked",
    });
  }

  async publish(abl: Record<string, unknown>) {
    const meta = abl["metadata"] as { name: string; version: string };
    const hash = ablContentHash(abl);
    const level = (abl["spec"] as { riskClassification: { level: string } }).riskClassification
      .level;
    const now = this.env.clock.now();
    const signature = signBlueprint(
      {
        namespace: this.namespace,
        name: meta.name,
        version: meta.version,
        riskLevel: level,
        contentHash: hash,
      },
      this.key,
      now,
    );
    const provenance = signStatement(
      buildStatement(
        {
          namespace: this.namespace,
          name: meta.name,
          version: meta.version,
          abl,
          builderId: "ci.example.com",
          sourceRef: "git+https://example.com/r@main",
          now,
        },
        hash,
      ),
      this.key,
    );
    return this.env.registry.publish(this.p, this.namespace, { abl, signature, provenance });
  }

  /** Publishes, submits for review and has a (different) reviewer approve it; lists it. Returns the version. */
  async release(
    name: string,
    version: string,
    spec: Record<string, unknown> = {},
    opts: { listing?: boolean; ack?: string[] } = {},
  ): Promise<string> {
    await this.publish(ablDoc(name, version, spec));
    const rv = await this.env.mp.reviews.submit(this.b, {
      namespace: this.namespace,
      name,
      version,
    });
    if (rv.state === "in_review") {
      await this.env.mp.reviews.decide(
        reviewer("rev-approve"),
        `${this.tenantId}|${this.namespace}/${name}@${version}`,
        {
          decision: "approve",
          note: "looks fine to me",
          acknowledged:
            opts.ack ?? rv.findings.filter((f) => f.severity === "high").map((f) => f.id),
        },
      );
    }
    if (opts.listing !== false)
      await this.env.mp.listings
        .create(this.b, {
          namespace: this.namespace,
          name,
          title: `${name} title`,
          summary: "A useful agent for tests",
          categories: ["support"],
        })
        .catch((e: { code?: string }) => {
          if (e.code !== "conflict") throw e;
        });
    return version;
  }
}
