import { randomBytes, randomUUID } from "node:crypto";
import { MemoryAuditLog } from "@axis/audit";
import pg from "pg";
import { inject } from "vitest";
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
  type DsseEnvelope,
  type PublishInput,
  type PublisherKeyPair,
  type RegistryStore,
  type TenantPrincipal,
} from "../src/index.js";

export const ROLE = "axis_app";
export const hex = (n: number): string => randomBytes(n / 2).toString("hex");
/** Random lowercase id made only of letters that normalizeName does not fold, so two ids never collide as "confusable". */
export const rid = (n = 6): string =>
  Array.from(randomBytes(n), (b) => "cdfghjkpquxyz"[b % 13]).join("");

export class Clock {
  constructor(public t: Date) {}
  now = (): Date => new Date(this.t.getTime());
  advance(ms: number): void {
    this.t = new Date(this.t.getTime() + ms);
  }
  set(iso: string): void {
    this.t = new Date(iso);
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
    [id, `t-${hex(10)}`],
  );
  return id;
}

export const principal = (
  tenantId: string,
  role: TenantPrincipal["role"] = "admin",
  subject = `user-${tenantId.slice(0, 4)}`,
): TenantPrincipal => ({
  kind: "tenant",
  tenantId,
  subject,
  role,
});

export const ablDoc = (
  name: string,
  version: string,
  extra: Record<string, unknown> = {},
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
    ...extra,
  },
});

export interface Harness {
  store: RegistryStore;
  audit: MemoryAuditLog;
  clock: Clock;
  svc: RegistryService;
}

export function harness(
  store: RegistryStore = new MemoryRegistryStore(),
  start = "2026-10-02T12:00:00Z",
): Harness {
  const clock = new Clock(new Date(start));
  const audit = new MemoryAuditLog({ now: clock.now });
  const svc = new RegistryService({
    store,
    audit: new ServiceAudit(audit, "registry", clock.now),
    now: clock.now,
  });
  return { store, audit, clock, svc };
}

export const pgStore = (pool: pg.Pool): PgRegistryStore =>
  new PgRegistryStore({ pool, role: ROLE });

/** A publisher: a tenant, a namespace and a registered signing key. */
export class Publisher {
  key!: PublisherKeyPair;
  constructor(
    readonly h: Harness,
    readonly p: TenantPrincipal,
    readonly namespace: string,
  ) {}

  static async create(
    h: Harness,
    tenantId: string,
    namespace: string,
    role: TenantPrincipal["role"] = "admin",
  ): Promise<Publisher> {
    const pub = new Publisher(h, principal(tenantId, role), namespace);
    await h.svc.claimNamespace(pub.p, namespace);
    pub.key = generatePublisherKey();
    await h.svc.addKey(pub.p, namespace, {
      publicKey: pub.key.publicKey,
      validFrom: new Date(h.clock.t.getTime() - 1000),
    });
    return pub;
  }

  /** Builds a correctly signed submission for `abl`. */
  submission(
    abl: Record<string, unknown>,
    opts: { key?: PublisherKeyPair; signedAt?: Date } = {},
  ): PublishInput {
    const key = opts.key ?? this.key;
    const meta = abl["metadata"] as { name: string; version: string };
    const hash = ablContentHash(abl);
    const spec = abl["spec"] as { riskClassification: { level: string } };
    const id = {
      namespace: this.namespace,
      name: meta.name,
      version: meta.version,
      riskLevel: spec.riskClassification.level,
      contentHash: hash,
    };
    const signature = signBlueprint(id, key, opts.signedAt ?? this.h.clock.now());
    const provenance: DsseEnvelope = signStatement(
      buildStatement(
        {
          namespace: this.namespace,
          name: meta.name,
          version: meta.version,
          abl,
          builderId: "ci.example.com/builder",
          sourceRef: "git+https://example.com/repo@refs/heads/main",
          now: this.h.clock.now(),
        },
        hash,
      ),
      key,
    );
    return { abl, signature, provenance };
  }

  publish(abl: Record<string, unknown>, opts: { key?: PublisherKeyPair; signedAt?: Date } = {}) {
    return this.h.svc.publish(this.p, this.namespace, this.submission(abl, opts));
  }
}
