import { hkdfSync } from "node:crypto";
import type pg from "pg";
import { GovernanceAudit, type GovAuditSink } from "./audit.js";
import { ManifestSigner } from "./bundle.js";
import { DsarEngine } from "./dsar.js";
import { MasterKeyProvider, Pseudonymiser, Sealer } from "./keys.js";
import { PgAttesterDirectory, PgRegionResolver, PgRetentionSettings } from "./pg-ports.js";
import { ApprovalsProvider } from "./providers/approvals.js";
import { BillingProvider } from "./providers/billing.js";
import { ChannelsProvider } from "./providers/channels.js";
import { EvalHubProvider } from "./providers/evalhub.js";
import { MembersProvider } from "./providers/members.js";
import { MemoryProvider } from "./providers/memory.js";
import { RunLogsProvider } from "./providers/runlogs.js";
import { HoldRegistry } from "./registry.js";
import { ResidencyPolicy, type TenantRegionResolver } from "./residency.js";
import { RetentionEngine, type RetentionSettingsPort } from "./retention.js";
import { PgGovernanceStore, type GovernanceStore } from "./store.js";
import { EvidenceVerifier, type AttesterDirectory } from "./verifier.js";
import type { SubjectDataProvider } from "./types.js";

export interface GovernanceKitOptions {
  /** A pool connected as a member of `axis_governance` (privileged: it can scrub one tenant's personal-data columns at a time). */
  pool: pg.Pool;
  /** `SET LOCAL ROLE` per transaction; default `axis_governance`. */
  role?: string;
  /** 32 bytes or more. A dev stand-in for a KMS (NEEDS 365). */
  masterKey: Buffer;
  /** The region this instance serves (the default export destination and the write-guard region). */
  region: string;
  /** The tenant's Postgres audit chain (a `PgAuditLog`). An append failure aborts the operation. */
  audit: GovAuditSink;
  now?: () => Date;
  /** Test seams. */
  store?: GovernanceStore;
  providers?: readonly SubjectDataProvider[];
  directory?: AttesterDirectory;
  signer?: ManifestSigner;
  regions?: TenantRegionResolver;
  settings?: RetentionSettingsPort;
}

/** Everything the gateway needs from the data-governance service, wired to the real stores. */
export interface GovernanceKit {
  store: GovernanceStore;
  dsar: DsarEngine;
  holds: HoldRegistry;
  retention: RetentionEngine;
  residency: ResidencyPolicy;
  regions: TenantRegionResolver;
  verifier: EvidenceVerifier;
  region: string;
}

/** The export-bundle signing key, derived from the master key so signatures stay verifiable across restarts. */
function derivedSigner(master: Buffer): ManifestSigner {
  const seed = Buffer.from(
    hkdfSync("sha256", master, Buffer.alloc(0), Buffer.from("axis-gov.v1:manifest-signing"), 32),
  );
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  return new ManifestSigner(
    `-----BEGIN PRIVATE KEY-----\n${der.toString("base64")}\n-----END PRIVATE KEY-----\n`,
  );
}

export function createGovernanceKit(o: GovernanceKitOptions): GovernanceKit {
  const pgo = { pool: o.pool, role: o.role ?? "axis_governance" };
  const now = o.now ?? (() => new Date());
  const store = o.store ?? new PgGovernanceStore(pgo);
  const keys = new MasterKeyProvider(o.masterKey);
  const pseudo = new Pseudonymiser(keys);
  const sealer = new Sealer(keys);
  const audit = new GovernanceAudit(o.audit, now);
  const regions: TenantRegionResolver = o.regions ?? new PgRegionResolver(pgo);
  const residency = new ResidencyPolicy(regions);
  const holds = new HoldRegistry({ store, pseudo, sealer, audit, now });
  const providers = o.providers ?? [
    new ChannelsProvider(pgo, true),
    new ChannelsProvider(pgo),
    new MemoryProvider(pgo),
    new MembersProvider(pgo),
    new BillingProvider(pgo),
    new EvalHubProvider(pgo),
    new RunLogsProvider(pgo),
    new ApprovalsProvider({ pg: pgo }),
  ];
  const verifier = new EvidenceVerifier(keys, o.directory ?? new PgAttesterDirectory(pgo), now);
  const dsar = new DsarEngine({
    store,
    pseudo,
    sealer,
    providers,
    audit,
    verifier,
    residency,
    holds,
    signer: o.signer ?? derivedSigner(o.masterKey),
    serviceRegion: o.region,
    now,
  });
  const retention = new RetentionEngine({
    store,
    providers,
    holds,
    audit,
    settings: o.settings ?? new PgRetentionSettings(pgo),
    now,
  });
  return { store, dsar, holds, retention, residency, regions, verifier, region: o.region };
}
