import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { PgAuditLog } from "@axis/audit";
import { HmacSealer, NeedsLimitations, PgDocStore as PgComplianceDocStore } from "@axis/compliance";
import { HmacSealSigner, PgUsageLedger } from "@axis/billing";
import {
  Authorizer,
  FakeDnsResolver,
  FakeIdentityProvider,
  FileBundleSink,
  LocalKms,
  PgControlPlaneStore,
  wireControlPlane,
} from "@axis/control-plane";
import {
  PgDocStore,
  FakeDomainProver,
  FakeIdentityProver,
  createMarketplace,
} from "@axis/marketplace";
import { PgDocStore as PgEvalDocStore, createEvalHub, createHubDevServer } from "@axis/eval-hub";
import { compileAbl } from "@axis/abl";
import {
  PgRegistryStore,
  RegistryService,
  ServiceAudit,
  generatePublisherKey,
  listenLoopback,
} from "@axis/registry";
import pg from "pg";
import { HttpApprovalsClient } from "./adapters/approvals-http.js";
import type { GatewayOptions } from "./context.js";
import { wireGateway } from "./dev-wire.js";
import type { Gateway } from "./server.js";
import { RunnerTokenTable, TokenTable, type StandaloneConfig } from "./standalone.js";

export interface RunningGateway {
  gateway: Gateway;
  port: number;
  /** The Eval Hub's runner-facing loopback port (only with `GW_EVAL_RUNNER_TOKENS_FILE`). */
  evalRunnerPort?: number;
  close(): Promise<void>;
}

/** Composition root of the standalone DEV gateway process. */
export async function startStandalone(
  c: StandaloneConfig,
  options: GatewayOptions = {},
): Promise<RunningGateway> {
  const pool = new pg.Pool({ connectionString: c.databaseUrl, max: 10 });
  const role = c.dbRole ? { role: c.dbRole } : {};
  const store = new PgControlPlaneStore({ pool, ...role });
  const audit = new PgAuditLog({ pool, ...role });
  const authorizer = await Authorizer.fromPackFile();
  const cp = wireControlPlane({
    store,
    auditSink: audit,
    auditReader: audit,
    authorizer,
    // Not used by the gateway (login, SSO and the admin API live in the control-plane process): inert stand-ins.
    idp: new FakeIdentityProvider(),
    kms: new LocalKms({ "gw-unused": Buffer.alloc(32, 1) }, "gw-unused"),
    dns: new FakeDnsResolver(),
    region: c.region,
    regions: [c.region],
    secrets: {
      pepper: c.secrets.pepper,
      cookieKey: c.secrets.cookieKey,
      signingKeys: [{ kid: "k1", key: c.secrets.signingKey }],
    },
    redirectUri: "http://127.0.0.1/unused",
    allowedReturnOrigins: [],
    ...(c.bundleDir ? { bundleSink: new FileBundleSink(c.bundleDir) } : {}),
    secureCookies: true,
  });
  // The Eval Hub and the registry gate each other: the registry asks the hub before it releases a version (fail-closed), and the hub
  // hands the registry a signed summary of every finished run. The attestation key lives in this process only (docs/NEEDS.md: KMS).
  const hubKey = generatePublisherKey();
  const late: { registry?: RegistryService } = {};
  const evals = createEvalHub({
    docs: new PgEvalDocStore({ pool, ...role }),
    audit: new ServiceAudit(audit, "eval-hub"),
    signing: hubKey,
    sink: {
      attach: async (_tenantId, ref, envelope) => {
        await (late.registry as RegistryService).attachEvalAttestation(
          { kind: "platform", subject: "eval-hub", service: "eval-hub" },
          ref,
          envelope,
        );
      },
    },
    publishers: {
      publisherOf: async (tenantId, b) =>
        b.namespace === null
          ? null
          : ((
              await (late.registry as RegistryService).listVersions(
                { tenantId },
                b.namespace,
                b.name,
              )
            ).find((v) => v.record.version === b.version)?.record.publishedBy ?? null),
    },
  });
  const registry = new RegistryService({
    store: new PgRegistryStore({ pool, ...role }),
    audit: new ServiceAudit(audit, "registry"),
    evalGate: evals.gatePort,
    evalHubKeys: [{ keyId: hubKey.keyId, publicKey: hubKey.publicKey }],
  });
  late.registry = registry;
  const marketplace = createMarketplace({
    docs: new PgDocStore({ pool, ...role }),
    registry,
    audit: new ServiceAudit(audit, "marketplace"),
    domain: new FakeDomainProver(),
    identity: new FakeIdentityProver(),
  });
  const runTokens = new TokenTable(c.runService.tokensFile);
  const kernelTokens = new TokenTable(c.kernel.tokensFile);
  const approvalTokens = new TokenTable(c.approvals.tokensFile);
  const ledger = new PgUsageLedger({
    pool,
    signer: new HmacSealSigner(Buffer.from(c.sealKey, "utf8")),
    ...role,
  });
  const { gateway, deps } = wireGateway(
    {
      controlPlane: cp,
      authorizer,
      store,
      registry,
      marketplace,
      evals,
      compliance: {
        docs: new PgComplianceDocStore({ pool, ...role }),
        // Documents are sealed with a key derived from the gateway's seal key: it survives restarts, so old documents keep verifying.
        sealer: new HmacSealer(
          createHmac("sha256", c.sealKey).update("axis-compliance-docs-v1").digest(),
          "gw-compliance-1",
        ),
        limitations: new NeedsLimitations(() =>
          c.complianceNeedsFile ? readFileSync(c.complianceNeedsFile, "utf8") : undefined,
        ),
      },
      audit,
      approvals: new HttpApprovalsClient(c.approvals.url, (t) => approvalTokens.get(t)) as never,
      ledger,
      runs: {
        url: c.runService.url,
        tokens: new Proxy(
          {},
          { get: (_t, k) => (typeof k === "string" ? runTokens.get(k) : undefined) },
        ),
      },
      kernel: {
        target: c.kernel.target,
        tokens: new Proxy(
          {},
          { get: (_t, k) => (typeof k === "string" ? kernelTokens.get(k) : undefined) },
        ),
      },
    },
    {
      allowedOrigins: c.allowedOrigins,
      ...(c.trustedProxies.length ? { trustedProxies: c.trustedProxies } : {}),
      ...(c.rate ? { rate: c.rate } : {}),
      log: (level, msg, fields) => {
        if (level !== "info") console.error(JSON.stringify({ level, msg, ...fields }));
      },
      ...options,
    },
  );
  const port = await gateway.listen(c.port, c.host);
  let runnerServer: ReturnType<typeof createHubDevServer> | undefined;
  let evalRunnerPort: number | undefined;
  if (c.evalRunner) {
    const table = new RunnerTokenTable(c.evalRunner.tokensFile);
    runnerServer = createHubDevServer({
      hub: evals,
      tokens: {},
      authenticate: (authorization) => {
        const cred = table.authenticate(authorization);
        return cred === undefined ? undefined : { kind: "runner", ...cred };
      },
      // The compiled manifest of a stored blueprint version, for the runner that is executing it. A registry version is re-verified
      // (hash, signature, provenance) on every read; a tenant-local blueprint comes from the gateway's own store.
      manifests: {
        manifest: async (tenantId, ref) => {
          try {
            const abl =
              ref.namespace === null
                ? (await deps.blueprints.get(tenantId, ref.name, ref.version))?.abl
                : (await registry.getVersion({ tenantId }, ref.namespace, ref.name, ref.version))
                    .abl;
            if (abl === undefined) return undefined;
            const r = compileAbl(abl);
            return r.ok ? r.manifest : undefined;
          } catch {
            return undefined;
          }
        },
      },
    });
    evalRunnerPort = await listenLoopback(runnerServer, c.evalRunner.port);
  }
  return {
    gateway,
    port,
    ...(evalRunnerPort !== undefined ? { evalRunnerPort } : {}),
    close: async () => {
      await gateway.close();
      if (runnerServer) await new Promise<void>((r) => runnerServer?.close(() => r()));
      await pool.end();
    },
  };
}
