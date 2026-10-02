import { PgAuditLog } from "@axis/audit";
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
import { PgRegistryStore, RegistryService, ServiceAudit } from "@axis/registry";
import pg from "pg";
import { HttpApprovalsClient } from "./adapters/approvals-http.js";
import type { GatewayOptions } from "./context.js";
import { wireGateway } from "./dev-wire.js";
import type { Gateway } from "./server.js";
import { TokenTable, type StandaloneConfig } from "./standalone.js";

export interface RunningGateway {
  gateway: Gateway;
  port: number;
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
  const registry = new RegistryService({
    store: new PgRegistryStore({ pool, ...role }),
    audit: new ServiceAudit(audit, "registry"),
  });
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
  const { gateway } = wireGateway(
    {
      controlPlane: cp,
      authorizer,
      store,
      registry,
      marketplace,
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
      ...(c.rate ? { rate: c.rate } : {}),
      log: (level, msg, fields) => {
        if (level !== "info") console.error(JSON.stringify({ level, msg, ...fields }));
      },
      ...options,
    },
  );
  const port = await gateway.listen(c.port, c.host);
  return {
    gateway,
    port,
    close: async () => {
      await gateway.close();
      await pool.end();
    },
  };
}
