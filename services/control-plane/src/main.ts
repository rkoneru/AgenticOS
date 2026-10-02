import { PgAuditLog } from "@axis/audit";
import { randomBytes } from "node:crypto";
import pg from "pg";
import { Authorizer } from "./authz.js";
import { FakeDnsResolver } from "./domains.js";
import { createControlPlaneServer, listenLoopback } from "./http.js";
import { FakeIdentityProvider } from "./idp.js";
import { LocalKms } from "./kms.js";
import { runtimeAuthFromTokens } from "./runtime-bridge.js";
import { PgControlPlaneStore } from "./pg-store.js";
import { wireControlPlane } from "./wire.js";

/**
 * DEV ENTRY POINT (not production): Postgres store, FAKE IdP/KMS/DNS, loopback listener. Environment:
 *   CP_PG_URL (required; a login role that is a member of axis_app), CP_REGION (us-east-1), CP_PORT (0 = random),
 *   CP_PEPPER / CP_COOKIE_KEY / CP_SIGNING_KEY / CP_KMS_KEY (64 hex chars each; random per start when unset, so sessions die on restart),
 *   CP_PLATFORM_TOKEN, CP_DEV_TOKEN (routes disabled when unset), CP_RUNTIME_TOKENS (JSON {"<tenant uuid>": "<token>"}).
 */
async function main(): Promise<void> {
  const env = process.env;
  const url = env["CP_PG_URL"];
  if (!url) throw new Error("CP_PG_URL is required");
  const key = (name: string): Buffer => {
    const v = env[name];
    if (v === undefined) return randomBytes(32);
    if (!/^[0-9a-f]{64}$/i.test(v)) throw new Error(`${name} must be 64 hex characters`);
    return Buffer.from(v, "hex");
  };
  const region = env["CP_REGION"] ?? "us-east-1";
  const pool = new pg.Pool({ connectionString: url, max: 10 });
  const audit = new PgAuditLog({ pool });
  const cp = wireControlPlane({
    store: new PgControlPlaneStore({ pool }),
    auditSink: audit,
    auditReader: audit,
    authorizer: await Authorizer.fromPackFile(),
    idp: new FakeIdentityProvider(),
    kms: new LocalKms({ "local-1": key("CP_KMS_KEY") }, "local-1"),
    dns: new FakeDnsResolver(),
    region,
    regions: [region],
    secrets: {
      pepper: key("CP_PEPPER"),
      cookieKey: key("CP_COOKIE_KEY"),
      signingKeys: [{ kid: "k1", key: key("CP_SIGNING_KEY") }],
    },
    redirectUri: env["CP_REDIRECT_URI"] ?? "http://127.0.0.1/auth/sso/callback",
    allowedReturnOrigins: (env["CP_RETURN_ORIGINS"] ?? "").split(",").filter(Boolean),
    ...(env["CP_PLATFORM_TOKEN"] ? { platformToken: env["CP_PLATFORM_TOKEN"] } : {}),
    ...(env["CP_DEV_TOKEN"] ? { devToken: env["CP_DEV_TOKEN"] } : {}),
    ...(env["CP_RUNTIME_TOKENS"]
      ? {
          runtimeAuth: runtimeAuthFromTokens(
            JSON.parse(env["CP_RUNTIME_TOKENS"]) as Record<string, string>,
          ),
        }
      : {}),
    secureCookies: env["CP_INSECURE_COOKIES"] !== "1",
  });
  const port = await listenLoopback(
    createControlPlaneServer(cp.deps),
    Number(env["CP_PORT"] ?? "0"),
  );
  console.log(
    `control-plane (DEV: fake IdP/KMS/DNS) listening on 127.0.0.1:${port} region=${region}`,
  );
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
