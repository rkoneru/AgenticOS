import { readFileSync, statSync } from "node:fs";

/** A refusal to start: the message says what to fix and never contains a secret. */
export class ConfigError extends Error {}

export interface StandaloneConfig {
  databaseUrl: string;
  /** Postgres role to assume per transaction (the unprivileged `axis_app`). */
  dbRole: string | undefined;
  port: number;
  host: string;
  allowedOrigins: string[];
  /** The control plane's secrets: sessions and API keys issued by the control plane must verify here. */
  secrets: { pepper: Buffer; cookieKey: Buffer; signingKey: Buffer };
  /** Key the billing ledger seals with (the gateway only reads; the signer is a constructor requirement). */
  sealKey: string;
  runService: { url: string; tokensFile: string };
  kernel: { target: string; tokensFile: string };
  approvals: { url: string; tokensFile: string };
  bundleDir: string | undefined;
  rate: { burst: number; perSecond: number } | undefined;
}

const HEX64 = /^[0-9a-f]{64}$/i;

/**
 * Environment contract of the DEV standalone gateway (docs/spec/api-gateway.md section 7a). Every value is validated here; nothing is
 * defaulted to something permissive. This composition uses dev adapters (static per-tenant token files for the run service, the kernel
 * and the approvals bridge; fake publisher provers; an in-memory blueprint store), so it REFUSES `NODE_ENV=production`: a production
 * wiring (workload identity, mTLS, a durable blueprint store) is Phase 10 and does not exist yet (docs/NEEDS.md #218).
 */
export function configFromEnv(env: Record<string, string | undefined>): StandaloneConfig {
  if (env["NODE_ENV"] === "production")
    throw new ConfigError(
      "refusing to start with NODE_ENV=production: this is the DEV composition (static token files, fake provers, in-memory blueprint store). A production wiring is not built yet (docs/NEEDS.md #218).",
    );
  const need = (k: string): string => {
    const v = env[k];
    if (v === undefined || v === "") throw new ConfigError(`${k} is required`);
    return v;
  };
  const hex = (k: string): Buffer => {
    const v = need(k);
    if (!HEX64.test(v)) throw new ConfigError(`${k} must be 64 hex characters (32 bytes)`);
    return Buffer.from(v, "hex");
  };
  const int = (k: string, dflt: number, min: number, max: number): number => {
    const v = env[k];
    if (v === undefined || v === "") return dflt;
    const n = Number(v);
    if (!Number.isInteger(n) || n < min || n > max)
      throw new ConfigError(`${k} must be an integer in [${min}, ${max}]`);
    return n;
  };
  const url = (k: string): string => {
    const v = need(k);
    try {
      const u = new URL(v);
      if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("scheme");
    } catch {
      throw new ConfigError(`${k} must be an http(s) URL`);
    }
    return v;
  };
  const host = env["GW_HOST"] ?? "127.0.0.1";
  if (host !== "127.0.0.1" && host !== "::1" && host !== "localhost")
    throw new ConfigError(
      "GW_HOST must be a loopback address: the dev composition has no TLS and static credentials",
    );
  const burst = env["GW_RATE_BURST"];
  const rate =
    burst === undefined
      ? undefined
      : { burst: int("GW_RATE_BURST", 60, 1, 1e7), perSecond: int("GW_RATE_PER_SEC", 30, 1, 1e7) };
  return {
    databaseUrl: need("GW_DATABASE_URL"),
    dbRole: env["GW_DB_ROLE"] || undefined,
    port: int("GW_PORT", 0, 0, 65535),
    host,
    allowedOrigins: (env["GW_ALLOWED_ORIGINS"] ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    secrets: {
      pepper: hex("GW_PEPPER"),
      cookieKey: hex("GW_COOKIE_KEY"),
      signingKey: hex("GW_SIGNING_KEY"),
    },
    sealKey: need("GW_SEAL_KEY"),
    runService: { url: url("GW_RUN_SERVICE_URL"), tokensFile: need("GW_RUN_TOKENS_FILE") },
    kernel: { target: need("GW_KERNEL_TARGET"), tokensFile: need("GW_KERNEL_TOKENS_FILE") },
    approvals: { url: url("GW_APPROVALS_URL"), tokensFile: need("GW_APPROVALS_TOKENS_FILE") },
    bundleDir: env["GW_BUNDLE_DIR"] || undefined,
    rate,
  };
}

/** `{ "<tenant uuid>": "<token>" }` re-read when the file changes (tenants are created after the gateway started). */
export class TokenTable {
  private mtime = -1;
  private data: Record<string, string> = {};
  constructor(private readonly path: string) {}
  get(tenantId: string): string | undefined {
    try {
      const m = statSync(this.path).mtimeMs;
      if (m !== this.mtime) {
        const j = JSON.parse(readFileSync(this.path, "utf8")) as Record<string, unknown>;
        this.data = Object.fromEntries(
          Object.entries(j).filter(([, v]) => typeof v === "string"),
        ) as Record<string, string>;
        this.mtime = m;
      }
    } catch {
      return undefined; // missing or malformed: no credential -> the port answers 503, never a guess
    }
    return Object.prototype.hasOwnProperty.call(this.data, tenantId)
      ? this.data[tenantId]
      : undefined;
  }
}
