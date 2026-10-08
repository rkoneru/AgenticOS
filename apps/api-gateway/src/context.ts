import type { ApiSpec } from "./spec.js";
import type { CursorCodec } from "./limits.js";
import type {
  ApiAudit,
  ApprovalsPort,
  AuditPort,
  Authenticator,
  Authz,
  BlueprintStore,
  EvalsPort,
  ExplainPort,
  IdempotencyStore,
  IdentityPort,
  KillSwitchPort,
  MarketplacePort,
  PolicyPort,
  Principal,
  RateLimiter,
  RegistryPort,
  RunEventDto,
  RunsPort,
  UsagePort,
} from "./ports.js";

export interface GatewayDeps {
  auth: Authenticator;
  authz: Authz;
  audit: ApiAudit;
  blueprints: BlueprintStore;
  runs: RunsPort;
  approvals: ApprovalsPort;
  policies: PolicyPort;
  auditLog: AuditPort;
  killSwitches: KillSwitchPort;
  usage: UsagePort;
  explain: ExplainPort;
  identity: IdentityPort;
  registry: RegistryPort;
  marketplace: MarketplacePort;
  evals: EvalsPort;
  idempotency: IdempotencyStore;
  /** Per-tenant buckets (key = tenant id). Defaults to `TokenBuckets` from the options. */
  limiter?: RateLimiter;
  /** Failed-authentication buckets (key = remote address). */
  unauthLimiter?: RateLimiter;
  cursors?: CursorCodec;
  spec?: ApiSpec;
}

export interface GatewayOptions {
  /** Origins allowed to call from a browser (exact match; the console). Empty = no cross-origin access. */
  allowedOrigins?: readonly string[];
  maxBodyBytes?: number;
  requestTimeoutMs?: number;
  /**
   * Addresses of reverse proxies in front of the gateway (the console's BFF, a load balancer). Only a connection FROM one of them may
   * name the client in `X-Forwarded-For`; the client is then the right-most entry that is not itself a trusted proxy. Default none:
   * the header is ignored and every failed authentication is counted against the peer address.
   */
  trustedProxies?: readonly string[];
  /** Per-tenant bucket. Default burst 60, 30/s. */
  rate?: { burst: number; perSecond: number };
  /** Failed authentications per remote address. Default burst 20, 1/s. */
  unauthRate?: { burst: number; perSecond: number };
  /** Cost of an operation in tokens (default 1). */
  costs?: Record<string, number>;
  maxSseStreamsPerTenant?: number;
  sseHeartbeatMs?: number;
  sseRecheckMs?: number;
  sseMaxMs?: number;
  idempotencyTtlMs?: number;
  /** Validate every response against the OpenAPI (on in tests/dev; a mismatch becomes a 500). */
  validateResponses?: boolean;
  /** Send HSTS (the gateway sits behind TLS termination). */
  behindTls?: boolean;
  /** Longest range `POST /audit/verify` will walk in one call. */
  maxVerifyEvents?: number;
  log?: (level: "info" | "warn" | "error", msg: string, fields?: Record<string, unknown>) => void;
  now?: () => number;
}

export interface Ctx {
  principal: Principal;
  tenantId: string;
  operationId: string;
  params: Record<string, unknown>;
  query: Record<string, unknown>;
  body: unknown;
  traceId: string;
  requestId: string;
  deps: GatewayDeps;
  opts: Required<Pick<GatewayOptions, "maxVerifyEvents">> & GatewayOptions;
  cursors: CursorCodec;
  wantsStream: boolean;
  lastEventId: number | undefined;
  signal: AbortSignal;
}

export interface JsonResult {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}
export interface StreamResult {
  stream: AsyncIterable<RunEventDto>;
  headers?: Record<string, string>;
}
export type HandlerResult = JsonResult | StreamResult;
export const isStream = (r: HandlerResult): r is StreamResult => "stream" in r;

export type Handler = (c: Ctx) => Promise<HandlerResult>;

export interface Route {
  /** The `api.<resource>.<verb>` action decided by the control-plane pack; `null` = any authenticated credential (identity only). */
  action: string | null;
  handler: Handler;
  /** Mutations are audited (allow and deny) before they execute. */
  mutation: boolean;
}
