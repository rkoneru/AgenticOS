import { DEFAULT_LIMITS, type Limits } from "../limits.js";
import type { ChannelId, Reject, RawRequest, RouteConfig, RoutingTable } from "../types.js";

export interface AdapterOptions {
  limits?: Limits;
  /** Replay window for timestamped providers, ms. */
  replayWindowMs?: number;
}

export const reject = (code: Reject["code"], reason: string, route?: RouteConfig): Reject => ({
  ok: false,
  code,
  reason,
  ...(route ? { route } : {}),
});

export const asObj = (v: unknown): Record<string, unknown> | undefined =>
  typeof v === "object" && v !== null && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : undefined;
export const asStr = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);
export const asArr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

export function parseJsonBody(req: RawRequest, limits: Limits): Record<string, unknown> | Reject {
  if (req.body.length > limits.maxBodyBytes) return reject("too_large", "body too large");
  try {
    const v = asObj(JSON.parse(req.body.toString("utf8")));
    return v ?? reject("malformed", "body must be a JSON object");
  } catch {
    return reject("malformed", "body is not valid JSON");
  }
}
export const isReject = (v: unknown): v is Reject =>
  typeof v === "object" && v !== null && (v as { ok?: unknown }).ok === false;

/** Look the CLAIMED provider key up. Not authentication: the caller must still verify with the route's own secret. */
export function claimRoute(
  routes: RoutingTable,
  channel: ChannelId,
  claimed: string | undefined,
): RouteConfig | Reject {
  if (claimed === undefined || claimed === "")
    return reject("unknown_route", "request names no provider identity");
  const route = routes.lookup(channel, claimed);
  if (!route) return reject("unknown_route", "no route for provider identity");
  if (!route.enabled) return reject("route_disabled", "route is disabled", route);
  return route;
}

export const limitsOf = (o: AdapterOptions | undefined): Limits => o?.limits ?? DEFAULT_LIMITS;

export const setting = (r: RouteConfig, k: string): string | undefined => {
  const v = r.settings[k];
  return typeof v === "string" ? v : undefined;
};
export const secret = (r: RouteConfig, k: string): string | undefined => {
  const v = r.secrets[k];
  return typeof v === "string" && v !== "" ? v : undefined;
};

export function cap(text: string, limits: Limits): string | undefined {
  return text.length > limits.maxTextChars ? undefined : text;
}
