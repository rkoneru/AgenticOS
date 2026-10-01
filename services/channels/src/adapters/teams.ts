import { verifyRs256Jwt, type JwksProvider } from "../jwt.js";
import { normalizeAttachments } from "../limits.js";
import { withinWindow } from "../replay.js";
import {
  ChannelError,
  type Capabilities,
  type ChannelAdapter,
  type InboundMessage,
  type OutboundMessage,
  type RawRequest,
  type RenderedCall,
  type Reject,
  type RouteConfig,
  type VerifiedInbound,
  type VerifyContext,
} from "../types.js";
import {
  asArr,
  asObj,
  asStr,
  claimRoute,
  isReject,
  limitsOf,
  parseJsonBody,
  reject,
  secret,
  setting,
  type AdapterOptions,
} from "./base.js";

export const TEAMS_CAPABILITIES: Capabilities = {
  threading: true,
  richText: true,
  attachments: true,
  maxLength: 20_000,
  rateLimitPerMinute: 60,
};

export const BOT_FRAMEWORK_ISSUER = "https://api.botframework.com";

export interface TeamsAdapterOptions extends AdapterOptions {
  /** Injected signing keys (the Bot Framework OpenID JWKS). Fetching/caching it is a NEEDS item. */
  jwks: JwksProvider;
  /** Accepted `iss` values. Default: the Bot Framework issuer. */
  issuers?: readonly string[];
}

const stripTeamsMarkup = (t: string): string =>
  t
    .replace(/<at>[^<]{0,200}<\/at>/gi, "")
    .replace(/\s+/g, " ")
    .trim();

/** Bot Framework-style: `Authorization: Bearer <RS256 JWT>` whose `aud` is the bot's app id (the route's provider key). */
export class TeamsAdapter implements ChannelAdapter {
  readonly channel = "teams" as const;
  readonly capabilities = TEAMS_CAPABILITIES;
  private readonly windowMs: number;

  constructor(private readonly opts: TeamsAdapterOptions) {
    this.windowMs = opts.replayWindowMs ?? 15 * 60_000;
  }

  async verifyInbound(req: RawRequest, ctx: VerifyContext): Promise<Reject | VerifiedInbound> {
    if (req.method !== "POST") return reject("unsupported", "method not allowed");
    const body = parseJsonBody(req, limitsOf(this.opts));
    if (isReject(body)) return body;
    const recipient = asStr(asObj(body["recipient"])?.["id"]);
    // `28:<app id>` is how Bot Framework addresses a bot; the claim only selects which audience to verify against.
    const claimed = recipient?.startsWith("28:") ? recipient.slice(3) : recipient;
    const route = claimRoute(ctx.routes, "teams", claimed);
    if (isReject(route)) return route;

    const auth = req.headers["authorization"];
    if (auth === undefined || !/^Bearer [A-Za-z0-9._-]+$/.test(auth))
      return reject("bad_signature", "missing bearer token", route);
    const res = await verifyRs256Jwt(auth.slice(7), {
      jwks: this.opts.jwks,
      issuers: this.opts.issuers ?? [BOT_FRAMEWORK_ISSUER],
      audience: route.provider_key,
      nowMs: ctx.nowMs,
    });
    if (!res.ok)
      return reject(
        res.reason === "expired" || res.reason === "not yet valid" ? "stale" : "bad_signature",
        `jwt: ${res.reason}`,
        route,
      );
    // Bot Framework binds the token to the service URL the activity claims; a token minted for another service URL is refused.
    const claimUrl = res.claims["serviceurl"];
    if (claimUrl !== undefined && claimUrl !== body["serviceUrl"])
      return reject("bad_signature", "serviceUrl does not match the token", route);
    const ts = asStr(body["timestamp"]);
    if (ts !== undefined && !withinWindow(Date.parse(ts), ctx.nowMs, this.windowMs))
      return reject("stale", "activity timestamp outside the replay window", route);
    return { ok: true, route, payload: body };
  }

  normalize(v: VerifiedInbound): InboundMessage[] {
    const a = asObj(v.payload);
    if (!a || a["type"] !== "message") return [];
    const from = asObj(a["from"]);
    const user = asStr(from?.["aadObjectId"]) ?? asStr(from?.["id"]);
    const conv = asStr(asObj(a["conversation"])?.["id"]);
    const id = asStr(a["id"]);
    if (!user || !conv || !id) return [];
    const limits = limitsOf(this.opts);
    const text = stripTeamsMarkup(asStr(a["text"]) ?? "");
    if (text.length > limits.maxTextChars) return [];
    const att = normalizeAttachments(
      asArr(a["attachments"]).map((x) => {
        const o = asObj(x) ?? {};
        // `contentUrl` is deliberately NOT read: attacker-controlled URLs are never kept or fetched.
        return { name: o["name"], content_type: o["contentType"], size: 0 };
      }),
      limits,
    );
    const ts = Date.parse(asStr(a["timestamp"]) ?? "");
    return [
      {
        tenant_id: v.route.tenant_id,
        channel: "teams",
        provider_key: v.route.provider_key,
        agent: v.route.agent,
        external_user_id: user,
        conversation_hint: conv,
        text,
        attachments: att.kept,
        dropped_attachments: att.dropped,
        idempotency_key: `teams:${id}`,
        timestamp_ms: Number.isFinite(ts) ? ts : 0,
      },
    ];
  }

  render(msg: OutboundMessage, route: RouteConfig): RenderedCall {
    const serviceUrl = setting(route, "service_url");
    const token = secret(route, "access_token");
    if (!serviceUrl || !/^https:\/\/[^/\s?#@]+(\/[^\s?#]*)?\/$/.test(serviceUrl))
      throw new ChannelError("INVALID", "teams route needs an https service_url ending in /");
    if (!token) throw new ChannelError("INVALID", "teams route has no access_token");
    if (!/^[A-Za-z0-9:@._;=-]{1,256}$/.test(msg.to))
      throw new ChannelError("INVALID", "invalid teams conversation id");
    return {
      kind: "http",
      method: "POST",
      url: `${serviceUrl}v3/conversations/${encodeURIComponent(msg.to)}/activities`,
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        type: "message",
        text: msg.text,
        textFormat: "plain",
        ...(msg.thread ? { replyToId: msg.thread } : {}),
      }),
    };
  }
}
