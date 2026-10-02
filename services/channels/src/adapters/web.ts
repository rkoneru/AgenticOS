import { b64urlDecode, b64urlEncode, hmacSha256Hex, randomToken, safeEqual } from "../crypto.js";
import { normalizeAttachments } from "../limits.js";
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
  type AdapterOptions,
} from "./base.js";

export const WEB_CAPABILITIES: Capabilities = {
  threading: false,
  richText: true,
  attachments: true,
  maxLength: 20_000,
  rateLimitPerMinute: 120,
};

const SID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const mac = (key: string, payload: string): string =>
  hmacSha256Hex(key, `axis-web-session.v1.${payload}`);

export interface WebSession {
  /** The widget site key = the route's provider key. */
  site: string;
  sid: string;
  exp: number;
}

/** Issue a session token for the widget. `sid` is random, so the visitor is anonymous until linked (identity linking needs proof). */
export function issueWebSession(
  route: RouteConfig,
  opts: { nowMs: number; ttlSec?: number; sid?: string },
): string {
  const key = secret(route, "session_secret");
  if (!key) throw new ChannelError("INVALID", "web route has no session_secret");
  const sid = opts.sid ?? randomToken(18);
  if (!SID_RE.test(sid)) throw new ChannelError("INVALID", "invalid session id");
  const payload = b64urlEncode(
    JSON.stringify({
      site: route.provider_key,
      sid,
      exp: Math.floor(opts.nowMs / 1000) + (opts.ttlSec ?? 3600),
    }),
  );
  return `v1.${payload}.${mac(key, payload)}`;
}

/** Verify a session token against the route its OWN `site` claim names (claim selects the secret; the MAC authenticates it). */
export function verifyWebSession(
  token: string,
  ctx: VerifyContext,
): { ok: true; route: RouteConfig; session: WebSession } | Reject {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== "v1" || token.length > 1024)
    return reject("bad_signature", "malformed session token");
  const [, payload, sig] = parts as [string, string, string];
  let claims: Record<string, unknown> | undefined;
  try {
    claims = asObj(JSON.parse(b64urlDecode(payload)?.toString("utf8") ?? ""));
  } catch {
    claims = undefined;
  }
  const site = asStr(claims?.["site"]);
  const route = claimRoute(ctx.routes, "web", site);
  if (isReject(route)) return route;
  const key = secret(route, "session_secret");
  if (!key || !safeEqual(mac(key, payload), sig))
    return reject("bad_signature", "session token does not verify", route);
  const sid = asStr(claims?.["sid"]);
  const exp = claims?.["exp"];
  if (!sid || !SID_RE.test(sid) || typeof exp !== "number")
    return reject("malformed", "bad session claims", route);
  if (exp * 1000 < ctx.nowMs) return reject("stale", "session token expired", route);
  return { ok: true, route, session: { site: route.provider_key, sid, exp } };
}

export function originAllowed(route: RouteConfig, origin: string | undefined): boolean {
  const allowed = route.settings["allowed_origins"];
  return Array.isArray(allowed) && origin !== undefined && allowed.includes(origin);
}

/** HTTP + SSE web widget. Inbound: `Authorization: Bearer <session token>` + JSON; outbound: pushed to the session's SSE stream. */
export class WebAdapter implements ChannelAdapter {
  readonly channel = "web" as const;
  readonly capabilities = WEB_CAPABILITIES;

  constructor(private readonly opts: AdapterOptions = {}) {}

  async verifyInbound(req: RawRequest, ctx: VerifyContext): Promise<Reject | VerifiedInbound> {
    if (req.method !== "POST") return reject("unsupported", "method not allowed");
    const auth = req.headers["authorization"];
    if (auth === undefined || !auth.startsWith("Bearer "))
      return reject("bad_signature", "missing session token");
    const s = verifyWebSession(auth.slice(7), ctx);
    if (isReject(s)) return s;
    if (!originAllowed(s.route, req.headers["origin"]))
      return reject("bad_signature", "origin is not allowed for this site", s.route);
    const body = parseJsonBody(req, limitsOf(this.opts));
    if (isReject(body)) return { ...body, route: s.route };
    return { ok: true, route: s.route, payload: { session: s.session, body } };
  }

  normalize(v: VerifiedInbound): InboundMessage[] {
    const p = asObj(v.payload);
    const session = p?.["session"] as WebSession | undefined;
    const b = asObj(p?.["body"]);
    if (!session || !b) return [];
    const cmid = asStr(b["client_message_id"]);
    const text = asStr(b["text"]);
    const limits = limitsOf(this.opts);
    if (
      !cmid ||
      !/^[A-Za-z0-9_-]{8,64}$/.test(cmid) ||
      text === undefined ||
      text.length > limits.maxTextChars
    )
      return [];
    const att = normalizeAttachments(
      asArr(b["attachments"]).map((x) => {
        const o = asObj(x) ?? {};
        return { name: o["name"], content_type: o["content_type"], size: o["size"] };
      }),
      limits,
    );
    return [
      {
        tenant_id: v.route.tenant_id,
        channel: "web",
        provider_key: v.route.provider_key,
        agent: v.route.agent,
        external_user_id: session.sid,
        text,
        attachments: att.kept,
        dropped_attachments: att.dropped,
        idempotency_key: `web:${session.sid}:${cmid}`,
        timestamp_ms: 0,
      },
    ];
  }

  render(msg: OutboundMessage): RenderedCall {
    if (!SID_RE.test(msg.to)) throw new ChannelError("INVALID", "invalid web session id");
    return {
      kind: "web",
      session_id: msg.to,
      event: { type: "message", data: { text: msg.text } },
    };
  }
}

export interface SseEvent {
  id: number;
  type: string;
  data: Record<string, unknown>;
}

/** Per-(tenant, session) SSE fan-out with a small replay buffer for `Last-Event-ID`. The key includes the tenant: sessions never cross. */
export class WebHub {
  private readonly subs = new Map<string, Set<(e: SseEvent) => void>>();
  /** Insertion order = recency (a publish re-inserts its key), so the first key without a subscriber is the oldest idle one. */
  private readonly buffer = new Map<string, SseEvent[]>();
  private seq = 0;
  private readonly maxSessions: number;

  /** `maxSessions` bounds the replay buffers: anonymous visitors can mint sessions without limit, so memory must not follow them. */
  constructor(o: { maxSessions?: number } = {}) {
    this.maxSessions = o.maxSessions ?? 10_000;
  }

  bufferedSessions(): number {
    return this.buffer.size;
  }

  private key = (tenant: string, sid: string): string => `${tenant}/${sid}`;

  publish(tenant: string, sid: string, type: string, data: Record<string, unknown>): void {
    const k = this.key(tenant, sid);
    const ev: SseEvent = { id: ++this.seq, type, data };
    const buf = this.buffer.get(k) ?? [];
    buf.push(ev);
    if (buf.length > 50) buf.shift();
    this.buffer.delete(k);
    this.buffer.set(k, buf);
    if (this.buffer.size > this.maxSessions)
      for (const old of this.buffer.keys()) {
        if (this.buffer.size <= this.maxSessions) break;
        if (old !== k && !this.subs.has(old)) this.buffer.delete(old);
      }
    for (const fn of this.subs.get(k) ?? []) fn(ev);
  }

  subscribe(tenant: string, sid: string, fn: (e: SseEvent) => void, lastEventId = 0): () => void {
    const k = this.key(tenant, sid);
    for (const ev of this.buffer.get(k) ?? []) if (ev.id > lastEventId) fn(ev);
    const set = this.subs.get(k) ?? new Set();
    set.add(fn);
    this.subs.set(k, set);
    return () => {
      set.delete(fn);
      if (set.size === 0) this.subs.delete(k);
    };
  }

  subscribers(tenant: string, sid: string): number {
    return this.subs.get(this.key(tenant, sid))?.size ?? 0;
  }
}

export function formatSse(ev: SseEvent): string {
  const data = JSON.stringify(ev.data).replace(/\r|\n/g, "");
  return `id: ${ev.id}\nevent: ${ev.type.replace(/[^a-z_]/g, "")}\ndata: ${data}\n\n`;
}
