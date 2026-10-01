import { safeEqual, verifyHmacSha256Hex } from "../crypto.js";
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
  type AdapterOptions,
} from "./base.js";

export const WHATSAPP_CAPABILITIES: Capabilities = {
  threading: false,
  richText: false,
  attachments: true,
  maxLength: 4_096,
  rateLimitPerMinute: 80,
};

export const WA_ID_RE = /^[1-9]\d{6,14}$/;

interface WaPayload {
  messages: {
    id: string;
    from: string;
    ts: number;
    text: string;
    media: Record<string, unknown>[];
  }[];
}

/** Meta Cloud API webhook: `X-Hub-Signature-256: sha256=<hex HMAC-SHA256(app secret, raw body)>` and the GET verify handshake. */
export class WhatsAppAdapter implements ChannelAdapter {
  readonly channel = "whatsapp" as const;
  readonly capabilities = WHATSAPP_CAPABILITIES;
  private readonly windowMs: number;

  constructor(private readonly opts: AdapterOptions = {}) {
    this.windowMs = opts.replayWindowMs ?? 24 * 3_600_000;
  }

  async verifyInbound(req: RawRequest, ctx: VerifyContext): Promise<Reject | VerifiedInbound> {
    if (req.method === "GET") return this.handshake(req, ctx);
    if (req.method !== "POST") return reject("unsupported", "method not allowed");
    const body = parseJsonBody(req, limitsOf(this.opts));
    if (isReject(body)) return body;
    const entries = asArr(body["entry"]).map(asObj);
    const keys = new Set<string>();
    for (const e of entries)
      for (const c of asArr(e?.["changes"]).map(asObj)) {
        const pid = asStr(asObj(asObj(c?.["value"])?.["metadata"])?.["phone_number_id"]);
        if (pid === undefined) return reject("malformed", "change without a phone_number_id");
        keys.add(pid);
      }
    // A single signed request may only address ONE route: a batch naming several numbers is refused rather than split.
    if (keys.size !== 1)
      return reject("malformed", "request must name exactly one phone_number_id");
    const route = claimRoute(ctx.routes, "whatsapp", [...keys][0]);
    if (isReject(route)) return route;
    const appSecret = secret(route, "app_secret");
    const header = req.headers["x-hub-signature-256"];
    if (!appSecret || header === undefined || !header.startsWith("sha256="))
      return reject("bad_signature", "missing signature", route);
    if (!verifyHmacSha256Hex(appSecret, req.body, header.slice(7)))
      return reject("bad_signature", "signature does not verify", route);

    const messages: WaPayload["messages"] = [];
    for (const e of entries)
      for (const c of asArr(e?.["changes"]).map(asObj)) {
        for (const m of asArr(asObj(c?.["value"])?.["messages"]).map(asObj)) {
          const id = asStr(m?.["id"]);
          const from = asStr(m?.["from"]);
          const ts = Number(asStr(m?.["timestamp"]));
          if (!m || !id || !from || !Number.isFinite(ts))
            return reject("malformed", "malformed message", route);
          if (!withinWindow(ts * 1000, ctx.nowMs, this.windowMs))
            return reject("stale", "message timestamp outside the replay window", route);
          const type = asStr(m["type"]);
          const text = type === "text" ? (asStr(asObj(m["text"])?.["body"]) ?? "") : "";
          const media = type && asObj(m[type]) && type !== "text" ? [asObj(m[type])!] : [];
          messages.push({ id, from, ts, text, media });
        }
      }
    return { ok: true, route, payload: { messages } satisfies WaPayload };
  }

  /** GET `?hub.mode=subscribe&hub.verify_token=..&hub.challenge=..`: answered only if the token matches a configured route. */
  private handshake(req: RawRequest, ctx: VerifyContext): Reject | VerifiedInbound {
    const q = req.query;
    const challenge = q["hub.challenge"];
    if (
      q["hub.mode"] !== "subscribe" ||
      q["hub.verify_token"] === undefined ||
      challenge === undefined ||
      !/^[\w.-]{1,128}$/.test(challenge)
    )
      return reject("malformed", "bad verification request");
    let match: RouteConfig | undefined;
    for (const r of ctx.routes.candidates("whatsapp")) {
      const t = secret(r, "verify_token");
      if (t !== undefined && safeEqual(t, q["hub.verify_token"])) match ??= r; // no early exit: every candidate is compared
    }
    if (!match) return reject("bad_signature", "verify token mismatch");
    return {
      ok: true,
      route: match,
      reply: { status: 200, headers: { "content-type": "text/plain" }, body: challenge },
    };
  }

  normalize(v: VerifiedInbound): InboundMessage[] {
    const p = v.payload as WaPayload | undefined;
    if (!p) return [];
    const limits = limitsOf(this.opts);
    const out: InboundMessage[] = [];
    for (const m of p.messages) {
      if (!WA_ID_RE.test(m.from) || m.text.length > limits.maxTextChars) continue;
      const att = normalizeAttachments(
        m.media.map((o) => ({
          name: o["filename"] ?? "media",
          content_type: o["mime_type"],
          size: 0,
          ref: o["id"],
        })),
        limits,
      );
      out.push({
        tenant_id: v.route.tenant_id,
        channel: "whatsapp",
        provider_key: v.route.provider_key,
        agent: v.route.agent,
        external_user_id: m.from,
        text: m.text,
        attachments: att.kept,
        dropped_attachments: att.dropped,
        idempotency_key: `whatsapp:${m.id}`,
        timestamp_ms: m.ts * 1000,
      });
    }
    return out;
  }

  render(msg: OutboundMessage, route: RouteConfig): RenderedCall {
    const token = secret(route, "access_token");
    if (!token) throw new ChannelError("INVALID", "whatsapp route has no access_token");
    if (!WA_ID_RE.test(msg.to)) throw new ChannelError("INVALID", "recipient must be a wa_id");
    if (!/^\d{5,20}$/.test(route.provider_key))
      throw new ChannelError("INVALID", "route phone_number_id is invalid");
    return {
      kind: "http",
      method: "POST",
      url: `https://graph.facebook.com/v19.0/${route.provider_key}/messages`,
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        messaging_product: "whatsapp",
        recipient_type: "individual",
        to: msg.to,
        type: "text",
        text: { body: msg.text, preview_url: false },
      }),
    };
  }
}
