import { safeEqual, twilioSignature } from "../crypto.js";
import { normalizeAttachments } from "../limits.js";
import {
  ChannelError,
  type Capabilities,
  type ChannelAdapter,
  type HttpReply,
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
  claimRoute,
  isReject,
  limitsOf,
  reject,
  secret,
  setting,
  type AdapterOptions,
} from "./base.js";

export const SMS_CAPABILITIES: Capabilities = {
  threading: false,
  richText: false,
  attachments: true,
  maxLength: 1_600,
  rateLimitPerMinute: 30,
};

export const E164_RE = /^\+[1-9]\d{6,14}$/;

/** Twilio-style webhook: form body, `X-Twilio-Signature` = base64(HMAC-SHA1(auth token, public URL + sorted params)). */
export class SmsAdapter implements ChannelAdapter {
  readonly channel = "sms" as const;
  readonly capabilities = SMS_CAPABILITIES;

  constructor(private readonly opts: AdapterOptions = {}) {}

  ack(): HttpReply {
    return { status: 200, headers: { "content-type": "text/xml" }, body: "<Response></Response>" };
  }

  async verifyInbound(req: RawRequest, ctx: VerifyContext): Promise<Reject | VerifiedInbound> {
    if (req.method !== "POST") return reject("unsupported", "method not allowed");
    if (req.body.length > limitsOf(this.opts).maxBodyBytes)
      return reject("too_large", "body too large");
    const params = new Map<string, string[]>();
    for (const [k, v] of new URLSearchParams(req.body.toString("utf8"))) {
      const list = params.get(k) ?? [];
      list.push(v);
      params.set(k, list);
    }
    const route = claimRoute(ctx.routes, "sms", params.get("To")?.[0]);
    if (isReject(route)) return route;
    const token = secret(route, "auth_token");
    // The URL that is signed is the one WE configured for the webhook, never one derived from the request's Host header.
    const url = setting(route, "public_url");
    const sig = req.headers["x-twilio-signature"];
    if (!token || !url || sig === undefined)
      return reject("bad_signature", "missing signature material", route);
    if (!safeEqual(twilioSignature(token, url, params), sig))
      return reject("bad_signature", "signature does not verify", route);
    return { ok: true, route, payload: params };
  }

  normalize(v: VerifiedInbound): InboundMessage[] {
    const p = v.payload;
    if (!(p instanceof Map)) return [];
    const one = (k: string): string | undefined => (p.get(k) as string[] | undefined)?.[0];
    const from = one("From");
    const sid = one("MessageSid") ?? one("SmsSid");
    if (!from || !E164_RE.test(from) || !sid || !/^[A-Za-z0-9]{10,64}$/.test(sid)) return [];
    const limits = limitsOf(this.opts);
    const text = one("Body") ?? "";
    if (text.length > limits.maxTextChars) return [];
    const n = Math.min(Number(one("NumMedia") ?? "0") || 0, 50);
    // MediaUrl{i} is never read: Twilio media URLs are provider URLs we do not fetch here. Size is not provided (0 = unknown).
    const media = Array.from({ length: n }, (_, i) => ({
      name: `media-${i}`,
      content_type: one(`MediaContentType${i}`),
      size: 0,
    }));
    const att = normalizeAttachments(media, limits);
    return [
      {
        tenant_id: v.route.tenant_id,
        channel: "sms",
        provider_key: v.route.provider_key,
        agent: v.route.agent,
        external_user_id: from,
        text,
        attachments: att.kept,
        dropped_attachments: att.dropped,
        idempotency_key: `sms:${sid}`,
        timestamp_ms: 0, // Twilio sends no timestamp: replay protection is the MessageSid dedupe (docs/security/channels-threat-model.md)
      },
    ];
  }

  render(msg: OutboundMessage, route: RouteConfig): RenderedCall {
    const sid = setting(route, "account_sid");
    const token = secret(route, "auth_token");
    if (!sid || !/^AC[0-9a-f]{32}$/i.test(sid))
      throw new ChannelError("INVALID", "sms route needs a valid account_sid");
    if (!token) throw new ChannelError("INVALID", "sms route has no auth_token");
    if (!E164_RE.test(msg.to)) throw new ChannelError("INVALID", "recipient must be E.164");
    if (!E164_RE.test(route.provider_key))
      throw new ChannelError("INVALID", "route number must be E.164");
    return {
      kind: "http",
      method: "POST",
      url: `https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`,
      headers: {
        authorization: `Basic ${Buffer.from(`${sid}:${token}`).toString("base64")}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        To: msg.to,
        From: route.provider_key,
        Body: msg.text,
      }).toString(),
    };
  }
}
