import { randomUUID } from "node:crypto";
import { hmacSha256Hex, sha256Hex, verifyHmacSha256Hex } from "../crypto.js";
import {
  composeEmail,
  extractAddress,
  suppressReason,
  validMessageId,
  validateAddress,
} from "../email-compose.js";
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

export const EMAIL_CAPABILITIES: Capabilities = {
  threading: true,
  richText: false,
  attachments: true,
  maxLength: 20_000,
  rateLimitPerMinute: 30,
};

export const emailSignature = (webhookSecret: string, ts: string, body: Buffer | string): string =>
  hmacSha256Hex(
    webhookSecret,
    Buffer.concat([
      Buffer.from(`${ts}.`),
      typeof body === "string" ? Buffer.from(body, "utf8") : body,
    ]),
  );

/**
 * Inbound-parse webhook (SendGrid/Postmark/Mailgun style, normalised to JSON by the receiving edge). Authenticity:
 * `x-axis-signature` = hex HMAC-SHA256(secret, `<x-axis-timestamp>.<raw body>`) within the replay window. Route = the recipient mailbox.
 */
export class EmailAdapter implements ChannelAdapter {
  readonly channel = "email" as const;
  readonly capabilities = EMAIL_CAPABILITIES;
  private readonly windowMs: number;

  constructor(private readonly opts: AdapterOptions = {}) {
    this.windowMs = opts.replayWindowMs ?? 5 * 60_000;
  }

  async verifyInbound(req: RawRequest, ctx: VerifyContext): Promise<Reject | VerifiedInbound> {
    if (req.method !== "POST") return reject("unsupported", "method not allowed");
    const body = parseJsonBody(req, limitsOf(this.opts));
    if (isReject(body)) return body;
    const recipients = asArr(body["to"]).map(extractAddress);
    let route: RouteConfig | Reject = reject("unknown_route", "no recipient has a route");
    for (const r of recipients) {
      if (r === undefined) continue;
      const c = claimRoute(ctx.routes, "email", r);
      if (!isReject(c) || c.code === "route_disabled") {
        route = c;
        break;
      }
    }
    if (isReject(route)) return route;
    const key = secret(route, "webhook_secret");
    const ts = req.headers["x-axis-timestamp"];
    if (!key || ts === undefined || !/^\d{1,12}$/.test(ts))
      return reject("bad_signature", "missing signature headers", route);
    if (
      !verifyHmacSha256Hex(
        key,
        Buffer.concat([Buffer.from(`${ts}.`), req.body]),
        req.headers["x-axis-signature"],
      )
    )
      return reject("bad_signature", "signature does not verify", route);
    if (!withinWindow(Number(ts) * 1000, ctx.nowMs, this.windowMs))
      return reject("stale", "timestamp outside the replay window", route);
    return { ok: true, route, payload: body };
  }

  normalize(v: VerifiedInbound): InboundMessage[] {
    const b = asObj(v.payload);
    if (!b) return [];
    const from = extractAddress(b["from"]);
    if (!from) return [];
    const mailbox = validateAddress(v.route.provider_key);
    if (from === mailbox) return []; // never answer ourselves
    const headers: Record<string, string> = {};
    for (const [k, val] of Object.entries(asObj(b["headers"]) ?? {}))
      if (typeof val === "string") headers[k.toLowerCase()] = val.slice(0, 998);
    if (suppressReason(headers, from) !== undefined) return [];
    const limits = limitsOf(this.opts);
    const text = asStr(b["text"]) ?? "";
    if (text.length > limits.maxTextChars) return [];
    const subject = (asStr(b["subject"]) ?? "").slice(0, 200);
    const mid = headers["message-id"];
    const refs = (headers["references"] ?? headers["in-reply-to"] ?? "")
      .split(/\s+/)
      .filter(validMessageId);
    const thread = refs[0] ?? (validMessageId(mid) ? mid : undefined);
    const att = normalizeAttachments(
      asArr(b["attachments"]).map((x) => {
        const o = asObj(x) ?? {};
        return { name: o["filename"], content_type: o["content_type"], size: o["size"] };
      }),
      limits,
    );
    const ts = Number(asStr(b["timestamp"]) ?? b["timestamp"]);
    return [
      {
        tenant_id: v.route.tenant_id,
        channel: "email",
        provider_key: v.route.provider_key,
        agent: v.route.agent,
        external_user_id: from,
        ...(thread ? { conversation_hint: thread } : {}),
        text: subject ? `${subject}\n\n${text}` : text,
        attachments: att.kept,
        dropped_attachments: att.dropped,
        idempotency_key: `email:${validMessageId(mid) ? mid : sha256Hex(JSON.stringify(b))}`,
        timestamp_ms: Number.isFinite(ts) ? ts * 1000 : 0,
      },
    ];
  }

  render(msg: OutboundMessage, route: RouteConfig): RenderedCall {
    const from = validateAddress(setting(route, "from_address") ?? route.provider_key);
    const to = validateAddress(msg.to);
    if (!from) throw new ChannelError("INVALID", "email route has no valid from address");
    if (!to) throw new ChannelError("INVALID", "invalid recipient address");
    if (to === from) throw new ChannelError("INVALID", "refusing to email the route's own mailbox");
    const domain = from.slice(from.lastIndexOf("@") + 1);
    const c = composeEmail({
      from,
      to,
      subject: msg.subject ?? "Re: your message",
      text: msg.text,
      messageId: `<${randomUUID()}@${domain}>`,
      ...(msg.thread && validMessageId(msg.thread) ? { inReplyTo: msg.thread } : {}),
    });
    return { kind: "email", raw: c.raw, envelope_from: c.from, envelope_to: [c.to] };
  }
}
