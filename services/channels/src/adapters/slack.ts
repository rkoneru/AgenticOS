import { hmacSha256Hex, safeEqual } from "../crypto.js";
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
  type RouteConfig,
  type VerifyContext,
  type VerifiedInbound,
  type Reject,
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

export const SLACK_CAPABILITIES: Capabilities = {
  threading: true,
  richText: true,
  attachments: true,
  maxLength: 3_000,
  rateLimitPerMinute: 60,
};

export function slackSignature(signingSecret: string, ts: string, body: Buffer | string): string {
  const bytes = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  return `v0=${hmacSha256Hex(signingSecret, Buffer.concat([Buffer.from(`v0:${ts}:`), bytes]))}`;
}

/** Escape Slack control characters so agent text can never create a mention (`<!channel>`, `<@U..>`) or a link. */
export const slackEscape = (t: string): string =>
  t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export class SlackAdapter implements ChannelAdapter {
  readonly channel = "slack" as const;
  readonly capabilities = SLACK_CAPABILITIES;
  private readonly windowMs: number;

  constructor(private readonly opts: AdapterOptions = {}) {
    this.windowMs = opts.replayWindowMs ?? 5 * 60_000;
  }

  private signatureOk(req: RawRequest, route: RouteConfig, nowMs: number): "ok" | "stale" | "bad" {
    const key = secret(route, "signing_secret");
    const ts = req.headers["x-slack-request-timestamp"];
    const sig = req.headers["x-slack-signature"];
    if (!key || ts === undefined || sig === undefined || !/^\d{1,12}$/.test(ts)) return "bad";
    // Compare first, THEN judge freshness, so a stale-but-genuine request is distinguishable from a forged one in the audit trail.
    if (!safeEqual(slackSignature(key, ts, req.body), sig)) return "bad";
    return withinWindow(Number(ts) * 1000, nowMs, this.windowMs) ? "ok" : "stale";
  }

  async verifyInbound(req: RawRequest, ctx: VerifyContext): Promise<Reject | VerifiedInbound> {
    if (req.method !== "POST") return reject("unsupported", "method not allowed");
    const body = parseJsonBody(req, limitsOf(this.opts));
    if (isReject(body)) return body;

    if (body["type"] === "url_verification") {
      // The handshake carries no workspace identity: it must verify against SOME configured Slack app's signing secret.
      const challenge = asStr(body["challenge"]);
      if (challenge === undefined || challenge.length > 512)
        return reject("malformed", "bad challenge");
      let match: RouteConfig | undefined;
      for (const r of ctx.routes.candidates("slack")) {
        const res = this.signatureOk(req, r, ctx.nowMs);
        if (res === "stale") return reject("stale", "stale timestamp", r);
        if (res === "ok") match ??= r;
      }
      if (!match) return reject("bad_signature", "signature does not verify");
      return {
        ok: true,
        route: match,
        reply: { status: 200, headers: { "content-type": "text/plain" }, body: challenge },
      };
    }

    const claimed = asStr(body["team_id"]);
    const route = claimRoute(ctx.routes, "slack", claimed);
    if (isReject(route)) return route;
    const sig = this.signatureOk(req, route, ctx.nowMs);
    if (sig === "bad") return reject("bad_signature", "signature does not verify", route);
    if (sig === "stale") return reject("stale", "timestamp outside the replay window", route);
    const app = setting(route, "api_app_id");
    if (app !== undefined && body["api_app_id"] !== app)
      return reject("bad_signature", "app id does not match the route", route);
    if (body["type"] !== "event_callback")
      return reject("unsupported", "unsupported payload type", route);
    return { ok: true, route, payload: body };
  }

  normalize(v: VerifiedInbound): InboundMessage[] {
    const body = asObj(v.payload);
    const ev = asObj(body?.["event"]);
    if (!body || !ev) return [];
    const type = asStr(ev["type"]);
    // Bots (including ourselves) and edits/deletes never produce a turn: this is the Slack side of loop prevention.
    if ((type !== "message" && type !== "app_mention") || ev["bot_id"] !== undefined) return [];
    const sub = asStr(ev["subtype"]);
    if (sub !== undefined && sub !== "file_share" && sub !== "thread_broadcast") return [];
    const user = asStr(ev["user"]);
    const channel = asStr(ev["channel"]);
    const ts = asStr(ev["ts"]);
    const eventId = asStr(body["event_id"]);
    if (!user || !channel || !ts || !eventId) return [];
    const limits = limitsOf(this.opts);
    let text = asStr(ev["text"]) ?? "";
    const botUser = setting(v.route, "bot_user_id");
    if (botUser)
      text = text.replace(new RegExp(`^\\s*<@${botUser.replace(/[^A-Za-z0-9]/g, "")}>\\s*`), "");
    if (text.length > limits.maxTextChars) return [];
    const files = asArr(ev["files"]).map((f) => {
      const o = asObj(f) ?? {};
      return { name: o["name"], content_type: o["mimetype"], size: o["size"], ref: o["id"] };
    });
    const att = normalizeAttachments(files, limits);
    const evTs = Number(asStr(body["event_time"]) ?? body["event_time"]);
    return [
      {
        tenant_id: v.route.tenant_id,
        channel: "slack",
        provider_key: v.route.provider_key,
        agent: v.route.agent,
        external_user_id: user,
        conversation_hint: `${channel}:${asStr(ev["thread_ts"]) ?? ts}`,
        text,
        attachments: att.kept,
        dropped_attachments: att.dropped,
        idempotency_key: `slack:${eventId}`,
        timestamp_ms: Number.isFinite(evTs) ? evTs * 1000 : Number(ts.split(".")[0]) * 1000,
      },
    ];
  }

  responseOk(status: number, body: string): boolean {
    if (status < 200 || status > 299) return false;
    try {
      return asObj(JSON.parse(body))?.["ok"] === true;
    } catch {
      return false;
    }
  }

  render(msg: OutboundMessage, route: RouteConfig): RenderedCall {
    const token = secret(route, "bot_token");
    if (!token) throw new ChannelError("INVALID", "slack route has no bot_token");
    // `to` is a Slack channel/DM id; `thread` is `<channel>:<thread_ts>` from the hint, only the ts is sent.
    const threadTs = msg.thread?.includes(":") ? msg.thread.split(":")[1] : msg.thread;
    if (!/^[A-Z0-9]{1,32}$/.test(msg.to))
      throw new ChannelError("INVALID", "invalid slack destination");
    if (threadTs !== undefined && !/^\d{1,12}\.\d{1,8}$/.test(threadTs))
      throw new ChannelError("INVALID", "invalid slack thread ts");
    return {
      kind: "http",
      method: "POST",
      url: "https://slack.com/api/chat.postMessage",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json; charset=utf-8",
      },
      body: JSON.stringify({
        channel: msg.to,
        text: slackEscape(msg.text),
        unfurl_links: false,
        unfurl_media: false,
        link_names: false,
        ...(threadTs ? { thread_ts: threadTs } : {}),
      }),
    };
  }
}
