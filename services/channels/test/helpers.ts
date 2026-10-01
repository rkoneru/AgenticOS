import { generateKeyPairSync, createSign } from "node:crypto";
import { MemoryAuditLog } from "@axis/audit";
import type { AuditEvent, AuditSink, UnsealedEvent } from "@axis/contracts";
import {
  ChannelGateway,
  EmailAdapter,
  IdentityService,
  MemoryConversationStore,
  MemoryIdempotencyStore,
  MemoryRateLimiter,
  SlackAdapter,
  SmsAdapter,
  StaticJwks,
  StaticRoutingTable,
  TeamsAdapter,
  WebAdapter,
  WebHub,
  WhatsAppAdapter,
  emailSignature,
  slackSignature,
  twilioSignature,
  hmacSha256Hex,
  keyedDigest,
  tenantDigestKey,
  type ChannelAdapter,
  type EmailCall,
  type EmailTransport,
  type GatewayDeps,
  type HttpCall,
  type HttpResponse,
  type HttpTransport,
  type Jwk,
  type RawRequest,
  type RouteConfig,
} from "../src/index.js";

export const T1 = "11111111-1111-4111-8111-111111111111";
export const T2 = "22222222-2222-4222-8222-222222222222";
export const NOW = Date.UTC(2026, 9, 1, 12, 0, 0);

export class Clock {
  constructor(public ms = NOW) {}
  now = (): number => this.ms;
  advance(ms: number): void {
    this.ms += ms;
  }
}

export class FakeHttp implements HttpTransport {
  calls: HttpCall[] = [];
  respond: (c: HttpCall) => HttpResponse = () => ({ status: 200, body: '{"ok":true}' });
  async request(call: HttpCall): Promise<HttpResponse> {
    this.calls.push(call);
    return this.respond(call);
  }
}
export class FakeEmail implements EmailTransport {
  sent: EmailCall[] = [];
  fail = false;
  async send(call: EmailCall): Promise<void> {
    if (this.fail) throw new Error("smtp down");
    this.sent.push(call);
  }
}

/** An AuditSink that can be made to fail, recording the events it accepted. */
export class FlakyAudit implements AuditSink {
  readonly inner = new MemoryAuditLog();
  fail = false;
  async append(e: UnsealedEvent): Promise<AuditEvent> {
    if (this.fail) throw new Error("audit down");
    return this.inner.append(e);
  }
  events(tenant: string): Promise<AuditEvent[]> {
    return this.inner.read(tenant);
  }
}

export const SLACK_SECRET = "slack-signing-secret-1";
export const SLACK_T2_SECRET = "slack-signing-secret-2";
export const EMAIL_SECRET = "email-webhook-secret";
export const TWILIO_TOKEN = "twilio-auth-token";
export const WA_SECRET = "wa-app-secret";
export const WA_VERIFY = "wa-verify-token";
export const WEB_SECRET = "web-session-secret";
export const SMS_URL = "https://hooks.example.test/v1/channels/sms/inbound";
export const HASH_KEY = "test-audit-digest-key-0123456789abcdef";
/** What the gateway writes to the chain / message log for `data` (HMAC under the tenant's derived key). */
export const digestOf = (tenant: string, label: string, data: string): string =>
  keyedDigest(tenantDigestKey(Buffer.from(HASH_KEY), tenant), label, data);
export const AGENT = { name: "support", version: "1.0.0" };

const base = {
  tenant_id: T1,
  agent: AGENT,
  transcript: { mode: "redacted_preview" as const },
  phi: false,
  enabled: true,
};

export function routes(): RouteConfig[] {
  return [
    {
      ...base,
      channel: "slack",
      provider_key: "T0001",
      secrets: { signing_secret: SLACK_SECRET, bot_token: "xoxb-1" },
      settings: { api_app_id: "A0001", bot_user_id: "UBOT" },
    },
    {
      ...base,
      tenant_id: T2,
      channel: "slack",
      provider_key: "T0002",
      secrets: { signing_secret: SLACK_T2_SECRET, bot_token: "xoxb-2" },
      settings: {},
    },
    {
      ...base,
      channel: "email",
      provider_key: "support@axis.example",
      secrets: { webhook_secret: EMAIL_SECRET },
      settings: { from_address: "support@axis.example" },
    },
    {
      ...base,
      channel: "sms",
      provider_key: "+15550001111",
      secrets: { auth_token: TWILIO_TOKEN },
      settings: { public_url: SMS_URL, account_sid: `AC${"a".repeat(32)}` },
    },
    {
      ...base,
      channel: "whatsapp",
      provider_key: "1234567890",
      secrets: { app_secret: WA_SECRET, verify_token: WA_VERIFY, access_token: "EAAG" },
      settings: {},
    },
    {
      ...base,
      channel: "web",
      provider_key: "site-1",
      secrets: { session_secret: WEB_SECRET },
      settings: { allowed_origins: ["https://app.example.test"] },
    },
    {
      ...base,
      channel: "teams",
      provider_key: "app-id-1",
      secrets: { access_token: "tok" },
      settings: { service_url: "https://smba.trafficmanager.net/emea/" },
    },
  ];
}

export const raw = (
  over: Partial<Omit<RawRequest, "body">> & { body?: Buffer | string },
): RawRequest => ({
  method: "POST",
  url: "/",
  headers: {},
  query: {},
  ...over,
  body: Buffer.isBuffer(over.body) ? over.body : Buffer.from(over.body ?? ""),
});

// ---- provider request builders (signed) --------------------------------------------------------------------------------------
export function slackReq(
  o: {
    team?: string;
    user?: string;
    text?: string;
    ts?: number;
    eventId?: string;
    secret?: string;
    channel?: string;
    thread?: string;
    extra?: Record<string, unknown>;
    now?: number;
    appId?: string;
  } = {},
): RawRequest {
  const now = o.now ?? NOW;
  const body = JSON.stringify({
    type: "event_callback",
    team_id: o.team ?? "T0001",
    api_app_id: o.appId ?? "A0001",
    event_id: o.eventId ?? `Ev${Math.random().toString(36).slice(2)}`,
    event_time: Math.floor(now / 1000),
    event: {
      type: "message",
      user: o.user ?? "U111",
      text: o.text ?? "hello",
      channel: o.channel ?? "C999",
      ts: "1700000000.000100",
      ...(o.thread ? { thread_ts: o.thread } : {}),
      ...(o.extra ?? {}),
    },
  });
  const ts = String(o.ts ?? Math.floor(now / 1000));
  return raw({
    headers: {
      "x-slack-request-timestamp": ts,
      "x-slack-signature": slackSignature(o.secret ?? SLACK_SECRET, ts, body),
      "content-type": "application/json",
    },
    body,
  });
}

export function smsParams(
  o: { from?: string; to?: string; body?: string; sid?: string } = {},
): Record<string, string> {
  return {
    MessageSid: o.sid ?? `SM${Math.random().toString(16).slice(2).padEnd(30, "0")}`,
    From: o.from ?? "+15557770000",
    To: o.to ?? "+15550001111",
    Body: o.body ?? "hi there",
    NumMedia: "0",
  };
}
export function smsReq(
  params: Record<string, string>,
  token = TWILIO_TOKEN,
  url = SMS_URL,
): RawRequest {
  return raw({
    headers: {
      "x-twilio-signature": twilioSignature(token, url, params),
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(params).toString(),
  });
}

export function emailReq(
  o: {
    from?: string;
    to?: string;
    text?: string;
    subject?: string;
    mid?: string;
    headers?: Record<string, string>;
    secret?: string;
    ts?: number;
    now?: number;
  } = {},
): RawRequest {
  const now = o.now ?? NOW;
  const body = JSON.stringify({
    from: o.from ?? "Alice <alice@example.org>",
    to: [o.to ?? "support@axis.example"],
    subject: o.subject ?? "Help",
    text: o.text ?? "I need help",
    headers: {
      "message-id": o.mid ?? `<${Math.random().toString(36).slice(2)}@example.org>`,
      ...(o.headers ?? {}),
    },
    attachments: [],
    timestamp: Math.floor(now / 1000),
  });
  const ts = String(o.ts ?? Math.floor(now / 1000));
  return raw({
    headers: {
      "x-axis-timestamp": ts,
      "x-axis-signature": emailSignature(o.secret ?? EMAIL_SECRET, ts, body),
    },
    body,
  });
}

export function waBody(
  o: {
    phoneId?: string;
    from?: string;
    text?: string;
    id?: string;
    ts?: number;
    now?: number;
  } = {},
): string {
  const now = o.now ?? NOW;
  return JSON.stringify({
    object: "whatsapp_business_account",
    entry: [
      {
        id: "WABA",
        changes: [
          {
            field: "messages",
            value: {
              metadata: { phone_number_id: o.phoneId ?? "1234567890" },
              messages: [
                {
                  id: o.id ?? `wamid.${Math.random().toString(36).slice(2)}`,
                  from: o.from ?? "15557770000",
                  timestamp: String(o.ts ?? Math.floor(now / 1000)),
                  type: "text",
                  text: { body: o.text ?? "hello wa" },
                },
              ],
            },
          },
        ],
      },
    ],
  });
}
export const waReq = (body: string, secret = WA_SECRET): RawRequest =>
  raw({ headers: { "x-hub-signature-256": `sha256=${hmacSha256Hex(secret, body)}` }, body });

// ---- Teams RSA fixtures ----------------------------------------------------------------------------------------------------------
export const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
export const otherRsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
export const jwkOf = (kp: typeof rsa, kid: string): Jwk => ({
  ...(kp.publicKey.export({ format: "jwk" }) as Jwk),
  kid,
  use: "sig",
  alg: "RS256",
});
export const KID = "key-1";
export const jwks = new StaticJwks([jwkOf(rsa, KID)]);

export function signJwt(
  claims: Record<string, unknown>,
  o: { kp?: typeof rsa; kid?: string; alg?: string; header?: Record<string, unknown> } = {},
): string {
  const enc = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString("base64url");
  const head = enc({ alg: o.alg ?? "RS256", typ: "JWT", kid: o.kid ?? KID, ...(o.header ?? {}) });
  const input = `${head}.${enc(claims)}`;
  const sig = createSign("RSA-SHA256")
    .update(input)
    .sign((o.kp ?? rsa).privateKey)
    .toString("base64url");
  return `${input}.${sig}`;
}
export const goodClaims = (
  now = NOW,
  over: Record<string, unknown> = {},
): Record<string, unknown> => ({
  iss: "https://api.botframework.com",
  aud: "app-id-1",
  exp: Math.floor(now / 1000) + 3600,
  nbf: Math.floor(now / 1000) - 60,
  serviceurl: "https://smba.trafficmanager.net/emea/",
  ...over,
});
export function teamsReq(
  o: {
    token?: string;
    id?: string;
    text?: string;
    now?: number;
    activity?: Record<string, unknown>;
  } = {},
): RawRequest {
  const now = o.now ?? NOW;
  const body = JSON.stringify({
    type: "message",
    id: o.id ?? `act-${Math.random().toString(36).slice(2)}`,
    timestamp: new Date(now).toISOString(),
    serviceUrl: "https://smba.trafficmanager.net/emea/",
    from: { id: "29:abc", aadObjectId: "aad-user-1" },
    conversation: { id: "19:conv@thread.v2" },
    recipient: { id: "28:app-id-1" },
    text: o.text ?? "<at>Bot</at> hi from teams",
    ...(o.activity ?? {}),
  });
  return raw({ headers: { authorization: `Bearer ${o.token ?? signJwt(goodClaims(now))}` }, body });
}

// ---- gateway wiring --------------------------------------------------------------------------------------------------------------
export interface Rig {
  gateway: ChannelGateway;
  store: MemoryConversationStore;
  identity: IdentityService;
  audit: FlakyAudit;
  http: FakeHttp;
  email: FakeEmail;
  hub: WebHub;
  clock: Clock;
  limiter: MemoryRateLimiter;
  idem: MemoryIdempotencyStore;
  table: StaticRoutingTable;
  received: { tenant: string; text: string; conv: string }[];
}

export function rig(
  over: { [K in keyof GatewayDeps]?: GatewayDeps[K] | undefined } = {},
  routeList: RouteConfig[] = routes(),
): Rig {
  const clock = new Clock();
  const store = new MemoryConversationStore(clock.now);
  const limiter = new MemoryRateLimiter(clock.now);
  const identity = new IdentityService({ store, now: clock.now, limiter });
  const audit = new FlakyAudit();
  const http = new FakeHttp();
  const email = new FakeEmail();
  const hub = new WebHub();
  const idem = new MemoryIdempotencyStore(clock.now);
  const table = new StaticRoutingTable(routeList);
  const received: Rig["received"] = [];
  const adapters: ChannelAdapter[] = [
    new SlackAdapter(),
    new TeamsAdapter({ jwks }),
    new EmailAdapter(),
    new SmsAdapter(),
    new WhatsAppAdapter(),
    new WebAdapter(),
  ];
  const gateway = new ChannelGateway({
    adapters,
    routes: table,
    store,
    identity,
    audit,
    idempotency: idem,
    limiter,
    http,
    email,
    hub,
    now: clock.now,
    hashKey: HASH_KEY,
    onMessage: async (c) => {
      received.push({ tenant: c.message.tenant_id, text: c.message.text, conv: c.conversation.id });
    },
    ...(over as Partial<GatewayDeps>),
  });
  return {
    gateway,
    store,
    identity,
    audit,
    http,
    email,
    hub,
    clock,
    limiter,
    idem,
    table,
    received,
  };
}
