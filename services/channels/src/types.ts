export const CHANNELS = ["web", "slack", "teams", "email", "sms", "whatsapp"] as const;
export type ChannelId = (typeof CHANNELS)[number];

export interface Logger {
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
}
export const silentLogger: Logger = { info() {}, warn() {}, error() {} };

export type ChannelErrorCode =
  | "INVALID"
  | "TOO_LARGE"
  | "TOO_LONG"
  | "RATE_LIMITED"
  | "UNKNOWN_ROUTE"
  | "TRANSPORT"
  | "NOT_FOUND"
  | "FORBIDDEN"
  | "AUDIT_FAILED"
  | "CONFLICT";

export class ChannelError extends Error {
  constructor(
    readonly code: ChannelErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "ChannelError";
  }
}

/** A provider request exactly as received. `headers` are lower-cased; `body` is the RAW bytes (signatures cover them). */
export interface RawRequest {
  method: string;
  /** The URL path (+ query) as received. Signature schemes that sign the public URL (Twilio) use the route's configured URL instead. */
  url: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  body: Buffer;
}

/** Attachment METADATA only. The platform never fetches an attacker-supplied URL; `ref` is an opaque provider media id at most. */
export interface AttachmentMeta {
  name: string;
  content_type: string;
  size: number;
  ref?: string;
}

export interface AgentRef {
  name: string;
  version: string;
}

export type SettingValue = string | number | boolean | string[];

/**
 * The per-tenant configuration of ONE provider identity (a Slack workspace, a phone number, a WhatsApp phone-number id, a Teams bot
 * app, a mailbox, a web site key). `secrets` verify inbound requests and authorise outbound calls; they never leave this process.
 */
export interface RouteConfig {
  channel: ChannelId;
  /** The provider identity: Slack team id, E.164 number, WhatsApp phone_number_id, Teams app id, mailbox address, web site key. */
  provider_key: string;
  tenant_id: string;
  agent: AgentRef;
  secrets: Record<string, string>;
  settings: Record<string, SettingValue>;
  /** Tenant transcript policy and PHI mode (docs/adr/0015). */
  transcript: TranscriptPolicy;
  phi: boolean;
  enabled: boolean;
}

export type TranscriptMode = "hash_only" | "redacted_preview" | "full";
export interface TranscriptPolicy {
  mode: TranscriptMode;
}
export const DEFAULT_TRANSCRIPT_POLICY: TranscriptPolicy = { mode: "redacted_preview" };

export interface InboundMessage {
  tenant_id: string;
  channel: ChannelId;
  provider_key: string;
  agent: AgentRef;
  /** Provider-verified identifier of the sender (stable per channel). */
  external_user_id: string;
  /** Provider thread / conversation key, if the channel has one. A hint: it never selects a TENANT, only a conversation of it. */
  conversation_hint?: string;
  text: string;
  attachments: AttachmentMeta[];
  /** Attachments dropped by the type / count / size caps (metadata is not kept for them). */
  dropped_attachments: number;
  idempotency_key: string;
  timestamp_ms: number;
}

export interface OutboundMessage {
  channel: ChannelId;
  /** Destination in the channel's own addressing: Slack channel/user id, E.164, wa_id, email address, web session id, Teams conversation id. */
  to: string;
  text: string;
  /** Thread / reply anchor (Slack `channel:thread_ts` is carried in `to` + this ts; email Message-ID; Teams reply-to activity id). */
  thread?: string;
  subject?: string;
}

export interface Capabilities {
  threading: boolean;
  richText: boolean;
  attachments: boolean;
  /** Maximum characters of one outbound message; longer text is split (up to `maxParts`) or refused. */
  maxLength: number;
  /** Provider-side outbound pacing we respect, messages per minute per route. */
  rateLimitPerMinute: number;
}

export interface HttpCall {
  kind: "http";
  method: "POST";
  url: string;
  headers: Record<string, string>;
  body: string;
}
export interface EmailCall {
  kind: "email";
  /** Already validated, CR/LF-free; see email-compose.ts. */
  raw: string;
  envelope_from: string;
  envelope_to: string[];
}
export interface WebCall {
  kind: "web";
  session_id: string;
  event: { type: "message"; data: Record<string, unknown> };
}
export type RenderedCall = HttpCall | EmailCall | WebCall;

export interface HttpReply {
  status: number;
  headers?: Record<string, string>;
  body: string;
}

export type RejectCode =
  | "bad_signature"
  | "stale"
  | "unknown_route"
  | "route_disabled"
  | "malformed"
  | "too_large"
  | "unsupported";

export interface Reject {
  ok: false;
  code: RejectCode;
  reason: string;
  /** The route the (unverified) request claimed, if one exists. Used to attribute the audit event; never to trust the request. */
  route?: RouteConfig;
}

export interface VerifiedInbound {
  ok: true;
  route: RouteConfig;
  /** A provider handshake the gateway answers directly (Slack url_verification, WhatsApp GET verify). No message. */
  reply?: HttpReply;
  /** Opaque, already authenticated provider payload for `normalize`. */
  payload?: unknown;
}

export interface VerifyContext {
  routes: RoutingTable;
  nowMs: number;
}

export interface RoutingTable {
  /** Looks up a route by the channel and the provider identity the request CLAIMS. The claim only chooses which secret to verify with. */
  lookup(channel: ChannelId, providerKey: string): RouteConfig | undefined;
  /** Every enabled route of a channel. Only for provider handshakes that carry no identity (Slack url_verification, WhatsApp GET). */
  candidates(channel: ChannelId): RouteConfig[];
  /** The routes a tenant has on a channel (outbound credentials). Never returns another tenant's route. */
  forTenant(tenant: string, channel: ChannelId): RouteConfig[];
}

export interface ChannelAdapter {
  readonly channel: ChannelId;
  readonly capabilities: Capabilities;
  /** Authenticate a provider request. A request that does not verify yields a Reject; nothing in an unverified body selects a tenant. */
  verifyInbound(req: RawRequest, ctx: VerifyContext): Promise<Reject | VerifiedInbound>;
  /** Normalise an authenticated payload into messages (no tenant is read from the content). */
  normalize(v: VerifiedInbound): InboundMessage[];
  /** Provider payload for an outbound message. Pure: no I/O. */
  render(msg: OutboundMessage, route: RouteConfig): RenderedCall;
  /** The HTTP reply for an accepted request. Default: 200 `{}`. */
  ack?(): HttpReply;
  /** Did the provider accept an outbound call? Default: HTTP 2xx. (Slack answers 200 with `{"ok":false}` on errors.) */
  responseOk?(status: number, body: string): boolean;
}
