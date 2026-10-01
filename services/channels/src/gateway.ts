import { randomBytes, randomUUID } from "node:crypto";
import { hashJson, type AuditSink, type UnsealedEvent } from "@axis/contracts";
import { isReject } from "./adapters/base.js";
import { WebHub } from "./adapters/web.js";
import { sha256Hex } from "./crypto.js";
import { IdentityService, parseLinkCommand } from "./identity.js";
import { DEFAULT_LIMITS, splitText, type Limits } from "./limits.js";
import { transcriptContent, type RedactionHook } from "./redact.js";
import type { IdempotencyStore, RateLimiter } from "./replay.js";
import type { Conversation, ConversationStore, StoredMessage } from "./store.js";
import type { EmailTransport, HttpTransport } from "./transport.js";
import type { TranscriptEvent } from "./transcript-events.js";
import {
  ChannelError,
  silentLogger,
  type AgentRef,
  type ChannelAdapter,
  type ChannelId,
  type HttpReply,
  type InboundMessage,
  type Logger,
  type RawRequest,
  type Reject,
  type RenderedCall,
  type RouteConfig,
  type RoutingTable,
} from "./types.js";

export const POLICY_VERSION = "channels@1";
const DAY_MS = 86_400_000;
const REJECT_AUDIT_PER_MINUTE = 20;

export interface InboundContext {
  /** The trace id of the inbound audit event. An agent run started for this message should use it, so one trace shows the whole turn. */
  trace_id: string;
  message: InboundMessage;
  conversation: Conversation;
  stored: StoredMessage;
  /** The conversation so far, across every channel the end user is linked on. */
  history(limit?: number): Promise<StoredMessage[]>;
}
export type InboundHandler = (ctx: InboundContext) => Promise<void>;

export interface GatewayDeps {
  adapters: readonly ChannelAdapter[];
  routes: RoutingTable;
  store: ConversationStore;
  identity: IdentityService;
  audit: AuditSink;
  idempotency: IdempotencyStore;
  limiter: RateLimiter;
  http: HttpTransport;
  email?: EmailTransport;
  hub?: WebHub;
  limits?: Limits;
  now?: () => number;
  logger?: Logger;
  redactionHook?: RedactionHook;
  /** Receives every accepted inbound message (enqueue it; a throwing handler is logged, the message stays recorded). */
  onMessage?: InboundHandler;
  /** Where verification failures that name NO known route are audited (a platform tenant). Without it they are only logged. */
  systemAudit?: { sink: AuditSink; tenant_id: string };
  idempotencyTtlMs?: number;
  httpTimeoutMs?: number;
}

export interface SendRequest {
  channel: ChannelId;
  /** Reply on an existing conversation (preferred) ... */
  conversation_id?: string;
  /** ... or address a KNOWN identity directly. Unknown addresses are refused unless the route sets `allow_unsolicited`. */
  to?: string;
  text: string;
  subject?: string;
  /** Which of the tenant's routes to send from (provider key). Optional when the tenant has exactly one on the channel. */
  from?: string;
  agent?: AgentRef;
  run_id?: string;
  trace_id?: string;
  idempotency_key?: string;
}

export interface SendResult {
  conversation_id: string | null;
  parts: number;
  message_ids: string[];
  audit_hashes: string[];
  duplicate: boolean;
}

export type InboundOutcome =
  | { kind: "accepted"; conversation_id: string; message_id: string }
  | { kind: "duplicate" }
  | { kind: "linked"; end_user_id: string }
  | { kind: "link_failed"; reason: string }
  | { kind: "rate_limited" };

export interface InboundResult {
  reply: HttpReply;
  outcomes: InboundOutcome[];
  rejected?: Reject;
}

const STATUS: Record<Reject["code"], number> = {
  bad_signature: 401,
  stale: 401,
  unknown_route: 401, // indistinguishable from a bad signature: no route enumeration
  route_disabled: 401,
  malformed: 400,
  too_large: 413,
  unsupported: 405,
};

const traceId = (): string => randomBytes(16).toString("hex");
const userRef = (channel: ChannelId, ext: string): string =>
  `${channel}:${sha256Hex(ext).slice(0, 16)}`;

export class ChannelGateway {
  private readonly adapters = new Map<ChannelId, ChannelAdapter>();
  private readonly limits: Limits;
  private readonly now: () => number;
  private readonly log: Logger;

  constructor(private readonly d: GatewayDeps) {
    for (const a of d.adapters) this.adapters.set(a.channel, a);
    this.limits = d.limits ?? DEFAULT_LIMITS;
    this.now = d.now ?? Date.now;
    this.log = d.logger ?? silentLogger;
  }

  adapter(channel: ChannelId): ChannelAdapter {
    const a = this.adapters.get(channel);
    if (!a) throw new ChannelError("INVALID", `channel ${channel} is not enabled`);
    return a;
  }

  // ---- inbound ---------------------------------------------------------------------------------------------------------------

  async handleInbound(channel: ChannelId, req: RawRequest): Promise<InboundResult> {
    const adapter = this.adapters.get(channel);
    if (!adapter) return { reply: { status: 404, body: "{}" }, outcomes: [] };
    if (req.body.length > this.limits.maxBodyBytes)
      return this.rejected(channel, { ok: false, code: "too_large", reason: "body too large" });

    let verified;
    try {
      verified = await adapter.verifyInbound(req, { routes: this.d.routes, nowMs: this.now() });
    } catch (err) {
      this.log.error("adapter threw during verification; rejecting", {
        channel,
        error: String(err),
      });
      return this.rejected(channel, { ok: false, code: "malformed", reason: "verification error" });
    }
    if (isReject(verified)) return this.rejected(channel, verified);
    if (verified.reply) return { reply: verified.reply, outcomes: [] };

    let messages: InboundMessage[];
    try {
      messages = adapter.normalize(verified);
    } catch (err) {
      this.log.error("adapter threw during normalisation; rejecting", {
        channel,
        error: String(err),
      });
      return this.rejected(channel, {
        ok: false,
        code: "malformed",
        reason: "normalisation error",
        route: verified.route,
      });
    }
    const outcomes: InboundOutcome[] = [];
    let status = 200;
    for (const m of messages) {
      // Defence in depth: the tenant on a message must be the verified route's tenant (an adapter bug cannot cross tenants).
      if (m.tenant_id !== verified.route.tenant_id || m.channel !== channel) {
        this.log.error("adapter produced a message for a different tenant/channel; dropped", {
          channel,
        });
        continue;
      }
      try {
        const o = await this.processInbound(verified.route, m);
        outcomes.push(o);
        if (o.kind === "rate_limited") status = 429;
      } catch (err) {
        this.log.error("inbound processing failed", {
          channel,
          error: err instanceof Error ? err.message : String(err),
        });
        return { reply: { status: 503, body: '{"error":"unavailable"}' }, outcomes };
      }
    }
    const ack = adapter.ack?.() ?? {
      status: 200,
      headers: { "content-type": "application/json" },
      body: "{}",
    };
    return { reply: status === 200 ? ack : { status, body: '{"error":"rate_limited"}' }, outcomes };
  }

  private async rejected(channel: ChannelId, r: Reject): Promise<InboundResult> {
    await this.auditRejection(channel, r);
    return {
      reply: {
        status: STATUS[r.code],
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "rejected" }),
      },
      outcomes: [],
      rejected: r,
    };
  }

  /** Verification failures are audited under the tenant of the route the request CLAIMED (or the platform tenant), rate limited. */
  private async auditRejection(channel: ChannelId, r: Reject): Promise<void> {
    const tenant = r.route?.tenant_id ?? this.d.systemAudit?.tenant_id;
    const sink = r.route ? this.d.audit : this.d.systemAudit?.sink;
    this.log.warn("inbound rejected", { channel, code: r.code, reason: r.reason, tenant });
    if (!tenant || !sink) return;
    if (!this.d.limiter.take(`rejaudit:${tenant}:${channel}`, REJECT_AUDIT_PER_MINUTE)) return;
    try {
      await sink.append(
        this.event(tenant, r.route?.agent ?? { name: "channels", version: "1" }, {
          actor: { type: "system", id: `channel:${channel}` },
          enforcement_point: "lifecycle",
          action: "channel.inbound.rejected",
          decision: "DENY",
          reason: `channel=${channel} code=${r.code} route=${r.route ? sha256Hex(r.route.provider_key).slice(0, 12) : "unknown"} detail=${r.reason}`,
          inputs: { channel, code: r.code },
          outputs: { rejected: true },
        }),
      );
    } catch (err) {
      this.log.error("audit append of a rejection failed", { error: String(err) });
    }
  }

  private event(
    tenant: string,
    agent: AgentRef,
    e: {
      actor: UnsealedEvent["actor"];
      enforcement_point: UnsealedEvent["enforcement_point"];
      action: string;
      decision: UnsealedEvent["decision"];
      reason: string;
      inputs: unknown;
      outputs: unknown;
      trace_id?: string;
    },
  ): UnsealedEvent {
    return {
      schema_version: 1,
      id: randomUUID(),
      tenant_id: tenant,
      ts: new Date(this.now()).toISOString(),
      trace_id: e.trace_id ?? traceId(),
      actor: e.actor,
      blueprint: agent,
      policy_version: POLICY_VERSION,
      enforcement_point: e.enforcement_point,
      action: e.action,
      decision: e.decision,
      reason: e.reason.slice(0, 1000),
      inputs_hash: hashJson(e.inputs),
      outputs_hash: hashJson(e.outputs),
    };
  }

  private async processInbound(route: RouteConfig, m: InboundMessage): Promise<InboundOutcome> {
    const tenant = route.tenant_id;
    const idemKey = `in:${tenant}:${m.channel}:${m.idempotency_key}`;
    if (!(await this.d.idempotency.claim(idemKey, this.d.idempotencyTtlMs ?? 2 * DAY_MS))) {
      await this.auditReplay(route, m);
      return { kind: "duplicate" };
    }
    try {
      if (
        !this.d.limiter.take(
          `in:${tenant}:${m.channel}:${m.external_user_id}`,
          this.limits.inboundPerMinute,
        )
      ) {
        await this.d.idempotency.release(idemKey); // the provider's retry must be accepted once the user is under the limit
        return { kind: "rate_limited" };
      }
      const code = parseLinkCommand(m.text);
      if (code !== undefined) return await this.processLink(route, m, code);

      const identity = await this.d.identity.resolve(tenant, m.channel, m.external_user_id);
      const conv = await this.conversationFor(route, m, identity.end_user_id);
      const t = transcriptContent(m.text, route.transcript.mode, route.phi, this.d.redactionHook);
      const contentHash = sha256Hex(m.text);
      const size = Buffer.byteLength(m.text, "utf8");
      const trace = traceId();
      const ev = await this.appendAudit(
        this.event(tenant, route.agent, {
          actor: { type: "human", id: userRef(m.channel, m.external_user_id) },
          enforcement_point: "lifecycle",
          trace_id: trace,
          action: "channel.inbound.message",
          decision: "ALLOW",
          reason: `channel=${m.channel} dir=in conv=${conv.id} size=${size} sha256=${contentHash} mode=${t.mode} attachments=${m.attachments.length} dropped=${m.dropped_attachments}`,
          inputs: {
            channel: m.channel,
            direction: "in",
            idempotency_key: m.idempotency_key,
            conversation_id: conv.id,
            user: userRef(m.channel, m.external_user_id),
          },
          outputs: {
            content_sha256: contentHash,
            size_bytes: size,
            attachments: m.attachments.map((a) => ({ type: a.content_type, size: a.size })),
          },
        }),
      );
      const { message } = await this.d.store.appendMessage(tenant, {
        tenant_id: tenant,
        conversation_id: conv.id,
        direction: "in",
        channel: m.channel,
        idempotency_key: m.idempotency_key,
        content_mode: t.mode,
        content: t.content,
        content_hash: contentHash,
        size_bytes: size,
        attachments: m.attachments,
        audit_event_id: ev.id,
        audit_hash: ev.hash,
      });
      await this.d.store.touchConversation(tenant, conv.id, m.channel);
      if (this.d.onMessage) {
        try {
          await this.d.onMessage({
            trace_id: trace,
            message: m,
            conversation: conv,
            stored: message,
            history: (limit) => this.d.store.messages(tenant, conv.id, limit),
          });
        } catch (err) {
          this.log.error("inbound handler failed; the message stays recorded", {
            error: String(err),
          });
        }
      }
      return { kind: "accepted", conversation_id: conv.id, message_id: message.id };
    } catch (err) {
      await this.d.idempotency.release(idemKey); // nothing took effect that a retry would duplicate except possibly one audit event
      throw err;
    }
  }

  private async conversationFor(
    route: RouteConfig,
    m: InboundMessage,
    endUserId: string,
  ): Promise<Conversation> {
    const tenant = route.tenant_id;
    let conv: Conversation | undefined;
    if (m.conversation_hint) {
      const byThread = await this.d.store.findByThread(tenant, m.channel, m.conversation_hint);
      // A thread hint may only resume a conversation of THIS end user. In a shared Slack thread, a second person gets their own.
      if (
        byThread &&
        byThread.end_user_id === endUserId &&
        byThread.agent.name === route.agent.name &&
        byThread.status === "open"
      )
        conv = byThread;
    }
    conv ??= await this.d.store.findOpenConversation(tenant, endUserId, route.agent.name);
    conv ??= await this.d.store.createConversation(tenant, endUserId, route.agent, m.channel);
    if (m.conversation_hint)
      await this.d.store.addThread(tenant, m.channel, m.conversation_hint, conv.id);
    return conv;
  }

  private async processLink(
    route: RouteConfig,
    m: InboundMessage,
    code: string,
  ): Promise<InboundOutcome> {
    const tenant = route.tenant_id;
    await this.d.identity.resolve(tenant, m.channel, m.external_user_id);
    const res = await this.d.identity.redeem(tenant, m.channel, m.external_user_id, code);
    await this.appendAudit(
      this.event(tenant, route.agent, {
        actor: { type: "human", id: userRef(m.channel, m.external_user_id) },
        enforcement_point: "lifecycle",
        action: "channel.identity.link",
        decision: res.ok ? "ALLOW" : "DENY",
        // The code itself is never recorded.
        reason: res.ok
          ? `channel=${m.channel} linked moved_conversations=${res.moved_conversations}`
          : `channel=${m.channel} link refused: ${res.reason}`,
        inputs: { channel: m.channel, user: userRef(m.channel, m.external_user_id) },
        outputs: { ok: res.ok },
      }),
    );
    return res.ok
      ? { kind: "linked", end_user_id: res.end_user_id }
      : { kind: "link_failed", reason: res.reason };
  }

  private async auditReplay(route: RouteConfig, m: InboundMessage): Promise<void> {
    if (!this.d.limiter.take(`rejaudit:${route.tenant_id}:${m.channel}`, REJECT_AUDIT_PER_MINUTE))
      return;
    try {
      await this.d.audit.append(
        this.event(route.tenant_id, route.agent, {
          actor: { type: "system", id: `channel:${m.channel}` },
          enforcement_point: "lifecycle",
          action: "channel.inbound.replayed",
          decision: "DENY",
          reason: `channel=${m.channel} duplicate idempotency key ${sha256Hex(m.idempotency_key).slice(0, 16)}`,
          inputs: { channel: m.channel, key: sha256Hex(m.idempotency_key) },
          outputs: { duplicate: true },
        }),
      );
    } catch (err) {
      this.log.error("audit append of a replay failed", { error: String(err) });
    }
  }

  /** Fail closed: no audit, no processing. */
  private async appendAudit(e: UnsealedEvent) {
    try {
      return await this.d.audit.append(e);
    } catch (err) {
      this.log.error("audit append failed", { action: e.action, error: String(err) });
      throw new ChannelError("AUDIT_FAILED", "audit append failed");
    }
  }

  // ---- outbound (the PERFORM half: the runtime has already gated the action) -----------------------------------------------------

  async send(tenant: string, req: SendRequest): Promise<SendResult> {
    const adapter = this.adapter(req.channel);
    if (typeof req.text !== "string" || req.text === "")
      throw new ChannelError("INVALID", "text is required");
    if (req.text.length > this.limits.maxTextChars * 4)
      throw new ChannelError("TOO_LONG", "text too long");
    const route = this.pickRoute(tenant, req);
    const target = await this.resolveTarget(tenant, route, req);

    const parts =
      req.channel === "email" ? [req.text] : splitText(req.text, adapter.capabilities.maxLength);
    if (!parts) throw new ChannelError("TOO_LONG", "message exceeds the channel limit");
    if (req.channel === "email" && req.text.length > adapter.capabilities.maxLength)
      throw new ChannelError("TOO_LONG", "message exceeds the channel limit");
    const keyBase = req.idempotency_key ?? randomUUID();
    if (
      !this.d.limiter.take(
        `out:${tenant}:${route.channel}:${route.provider_key}`,
        adapter.capabilities.rateLimitPerMinute,
      )
    )
      throw new ChannelError("RATE_LIMITED", "outbound rate limit");

    const result: SendResult = {
      conversation_id: target.conversation?.id ?? null,
      parts: parts.length,
      message_ids: [],
      audit_hashes: [],
      duplicate: false,
    };
    const agent = req.agent ?? route.agent;
    const trace = req.trace_id && /^[0-9a-f]{32}$/.test(req.trace_id) ? req.trace_id : traceId();
    for (const [i, text] of parts.entries()) {
      const key = `${keyBase}:${i}`;
      const idemKey = `out:${tenant}:${req.channel}:${key}`;
      if (!(await this.d.idempotency.claim(idemKey, this.d.idempotencyTtlMs ?? 2 * DAY_MS))) {
        result.duplicate = true;
        continue;
      }
      try {
        const call = adapter.render(
          {
            channel: req.channel,
            to: target.to,
            text,
            ...(target.thread ? { thread: target.thread } : {}),
            ...(req.subject ? { subject: req.subject } : {}),
          },
          route,
        );
        const contentHash = sha256Hex(text);
        const size = Buffer.byteLength(text, "utf8");
        const t = transcriptContent(text, route.transcript.mode, route.phi, this.d.redactionHook);
        const ev = await this.appendAudit(
          this.event(tenant, agent, {
            actor: { type: "system", id: `channel:${req.channel}` },
            enforcement_point: "message_send",
            action: "channel.outbound.message",
            decision: "ALLOW",
            reason: `channel=${req.channel} dir=out conv=${target.conversation?.id ?? "none"} size=${size} sha256=${contentHash} mode=${t.mode} run=${req.run_id ?? "-"}`,
            inputs: {
              channel: req.channel,
              direction: "out",
              idempotency_key: key,
              conversation_id: target.conversation?.id ?? null,
              to: userRef(req.channel, target.to),
            },
            outputs: { content_sha256: contentHash, size_bytes: size },
            trace_id: trace,
          }),
        );
        result.audit_hashes.push(ev.hash);
        try {
          await this.perform(tenant, adapter, call);
        } catch (err) {
          await this.auditFailure(tenant, agent, req.channel, trace, key, err);
          throw err;
        }
        if (target.conversation) {
          const { message } = await this.d.store.appendMessage(tenant, {
            tenant_id: tenant,
            conversation_id: target.conversation.id,
            direction: "out",
            channel: req.channel,
            idempotency_key: key,
            content_mode: t.mode,
            content: t.content,
            content_hash: contentHash,
            size_bytes: size,
            attachments: [],
            audit_event_id: ev.id,
            audit_hash: ev.hash,
          });
          result.message_ids.push(message.id);
          await this.d.store.touchConversation(tenant, target.conversation.id, req.channel);
        }
      } catch (err) {
        // Not performed (render / audit / transport failure): the caller's retry with the same key must be allowed. If the send
        // itself succeeded and only the log append failed, a retry could double-send; that window is logged loudly.
        await this.d.idempotency.release(idemKey);
        throw err;
      }
    }
    return result;
  }

  // ---- transcript relay (voice) --------------------------------------------------------------------------------------------------

  /**
   * Appends one voice call/turn event to the tenant's audit chain (fail closed: no audit, no success). The runtime has already
   * redacted the transcript before hashing it (PHI mode), so `text_sha256` is the hash of what was persisted. Direction: the caller
   * speaking is inbound (`lifecycle`), the agent speaking is outbound (`message_send`); call lifecycle events are `lifecycle`.
   */
  async recordTranscriptEvent(
    tenant: string,
    e: TranscriptEvent,
  ): Promise<{ audit_event_id: string; audit_hash: string }> {
    const actorId = `voice:${sha256Hex(e.call_id).slice(0, 16)}`;
    let ev: UnsealedEvent;
    if (e.kind === "call") {
      const detail = Object.entries(e.detail ?? {})
        .map(([k, v]) => `${k}=${String(v)}`)
        .join(",");
      ev = this.event(tenant, e.agent, {
        actor: { type: "system", id: "voice" },
        enforcement_point: "lifecycle",
        action: `voice.call.${e.phase}`,
        decision: e.detail?.["granted"] === false ? "DENY" : "ALLOW",
        reason: `channel=voice call=${e.call_id} phase=${e.phase} reason=${e.reason ?? "-"} duration_ms=${e.duration_ms ?? "-"} detail=${detail || "-"}`,
        inputs: { channel: "voice", call_id: e.call_id, phase: e.phase },
        outputs: {
          reason: e.reason ?? null,
          duration_ms: e.duration_ms ?? null,
          detail: e.detail ?? {},
        },
        trace_id: e.trace_id,
      });
    } else {
      const outbound = e.role === "agent";
      ev = this.event(tenant, e.agent, {
        actor: outbound ? { type: "system", id: "voice" } : { type: "human", id: actorId },
        enforcement_point: outbound ? "message_send" : "lifecycle",
        action: `voice.turn.${e.role}`,
        decision: "ALLOW",
        reason: `channel=voice dir=${outbound ? "out" : "in"} call=${e.call_id} turn=${e.turn} role=${e.role} size=${e.size} sha256=${e.text_sha256} redacted=${e.redacted} truncated=${e.truncated} audio_bytes=${e.audio_bytes} run=${e.run_id ?? "-"}`,
        inputs: {
          channel: "voice",
          direction: outbound ? "out" : "in",
          call_id: e.call_id,
          turn: e.turn,
          role: e.role,
        },
        outputs: {
          content_sha256: e.text_sha256,
          size_bytes: e.size,
          audio_sha256: e.audio_sha256 ?? null,
          audio_bytes: e.audio_bytes,
        },
        trace_id: e.trace_id,
      });
    }
    const out = await this.appendAudit(ev);
    return { audit_event_id: out.id, audit_hash: out.hash };
  }

  private pickRoute(tenant: string, req: SendRequest): RouteConfig {
    const candidates = this.d.routes
      .forTenant(tenant, req.channel)
      .filter((r) => r.tenant_id === tenant);
    const route = req.from
      ? candidates.find((r) => r.provider_key === req.from)
      : candidates.length === 1
        ? candidates[0]
        : undefined;
    if (!route)
      throw new ChannelError(
        "UNKNOWN_ROUTE",
        `no unambiguous ${req.channel} route for this tenant`,
      );
    return route;
  }

  private async resolveTarget(
    tenant: string,
    route: RouteConfig,
    req: SendRequest,
  ): Promise<{ to: string; thread?: string; conversation?: Conversation }> {
    let conversation: Conversation | undefined;
    let to = req.to;
    if (req.conversation_id) {
      conversation = await this.d.store.getConversation(tenant, req.conversation_id);
      if (!conversation) throw new ChannelError("NOT_FOUND", "unknown conversation");
      if (to === undefined) {
        const idents = (await this.d.store.identitiesOf(tenant, conversation.end_user_id)).filter(
          (i) => i.channel === req.channel,
        );
        if (idents.length === 0)
          throw new ChannelError("NOT_FOUND", "the end user has no identity on that channel");
        to = idents[idents.length - 1]!.external_id;
      }
    }
    if (to === undefined) throw new ChannelError("INVALID", "conversation_id or to is required");
    const ident = await this.d.store.findIdentity(tenant, req.channel, to);
    if (conversation && ident && ident.end_user_id !== conversation.end_user_id)
      throw new ChannelError(
        "FORBIDDEN",
        "destination belongs to a different end user than the conversation",
      );
    if (!ident && route.settings["allow_unsolicited"] !== true)
      throw new ChannelError("FORBIDDEN", "destination is not a known identity of this tenant");
    if (!conversation && ident)
      conversation = await this.d.store.findOpenConversation(
        tenant,
        ident.end_user_id,
        route.agent.name,
      );
    const hint = conversation
      ? await this.d.store.lastThread(tenant, conversation.id, req.channel)
      : undefined;
    let dest = to;
    // Slack hints are `<channel id>:<thread ts>`: a reply goes to the thread's channel.
    if (req.channel === "slack" && hint?.includes(":")) dest = hint.split(":")[0]!;
    // Teams addresses a conversation reference, not a user: only a conversation the user has already opened can be answered.
    if (req.channel === "teams") {
      if (!hint)
        throw new ChannelError("NOT_FOUND", "no Teams conversation reference for this end user");
      dest = hint;
    }
    return {
      to: dest,
      ...(hint ? { thread: hint } : {}),
      ...(conversation ? { conversation } : {}),
    };
  }

  private async perform(
    tenant: string,
    adapter: ChannelAdapter,
    call: RenderedCall,
  ): Promise<void> {
    try {
      if (call.kind === "http") {
        const res = await this.d.http.request(call, { timeoutMs: this.d.httpTimeoutMs ?? 10_000 });
        const ok = adapter.responseOk
          ? adapter.responseOk(res.status, res.body)
          : res.status >= 200 && res.status <= 299;
        if (!ok)
          throw new ChannelError("TRANSPORT", `provider refused the message (HTTP ${res.status})`);
      } else if (call.kind === "email") {
        if (!this.d.email) throw new ChannelError("TRANSPORT", "no email transport configured");
        await this.d.email.send(call);
      } else {
        if (!this.d.hub) throw new ChannelError("TRANSPORT", "no web hub configured");
        // The hub key includes the tenant: a session id of another tenant is a different stream.
        this.d.hub.publish(tenant, call.session_id, call.event.type, call.event.data);
      }
    } catch (err) {
      if (err instanceof ChannelError) throw err;
      throw new ChannelError("TRANSPORT", "transport failure");
    }
  }

  private async auditFailure(
    tenant: string,
    agent: AgentRef,
    channel: ChannelId,
    trace: string,
    key: string,
    err: unknown,
  ): Promise<void> {
    try {
      await this.d.audit.append(
        this.event(tenant, agent, {
          actor: { type: "system", id: `channel:${channel}` },
          enforcement_point: "message_send",
          action: "channel.outbound.failed",
          decision: "ALLOW",
          reason: `channel=${channel} send failed after the action was allowed: ${err instanceof Error ? err.message : "error"}`,
          inputs: { channel, key },
          outputs: { sent: false },
          trace_id: trace,
        }),
      );
    } catch (e) {
      this.log.error("audit append of a send failure failed", { error: String(e) });
    }
  }
}
