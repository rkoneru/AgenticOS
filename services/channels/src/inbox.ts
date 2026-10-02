import type { InboundContext, InboundHandler } from "./gateway.js";
import type { AgentRef, ChannelId } from "./types.js";

/**
 * DEV / E2E ONLY (docs/adr/0017, docs/NEEDS.md). The bridge from a verified inbound message to an agent run.
 *
 * The gateway's `onMessage` hook enqueues an `InboxItem` for the message's tenant (the tenant the PROVIDER signature verified, never
 * one named in the content); the runtime's `ChannelAgentRunner` long-polls `POST /v1/channels/inbox/next` with a bearer token that
 * fixes its own tenant, so a runner of tenant B can never receive tenant A's message. The queue is in memory and per process: an
 * item is lost on restart (the message itself stays in the conversation log and the audit chain), there is no ack/redelivery and no
 * visibility timeout. A durable queue (Temporal signal or SQS) replaces it in production.
 */
export interface InboxItem {
  /** Unique per delivery; the runner derives its run id from it. */
  id: string;
  tenant_id: string;
  channel: ChannelId;
  provider_key: string;
  agent: AgentRef;
  /** The provider-verified sender identifier (an address on `channel`). */
  external_user_id: string;
  end_user_id: string;
  conversation_id: string;
  message_id: string;
  /** The trace id of the inbound audit event; the run uses it so the chain shows one trace per turn. */
  trace_id: string;
  text: string;
  timestamp_ms: number;
}

interface Waiter {
  resolve: (item: InboxItem | undefined) => void;
  timer: NodeJS.Timeout;
}

export class InboxQueue {
  private readonly queues = new Map<string, InboxItem[]>();
  private readonly waiters = new Map<string, Waiter[]>();
  private seq = 0;

  constructor(private readonly maxPerTenant = 1000) {}

  /** The gateway's `onMessage`. Throws when the tenant's queue is full (the gateway logs it; the message stays recorded). */
  readonly handler: InboundHandler = async (ctx: InboundContext) => {
    const m = ctx.message;
    this.push({
      id: `in-${Date.now().toString(36)}-${++this.seq}`,
      tenant_id: m.tenant_id,
      channel: m.channel,
      provider_key: m.provider_key,
      agent: ctx.conversation.agent,
      external_user_id: m.external_user_id,
      end_user_id: ctx.conversation.end_user_id,
      conversation_id: ctx.conversation.id,
      message_id: ctx.stored.id,
      trace_id: ctx.trace_id,
      text: m.text,
      timestamp_ms: m.timestamp_ms,
    });
  };

  push(item: InboxItem): void {
    const w = this.waiters.get(item.tenant_id)?.shift();
    if (w) {
      clearTimeout(w.timer);
      w.resolve(item);
      return;
    }
    const q = this.queues.get(item.tenant_id) ?? [];
    if (q.length >= this.maxPerTenant) throw new Error("inbox full");
    q.push(item);
    this.queues.set(item.tenant_id, q);
  }

  size(tenant: string): number {
    return this.queues.get(tenant)?.length ?? 0;
  }

  /** The next item of `tenant`, waiting up to `waitMs`; undefined on timeout. Only ever returns this tenant's items. */
  take(tenant: string, waitMs: number, signal?: AbortSignal): Promise<InboxItem | undefined> {
    const q = this.queues.get(tenant);
    const next = q?.shift();
    if (next) return Promise.resolve(next);
    if (waitMs <= 0 || signal?.aborted) return Promise.resolve(undefined);
    return new Promise((resolve) => {
      const leave = (): void => {
        const list = this.waiters.get(tenant) ?? [];
        const i = list.indexOf(waiter);
        if (i >= 0) list.splice(i, 1);
        if (list.length === 0) this.waiters.delete(tenant);
      };
      const onAbort = (): void => {
        // The poller is gone (its connection dropped): it must not be handed an item nobody will read.
        clearTimeout(waiter.timer);
        leave();
        resolve(undefined);
      };
      const waiter: Waiter = {
        resolve: (item) => {
          signal?.removeEventListener("abort", onAbort);
          resolve(item);
        },
        timer: setTimeout(() => {
          signal?.removeEventListener("abort", onAbort);
          leave();
          resolve(undefined);
        }, waitMs),
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      this.waiters.set(tenant, [...(this.waiters.get(tenant) ?? []), waiter]);
    });
  }
}
