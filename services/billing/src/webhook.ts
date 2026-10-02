import { createHmac, timingSafeEqual } from "node:crypto";
import { BillingError } from "./errors.js";

export const DEFAULT_TOLERANCE_SECONDS = 300;

function parseHeader(header: string): { t: number; v1: string[] } {
  let t: number | undefined;
  const v1: string[] = [];
  for (const part of header.split(",")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k === "t" && /^\d{1,12}$/.test(v)) t = Number(v);
    else if (k === "v1" && /^[0-9a-f]{64}$/.test(v)) v1.push(v);
  }
  if (t === undefined || v1.length === 0)
    throw new BillingError("SIGNATURE_INVALID", "malformed Stripe-Signature header");
  return { t, v1 };
}

/** The signature Stripe computes: HMAC-SHA256(secret, `${t}.${payload}`) as lowercase hex. */
export function stripeSignature(secret: string, t: number, payload: string | Buffer): string {
  return createHmac("sha256", secret).update(`${t}.`).update(payload).digest("hex");
}

/**
 * Verifies a Stripe webhook (Stripe-Signature `t=...,v1=...`). Rejects: malformed header, timestamp outside the tolerance window
 * (replay of an old delivery, or a far-future one), and any signature mismatch. Comparison is constant time. `payload` MUST be the
 * raw request body bytes, never re-serialised JSON.
 */
export function verifyStripeSignature(args: {
  payload: string | Buffer;
  header: string | undefined;
  secret: string;
  nowMs: number;
  toleranceSeconds?: number;
}): void {
  if (!args.secret) throw new BillingError("SIGNATURE_INVALID", "webhook secret is not configured");
  if (!args.header) throw new BillingError("SIGNATURE_INVALID", "missing Stripe-Signature header");
  const { t, v1 } = parseHeader(args.header);
  const tol = args.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  if (Math.abs(args.nowMs / 1000 - t) > tol)
    throw new BillingError("SIGNATURE_INVALID", "timestamp outside the tolerance window");
  const expected = Buffer.from(stripeSignature(args.secret, t, args.payload), "hex");
  let ok = false;
  for (const candidate of v1) {
    const got = Buffer.from(candidate, "hex");
    // parseHeader only admits 64-hex candidates, so the lengths always match (timingSafeEqual would throw otherwise)
    if (timingSafeEqual(got, expected)) ok = true; // no early exit: constant time per candidate
  }
  if (!ok) throw new BillingError("SIGNATURE_INVALID", "signature mismatch");
}

export interface WebhookEvent {
  id: string;
  type: string;
  data: unknown;
}

export interface EventDedupe {
  /** True the first time an id is claimed. */
  claim(id: string): Promise<boolean>;
}

export class MemoryEventDedupe implements EventDedupe {
  private readonly seen = new Set<string>();
  claim(id: string): Promise<boolean> {
    const fresh = !this.seen.has(id);
    this.seen.add(id);
    return Promise.resolve(fresh);
  }
}

export type WebhookHandler = (event: WebhookEvent) => Promise<void>;

/** Verifies, parses and de-duplicates provider events, then dispatches by type. Unknown types are acknowledged and ignored. */
export class StripeWebhookProcessor {
  constructor(
    private readonly o: {
      secret: string;
      handlers: Readonly<Record<string, WebhookHandler>>;
      dedupe?: EventDedupe;
      now?: () => number;
      toleranceSeconds?: number;
    },
  ) {}

  async handle(
    rawBody: string | Buffer,
    header: string | undefined,
  ): Promise<"processed" | "duplicate" | "ignored"> {
    verifyStripeSignature({
      payload: rawBody,
      header,
      secret: this.o.secret,
      nowMs: (this.o.now ?? Date.now)(),
      ...(this.o.toleranceSeconds === undefined
        ? {}
        : { toleranceSeconds: this.o.toleranceSeconds }),
    });
    let ev: unknown;
    try {
      ev = JSON.parse(rawBody.toString("utf8"));
    } catch {
      throw new BillingError("INVALID", "webhook body is not JSON");
    }
    const o = ev as {
      id?: unknown;
      type?: unknown;
      data?: { object?: unknown };
      livemode?: unknown;
    };
    if (typeof o.id !== "string" || typeof o.type !== "string")
      throw new BillingError("INVALID", "webhook event has no id or type");
    if (o.livemode === true)
      throw new BillingError("LIVE_KEY_REFUSED", "live-mode events are refused");
    const handler = this.o.handlers[o.type];
    if (!handler) return "ignored";
    if (!(await (this.o.dedupe ?? (this.o.dedupe = new MemoryEventDedupe())).claim(o.id)))
      return "duplicate";
    await handler({ id: o.id, type: o.type, data: o.data?.object });
    return "processed";
  }
}
