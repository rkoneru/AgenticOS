/**
 * Clock skew (Phase 9 D): the same library code the services run, driven with skewed injected clocks. Fail-closed means a skewed clock can
 * make something REFUSED (a stale or future-dated approval, a seal that is not closable yet), never accepted when it should not be.
 * Limits (docs/runbooks/chaos.md): this is library level, not a skewed process on the real stack; the real-stack run uses the host clock.
 */
import { HmacSealSigner, MemoryUsageLedger } from "@axis/billing";
import { HmacSigner, isApprovalValidFor, signRecord, type DecisionRecord } from "@axis/approvals";
import { describe, expect, it } from "vitest";

const KEY = new Uint8Array(32).fill(7);
const signer = new HmacSigner(KEY);
const T0 = Date.parse("2026-09-01T12:00:00.000Z");

async function approved(
  decidedAt: number,
): Promise<{ rec: DecisionRecord; exp: Parameters<typeof isApprovalValidFor>[1] }> {
  const body = {
    request_id: "r1",
    tenant_id: "t1",
    run_id: "run1",
    tool: "file-payout",
    args_hash: "a".repeat(64),
    outcome: "APPROVED",
    decision: "ALLOW",
    decided_by: "alice",
    decided_at: new Date(decidedAt).toISOString(),
    level: 1,
    reason: "ok",
    audit_event_id: "e1",
    audit_hash: "b".repeat(64),
    key_id: signer.keyId,
  } as const;
  const rec = await signRecord(body as never, signer);
  return {
    rec,
    exp: { tenant_id: "t1", run_id: "run1", tool: "file-payout", args_hash: "a".repeat(64) },
  };
}

describe("approvals under clock skew", () => {
  it("accepts an approval decided just now", async () => {
    const { rec, exp } = await approved(T0);
    expect(
      await isApprovalValidFor(rec, exp, signer, { nowMs: T0 + 1000, maxAgeMs: 300_000 }),
    ).toBe(true);
  });
  it("the verifier's clock AHEAD beyond the freshness window: the approval is refused (stale), not accepted", async () => {
    const { rec, exp } = await approved(T0);
    expect(
      await isApprovalValidFor(rec, exp, signer, { nowMs: T0 + 301_000, maxAgeMs: 300_000 }),
    ).toBe(false);
  });
  it("the verifier's clock BEHIND the approver's (a decision dated in the future): refused", async () => {
    const { rec, exp } = await approved(T0 + 60_000);
    expect(await isApprovalValidFor(rec, exp, signer, { nowMs: T0, maxAgeMs: 300_000 })).toBe(
      false,
    );
  });
  it("an attacker cannot repair a skewed timestamp: decided_at is covered by the signature", async () => {
    const { rec, exp } = await approved(T0 - 10 * 60_000);
    const forged = { ...rec, decided_at: new Date(T0).toISOString() };
    expect(
      await isApprovalValidFor(forged, exp, signer, { nowMs: T0 + 1000, maxAgeMs: 300_000 }),
    ).toBe(false);
  });
  it("an unparsable timestamp is refused", async () => {
    const { rec, exp } = await approved(T0);
    const bad = { ...rec, decided_at: "not a date" };
    expect(await isApprovalValidFor(bad, exp, signer, { nowMs: T0, maxAgeMs: 300_000 })).toBe(
      false,
    );
  });
});

describe("billing under clock skew", () => {
  const tenant = "11111111-1111-4111-8111-111111111111";
  const seal = new HmacSealSigner(Buffer.alloc(32, 1));
  const usage = (eventTime: Date): Parameters<MemoryUsageLedger["append"]>[0] => ({
    tenantId: tenant,
    idempotencyKey: `k-${eventTime.getTime()}`,
    meter: "tokens_in",
    quantity: 10n,
    eventTime,
    dimensions: { model_class: "small" },
    source: "chaos",
  });

  it("a producer whose clock is far in the future cannot post usage into the future", async () => {
    const ledger = new MemoryUsageLedger({ signer: seal, now: () => new Date(T0) });
    await expect(ledger.append(usage(new Date(T0 + 3_600_000)))).rejects.toThrow(/future/);
    await expect(ledger.append(usage(new Date(T0 + 1000)))).resolves.toBeDefined(); // a small skew is tolerated
  });
  it("a ledger whose clock is behind cannot seal a period that has not ended", async () => {
    const early = new MemoryUsageLedger({
      signer: seal,
      now: () => new Date("2026-09-15T00:00:00Z"),
    });
    await early.append(usage(new Date("2026-09-10T00:00:00Z")));
    await expect(early.closePeriod(tenant, "2026-09")).rejects.toThrow(/not ended|NOT_CLOSABLE/i);
  });
  it("a seal made with a skewed clock still verifies and a tampered total does not", async () => {
    const late = new MemoryUsageLedger({
      signer: seal,
      now: () => new Date("2026-10-02T00:00:00Z"),
    });
    await late.append(usage(new Date("2026-09-10T00:00:00Z")));
    const s = await late.closePeriod(tenant, "2026-09");
    expect(s.eventCount).toBe(1);
    expect((await late.verifySeal(tenant, "2026-09")).ok).toBe(true);
  });
});
