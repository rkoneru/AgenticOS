import { describe, expect, it } from "vitest";
import {
  GENESIS_HASH,
  hashPayload,
  sealEvent,
  validateAuditEvent,
  verifyChain,
  canonicalize,
} from "../src/index.js";
import { chain, T1, T2 } from "./helpers.js";

describe("canonicalize", () => {
  it("sorts keys and is whitespace free", () => {
    expect(canonicalize({ b: 1, a: [true, null, "x"], c: { z: 1, y: 2 } })).toBe(
      '{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":1}}',
    );
  });
  it("rejects floats, NaN, undefined, functions", () => {
    for (const bad of [1.5, NaN, Infinity, undefined, () => 1, 10n]) {
      expect(() => canonicalize(bad)).toThrow(TypeError);
    }
  });
  it("hashPayload is key-order independent and stable", () => {
    expect(hashPayload({ a: 1, b: 2 })).toBe(hashPayload({ b: 2, a: 1 }));
    expect(hashPayload({})).toBe(
      "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    );
  });
});

describe("audit chain", () => {
  const events = chain(T1, 5, sealEvent);

  it("genesis links to zeros, then each event links to the previous hash", () => {
    expect(events[0]?.seq).toBe(1);
    expect(events[0]?.prev_hash).toBe(GENESIS_HASH);
    for (let i = 1; i < events.length; i++) expect(events[i]?.prev_hash).toBe(events[i - 1]?.hash);
  });

  it("sealed events satisfy the JSON schema", () => {
    for (const e of events)
      expect(validateAuditEvent(e), JSON.stringify(validateAuditEvent.errors)).toBe(true);
  });

  it("verifies an intact chain and an empty chain", () => {
    expect(verifyChain(events)).toEqual({ ok: true, length: 5 });
    expect(verifyChain([])).toEqual({ ok: true, length: 0 });
  });

  it("verifies a slice given the preceding event", () => {
    expect(verifyChain(events.slice(2), events[1])).toEqual({ ok: true, length: 3 });
  });

  it("detects tampering with any field (hash_mismatch)", () => {
    const t = events.map((e) => ({ ...e }));
    t[2] = { ...t[2]!, decision: "DENY" };
    expect(verifyChain(t)).toEqual({ ok: false, brokenAtSeq: 3, reason: "hash_mismatch" });
  });

  it("detects a deleted event (seq_gap)", () => {
    const t = [events[0]!, events[1]!, events[3]!];
    expect(verifyChain(t)).toEqual({ ok: false, brokenAtSeq: 4, reason: "seq_gap" });
  });

  it("detects a slice that does not start at genesis", () => {
    expect(verifyChain(events.slice(1))).toEqual({ ok: false, brokenAtSeq: 2, reason: "seq_gap" });
  });

  it("detects a rewritten link (prev_hash_mismatch)", () => {
    const t = events.map((e) => ({ ...e }));
    const forged = { ...t[1]!, prev_hash: "d".repeat(64) };
    const { hash: _h, ...rest } = forged;
    void _h;
    t[1] = sealEventRaw(rest);
    expect(verifyChain(t)).toEqual({ ok: false, brokenAtSeq: 2, reason: "prev_hash_mismatch" });
  });

  it("detects mixing tenants in a chain", () => {
    const other = chain(T2, 2, sealEvent);
    expect(verifyChain([events[0]!, other[1]!])).toMatchObject({
      ok: false,
      reason: "tenant_mismatch",
    });
    expect(verifyChain([other[1]!], events[0])).toMatchObject({
      ok: false,
      reason: "tenant_mismatch",
    });
  });

  it("schema rejects agent actors without a pid and malformed hashes", () => {
    const e = { ...events[0]!, actor: { type: "agent", id: "x" } };
    expect(validateAuditEvent(e)).toBe(false);
    expect(validateAuditEvent({ ...events[0]!, hash: "xyz" })).toBe(false);
    expect(validateAuditEvent({ ...events[0]!, actor: { type: "human", id: "u1" } })).toBe(true);
  });
});

import { computeEventHash } from "../src/index.js";
import type { AuditEvent } from "../src/index.js";
function sealEventRaw(e: Omit<AuditEvent, "hash">): AuditEvent {
  return { ...e, hash: computeEventHash(e) };
}

import { canonicalizePayload, hashJson } from "../src/index.js";

describe("canonicalizePayload / hashJson (float-tolerant payload hashing)", () => {
  it("sorts keys, keeps floats in ES number form, and is order independent", () => {
    expect(canonicalizePayload({ b: 1.5, a: [0.1, -2, 1e21, "x"], c: null, d: true })).toBe(
      '{"a":[0.1,-2,1e+21,"x"],"b":1.5,"c":null,"d":true}',
    );
    expect(hashJson({ x: 1.25, y: 2 })).toBe(hashJson({ y: 2, x: 1.25 }));
    expect(hashJson({})).toBe(hashPayload({}));
  });
  it("rejects non-finite numbers and unsupported types", () => {
    for (const bad of [NaN, Infinity, -Infinity, undefined, () => 1, 10n, Symbol("s")]) {
      expect(() => canonicalizePayload(bad)).toThrow(TypeError);
    }
  });
});
