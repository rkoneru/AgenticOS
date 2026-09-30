import { randomUUID, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  AuditCheckpointer,
  Ed25519Signer,
  MemoryAuditLog,
  MemoryCheckpointStore,
  checkpointMessage,
  generateEd25519,
  verifyCheckpointSignature,
  type Checkpoint,
} from "../src/index.js";
import { ev } from "./helpers.js";

class Tamperable extends MemoryAuditLog {
  chain(t: string) {
    return this.chains.get(t)!;
  }
}

async function setup(n = 5) {
  const log = new Tamperable();
  const t = randomUUID();
  for (let i = 0; i < n; i++) await log.append(ev(t));
  const store = new MemoryCheckpointStore();
  const { signer, publicKey } = generateEd25519();
  const cp = new AuditCheckpointer(log, store, signer, {
    now: () => new Date("2031-01-02T03:04:05.006Z"),
  });
  return { log, t, store, signer, publicKey, cp };
}

describe("checkpoints", () => {
  it("creates a signed, persisted checkpoint of the head and verifies it", async () => {
    const { log, t, store, publicKey, cp } = await setup();
    const c = await cp.createCheckpoint(t);
    expect(c).toMatchObject({
      tenant_id: t,
      seq: 5,
      hash: (await log.head(t))!.hash,
      ts: "2031-01-02T03:04:05.006Z",
    });
    expect(await store.latest(t)).toEqual(c);
    expect(verifyCheckpointSignature(c, publicKey)).toBe(true);
    expect(await cp.verifyAgainstCheckpoint(t, c, publicKey)).toEqual({
      ok: true,
      checkpointSeq: 5,
      headSeq: 5,
    });
    await log.append(ev(t)); // log grew after the checkpoint: still fine
    expect(await cp.verifyAgainstCheckpoint(t, c, publicKey)).toEqual({
      ok: true,
      checkpointSeq: 5,
      headSeq: 6,
    });
  });

  it("refuses to checkpoint an empty log", async () => {
    const { cp } = await setup(0);
    await expect(cp.createCheckpoint(randomUUID())).rejects.toThrow(/empty/);
  });

  it("does not hand back a checkpoint that failed to persist", async () => {
    const { log, t, signer } = await setup();
    const failing = {
      save: () => Promise.reject(new Error("disk full")),
      latest: async () => undefined,
      list: async () => [],
    };
    await expect(new AuditCheckpointer(log, failing, signer).createCheckpoint(t)).rejects.toThrow(
      "disk full",
    );
  });

  it("detects truncation (head behind checkpoint), including total wipe", async () => {
    const { log, t, publicKey, cp } = await setup();
    const c = await cp.createCheckpoint(t);
    log.chain(t).length = 3;
    expect(await cp.verifyAgainstCheckpoint(t, c, publicKey)).toMatchObject({
      ok: false,
      reason: "truncated",
    });
    log.chain(t).length = 0;
    expect(await cp.verifyAgainstCheckpoint(t, c, publicKey)).toMatchObject({
      ok: false,
      reason: "truncated",
    });
  });

  it("detects a rewrite (hash at the checkpoint seq differs) and a missing row at that seq", async () => {
    const { log, t, publicKey, cp } = await setup();
    const c = await cp.createCheckpoint(t);
    const saved = structuredClone(log.chain(t));
    // re-seal the last event differently: a fully self-consistent alternative history
    log.chain(t).splice(4, 1);
    await log.append(ev(t, { action: "rewritten" }));
    expect(await log.verify(t)).toMatchObject({ ok: true }); // the bare chain cannot tell
    expect(await cp.verifyAgainstCheckpoint(t, c, publicKey)).toMatchObject({
      ok: false,
      reason: "hash_mismatch",
    });
    log.chain(t).splice(0, log.chain(t).length, ...saved);
    log.chain(t).splice(4, 1); // head.seq would be 4 -> truncated; make a hole instead
    log.chain(t).push({ ...saved[4]!, seq: 6 });
    expect(await cp.verifyAgainstCheckpoint(t, c, publicKey)).toMatchObject({
      ok: false,
      reason: "hash_mismatch",
      detail: expect.stringContaining("no event at seq 5"),
    });
  });

  it("detects a broken chain before the checkpoint", async () => {
    const { log, t, publicKey, cp } = await setup();
    const c = await cp.createCheckpoint(t);
    log.chain(t)[1]!.action = "evil";
    expect(await cp.verifyAgainstCheckpoint(t, c, publicKey)).toMatchObject({
      ok: false,
      reason: "chain_broken",
      chain: { ok: false, brokenAtSeq: 2, reason: "hash_mismatch" },
    });
  });

  it("rejects a bad signature: altered body, wrong key, garbage signature", async () => {
    const { t, publicKey, cp } = await setup();
    const c = await cp.createCheckpoint(t);
    const other = generateEd25519().publicKey;
    expect(await cp.verifyAgainstCheckpoint(t, { ...c, seq: 4 }, publicKey)).toMatchObject({
      reason: "bad_signature",
    });
    expect(
      await cp.verifyAgainstCheckpoint(t, { ...c, hash: "0".repeat(64) }, publicKey),
    ).toMatchObject({
      reason: "bad_signature",
    });
    expect(await cp.verifyAgainstCheckpoint(t, c, other)).toMatchObject({
      reason: "bad_signature",
    });
    expect(
      await cp.verifyAgainstCheckpoint(t, { ...c, signature: "AAAA" }, publicKey),
    ).toMatchObject({
      reason: "bad_signature",
    });
    expect(verifyCheckpointSignature(c, "not a pem")).toBe(false);
  });

  it("rejects malformed checkpoints and another tenant's checkpoint", async () => {
    const { log, t, publicKey, cp } = await setup();
    const c = await cp.createCheckpoint(t);
    const bad: unknown[] = [
      null,
      "x",
      { ...c, tenant_id: "nope" },
      { ...c, seq: 0 },
      { ...c, seq: "5" },
      { ...c, hash: "zz" },
      { ...c, ts: "yesterday" },
      { ...c, signature: "***" },
      { ...c, signature: undefined },
    ];
    for (const b of bad)
      expect(await cp.verifyAgainstCheckpoint(t, b as Checkpoint, publicKey)).toEqual({
        ok: false,
        reason: "malformed",
      });
    const t2 = randomUUID();
    await log.append(ev(t2));
    expect(await cp.verifyAgainstCheckpoint(t2, c, publicKey)).toEqual({
      ok: false,
      reason: "tenant_mismatch",
    });
  });

  it("the signed message is domain separated and canonical", () => {
    const m = checkpointMessage({ tenant_id: "t", seq: 1, hash: "h", ts: "z" }).toString();
    expect(m).toBe('axis-audit-checkpoint-v1\n{"hash":"h","seq":1,"tenant_id":"t","ts":"z"}');
  });

  it("Ed25519Signer accepts PEM, exposes its public key, and rejects other key types", async () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const s = new Ed25519Signer(pem);
    const sig = await s.sign(Buffer.from("x"));
    expect(sig.length).toBe(64);
    expect(s.publicKey.asymmetricKeyType).toBe("ed25519");
    expect(
      () => new Ed25519Signer(generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey),
    ).toThrow(/ed25519/);
  });

  it("MemoryCheckpointStore.latest prefers the highest seq and returns copies", async () => {
    const store = new MemoryCheckpointStore();
    const t = randomUUID();
    const mk = (seq: number): Checkpoint => ({
      tenant_id: t,
      seq,
      hash: "a".repeat(64),
      ts: "2031-01-02T03:04:05.006Z",
      signature: "AA==",
    });
    expect(await store.latest(t)).toBeUndefined();
    await store.save(mk(3));
    await store.save(mk(5));
    await store.save(mk(4));
    const latest = (await store.latest(t))!;
    expect(latest.seq).toBe(5);
    latest.seq = 99;
    expect((await store.latest(t))!.seq).toBe(5);
    expect((await store.list(t)).map((c) => c.seq)).toEqual([3, 5, 4]);
  });
});
