import { describe, expect, it } from "vitest";
import {
  ChannelError,
  hashLinkCode,
  type ConversationStore,
  type NewMessage,
} from "../src/index.js";
import { AGENT, NOW } from "./helpers.js";
import { randomUUID } from "node:crypto";

const H = (c: string): string => c.repeat(64);

/** The behaviour every ConversationStore must have, run against the in-memory and the Postgres implementation. */
export function storeContract(
  name: string,
  make: () => Promise<{ store: ConversationStore; tenant: () => Promise<string> }>,
): void {
  describe(`ConversationStore contract: ${name}`, () => {
    const msg = (conv: string, key: string, over: Partial<NewMessage> = {}): NewMessage => ({
      tenant_id: "ignored",
      conversation_id: conv,
      direction: "in",
      channel: "slack",
      idempotency_key: key,
      content_mode: "hash_only",
      content: null,
      content_hash: H("a"),
      size_bytes: 3,
      attachments: [],
      audit_event_id: null,
      audit_hash: null,
      ...over,
    });

    it("resolveIdentity is get-or-create per (tenant, channel, external id) and never merges", async () => {
      const { store, tenant } = await make();
      const t1 = await tenant();
      const t2 = await tenant();
      const a = await store.resolveIdentity(t1, "slack", "U1");
      const b = await store.resolveIdentity(t1, "slack", "U1");
      const c = await store.resolveIdentity(t1, "sms", "+15550001");
      const d = await store.resolveIdentity(t2, "slack", "U1");
      expect(a.created).toBe(true);
      expect(b.created).toBe(false);
      expect(b.identity.id).toBe(a.identity.id);
      expect(c.identity.end_user_id).not.toBe(a.identity.end_user_id);
      expect(d.identity.end_user_id).not.toBe(a.identity.end_user_id);
      expect(d.identity.tenant_id).toBe(t2);
      expect(a.identity.verified_by).toBe("provider");
      expect(await store.findIdentity(t1, "slack", "nobody")).toBeUndefined();
      expect(
        (await store.identitiesOf(t1, a.identity.end_user_id)).map((i) => i.external_id),
      ).toEqual(["U1"]);
      expect(await store.identitiesOf(t2, a.identity.end_user_id)).toEqual([]);
    });

    it("concurrent first sightings of one identifier converge on one identity", async () => {
      const { store, tenant } = await make();
      const t = await tenant();
      const rs = await Promise.all(
        Array.from({ length: 8 }, () => store.resolveIdentity(t, "web", "sid-1")),
      );
      expect(new Set(rs.map((r) => r.identity.id)).size).toBe(1);
      expect(rs.filter((r) => r.created).length).toBe(1);
    });

    it("link challenge: redeem moves the redeemer identity (and its history when it has no other identity)", async () => {
      const { store, tenant } = await make();
      const t = await tenant();
      const a = (await store.resolveIdentity(t, "slack", "UA")).identity;
      const conv = await store.createConversation(t, a.end_user_id, AGENT, "slack");
      const b = (await store.resolveIdentity(t, "sms", "+1555")).identity;
      const convB = await store.createConversation(t, b.end_user_id, AGENT, "sms");
      await store.createChallenge(t, a.end_user_id, hashLinkCode(t, "ABCDEFGHJK"), NOW + 60_000);
      const r = await store.redeemChallenge(t, hashLinkCode(t, "ABCDEFGHJK"), NOW, {
        channel: "sms",
        externalId: "+1555",
      });
      expect(r).toMatchObject({
        ok: true,
        end_user_id: a.end_user_id,
        moved_conversations: 1,
        already_linked: false,
      });
      if (r.ok)
        expect(r.identity).toMatchObject({ verified_by: "link", end_user_id: a.end_user_id });
      expect((await store.getConversation(t, convB.id))!.end_user_id).toBe(a.end_user_id);
      expect((await store.getConversation(t, conv.id))!.end_user_id).toBe(a.end_user_id);
      expect((await store.identitiesOf(t, a.end_user_id)).map((i) => i.channel).sort()).toEqual([
        "slack",
        "sms",
      ]);
      // the SAME end user is now found from both identifiers
      expect((await store.findIdentity(t, "sms", "+1555"))!.end_user_id).toBe(
        (await store.findIdentity(t, "slack", "UA"))!.end_user_id,
      );
      // single use
      expect(
        await store.redeemChallenge(t, hashLinkCode(t, "ABCDEFGHJK"), NOW, {
          channel: "sms",
          externalId: "+1555",
        }),
      ).toEqual({ ok: false, reason: "consumed" });
    });

    it("redeeming does not drag history along when the redeemer's old end user keeps another identity", async () => {
      const { store, tenant } = await make();
      const t = await tenant();
      const a = (await store.resolveIdentity(t, "slack", "UA")).identity;
      const b1 = (await store.resolveIdentity(t, "sms", "+1555")).identity;
      // give b's end user a second identity by a first link
      await store.createChallenge(t, b1.end_user_id, H("1"), NOW + 60_000);
      await store.redeemChallenge(t, H("1"), NOW, { channel: "whatsapp", externalId: "1555" });
      const convB = await store.createConversation(t, b1.end_user_id, AGENT, "sms");
      await store.createChallenge(t, a.end_user_id, H("2"), NOW + 60_000);
      const r = await store.redeemChallenge(t, H("2"), NOW, {
        channel: "sms",
        externalId: "+1555",
      });
      expect(r).toMatchObject({ ok: true, moved_conversations: 0 });
      expect((await store.getConversation(t, convB.id))!.end_user_id).toBe(b1.end_user_id);
    });

    it("redeeming from an identity that already belongs to the challenge's user is a no-op", async () => {
      const { store, tenant } = await make();
      const t = await tenant();
      const a = (await store.resolveIdentity(t, "slack", "UA")).identity;
      await store.createChallenge(t, a.end_user_id, H("3"), NOW + 60_000);
      expect(
        await store.redeemChallenge(t, H("3"), NOW, { channel: "slack", externalId: "UA" }),
      ).toMatchObject({ ok: true, already_linked: true, moved_conversations: 0 });
    });

    it("invalid, expired and cross-tenant codes redeem nothing", async () => {
      const { store, tenant } = await make();
      const t1 = await tenant();
      const t2 = await tenant();
      const a = (await store.resolveIdentity(t1, "slack", "UA")).identity;
      await store.createChallenge(t1, a.end_user_id, H("4"), NOW + 60_000);
      await store.createChallenge(t1, a.end_user_id, H("5"), NOW - 1);
      expect(
        await store.redeemChallenge(t1, H("9"), NOW, { channel: "sms", externalId: "+1" }),
      ).toEqual({ ok: false, reason: "invalid" });
      expect(
        await store.redeemChallenge(t1, H("5"), NOW, { channel: "sms", externalId: "+1" }),
      ).toEqual({ ok: false, reason: "expired" });
      // the other tenant cannot see or use T1's code
      expect(
        await store.redeemChallenge(t2, H("4"), NOW, { channel: "sms", externalId: "+1" }),
      ).toEqual({ ok: false, reason: "invalid" });
      expect(await store.findIdentity(t2, "sms", "+1")).toBeUndefined();
      // and cannot create a challenge for T1's end user
      await expect(
        store.createChallenge(t2, a.end_user_id, H("6"), NOW + 1000),
      ).rejects.toMatchObject({ code: "NOT_FOUND" });
    });

    it("conversations: open lookup prefers the most recently active; threads resolve; tenants are separate", async () => {
      const { store, tenant } = await make();
      const t1 = await tenant();
      const t2 = await tenant();
      const eu = (await store.resolveIdentity(t1, "slack", "UA")).identity.end_user_id;
      const c1 = await store.createConversation(t1, eu, AGENT, "slack");
      await new Promise((r) => setTimeout(r, 5));
      const c2 = await store.createConversation(t1, eu, AGENT, "slack");
      expect((await store.findOpenConversation(t1, eu, AGENT.name))!.id).toBe(c2.id);
      await new Promise((r) => setTimeout(r, 5));
      await store.touchConversation(t1, c1.id, "sms");
      const open = await store.findOpenConversation(t1, eu, AGENT.name);
      expect(open).toMatchObject({ id: c1.id, last_channel: "sms" });
      expect(await store.findOpenConversation(t1, eu, "other-agent")).toBeUndefined();

      await store.addThread(t1, "slack", "C1:1.1", c1.id);
      await store.addThread(t1, "slack", "C1:1.1", c1.id); // idempotent
      expect((await store.findByThread(t1, "slack", "C1:1.1"))!.id).toBe(c1.id);
      expect(await store.findByThread(t1, "slack", "C1:9.9")).toBeUndefined();
      expect(await store.findByThread(t1, "sms", "C1:1.1")).toBeUndefined();
      expect(await store.findByThread(t2, "slack", "C1:1.1")).toBeUndefined();
      await store.addThread(t1, "slack", "C2:2.2", c1.id);
      expect(await store.lastThread(t1, c1.id, "slack")).toBe("C2:2.2");
      expect(await store.lastThread(t1, c1.id, "sms")).toBeUndefined();
      expect(await store.lastThread(t2, c1.id, "slack")).toBeUndefined();

      expect(await store.getConversation(t2, c1.id)).toBeUndefined();
      await expect(store.createConversation(t2, eu, AGENT, "slack")).rejects.toMatchObject({
        code: "NOT_FOUND",
      });
      await expect(store.addThread(t2, "slack", "x", c1.id)).rejects.toMatchObject({
        code: "NOT_FOUND",
      });
      await expect(
        store.createConversation(t1, randomUUID(), AGENT, "slack"),
      ).rejects.toBeInstanceOf(ChannelError);
      await store.touchConversation(t1, randomUUID(), "slack"); // unknown id: no-op
    });

    it("messages are idempotent per (channel, direction, key), ordered, limited and tenant-scoped", async () => {
      const { store, tenant } = await make();
      const t1 = await tenant();
      const t2 = await tenant();
      const eu = (await store.resolveIdentity(t1, "slack", "UA")).identity.end_user_id;
      const c = await store.createConversation(t1, eu, AGENT, "slack");
      const a = await store.appendMessage(
        t1,
        msg(c.id, "k1", {
          content_mode: "full",
          content: "hello",
          attachments: [{ name: "a", content_type: "image/png", size: 1 }],
          audit_event_id: "ev",
          audit_hash: H("b"),
        }),
      );
      expect(a.inserted).toBe(true);
      expect(a.message).toMatchObject({
        tenant_id: t1,
        content: "hello",
        attachments: [{ name: "a", content_type: "image/png", size: 1 }],
        audit_event_id: "ev",
        audit_hash: H("b"),
      });
      const dup = await store.appendMessage(t1, msg(c.id, "k1", { content_hash: H("c") }));
      expect(dup.inserted).toBe(false);
      expect(dup.message.id).toBe(a.message.id);
      expect(dup.message.content_hash).toBe(H("a")); // the original stands
      expect((await store.appendMessage(t1, msg(c.id, "k1", { direction: "out" }))).inserted).toBe(
        true,
      );
      expect((await store.appendMessage(t1, msg(c.id, "k1", { channel: "sms" }))).inserted).toBe(
        true,
      );
      await store.appendMessage(t1, msg(c.id, "k2"));
      expect((await store.messages(t1, c.id)).map((m) => m.idempotency_key)).toEqual([
        "k1",
        "k1",
        "k1",
        "k2",
      ]);
      expect(await store.messages(t1, c.id, 2)).toHaveLength(2);
      expect(await store.messages(t2, c.id)).toEqual([]);
      await expect(store.appendMessage(t2, msg(c.id, "x"))).rejects.toMatchObject({
        code: "NOT_FOUND",
      });
      await expect(store.appendMessage(t1, msg(randomUUID(), "x"))).rejects.toMatchObject({
        code: "NOT_FOUND",
      });
    });
  });
}
