import { describe, expect, it } from "vitest";
import {
  StoreConflict,
  StoreForbidden,
  normalizeName,
  type PublisherKey,
  type RegistryStore,
  type VersionRecord,
} from "../src/index.js";
import { rid } from "./helpers.js";

export interface ContractEnv {
  store: RegistryStore;
  tenants: () => Promise<string>;
}

const T0 = new Date("2026-10-02T12:00:00Z");
const nsRec = (namespace: string, tenantId: string) => ({
  namespace,
  tenantId,
  normalized: normalizeName(namespace),
  createdAt: T0,
  createdBy: "u",
});
const keyRec = (
  namespace: string,
  tenantId: string,
  keyId = "k1-" + "a".repeat(32),
): PublisherKey => ({
  namespace,
  keyId,
  tenantId,
  publicKey: "A".repeat(43),
  validFrom: T0,
  validUntil: null,
  revokedAt: null,
  revokeReason: null,
  createdAt: T0,
  createdBy: "u",
});
const verRec = (
  namespace: string,
  tenantId: string,
  name = "agent-one",
  version = "1.0.0",
): VersionRecord => ({
  namespace,
  name,
  version,
  tenantId,
  abl: '{"x":1}',
  contentHash: "a".repeat(64),
  riskLevel: "minimal",
  signature: { keyId: "k1-" + "a".repeat(32), signedAt: T0.toISOString(), sig: "s" },
  provenance: { payloadType: "t", payload: "p", signatures: [] },
  publishedAt: T0,
  publishedBy: "u",
});

/** The behaviour every RegistryStore must have. Run against the memory store and the Postgres store (forced RLS). */
export function storeContract(name: string, env: () => Promise<ContractEnv>): void {
  describe(`RegistryStore contract: ${name}`, () => {
    const sfx = (): string => rid(6);

    it("namespaces: claim, duplicates, confusables, visibility", async () => {
      const { store, tenants } = await env();
      const [a, b] = [await tenants(), await tenants()];
      const ns = `acme-${sfx()}`;
      const rec = await store.claimNamespace(nsRec(ns, a));
      expect(rec.public).toBe(false);
      await expect(store.claimNamespace(nsRec(ns, b))).rejects.toMatchObject({ what: "namespace" });
      await expect(
        store.claimNamespace({ ...nsRec(`${ns}-2`, b), normalized: rec.normalized }),
      ).rejects.toBeInstanceOf(StoreConflict);
      expect(await store.getNamespace({ tenantId: a }, ns)).toMatchObject({
        namespace: ns,
        tenantId: a,
      });
      expect(await store.getNamespace({ tenantId: b }, ns)).toBeUndefined();
      expect(await store.getNamespace({ tenantId: null }, ns)).toBeUndefined();
      expect(await store.ownerOf(ns)).toBe(a);
      expect(await store.ownerOf("no-such-ns")).toBeUndefined();
      expect((await store.listNamespaces(a)).map((n) => n.namespace)).toContain(ns);
      expect((await store.listNamespaces(b)).map((n) => n.namespace)).not.toContain(ns);
      // only the owner can make it public
      await expect(store.setPublic(b, ns, "m", T0)).rejects.toBeInstanceOf(StoreForbidden);
      await store.setPublic(a, ns, "m", T0);
      await store.setPublic(a, ns, "m", T0); // idempotent
      expect(await store.getNamespace({ tenantId: b }, ns)).toMatchObject({ public: true });
      expect(await store.getNamespace({ tenantId: null }, ns)).toMatchObject({ public: true });
      expect((await store.listPublicNamespaces()).map((n) => n.namespace)).toContain(ns);
    });

    it("keys: owner-only writes, monotonic updates, visibility follows the namespace", async () => {
      const { store, tenants } = await env();
      const [a, b] = [await tenants(), await tenants()];
      const ns = `keys-${sfx()}`;
      await store.claimNamespace(nsRec(ns, a));
      await expect(store.addKey(keyRec(ns, b))).rejects.toBeInstanceOf(StoreForbidden);
      await store.addKey(keyRec(ns, a));
      await expect(store.addKey(keyRec(ns, a))).rejects.toMatchObject({ what: "key" });
      expect(await store.getKeys({ tenantId: a }, ns)).toHaveLength(1);
      expect(await store.getKeys({ tenantId: b }, ns)).toHaveLength(0);
      expect(await store.getKeys({ tenantId: null }, ns)).toHaveLength(0);
      const kid = "k1-" + "a".repeat(32);
      await expect(
        store.updateKey(b, ns, kid, { validUntil: new Date(T0.getTime() + 1000) }),
      ).rejects.toBeInstanceOf(StoreForbidden);
      const rotated = await store.updateKey(a, ns, kid, {
        validUntil: new Date(T0.getTime() + 1000),
      });
      expect(rotated.validUntil).toEqual(new Date(T0.getTime() + 1000));
      await expect(
        store.updateKey(a, ns, kid, { validUntil: new Date(T0.getTime() + 2000) }),
      ).rejects.toMatchObject({ what: "key_state" });
      const revoked = await store.updateKey(a, ns, kid, {
        revoke: { at: T0, reason: "compromised" },
      });
      expect(revoked.revokeReason).toBe("compromised");
      await expect(
        store.updateKey(a, ns, kid, { revoke: { at: T0, reason: "retired" } }),
      ).rejects.toMatchObject({ what: "key_state" });
      const k2 = keyRec(ns, a, "k1-" + "b".repeat(32));
      await store.addKey(k2);
      await expect(store.updateKey(a, ns, k2.keyId, { validUntil: T0 })).rejects.toMatchObject({
        what: "key_state",
      }); // end must follow start
      await store.setPublic(a, ns, "m", T0);
      expect(await store.getKeys({ tenantId: b }, ns)).toHaveLength(2);
      expect(await store.getKeys({ tenantId: null }, ns)).toHaveLength(2);
    });

    it("versions: immutable, typosquat-guarded names, isolated, events decide status", async () => {
      const { store, tenants } = await env();
      const [a, b] = [await tenants(), await tenants()];
      const ns = `vers-${sfx()}`;
      await store.claimNamespace(nsRec(ns, a));
      const v1 = verRec(ns, a);
      await expect(store.insertVersion(verRec(ns, b), "agentone")).rejects.toBeInstanceOf(
        StoreForbidden,
      );
      await store.insertVersion(v1, normalizeName(v1.name));
      await expect(
        store.insertVersion({ ...v1, abl: '{"x":2}' }, normalizeName(v1.name)),
      ).rejects.toMatchObject({ what: "version" });
      await store.insertVersion({ ...v1, version: "1.1.0" }, normalizeName(v1.name)); // same name: fine
      await expect(
        store.insertVersion(verRec(ns, a, "agentone"), normalizeName("agentone")),
      ).rejects.toMatchObject({ what: "name_confusable" });
      await store.insertVersion(verRec(ns, a, "agent-two"), normalizeName("agent-two"));
      expect(await store.listNames({ tenantId: a }, ns)).toEqual(["agent-one", "agent-two"]);
      expect(await store.listNames({ tenantId: b }, ns)).toEqual([]);

      expect(
        (await store.getVersion({ tenantId: a }, ns, "agent-one", "1.0.0"))?.record,
      ).toMatchObject({ abl: '{"x":1}', contentHash: "a".repeat(64), publishedAt: T0 });
      expect(await store.getVersion({ tenantId: b }, ns, "agent-one", "1.0.0")).toBeUndefined();
      expect(await store.getVersion({ tenantId: null }, ns, "agent-one", "1.0.0")).toBeUndefined();
      expect(await store.listVersions({ tenantId: b }, ns, "agent-one")).toEqual([]);
      expect(await store.listVersions({ tenantId: a }, ns, "agent-one")).toHaveLength(2);

      const ev = (kind: "yank" | "deprecate", reason: string, tenantId = a) => ({
        namespace: ns,
        name: "agent-one",
        version: "1.0.0",
        tenantId,
        kind,
        reason,
        actor: "u",
        at: T0,
      });
      await expect(store.appendEvent(ev("yank", "bad", b))).rejects.toBeInstanceOf(StoreForbidden);
      await store.appendEvent(ev("deprecate", "old"));
      expect(
        (await store.getVersion({ tenantId: a }, ns, "agent-one", "1.0.0"))?.status,
      ).toMatchObject({ state: "deprecated", reason: "old" });
      await store.appendEvent(ev("yank", "broken"));
      await store.appendEvent(ev("deprecate", "later"));
      expect(
        (await store.getVersion({ tenantId: a }, ns, "agent-one", "1.0.0"))?.status,
      ).toMatchObject({ state: "yanked", reason: "broken" });
      expect(await store.events({ tenantId: a }, ns, "agent-one", "1.0.0")).toHaveLength(3);
      expect(await store.events({ tenantId: b }, ns, "agent-one", "1.0.0")).toEqual([]);

      await store.setPublic(a, ns, "m", T0);
      expect(await store.getVersion({ tenantId: b }, ns, "agent-one", "1.0.0")).toBeDefined();
      expect(await store.listVersions({ tenantId: null }, ns, "agent-one")).toHaveLength(2);
      expect(await store.listNames({ tenantId: null }, ns)).toEqual(["agent-one", "agent-two"]);
      expect(await store.events({ tenantId: null }, ns, "agent-one", "1.0.0")).toHaveLength(3);
      // still not writable by others
      await expect(
        store.insertVersion(verRec(ns, b, "agent-three"), "agentthree"),
      ).rejects.toBeInstanceOf(StoreForbidden);
    });
  });
}
