import { StoreConflict, StoreForbidden, type RegistryStore } from "./store.js";
import {
  statusOf,
  type EvalAttestationRecord,
  type NamespaceRecord,
  type PublisherKey,
  type RevokeReason,
  type VersionEvent,
  type VersionRecord,
  type VersionRow,
  type Viewer,
} from "./types.js";

const k = (...p: string[]): string => p.join("\u0000");

/** Reference implementation of the port: same visibility, ownership and immutability rules as the Postgres store + RLS. */
export class MemoryRegistryStore implements RegistryStore {
  private ns = new Map<string, NamespaceRecord>();
  private pub = new Set<string>();
  private pubVersions = new Set<string>(); // ns\0name\0version
  private keys = new Map<string, PublisherKey>();
  private names = new Map<string, { tenantId: string; normalized: string }>(); // ns\0name
  private versions = new Map<string, VersionRecord>();
  private evs: VersionEvent[] = [];
  private atts: EvalAttestationRecord[] = [];

  private visible(viewer: Viewer, namespace: string, owner: string): boolean {
    return this.pub.has(namespace) || (viewer.tenantId !== null && viewer.tenantId === owner);
  }
  private versionVisible(viewer: Viewer, r: VersionRecord): boolean {
    return (
      (viewer.tenantId !== null && viewer.tenantId === r.tenantId) ||
      this.pubVersions.has(k(r.namespace, r.name, r.version))
    );
  }
  private nsOf(namespace: string): NamespaceRecord | undefined {
    const n = this.ns.get(namespace);
    return n ? { ...n, public: this.pub.has(namespace) } : undefined;
  }

  claimNamespace(n: Omit<NamespaceRecord, "public">): Promise<NamespaceRecord> {
    if (this.ns.has(n.namespace))
      return Promise.reject(new StoreConflict("namespace", "namespace taken"));
    for (const o of this.ns.values())
      if (o.normalized === n.normalized)
        return Promise.reject(
          new StoreConflict("namespace_confusable", "namespace is confusable with an existing one"),
        );
    this.ns.set(n.namespace, { ...n, public: false });
    return Promise.resolve({ ...n, public: false });
  }
  getNamespace(viewer: Viewer, namespace: string): Promise<NamespaceRecord | undefined> {
    const n = this.nsOf(namespace);
    // Names are global, but a namespace's record is shown to its owner and (when public) to everyone.
    return Promise.resolve(n && this.visible(viewer, namespace, n.tenantId) ? n : undefined);
  }
  ownerOf(namespace: string): Promise<string | undefined> {
    return Promise.resolve(this.ns.get(namespace)?.tenantId);
  }
  listNamespaces(tenantId: string): Promise<NamespaceRecord[]> {
    return Promise.resolve(
      [...this.ns.values()]
        .filter((n) => n.tenantId === tenantId)
        .map((n) => this.nsOf(n.namespace) as NamespaceRecord),
    );
  }
  setPublic(tenantId: string, namespace: string): Promise<void> {
    const n = this.ns.get(namespace);
    if (!n || n.tenantId !== tenantId)
      return Promise.reject(new StoreForbidden("not the namespace owner"));
    this.pub.add(namespace);
    return Promise.resolve();
  }
  setVersionPublic(
    tenantId: string,
    namespace: string,
    name: string,
    version: string,
  ): Promise<void> {
    const rec = this.versions.get(k(namespace, name, version));
    if (!rec || rec.tenantId !== tenantId)
      return Promise.reject(new StoreForbidden("not the version owner"));
    this.pubVersions.add(k(namespace, name, version));
    return Promise.resolve();
  }
  listPublicNamespaces(): Promise<NamespaceRecord[]> {
    return Promise.resolve([...this.pub].map((p) => this.nsOf(p) as NamespaceRecord));
  }

  addKey(key: PublisherKey): Promise<void> {
    const n = this.ns.get(key.namespace);
    if (!n || n.tenantId !== key.tenantId)
      return Promise.reject(new StoreForbidden("not the namespace owner"));
    const id = k(key.namespace, key.keyId);
    if (this.keys.has(id))
      return Promise.reject(new StoreConflict("key", "key already registered"));
    this.keys.set(id, { ...key });
    return Promise.resolve();
  }
  getKeys(viewer: Viewer, namespace: string): Promise<PublisherKey[]> {
    const n = this.ns.get(namespace);
    if (!n || !this.visible(viewer, namespace, n.tenantId)) return Promise.resolve([]);
    return Promise.resolve(
      [...this.keys.values()].filter((x) => x.namespace === namespace).map((x) => ({ ...x })),
    );
  }
  updateKey(
    tenantId: string,
    namespace: string,
    keyId: string,
    patch: { validUntil?: Date; revoke?: { at: Date; reason: RevokeReason } },
  ): Promise<PublisherKey> {
    const key = this.keys.get(k(namespace, keyId));
    if (!key || key.tenantId !== tenantId)
      return Promise.reject(new StoreForbidden("not the key owner"));
    if (patch.validUntil) {
      if (key.validUntil)
        return Promise.reject(new StoreConflict("key_state", "key validity end is already set"));
      if (patch.validUntil.getTime() <= key.validFrom.getTime())
        return Promise.reject(new StoreConflict("key_state", "validity end must follow its start"));
      key.validUntil = patch.validUntil;
    }
    if (patch.revoke) {
      if (key.revokedAt)
        return Promise.reject(new StoreConflict("key_state", "key is already revoked"));
      key.revokedAt = patch.revoke.at;
      key.revokeReason = patch.revoke.reason;
    }
    return Promise.resolve({ ...key });
  }

  insertVersion(rec: VersionRecord, normalizedName: string): Promise<void> {
    const n = this.ns.get(rec.namespace);
    if (!n || n.tenantId !== rec.tenantId)
      return Promise.reject(new StoreForbidden("not the namespace owner"));
    const nk = k(rec.namespace, rec.name);
    if (!this.names.has(nk)) {
      for (const [key, v] of this.names)
        if (key.startsWith(rec.namespace + "\u0000") && v.normalized === normalizedName)
          return Promise.reject(
            new StoreConflict("name_confusable", "name is confusable with an existing blueprint"),
          );
      this.names.set(nk, { tenantId: rec.tenantId, normalized: normalizedName });
    }
    const vk = k(rec.namespace, rec.name, rec.version);
    if (this.versions.has(vk))
      return Promise.reject(new StoreConflict("version", "version already published"));
    this.versions.set(vk, { ...rec });
    return Promise.resolve();
  }
  private row(rec: VersionRecord): VersionRow {
    return {
      record: { ...rec },
      status: statusOf(
        this.evs.filter(
          (e) => e.namespace === rec.namespace && e.name === rec.name && e.version === rec.version,
        ),
      ),
    };
  }
  getVersion(
    viewer: Viewer,
    ns: string,
    name: string,
    version: string,
  ): Promise<VersionRow | undefined> {
    const rec = this.versions.get(k(ns, name, version));
    return Promise.resolve(rec && this.versionVisible(viewer, rec) ? this.row(rec) : undefined);
  }
  listVersions(viewer: Viewer, ns: string, name: string): Promise<VersionRow[]> {
    return Promise.resolve(
      [...this.versions.values()]
        .filter((r) => r.namespace === ns && r.name === name && this.versionVisible(viewer, r))
        .map((r) => this.row(r)),
    );
  }
  listNames(viewer: Viewer, ns: string): Promise<string[]> {
    const out: string[] = [];
    for (const [key, v] of this.names) {
      const [n, name] = key.split("\u0000") as [string, string];
      const released = [...this.pubVersions].some((p) => p.startsWith(`${ns}\u0000${name}\u0000`));
      if (n === ns && ((viewer.tenantId !== null && viewer.tenantId === v.tenantId) || released))
        out.push(name);
    }
    return Promise.resolve(out.sort());
  }
  addAttestation(a: EvalAttestationRecord): Promise<void> {
    const rec = this.versions.get(k(a.namespace, a.name, a.version));
    if (!rec || rec.tenantId !== a.tenantId)
      return Promise.reject(new StoreForbidden("not the version owner"));
    if (this.atts.some((x) => x.namespace === a.namespace && x.name === a.name && x.version === a.version && x.runId === a.runId))
      return Promise.reject(new StoreConflict("version", "attestation exists for this run"));
    this.atts.push(structuredClone(a));
    return Promise.resolve();
  }
  attestations(viewer: Viewer, ns: string, name: string, version: string): Promise<EvalAttestationRecord[]> {
    const rec = this.versions.get(k(ns, name, version));
    if (!rec || !this.versionVisible(viewer, rec)) return Promise.resolve([]);
    return Promise.resolve(
      this.atts
        .filter((a) => a.namespace === ns && a.name === name && a.version === version)
        .map((a) => structuredClone(a)),
    );
  }
  appendEvent(e: VersionEvent): Promise<void> {
    const rec = this.versions.get(k(e.namespace, e.name, e.version));
    if (!rec || rec.tenantId !== e.tenantId)
      return Promise.reject(new StoreForbidden("not the version owner"));
    this.evs.push({ ...e });
    return Promise.resolve();
  }
  events(viewer: Viewer, ns: string, name: string, version: string): Promise<VersionEvent[]> {
    const rec = this.versions.get(k(ns, name, version));
    if (!rec || !this.versionVisible(viewer, rec)) return Promise.resolve([]);
    return Promise.resolve(
      this.evs.filter((e) => e.namespace === ns && e.name === name && e.version === version),
    );
  }
}
