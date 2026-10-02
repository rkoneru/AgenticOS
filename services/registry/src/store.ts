import type {
  EventKind,
  NamespaceRecord,
  PublisherKey,
  RevokeReason,
  VersionEvent,
  VersionRecord,
  VersionRow,
  Viewer,
} from "./types.js";

export class StoreConflict extends Error {
  constructor(
    readonly what:
      "namespace" | "namespace_confusable" | "name_confusable" | "version" | "key" | "key_state",
    message: string,
  ) {
    super(message);
  }
}
/** The write was for a row the tenant does not own (what RLS WITH CHECK enforces in Postgres). */
export class StoreForbidden extends Error {}

/**
 * Persistence port. Reads take a `Viewer` (a tenant, or anonymous): they see the viewer's own namespaces and public namespaces, and
 * nothing else. Writes take the OWNER tenant explicitly. There is deliberately no delete and no update of a version.
 * Implementations: MemoryRegistryStore (reference), PgRegistryStore (forced RLS); one contract suite runs against both.
 */
export interface RegistryStore {
  claimNamespace(n: Omit<NamespaceRecord, "public">): Promise<NamespaceRecord>;
  getNamespace(viewer: Viewer, namespace: string): Promise<NamespaceRecord | undefined>;
  /** Existence + owner, regardless of visibility (names are global). Used for ownership decisions. */
  ownerOf(namespace: string): Promise<string | undefined>;
  listNamespaces(tenantId: string): Promise<NamespaceRecord[]>;
  /** Idempotent. Only the owner tenant's context may do this; the SERVICE restricts it to the marketplace. */
  setPublic(tenantId: string, namespace: string, listedBy: string, at: Date): Promise<void>;
  listPublicNamespaces(): Promise<NamespaceRecord[]>;

  addKey(key: PublisherKey): Promise<void>;
  getKeys(viewer: Viewer, namespace: string): Promise<PublisherKey[]>;
  /** Sets validUntil (rotation) and/or the revocation; each may only go from unset to set. */
  updateKey(
    tenantId: string,
    namespace: string,
    keyId: string,
    patch: { validUntil?: Date; revoke?: { at: Date; reason: RevokeReason } },
  ): Promise<PublisherKey>;

  /** Inserts the name (typosquat-checked) when new, then the version. Throws StoreConflict on an existing version. */
  insertVersion(rec: VersionRecord, normalizedName: string): Promise<void>;
  getVersion(
    viewer: Viewer,
    ns: string,
    name: string,
    version: string,
  ): Promise<VersionRow | undefined>;
  listVersions(viewer: Viewer, ns: string, name: string): Promise<VersionRow[]>;
  listNames(viewer: Viewer, ns: string): Promise<string[]>;
  appendEvent(e: VersionEvent): Promise<void>;
  events(viewer: Viewer, ns: string, name: string, version: string): Promise<VersionEvent[]>;
}

export type { EventKind };
