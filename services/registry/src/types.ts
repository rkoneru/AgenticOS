export const NAME_RE = /^[a-z][a-z0-9-]{1,62}$/;
export const NAMESPACE_RE = /^[a-z][a-z0-9-]{1,62}$/;

/** Namespaces only the platform may hold; a tenant can never claim them. */
export const RESERVED_NAMESPACES: readonly string[] = [
  "axis",
  "official",
  "system",
  "public",
  "marketplace",
  "registry",
  "admin",
  "root",
  "internal",
  "security",
  "support",
  "verified",
  "std",
  "core",
];

/** Who is calling. The tenant comes from the credential, never from a request body. Roles are the control plane's. */
export interface TenantPrincipal {
  kind: "tenant";
  tenantId: string;
  subject: string;
  role: "owner" | "admin" | "builder" | "operator" | "auditor" | "billing" | "viewer";
}

/** The marketplace service (public namespaces, takedowns) or the Eval Hub (attestations) acting for the platform. Never producible from an HTTP credential. */
export interface PlatformPrincipal {
  kind: "platform";
  subject: string;
  service: "marketplace" | "eval-hub";
}

export type Principal = TenantPrincipal | PlatformPrincipal;

/** Read context: a tenant, or anonymous (`null`: public namespaces only). */
export interface Viewer {
  tenantId: string | null;
}

export interface NamespaceRecord {
  namespace: string;
  tenantId: string;
  normalized: string;
  createdAt: Date;
  createdBy: string;
  public: boolean;
}

export type RevokeReason = "retired" | "compromised";

export interface PublisherKey {
  namespace: string;
  keyId: string;
  tenantId: string;
  /** base64url of the raw 32-byte Ed25519 public key. */
  publicKey: string;
  validFrom: Date;
  validUntil: Date | null;
  revokedAt: Date | null;
  revokeReason: RevokeReason | null;
  createdAt: Date;
  createdBy: string;
}

export interface BlueprintSignature {
  keyId: string;
  /** ISO-8601, as claimed by the signer. Bound into the signed message. */
  signedAt: string;
  /** base64url Ed25519 signature (64 bytes). */
  sig: string;
}

/** DSSE envelope carrying an in-toto style statement. */
export interface DsseEnvelope {
  payloadType: string;
  /** base64 (standard alphabet) of the canonical JSON statement. */
  payload: string;
  signatures: { keyid: string; sig: string }[];
}

export interface VersionRecord {
  namespace: string;
  name: string;
  version: string;
  tenantId: string;
  /** Canonical JSON text of the ABL document: the exact bytes that were hashed. */
  abl: string;
  contentHash: string;
  riskLevel: "minimal" | "limited" | "high";
  signature: BlueprintSignature;
  provenance: DsseEnvelope;
  publishedAt: Date;
  publishedBy: string;
}

/** A signed Eval Hub summary of one finished eval run, attached to the version it is about (append-only). */
export interface EvalAttestationRecord {
  tenantId: string;
  namespace: string;
  name: string;
  version: string;
  runId: string;
  suiteRef: string;
  contentHash: string;
  overall: number;
  envelope: DsseEnvelope;
  attachedAt: Date;
  attachedBy: string;
}

export type EventKind = "yank" | "deprecate";

export interface VersionEvent {
  namespace: string;
  name: string;
  version: string;
  tenantId: string;
  kind: EventKind;
  reason: string;
  actor: string;
  at: Date;
}

export type VersionState = "active" | "deprecated" | "yanked";

export interface VersionStatus {
  state: VersionState;
  reason: string | null;
  at: Date | null;
}

/** A version with its status, as the store returns it. */
export interface VersionRow {
  record: VersionRecord;
  status: VersionStatus;
}

/** Status of a version given its events in order (latest decides; a yank is never undone by a later deprecation). */
export function statusOf(events: readonly VersionEvent[]): VersionStatus {
  let cur: VersionStatus = { state: "active", reason: null, at: null };
  for (const e of events) {
    if (cur.state === "yanked") break;
    cur = { state: e.kind === "yank" ? "yanked" : "deprecated", reason: e.reason, at: e.at };
  }
  return cur;
}

/**
 * Lower-cased, hyphens removed, look-alike characters folded (i/l/1, o/0, rn/m, vv/w, 3/e, ...): two names with the same value are
 * confusable, and the registry refuses the second one.
 */
export function normalizeName(s: string): string {
  const fold: Record<string, string> = {
    "0": "o",
    "1": "l",
    i: "l",
    "5": "s",
    "3": "e",
    "4": "a",
    "7": "t",
    "8": "b",
  };
  return s
    .toLowerCase()
    .replaceAll("-", "")
    .replaceAll("rn", "m")
    .replaceAll("vv", "w")
    .replace(/[01i53478]/g, (c) => fold[c] ?? c);
}
