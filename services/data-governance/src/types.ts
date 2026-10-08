/** Data classes the retention engine knows (docs/spec/data-governance.md section 4). */
export const DATA_CLASSES = [
  "conversation",
  "memory",
  "run_logs",
  "transcripts",
  "eval_data",
  "telemetry",
  "billing",
  "audit",
] as const;
export type DataClass = (typeof DATA_CLASSES)[number];
export const isDataClass = (v: unknown): v is DataClass =>
  typeof v === "string" && (DATA_CLASSES as readonly string[]).includes(v);

/** Identifier kinds a requester can supply or a provider can discover. */
export const IDENTIFIER_KINDS = [
  "email",
  "phone",
  "user_ref", // WorkOS / IdP user id (control-plane members, approvals, memory authors)
  "end_user_id", // channels end user
  "channel_identity", // "<channel>:<external_id>"
  "subject_key", // free subject key used by memory / eval / run input (`subject`)
  "billing_customer",
] as const;
export type IdentifierKind = (typeof IDENTIFIER_KINDS)[number];

export interface Identifier {
  kind: IdentifierKind;
  value: string;
}

export class GovernanceError extends Error {
  constructor(
    readonly code:
      | "forbidden"
      | "not_found"
      | "invalid"
      | "conflict"
      | "not_verified"
      | "residency"
      | "held"
      | "residual_data"
      | "restricted"
      | "unavailable",
    message: string,
  ) {
    super(message);
    this.name = "GovernanceError";
  }
}

/** The caller. Authentication happens upstream; the roles are the tenant's own. */
export interface Principal {
  tenantId: string;
  id: string;
  roles: readonly string[];
}
export const PRIVACY_OFFICER = "privacy_officer";

export interface ProviderContext {
  tenantId: string;
  now: Date;
  /** Keyed pseudonyms for retained rows: (kind, value) -> stable opaque token, unlinkable after the subject is shredded. */
  pseudonym: (kind: string, value: string) => Promise<string>;
}

export interface RetainedItem {
  what: string;
  legalBasis: string;
}

/** What a store holds about a subject and what governance may do with it. Rendered into the manifest and the spec. */
export interface ProviderDeclaration {
  /** Plain-language list of what is included in an export. */
  exports: string[];
  /** What is deleted (or irreversibly scrubbed) on erasure. */
  erases: string[];
  /** What must be kept, with the legal basis. Counted as `retained`, never as residual. */
  retains: RetainedItem[];
  /** What is kept but with the subject reference replaced by a keyed pseudonym. */
  pseudonymises: string[];
  dataClasses: DataClass[];
}

export interface FindResult {
  count: number;
  /** Extra identifiers of the same person this store knows (e.g. the end user behind a channel identity). */
  discovered?: Identifier[];
}

export interface ExportCollection {
  name: string;
  records: unknown[];
}

export interface EraseResult {
  erased: number;
  pseudonymised: number;
  retained: number;
}

export interface CountResult {
  /** Identifiable subject data still present that governance should have removed. Must be 0 after erase. */
  residual: number;
  /** Declared-retained rows (see `declaration.retains`). */
  retained: number;
  /** Rows kept with a pseudonym in place of the subject. */
  pseudonymised: number;
}

export interface Protection {
  /** Identifiers of subjects under legal hold: rows linked to them must not be purged. */
  subjects: Identifier[][];
}

export interface PurgeRequest {
  dataClass: DataClass;
  olderThan: Date;
  dryRun: boolean;
  protect: Protection;
}
export interface PurgeResult {
  matched: number;
  purged: number;
  protectedByHold: number;
}

/**
 * One per store that can hold subject data. Every call is for ONE tenant; an implementation must never touch another tenant
 * (Postgres providers run in a tenant-scoped transaction under forced RLS, so a bug cannot widen the scope).
 */
export interface SubjectDataProvider {
  readonly id: string;
  readonly declaration: ProviderDeclaration;
  find(ctx: ProviderContext, ids: readonly Identifier[]): Promise<FindResult>;
  export(ctx: ProviderContext, ids: readonly Identifier[]): Promise<ExportCollection[]>;
  /** Idempotent: a second call with nothing left returns zeros. */
  erase(ctx: ProviderContext, ids: readonly Identifier[]): Promise<EraseResult>;
  count(ctx: ProviderContext, ids: readonly Identifier[]): Promise<CountResult>;
  /** Retention purge for the classes in `declaration.dataClasses`. Absent when the store has nothing to purge. */
  purge?(ctx: ProviderContext, req: PurgeRequest): Promise<PurgeResult>;
}

export const norm = (id: Identifier): string => {
  const v = id.value.normalize("NFKC").trim();
  switch (id.kind) {
    case "email":
      return v.toLowerCase();
    case "phone":
      return v.replace(/[^0-9+]/g, "");
    case "end_user_id":
      return v.toLowerCase();
    default:
      return v;
  }
};

export function normalizeIds(ids: readonly Identifier[]): Identifier[] {
  const seen = new Set<string>();
  const out: Identifier[] = [];
  for (const i of ids) {
    if (!(IDENTIFIER_KINDS as readonly string[]).includes(i.kind))
      throw new GovernanceError("invalid", `unknown identifier kind ${String(i.kind)}`);
    const value = norm(i);
    if (value === "" || value.length > 512)
      throw new GovernanceError("invalid", "identifier must be 1..512 characters");
    const k = `${i.kind}\u0000${value}`;
    if (!seen.has(k)) {
      seen.add(k);
      out.push({ kind: i.kind, value });
    }
  }
  return out.sort((a, b) => (a.kind + a.value < b.kind + b.value ? -1 : 1));
}

export const valuesOf = (ids: readonly Identifier[], ...kinds: IdentifierKind[]): string[] =>
  ids.filter((i) => kinds.includes(i.kind)).map((i) => i.value);
