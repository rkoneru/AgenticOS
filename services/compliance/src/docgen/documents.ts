import { createHash } from "node:crypto";
import { requireRole, type ComplianceActor } from "../authz.js";
import { denyAudit, guarded, iso, mutate, type Ctx } from "../context.js";
import { invalid, notFound } from "../errors.js";
import type { BlueprintRef } from "../types.js";
import { Problems } from "../records/validate.js";
import { assemble } from "./assemble.js";
import { missing, type Sourced, type SourcePorts } from "./ports.js";
import type { DocSealer } from "./seal.js";
import { sealDocument, verifyDocument, type SealedDocument, type Verification } from "./verify.js";

/** A stored document and the facts a list needs. */
export interface StoredDocument {
  document_id: string;
  blueprint_name: string;
  blueprint_version: string;
  doc_version: number;
  content_hash: string;
  generated_at: string;
  generated_by: string;
  gap_count: number;
  document: SealedDocument;
}

export interface DocumentSummary {
  document_id: string;
  blueprint: BlueprintRef;
  doc_version: number;
  content_hash: string;
  generated_at: string;
  generated_by: string;
  gap_count: number;
  seal: { alg: string; key_id: string };
}

export interface GenerateResult {
  document: SealedDocument;
  /** False when the sources produced exactly the content of the latest stored version: nothing new is stored. */
  created: boolean;
}

const NAME = /^[a-z][a-z0-9-]{1,62}$/;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export const documentIdOf = (tenantId: string, ref: BlueprintRef, n: number): string =>
  `cdoc-${createHash("sha256").update(`${tenantId}\u0000${ref.name}\u0000${ref.version}\u0000${n}`).digest("hex").slice(0, 24)}`;

/** A source that throws is a gap with a fixed reason (the exception text is never copied into the document). */
async function safely<T>(name: string, f: () => Promise<Sourced<T>>): Promise<Sourced<T>> {
  try {
    const r = await f();
    return r.ok ? r : missing(r.reason === "" ? `${name} source unavailable` : r.reason);
  } catch {
    return missing(`${name} source failed`);
  }
}

export class DocumentService {
  constructor(
    private readonly c: Ctx,
    private readonly ports: SourcePorts,
    /** Seals new documents. */
    private readonly sealer: DocSealer,
    /** Keys whose seals still verify (the current one, and retired ones). */
    private readonly trusted: readonly DocSealer[] = [],
  ) {}

  private keys(): readonly DocSealer[] {
    return [this.sealer, ...this.trusted];
  }

  private parseRef(ref: unknown): BlueprintRef {
    const pr = new Problems();
    const o = (typeof ref === "object" && ref !== null ? ref : {}) as Record<string, unknown>;
    const name = typeof o["name"] === "string" && NAME.test(o["name"]) ? o["name"] : (pr.add("/name"), "");
    const version =
      typeof o["version"] === "string" && SEMVER.test(o["version"]) ? o["version"] : (pr.add("/version"), "");
    pr.done("document request");
    return { name, version };
  }

  /**
   * Assembles the Annex IV technical documentation of one blueprint version from the platform's records, seals it, and stores it as the
   * next version (or returns the latest when nothing changed). Every source is read for the CALLER's tenant only.
   */
  async generate(p: ComplianceActor, ref: BlueprintRef): Promise<GenerateResult> {
    try {
      requireRole(p, "compliance.write");
    } catch (e) {
      return denyAudit(this.c, p, "compliance.document.generate", e);
    }
    const r = this.parseRef(ref);
    return mutate(
      this.c,
      p,
      "compliance.document.generate",
      { blueprint: r.name, version: r.version },
      async () => {
        const t = p.tenantId;
        const blueprint = await safely("blueprint", () => this.ports.blueprints.get(t, r));
        const declared = blueprint.ok ? (blueprint.value.abl.spec.evals?.suites ?? []) : [];
        const evals = blueprint.ok
          ? await safely("evals", () =>
              this.ports.evals.evidence(
                t,
                { ...r, content_hash: (blueprint as { ok: true; value: { content_hash: string } }).value.content_hash },
                declared.map((s) => ({ ref: s.ref, threshold: s.threshold })),
              ),
            )
          : missing<never>("evals not read: the blueprint source is unavailable");
        const [policies, audit, limitations] = await Promise.all([
          safely("policies", () => this.ports.policies.activePacks(t)),
          safely("audit", () => this.ports.audit.statistics(t)),
          safely("limitations", () => this.ports.limitations.list(t, r)),
        ]);
        const body = assemble({ ref: r, blueprint, evals, policies, audit, limitations });
        const existing = (
          await this.c.docs.find<StoredDocument>(t, "documents", {
            blueprint_name: r.name,
            blueprint_version: r.version,
          })
        ).sort((a, b) => a.data.doc_version - b.data.doc_version);
        const last = existing[existing.length - 1]?.data;
        const doc = sealDocument(
          {
            body,
            meta: {
              document_id: documentIdOf(t, r, (last?.doc_version ?? 0) + 1),
              tenant_id: t,
              doc_version: (last?.doc_version ?? 0) + 1,
              generated_at: iso(this.c.now()),
              generated_by: p.subject,
            },
          },
          this.sealer,
        );
        if (last && last.content_hash === doc.content_hash)
          return { document: last.document, created: false };
        const stored: StoredDocument = {
          document_id: doc.meta.document_id,
          blueprint_name: r.name,
          blueprint_version: r.version,
          doc_version: doc.meta.doc_version,
          content_hash: doc.content_hash,
          generated_at: doc.meta.generated_at,
          generated_by: p.subject,
          gap_count: body.gaps.length,
          document: doc,
        };
        await guarded(
          () => this.c.docs.insert(t, "documents", doc.meta.document_id, stored),
          "document",
        );
        return { document: doc, created: true };
      },
    );
  }

  /** The stored document and a FRESH verification (hash, markdown, seal) computed on this read. */
  async get(
    p: ComplianceActor,
    id: string,
  ): Promise<{ document: SealedDocument; verification: Verification }> {
    requireRole(p, "compliance.read");
    const d = await this.c.docs.get<StoredDocument>(p.tenantId, "documents", id);
    if (!d) throw notFound("document not found");
    return { document: d.data.document, verification: verifyDocument(d.data.document, this.keys()) };
  }

  async list(
    p: ComplianceActor,
    f: { blueprint_name?: string; blueprint_version?: string } = {},
  ): Promise<DocumentSummary[]> {
    requireRole(p, "compliance.read");
    if (f.blueprint_version !== undefined && f.blueprint_name === undefined)
      throw invalid("list: blueprint_name is required with blueprint_version");
    const rows = await this.c.docs.find<StoredDocument>(p.tenantId, "documents", {
      ...(f.blueprint_name ? { blueprint_name: f.blueprint_name } : {}),
      ...(f.blueprint_version ? { blueprint_version: f.blueprint_version } : {}),
    });
    return rows
      .map((d) => d.data)
      .sort(
        (a, b) =>
          (a.blueprint_name < b.blueprint_name ? -1 : a.blueprint_name > b.blueprint_name ? 1 : 0) ||
          (a.blueprint_version < b.blueprint_version ? -1 : a.blueprint_version > b.blueprint_version ? 1 : 0) ||
          a.doc_version - b.doc_version,
      )
      .map((d) => ({
        document_id: d.document_id,
        blueprint: { name: d.blueprint_name, version: d.blueprint_version },
        doc_version: d.doc_version,
        content_hash: d.content_hash,
        generated_at: d.generated_at,
        generated_by: d.generated_by,
        gap_count: d.gap_count,
        seal: { alg: d.document.seal.alg, key_id: d.document.seal.key_id },
      }));
  }
}
