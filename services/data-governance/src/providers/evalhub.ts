import type { ClientBase } from "pg";
import { governedTx, type PgGovOptions } from "../store.js";
import type {
  CountResult,
  EraseResult,
  ExportCollection,
  FindResult,
  Identifier,
  ProviderContext,
  ProviderDeclaration,
  PurgeRequest,
  PurgeResult,
  SubjectDataProvider,
} from "../types.js";
import { SUBJECT_KINDS, vals } from "./util.js";

interface Case {
  id: string;
  input: unknown;
  expected: unknown;
  tags: string[];
  metadata: Record<string, unknown>;
}
interface CaseResult {
  case_id: string;
  output: string | null;
  error: string | null;
  trace: unknown;
  [k: string]: unknown;
}
type DocRow = { key: string; rev: number; data: Record<string, unknown> };

const ERASED = { governance: "erased" };

const linked = (c: Case, values: Set<string>): boolean => {
  const s = c.metadata?.["subject_ref"];
  return typeof s === "string" && values.has(s);
};

/**
 * Eval Hub: dataset cases linked to a subject by `metadata.subject_ref` (the documented convention) and the finished runs over those
 * datasets. A case is TOMBSTONED in place (input/expected/tags/metadata replaced) so the dataset version, case ids and counts remain; the
 * dataset's content hash then no longer matches and the hub/runner refuse that version until a new one is ingested (ADR-0082).
 */
export class EvalHubProvider implements SubjectDataProvider {
  readonly id = "eval-hub";
  readonly declaration: ProviderDeclaration = {
    exports: [
      "dataset cases whose metadata.subject_ref is the person",
      "per-case outputs and traces of eval runs over those cases",
    ],
    erases: [
      "input, expected answer, tags and metadata of those cases (tombstoned in place); outputs, errors and traces of the runs' results for those cases",
    ],
    retains: [
      {
        what: "dataset version records, case ids, grades and aggregate scores",
        legalBasis:
          "reproducibility of evaluation evidence; contain no personal data after tombstoning. Stored content/record hashes of the affected versions no longer verify (documented)",
      },
    ],
    pseudonymises: [],
    dataClasses: ["eval_data"],
  };
  constructor(private readonly o: PgGovOptions) {}

  private values(ids: readonly Identifier[]): Set<string> {
    return new Set(vals(ids, ...SUBJECT_KINDS));
  }
  private async docs(c: ClientBase, coll: string): Promise<DocRow[]> {
    return (
      await c.query("SELECT key, rev, data FROM eval_hub_docs WHERE coll = $1 ORDER BY key", [coll])
    ).rows as DocRow[];
  }
  /** dataset ref -> ids of cases linked to the subject (only datasets that still hold such cases). */
  private async hits(c: ClientBase, values: Set<string>): Promise<Map<string, string[]>> {
    const out = new Map<string, string[]>();
    for (const d of await this.docs(c, "datasets")) {
      const cases = (d.data["cases"] as Case[] | undefined) ?? [];
      const ids = cases.filter((x) => linked(x, values)).map((x) => x.id);
      if (ids.length) out.set(d.key, ids);
    }
    return out;
  }

  find(ctx: ProviderContext, ids: readonly Identifier[]): Promise<FindResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => ({
      count: [...(await this.hits(c, this.values(ids))).values()].reduce((a, b) => a + b.length, 0),
    }));
  }

  export(ctx: ProviderContext, ids: readonly Identifier[]): Promise<ExportCollection[]> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const values = this.values(ids);
      const hits = await this.hits(c, values);
      const cases: unknown[] = [];
      for (const d of await this.docs(c, "datasets"))
        for (const x of ((d.data["cases"] as Case[]) ?? []).filter((y) => linked(y, values)))
          cases.push({ dataset: d.key, ...x });
      const results: unknown[] = [];
      for (const r of await this.docs(c, "runs")) {
        const dids = hits.get(String(r.data["dataset_ref"]));
        if (!dids) continue;
        for (const cr of (r.data["case_results"] as CaseResult[]) ?? [])
          if (dids.includes(cr.case_id))
            results.push({
              run: r.key,
              case_id: cr.case_id,
              output: cr.output,
              error: cr.error,
              trace: cr.trace,
            });
      }
      return [
        { name: "dataset_cases", records: cases },
        { name: "run_case_results", records: results },
      ];
    });
  }

  erase(ctx: ProviderContext, ids: readonly Identifier[]): Promise<EraseResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const values = this.values(ids);
      const hits = await this.hits(c, values);
      let n = 0;
      for (const d of await this.docs(c, "datasets")) {
        const hit = hits.get(d.key);
        if (!hit) continue;
        const cases = (d.data["cases"] as Case[]).map((x) =>
          hit.includes(x.id)
            ? {
                ...x,
                input: ERASED,
                expected: null,
                tags: [],
                metadata: { governance_erased: true },
              }
            : x,
        );
        await c.query(
          "UPDATE eval_hub_docs SET data = $4, rev = rev + 1, updated_at = now() WHERE coll = 'datasets' AND key = $1 AND rev = $2 AND tenant_id = $3",
          [d.key, d.rev, ctx.tenantId, JSON.stringify({ ...d.data, cases })],
        );
        n += hit.length;
      }
      for (const r of await this.docs(c, "runs")) {
        const dids = hits.get(String(r.data["dataset_ref"]));
        if (!dids) continue;
        const results = ((r.data["case_results"] as CaseResult[]) ?? []).map((cr) =>
          dids.includes(cr.case_id) ? { ...cr, output: null, error: null, trace: null } : cr,
        );
        await c.query(
          "UPDATE eval_hub_docs SET data = $4, rev = rev + 1, updated_at = now() WHERE coll = 'runs' AND key = $1 AND rev = $2 AND tenant_id = $3",
          [r.key, r.rev, ctx.tenantId, JSON.stringify({ ...r.data, case_results: results })],
        );
      }
      return { erased: n, pseudonymised: 0, retained: 0 };
    });
  }

  async count(ctx: ProviderContext, ids: readonly Identifier[]): Promise<CountResult> {
    const f = await this.find(ctx, ids);
    return { residual: f.count, retained: 0, pseudonymised: 0 };
  }

  async purge(ctx: ProviderContext, req: PurgeRequest): Promise<PurgeResult> {
    const prot = new Set(req.protect.subjects.flatMap((g) => [...this.values(g)]));
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const cutoff = req.olderThan.toISOString();
      const protectedDatasets = new Set((await this.hits(c, prot)).keys());
      let matched = 0;
      let purged = 0;
      let held = 0;
      const final = new Set(["passed", "failed", "errored", "completed"]);
      for (const r of await this.docs(c, "runs")) {
        const created = String(r.data["created_at"] ?? "");
        if (created === "" || created >= cutoff || !final.has(String(r.data["status"]))) continue;
        matched++;
        if (protectedDatasets.has(String(r.data["dataset_ref"]))) {
          held++;
          continue;
        }
        if (!req.dryRun) {
          await c.query(
            "DELETE FROM eval_hub_docs WHERE coll = 'runs' AND key = $1 AND tenant_id = $2",
            [r.key, ctx.tenantId],
          );
          purged++;
        }
      }
      return { matched, purged, protectedByHold: held };
    });
  }
}
