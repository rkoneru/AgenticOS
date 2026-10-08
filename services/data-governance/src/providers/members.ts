import { GovernanceError } from "../types.js";
import { governedTx, type PgGovOptions } from "../store.js";
import type {
  CountResult,
  EraseResult,
  ExportCollection,
  FindResult,
  Identifier,
  ProviderContext,
  ProviderDeclaration,
  SubjectDataProvider,
} from "../types.js";
import { iso, vals } from "./util.js";

const ERASED_DOMAIN = "@erased.invalid";

/**
 * Control-plane members (employee subjects). Erasure is DEPROVISIONING plus scrubbing the identifying columns: the row, its opaque
 * `user_ref` and role history stay so admin actions in the audit chain keep a stable (now unidentifiable) actor id. The sole active
 * owner cannot be erased (it would orphan the tenant).
 */
export class MembersProvider implements SubjectDataProvider {
  readonly id = "control-plane-members";
  readonly declaration: ProviderDeclaration = {
    exports: ["member record: user_ref, email, display name, role, status, timestamps"],
    erases: [
      "email, display name, directory external id; sessions are revoked, API keys owned by the member are revoked",
    ],
    retains: [
      {
        what: "the member row with its opaque user_ref, role and deprovisioning timestamp",
        legalBasis:
          "GDPR Art. 17(3)(e)/Art. 6(1)(f): accountability of administrative actions; user_ref is an opaque IdP id and is unlinkable once the email is scrubbed",
      },
    ],
    pseudonymises: ["email becomes a keyed token at the reserved .invalid domain"],
    dataClasses: ["audit"],
  };
  constructor(private readonly o: PgGovOptions) {}

  private match = `(lower(email) = ANY($1) OR user_ref = ANY($2) OR external_id = ANY($2))`;
  private params(ids: readonly Identifier[]): [string[], string[]] {
    return [vals(ids, "email").map((e) => e.toLowerCase()), vals(ids, "user_ref", "subject_key")];
  }

  find(ctx: ProviderContext, ids: readonly Identifier[]): Promise<FindResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const { rows } = await c.query(
        `SELECT user_ref, email FROM members WHERE ${this.match}`,
        this.params(ids),
      );
      const discovered: Identifier[] = [];
      for (const r of rows as { user_ref: string; email: string }[]) {
        discovered.push({ kind: "user_ref", value: r.user_ref });
        if (!r.email.endsWith(ERASED_DOMAIN)) discovered.push({ kind: "email", value: r.email });
      }
      return { count: rows.length, discovered };
    });
  }

  export(ctx: ProviderContext, ids: readonly Identifier[]): Promise<ExportCollection[]> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const { rows } = await c.query(
        `SELECT id, user_ref, email, display_name, role, status, external_id, created_at, deprovisioned_at FROM members WHERE ${this.match} ORDER BY id`,
        this.params(ids),
      );
      return [
        {
          name: "members",
          records: rows.map((r) => ({
            ...r,
            created_at: iso(r.created_at),
            deprovisioned_at: iso(r.deprovisioned_at),
          })),
        },
      ];
    });
  }

  erase(ctx: ProviderContext, ids: readonly Identifier[]): Promise<EraseResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const { rows } = await c.query(
        `SELECT id, user_ref, email, role, status, display_name, external_id FROM members WHERE ${this.match} FOR UPDATE`,
        this.params(ids),
      );
      let erased = 0;
      for (const m of rows as {
        id: string;
        user_ref: string;
        email: string;
        role: string;
        status: string;
        display_name: string | null;
        external_id: string | null;
      }[]) {
        const already =
          m.email.endsWith(ERASED_DOMAIN) &&
          m.display_name === null &&
          m.external_id === null &&
          m.status === "deprovisioned";
        if (!already && m.role === "owner" && m.status === "active") {
          const o = await c.query(
            "SELECT count(*) n FROM members WHERE role = 'owner' AND status = 'active' AND id <> $1",
            [m.id],
          );
          if (Number((o.rows[0] as { n: string }).n) === 0)
            throw new GovernanceError(
              "conflict",
              "cannot erase the sole active owner; transfer ownership first",
            );
        }
        const tok = await ctx.pseudonym("user_ref", m.user_ref);
        await c.query(
          `UPDATE members SET email = $2, display_name = NULL, external_id = NULL, status = 'deprovisioned',
             deprovisioned_at = COALESCE(deprovisioned_at, $3), updated_at = $3 WHERE id = $1`,
          [m.id, `${tok}${ERASED_DOMAIN}`, ctx.now],
        );
        await c.query(
          "UPDATE sessions SET revoked_at = $2, revoked_reason = 'dsar_erasure' WHERE member_id = $1 AND revoked_at IS NULL",
          [m.id, ctx.now],
        );
        await c.query(
          "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, $2), name = 'revoked (owner erased)' WHERE owner_member_id = $1 OR created_by = $1",
          [m.id, ctx.now],
        );
        if (!already) erased++;
      }
      return { erased: 0, pseudonymised: erased, retained: rows.length };
    });
  }

  count(ctx: ProviderContext, ids: readonly Identifier[]): Promise<CountResult> {
    return governedTx(this.o, ctx.tenantId, async (c) => {
      const p = this.params(ids);
      const q = async (sql: string): Promise<number> =>
        Number(((await c.query(sql, p)).rows[0] as { n: string }).n);
      const dirty = await q(
        `SELECT count(*) n FROM members WHERE ${this.match} AND NOT (email LIKE '%${ERASED_DOMAIN}' AND display_name IS NULL AND external_id IS NULL AND status = 'deprovisioned')`,
      );
      const live = await q(
        `SELECT count(*) n FROM sessions WHERE revoked_at IS NULL AND member_id IN (SELECT id FROM members WHERE ${this.match})`,
      );
      const kept = await q(
        `SELECT count(*) n FROM members WHERE ${this.match} AND email LIKE '%${ERASED_DOMAIN}'`,
      );
      return { residual: dirty + live, retained: kept, pseudonymised: kept };
    });
  }
}
