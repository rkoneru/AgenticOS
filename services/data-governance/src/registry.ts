import { randomUUID } from "node:crypto";
import type { GovernanceAudit } from "./audit.js";
import { requireOfficer } from "./authz.js";
import { overlaps, type SealedGroups } from "./holds.js";
import { Sealer } from "./keys.js";
import type { GovernanceStore, Hold, HoldKind, HoldScope } from "./store.js";
import {
  GovernanceError,
  isDataClass,
  normalizeIds,
  type DataClass,
  type Identifier,
  type Principal,
} from "./types.js";
import type { Pseudonymiser } from "./keys.js";
import { resolveSubject } from "./subjects.js";

export interface PlaceHoldInput {
  scope: HoldScope;
  reason: string;
  /** null/undefined = every class. */
  dataClasses?: readonly DataClass[] | undefined;
  caseRef?: string | undefined;
  /** subject scope: exactly one person's identifiers. case scope: zero (class-wide) or more groups. */
  groups?: readonly (readonly Identifier[])[] | undefined;
}

/** Legal holds and restrictions (Art. 18). Identifiers are sealed; audit events carry only subject refs. */
export class HoldRegistry {
  constructor(
    private readonly d: {
      store: GovernanceStore;
      pseudo: Pseudonymiser;
      sealer: Sealer;
      audit: GovernanceAudit;
      now: () => Date;
    },
  ) {}

  private async place(p: Principal, kind: HoldKind, i: PlaceHoldInput): Promise<Hold> {
    requireOfficer(p, p.tenantId);
    const t = p.tenantId;
    if (i.reason.trim().length < 3 || i.reason.length > 500)
      throw new GovernanceError("invalid", "reason must be 3..500 characters");
    for (const c of i.dataClasses ?? [])
      if (!isDataClass(c)) throw new GovernanceError("invalid", `unknown data class ${String(c)}`);
    const groups = (i.groups ?? []).map((g) => normalizeIds(g));
    if (kind === "restriction" && i.scope !== "subject")
      throw new GovernanceError("invalid", "a restriction is subject-scoped");
    if (i.scope === "subject" && groups.length !== 1)
      throw new GovernanceError("invalid", "a subject hold names exactly one subject");
    if (i.scope === "tenant" && groups.length > 0)
      throw new GovernanceError("invalid", "a tenant hold names no subjects");
    if (i.scope === "case" && (i.caseRef === undefined || i.caseRef.trim() === ""))
      throw new GovernanceError("invalid", "a case hold needs a case reference");
    let subjectId: string | null = null;
    let subjectRef: string | null = null;
    if (i.scope === "subject") {
      subjectId = (await resolveSubject(this.d.store, this.d.pseudo, t, groups[0] as Identifier[]))
        .subjectId;
      subjectRef = await this.d.pseudo.subjectRef(t, subjectId);
    }
    const id = randomUUID();
    const raw = groups.flat().map((x) => x.value);
    await this.d.audit.emit({
      tenantId: t,
      action: kind === "legal_hold" ? "governance.hold.placed" : "governance.restriction.placed",
      actorId: p.id,
      reason: `scope=${i.scope}`,
      input: {
        hold_id: id,
        scope: i.scope,
        subject_ref: subjectRef,
        case_ref: i.caseRef ?? null,
        classes: i.dataClasses ?? "all",
      },
      raw,
    });
    const hold: Hold = {
      tenantId: t,
      id,
      kind,
      scope: i.scope,
      subjectId,
      caseRef: i.caseRef ?? null,
      dataClasses: i.dataClasses ? [...i.dataClasses] : null,
      reason: i.reason,
      sealedIdentifiers: groups.length
        ? await this.d.sealer.seal(t, { groups } satisfies SealedGroups)
        : null,
      placedBy: p.id,
      placedAt: this.d.now(),
      releasedBy: null,
      releasedAt: null,
    };
    await this.d.store.insertHold(hold);
    return hold;
  }

  placeHold(p: Principal, i: PlaceHoldInput): Promise<Hold> {
    return this.place(p, "legal_hold", i);
  }
  restrict(p: Principal, identifiers: readonly Identifier[], reason: string): Promise<Hold> {
    return this.place(p, "restriction", { scope: "subject", reason, groups: [identifiers] });
  }

  async release(p: Principal, holdId: string): Promise<Hold> {
    requireOfficer(p, p.tenantId);
    const h = await this.d.store.getHold(p.tenantId, holdId);
    if (!h) throw new GovernanceError("not_found", "hold not found");
    if (h.releasedAt !== null) return h;
    await this.d.audit.emit({
      tenantId: p.tenantId,
      action:
        h.kind === "legal_hold" ? "governance.hold.released" : "governance.restriction.lifted",
      actorId: p.id,
      input: { hold_id: h.id, scope: h.scope },
    });
    return this.d.store.releaseHold(p.tenantId, holdId, p.id, this.d.now());
  }

  async list(p: Principal, activeOnly = true): Promise<Hold[]> {
    requireOfficer(p, p.tenantId);
    return this.d.store.listHolds(p.tenantId, activeOnly);
  }

  /** Active sealed groups of subject/case holds covering `cls` (opened here; callers never see ciphertext). */
  async activeGroups(
    tenantId: string,
    holds: readonly Hold[],
  ): Promise<Map<string, Identifier[][]>> {
    const out = new Map<string, Identifier[][]>();
    for (const h of holds)
      if (h.sealedIdentifiers)
        out.set(
          h.id,
          (await this.d.sealer.open<SealedGroups>(tenantId, h.sealedIdentifiers)).groups,
        );
    return out;
  }

  /** Is processing of this person restricted (Art. 18)? Used by write paths that must not process a restricted subject. */
  async isRestricted(tenantId: string, ids: readonly Identifier[]): Promise<boolean> {
    const norm = normalizeIds(ids);
    const holds = (await this.d.store.listHolds(tenantId, true)).filter(
      (h) => h.kind === "restriction",
    );
    for (const h of holds) {
      if (!h.sealedIdentifiers) continue;
      const g = (await this.d.sealer.open<SealedGroups>(tenantId, h.sealedIdentifiers)).groups;
      if (g.some((grp) => overlaps(grp, norm))) return true;
    }
    return false;
  }
}
