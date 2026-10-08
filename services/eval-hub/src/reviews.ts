import { redactPatterns } from "@axis/channels";
import { requireTenant } from "./authz.js";
import { denyAudit, guarded, iso, mutate, type Ctx } from "./context.js";
import { conflict, forbidden, invalid, notFound } from "./errors.js";
import type { RunService } from "./runs.js";
import { ID_RE, type HubPrincipal, type ReviewTaskDoc, type TenantActor } from "./types.js";

export interface TaskView extends ReviewTaskDoc {
  sla_breached: boolean;
}

const MAX_COMMENT = 2000;

/**
 * Human review queue. Rules (each is a tested safety property):
 *  - the reviewer is NEVER the run's starter or the blueprint's publisher (`conflicts`), checked at list, claim and grade;
 *  - a task is graded by someone who holds a live claim (claims expire, so a stuck reviewer does not block the queue);
 *  - a double-graded task needs two DIFFERENT reviewers; grades within the grader's `agreement_tolerance` resolve to their mean,
 *    grades farther apart need a third, different reviewer whose grade decides;
 *  - the hub sets the human scores itself from resolved tasks; a runner can never submit one;
 *  - every transition is audited; SLA breaches are recorded once (`sweep`) and shown on every view.
 */
export class ReviewService {
  constructor(
    private readonly c: Ctx,
    private readonly runs: RunService,
  ) {}

  private view(t: ReviewTaskDoc): TaskView {
    return {
      ...t,
      sla_breached:
        t.resolution === null && this.c.now().getTime() > new Date(t.sla_deadline).getTime(),
    };
  }

  private blocked(t: ReviewTaskDoc, who: string): string | undefined {
    if (t.conflicts.includes(who))
      return "the starter or publisher of this blueprint cannot review it";
    if (t.skipped_by.includes(who)) return "you skipped this task";
    if (t.grades.some((g) => g.reviewer === who)) return "you already graded this task";
    return undefined;
  }

  /** Tasks the caller may work on (or all, for an admin asking `all`). Conflicted tasks are not even shown to the conflicted person. */
  async list(
    p: HubPrincipal,
    q: { state?: string; run_id?: string; all?: boolean } = {},
  ): Promise<TaskView[]> {
    const t = requireTenant(p, "evals.review");
    const filter: Record<string, string> = {};
    if (q.state) filter["state"] = q.state;
    if (q.run_id) filter["run_id"] = q.run_id;
    const all = (await this.c.docs.find<ReviewTaskDoc>(p.tenantId, "tasks", filter)).map(
      (d) => d.data,
    );
    return all
      .filter(
        (x) =>
          !x.conflicts.includes(t.subject) &&
          (q.all === true || this.blocked(x, t.subject) === undefined),
      )
      .map((x) => this.view(x))
      .sort((a, b) =>
        a.sla_deadline === b.sla_deadline
          ? a.id < b.id
            ? -1
            : 1
          : a.sla_deadline < b.sla_deadline
            ? -1
            : 1,
      );
  }

  async get(p: HubPrincipal, id: string): Promise<TaskView> {
    const t = requireTenant(p, "evals.review");
    const d = await this.load(p.tenantId, id);
    if (d.data.conflicts.includes(t.subject)) throw notFound("task not found");
    return this.view(d.data);
  }

  private async load(tenantId: string, id: string) {
    if (!ID_RE.test(id)) throw notFound("task not found");
    const d = await this.c.docs.get<ReviewTaskDoc>(tenantId, "tasks", id);
    if (!d) throw notFound("task not found");
    return d;
  }

  private claimLive(t: ReviewTaskDoc): boolean {
    return (
      t.claimed_by !== null &&
      t.claim_expires_at !== null &&
      new Date(t.claim_expires_at).getTime() > this.c.now().getTime()
    );
  }

  async claim(p: HubPrincipal, id: string): Promise<TaskView> {
    let who: TenantActor;
    try {
      who = requireTenant(p, "evals.review");
    } catch (e) {
      return denyAudit(this.c, p, "evals.review.claim", e);
    }
    return mutate(this.c, p, "evals.review.claim", { task_id: id }, async () => {
      const d = await this.load(p.tenantId, id);
      const t = d.data;
      const why = this.blocked(t, who.subject);
      if (why !== undefined) throw forbidden(why);
      if (t.state === "resolved") throw conflict("task is resolved");
      if (this.claimLive(t) && t.claimed_by !== who.subject)
        throw conflict("task is claimed by someone else");
      const next: ReviewTaskDoc = {
        ...t,
        state: t.state === "needs_adjudication" ? "needs_adjudication" : "claimed",
        claimed_by: who.subject,
        claim_expires_at: iso(new Date(this.c.now().getTime() + this.c.claimTtlMs)),
      };
      await guarded(() => this.c.docs.update(p.tenantId, "tasks", id, d.rev, next), "review task");
      return this.view(next);
    });
  }

  async grade(
    p: HubPrincipal,
    id: string,
    input: { score: unknown; comment: unknown },
  ): Promise<TaskView> {
    let who: TenantActor;
    try {
      who = requireTenant(p, "evals.review");
    } catch (e) {
      return denyAudit(this.c, p, "evals.review.grade", e);
    }
    const score = input.score;
    if (typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 1)
      throw invalid("score must be a number in [0, 1]", ["score"]);
    const comment = input.comment;
    if (typeof comment !== "string" || comment.trim() === "" || comment.length > MAX_COMMENT)
      throw invalid(`comment must be a string of 1-${MAX_COMMENT} characters`, ["comment"]);
    let resolvedRun: string | undefined;
    const out = await mutate(this.c, p, "evals.review.grade", { task_id: id }, async () => {
      const d = await this.load(p.tenantId, id);
      const t = d.data;
      const why = this.blocked(t, who.subject);
      if (why !== undefined) throw forbidden(why);
      if (t.state === "resolved") throw conflict("task is resolved");
      if (!(t.claimed_by === who.subject && this.claimLive(t)))
        throw conflict("claim the task first (your claim may have expired)");
      const adjudication = t.state === "needs_adjudication";
      const grades = [
        ...t.grades,
        // Reviewers' comments can quote PHI from the case: the persisted comment passes the same net as everything else.
        {
          reviewer: who.subject,
          score,
          comment: redactPatterns(comment),
          at: iso(this.c.now()),
          adjudication,
        },
      ];
      let next: ReviewTaskDoc = { ...t, grades, claimed_by: null, claim_expires_at: null };
      const resolve = (s: number, method: "single" | "agreed" | "adjudicated"): void => {
        next = {
          ...next,
          state: "resolved",
          resolution: { score: Math.round(s * 1e9) / 1e9, method },
          resolved_at: iso(this.c.now()),
        };
      };
      if (adjudication) resolve(score, "adjudicated");
      else if (!t.double_grade) resolve(score, "single");
      else if (grades.length === 1) next = { ...next, state: "open" };
      else {
        const [a, b] = grades as unknown as [{ score: number }, { score: number }];
        if (Math.abs(a.score - b.score) <= t.agreement_tolerance + 1e-12)
          resolve((a.score + b.score) / 2, "agreed");
        else next = { ...next, state: "needs_adjudication" };
      }
      await guarded(() => this.c.docs.update(p.tenantId, "tasks", id, d.rev, next), "review task");
      if (next.state === "resolved") resolvedRun = next.run_id;
      return this.view(next);
    });
    if (resolvedRun !== undefined) await this.runs.humanResolved(p.tenantId, resolvedRun);
    return out;
  }

  /** The claimant gives the task back (not their area, a conflict they did not know of). They are not offered it again. */
  async skip(p: HubPrincipal, id: string, reason: unknown): Promise<TaskView> {
    let who: TenantActor;
    try {
      who = requireTenant(p, "evals.review");
    } catch (e) {
      return denyAudit(this.c, p, "evals.review.skip", e);
    }
    if (typeof reason !== "string" || reason.trim() === "" || reason.length > 500)
      throw invalid("reason must be a string of 1-500 characters", ["reason"]);
    return mutate(this.c, p, "evals.review.skip", { task_id: id }, async () => {
      const d = await this.load(p.tenantId, id);
      const t = d.data;
      if (t.state === "resolved") throw conflict("task is resolved");
      if (t.claimed_by !== who.subject) throw conflict("only the claimant can skip a task");
      const next: ReviewTaskDoc = {
        ...t,
        state: t.state === "needs_adjudication" ? "needs_adjudication" : "open",
        claimed_by: null,
        claim_expires_at: null,
        skipped_by: [...t.skipped_by, who.subject],
      };
      await guarded(() => this.c.docs.update(p.tenantId, "tasks", id, d.rev, next), "review task");
      return this.view(next);
    });
  }

  /** Admin: records (once per task) every unresolved task past its SLA. Returns the ids newly marked. */
  async sweep(p: HubPrincipal): Promise<string[]> {
    try {
      requireTenant(p, "evals.admin");
    } catch (e) {
      return denyAudit(this.c, p, "evals.review.sweep", e);
    }
    return mutate(this.c, p, "evals.review.sweep", {}, async () => {
      const marked: string[] = [];
      const now = this.c.now().getTime();
      for (const d of await this.c.docs.find<ReviewTaskDoc>(p.tenantId, "tasks")) {
        const t = d.data;
        if (
          t.resolution !== null ||
          t.sla_breached_at !== null ||
          now <= new Date(t.sla_deadline).getTime()
        )
          continue;
        await guarded(
          () =>
            this.c.docs.update(p.tenantId, "tasks", t.id, d.rev, {
              ...t,
              sla_breached_at: iso(this.c.now()),
            }),
          "review task",
        );
        await this.c.audit.record({
          tenantId: p.tenantId,
          actor: { type: "system", id: "eval-hub" },
          action: "evals.review.sla_breached",
          decision: "DENY",
          reason: `task=${t.id} run=${t.run_id} deadline=${t.sla_deadline}`,
        });
        marked.push(t.id);
      }
      return marked;
    });
  }
}
