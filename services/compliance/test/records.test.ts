import { describe, expect, it } from "vitest";
import {
  isFinal,
  nextState,
  overdueReason,
  reviewerConflict,
  type AssessmentState,
} from "../src/index.js";
import { DAY, T1, T2, input, user, world } from "./helpers.js";

const owner = user(T1, "owner", "olivia");
const builder = user(T1, "builder", "bob");
const auditor = user(T1, "auditor", "alice");
const admin = user(T1, "admin", "adam");

describe("review state machine", () => {
  it("allows exactly the documented transitions", () => {
    const table: [
      AssessmentState,
      "submit" | "withdraw" | "approve" | "reject",
      AssessmentState,
    ][] = [
      ["draft", "submit", "in_review"],
      ["in_review", "approve", "approved"],
      ["in_review", "reject", "rejected"],
      ["in_review", "withdraw", "draft"],
    ];
    for (const [from, ev, to] of table) expect(nextState(from, ev)).toBe(to);
    const all: AssessmentState[] = ["draft", "in_review", "approved", "rejected"];
    const events = ["submit", "withdraw", "approve", "reject"] as const;
    for (const s of all)
      for (const e of events) {
        const ok = table.some(([f, ev]) => f === s && ev === e);
        if (!ok) expect(() => nextState(s, e), `${s} ${e}`).toThrow(/cannot/);
      }
    expect(isFinal("approved") && isFinal("rejected")).toBe(true);
    expect(isFinal("draft") || isFinal("in_review")).toBe(false);
  });

  it("excludes the author, contributors and the submitter from review", () => {
    const a = { author: "a", contributors: ["a", "c"], submitted_by: "s" };
    expect(reviewerConflict(a, "a")).toMatch(/author/);
    expect(reviewerConflict(a, "c")).toMatch(/contributed/);
    expect(reviewerConflict(a, "s")).toMatch(/submitted/);
    expect(reviewerConflict(a, "r")).toBeNull();
  });

  it("detects overdue approved assessments and slow reviews", () => {
    const now = new Date("2026-03-01T00:00:00Z");
    const approved = (due: string) => ({
      state: "approved" as const,
      review_due: due,
      submitted_at: null,
    });
    expect(overdueReason(approved("2026-02-28"), now, DAY)).toBe("review_due_passed");
    expect(overdueReason(approved("2026-03-01"), now, DAY)).toBeNull(); // the whole due day counts
    expect(overdueReason(approved("2026-03-02"), now, DAY)).toBeNull();
    const pending = (at: string | null) => ({
      state: "in_review" as const,
      review_due: "2030-01-01",
      submitted_at: at,
    });
    expect(overdueReason(pending("2026-02-01T00:00:00Z"), now, 14 * DAY)).toBe(
      "review_pending_too_long",
    );
    expect(overdueReason(pending("2026-02-27T00:00:00Z"), now, 14 * DAY)).toBeNull();
    expect(overdueReason(pending(null), now, 14 * DAY)).toBeNull();
    expect(
      overdueReason({ state: "draft", review_due: "2000-01-01", submitted_at: null }, now, DAY),
    ).toBeNull();
    expect(
      overdueReason({ state: "rejected", review_due: "2000-01-01", submitted_at: null }, now, DAY),
    ).toBeNull();
  });
});

describe("AI system inventory", () => {
  it("creates, versions and lists records; history keeps every version", async () => {
    const w = world();
    const s = await w.svc.systems.create(builder, input.system({ system_id: "claims-triage" }));
    expect(s).toMatchObject({
      system_id: "claims-triage",
      version: 1,
      lifecycle_stage: "design",
      created_by: "bob",
    });
    w.clock.advance(DAY);
    const s2 = await w.svc.systems.update(admin, "claims-triage", 1, {
      lifecycle_stage: "deployed",
      risk_level: "limited",
    });
    expect(s2).toMatchObject({
      version: 2,
      lifecycle_stage: "deployed",
      risk_level: "limited",
      updated_by: "adam",
      created_by: "bob",
    });
    expect((await w.svc.systems.get(builder, "claims-triage")).version).toBe(2);
    expect((await w.svc.systems.get(builder, "claims-triage", 1)).lifecycle_stage).toBe("design");
    expect((await w.svc.systems.history(builder, "claims-triage")).map((x) => x.version)).toEqual([
      1, 2,
    ]);
    expect((await w.svc.systems.list(builder, { risk_level: "limited" })).length).toBe(1);
    expect((await w.svc.systems.list(builder, { lifecycle_stage: "design" })).length).toBe(0);
    expect((await w.svc.systems.list(builder)).length).toBe(1);
    // retire instead of delete
    const r = await w.svc.systems.update(admin, "claims-triage", 2, { lifecycle_stage: "retired" });
    expect(r.lifecycle_stage).toBe("retired");
  });

  it("generates ids, rejects bad input with paths, stale versions, duplicates and unknown ids", async () => {
    const w = world();
    const s = await w.svc.systems.create(builder, input.system());
    expect(s.system_id).toMatch(/^sys-[0-9a-f]{12}$/);
    await expect(
      w.svc.systems.create(builder, input.system({ system_id: "Bad Id" })),
    ).rejects.toMatchObject({
      code: "invalid",
      checks: ["/system_id"],
    });
    await expect(
      w.svc.systems.create(
        builder,
        input.system({
          name: "",
          risk_level: "extreme",
          blueprints: [{ name: "X", version: "1" }],
        }),
      ),
    ).rejects.toMatchObject({
      code: "invalid",
      checks: expect.arrayContaining([
        "/name",
        "/risk_level",
        "/blueprints/0/name",
        "/blueprints/0/version",
      ]),
    });
    await expect(w.svc.systems.create(builder, null as never)).rejects.toMatchObject({
      code: "invalid",
    });
    await w.svc.systems.create(builder, input.system({ system_id: "dup-one" }));
    await expect(
      w.svc.systems.create(builder, input.system({ system_id: "dup-one" })),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(w.svc.systems.update(builder, s.system_id, 5, {})).rejects.toMatchObject({
      code: "conflict",
    });
    await expect(w.svc.systems.update(builder, "nope-nope", 1, {})).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(w.svc.systems.get(builder, "nope-nope")).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(w.svc.systems.get(builder, s.system_id, 9)).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(
      w.svc.systems.update(builder, s.system_id, 1, { risk_level: "x" as never }),
    ).rejects.toMatchObject({ code: "invalid" });
  });

  it("validates lists, stakeholders and text lengths", async () => {
    const w = world();
    const tooMany = Array.from({ length: 101 }, (_, i) => `c${i}`);
    await expect(
      w.svc.systems.create(builder, input.system({ data_categories: tooMany })),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(
      w.svc.systems.create(builder, input.system({ stakeholders: [{ role: "r" }, 5] })),
    ).rejects.toMatchObject({
      checks: expect.arrayContaining(["/stakeholders/0/name", "/stakeholders/1"]),
    });
    await expect(
      w.svc.systems.create(builder, input.system({ purpose: "x".repeat(4001) })),
    ).rejects.toMatchObject({ checks: ["/purpose"] });
    await expect(
      w.svc.systems.create(builder, input.system({ blueprints: [5] })),
    ).rejects.toMatchObject({ checks: ["/blueprints/0"] });
    await expect(
      w.svc.systems.create(builder, input.system({ data_categories: "x" })),
    ).rejects.toMatchObject({ checks: ["/data_categories"] });
  });

  it("enforces roles and tenancy; every mutation is audited", async () => {
    const w = world();
    await expect(w.svc.systems.create(user(T1, "viewer"), input.system())).rejects.toMatchObject({
      code: "forbidden",
    });
    await expect(w.svc.systems.update(user(T1, "operator"), "x", 1, {})).rejects.toMatchObject({
      code: "forbidden",
    });
    await expect(w.svc.systems.list(user(T1, "billing"))).rejects.toMatchObject({
      code: "forbidden",
    });
    const s = await w.svc.systems.create(builder, input.system({ system_id: "mine-one" }));
    const mallory = user(T2, "owner", "mallory");
    await expect(w.svc.systems.get(mallory, s.system_id)).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(w.svc.systems.update(mallory, s.system_id, 1, {})).rejects.toMatchObject({
      code: "not_found",
    });
    expect(await w.svc.systems.list(mallory)).toEqual([]);
    await w.svc.systems.update(builder, s.system_id, 1, { purpose: "new purpose" });
    const actions = (await w.log.read(T1, {})).map((e) => `${e.action}:${e.decision}`);
    expect(actions).toEqual([
      "compliance.system.create:DENY",
      "compliance.system.update:DENY",
      "compliance.system.create:ALLOW",
      "compliance.system.create.done:ALLOW",
      "compliance.system.update:ALLOW",
      "compliance.system.update.done:ALLOW",
    ]);
    expect((await w.log.read(T2, {})).length).toBe(0);
  });
});

describe("AI impact assessments", () => {
  async function setup() {
    const w = world();
    const sys = await w.svc.systems.create(builder, input.system({ system_id: "claims-triage" }));
    return { w, sys };
  }

  it("runs the whole workflow: draft, submit, approve; reviewed versions are frozen", async () => {
    const { w, sys } = await setup();
    const a = await w.svc.assessments.create(builder, input.assessment(sys.system_id));
    expect(a).toMatchObject({
      version: 1,
      state: "draft",
      author: "bob",
      overdue: false,
      superseded: false,
    });
    const sub = await w.svc.assessments.submit(builder, a.assessment_id, 1);
    expect(sub).toMatchObject({ state: "in_review", submitted_by: "bob" });
    const done = await w.svc.assessments.review(
      auditor,
      a.assessment_id,
      1,
      "approve",
      "reviewed with the DPO",
    );
    expect(done).toMatchObject({
      state: "approved",
      reviewed_by: "alice",
      review_comment: "reviewed with the DPO",
    });
    // frozen: cannot submit/review again
    await expect(w.svc.assessments.submit(builder, a.assessment_id, 1)).rejects.toMatchObject({
      code: "invalid",
    });
    await expect(
      w.svc.assessments.review(owner, a.assessment_id, 1, "approve", ""),
    ).rejects.toMatchObject({ code: "invalid" });
  });

  it("the reviewer is never the author, a contributor or the submitter", async () => {
    const { w, sys } = await setup();
    const a = await w.svc.assessments.create(admin, input.assessment(sys.system_id));
    await w.svc.assessments.revise(owner, a.assessment_id, 1, { title: "edited by owner" });
    await w.svc.assessments.submit(builder, a.assessment_id, 1);
    for (const who of [admin, owner]) {
      await expect(
        w.svc.assessments.review(who, a.assessment_id, 1, "approve", "ok"),
      ).rejects.toMatchObject({
        code: "forbidden",
        message: expect.stringMatching(/review refused/),
      });
    }
    // an auditor who happens to be the submitter is refused as well
    const b = await w.svc.assessments.create(builder, input.assessment(sys.system_id));
    await w.svc.assessments
      .submit(auditor, b.assessment_id, 1)
      .catch((e) => expect(e.code).toBe("forbidden")); // auditors cannot write
    const sub = user(T1, "admin", "sam");
    const c = await w.svc.assessments.create(builder, input.assessment(sys.system_id));
    await w.svc.assessments.submit(sub, c.assessment_id, 1);
    await expect(
      w.svc.assessments.review(sub, c.assessment_id, 1, "approve", "ok"),
    ).rejects.toMatchObject({ code: "forbidden" });
    // the refusals are audited as DENY, nothing was approved
    const denies = (await w.log.read(T1, {})).filter(
      (e) => e.action === "compliance.assessment.review" && e.decision === "DENY",
    );
    expect(denies.length).toBe(3);
    expect((await w.svc.assessments.get(auditor, a.assessment_id)).state).toBe("in_review");
    // an independent reviewer succeeds
    expect(
      (await w.svc.assessments.review(auditor, a.assessment_id, 1, "approve", "ok")).state,
    ).toBe("approved");
  });

  it("rejection needs a comment; a revised version starts a new draft authored by the reviser", async () => {
    const { w, sys } = await setup();
    const a = await w.svc.assessments.create(builder, input.assessment(sys.system_id));
    await w.svc.assessments.submit(builder, a.assessment_id, 1);
    await expect(
      w.svc.assessments.review(auditor, a.assessment_id, 1, "reject", ""),
    ).rejects.toMatchObject({ code: "invalid", checks: ["/comment"] });
    const rej = await w.svc.assessments.review(
      auditor,
      a.assessment_id,
      1,
      "reject",
      "mitigations are missing",
    );
    expect(rej.state).toBe("rejected");
    const v2 = await w.svc.assessments.revise(admin, a.assessment_id, 1, {
      risk_rating: "critical",
    });
    expect(v2).toMatchObject({
      version: 2,
      state: "draft",
      author: "adam",
      supersedes: 1,
      risk_rating: "critical",
      reviewed_by: null,
    });
    expect((await w.svc.assessments.get(builder, a.assessment_id, 1)).superseded).toBe(true);
    expect((await w.svc.assessments.get(builder, a.assessment_id, 1)).state).toBe("rejected");
    expect(
      (await w.svc.assessments.history(builder, a.assessment_id)).map((x) => x.version),
    ).toEqual([1, 2]);
    // bob (author of v1) may review v2: independence is per version
    await w.svc.assessments.submit(admin, a.assessment_id, 2);
    expect((await w.svc.assessments.review(auditor, a.assessment_id, 2, "approve", "")).state).toBe(
      "approved",
    );
  });

  it("drafts are edited in place; a version waiting for review cannot be edited but can be withdrawn", async () => {
    const { w, sys } = await setup();
    const a = await w.svc.assessments.create(builder, input.assessment(sys.system_id));
    const e = await w.svc.assessments.revise(admin, a.assessment_id, 1, { title: "better title" });
    expect(e).toMatchObject({ version: 1, title: "better title", contributors: ["bob", "adam"] });
    await w.svc.assessments.revise(admin, a.assessment_id, 1, { title: "again" });
    expect((await w.svc.assessments.get(admin, a.assessment_id)).contributors).toEqual([
      "bob",
      "adam",
    ]);
    await w.svc.assessments.submit(builder, a.assessment_id, 1);
    await expect(
      w.svc.assessments.revise(builder, a.assessment_id, 1, { title: "x" }),
    ).rejects.toMatchObject({ code: "conflict" });
    const back = await w.svc.assessments.withdraw(builder, a.assessment_id, 1);
    expect(back).toMatchObject({ state: "draft", submitted_by: null });
    await expect(w.svc.assessments.withdraw(builder, a.assessment_id, 1)).rejects.toMatchObject({
      code: "invalid",
    });
  });

  it("stale versions, unknown ids and bad fields are refused", async () => {
    const { w, sys } = await setup();
    const a = await w.svc.assessments.create(builder, input.assessment(sys.system_id));
    await expect(w.svc.assessments.revise(builder, a.assessment_id, 3, {})).rejects.toMatchObject({
      code: "conflict",
    });
    await expect(w.svc.assessments.submit(builder, a.assessment_id, 2)).rejects.toMatchObject({
      code: "conflict",
    });
    await w.svc.assessments.submit(builder, a.assessment_id, 1);
    await expect(
      w.svc.assessments.review(auditor, a.assessment_id, 7, "approve", ""),
    ).rejects.toMatchObject({ code: "conflict" });
    await expect(
      w.svc.assessments.review(auditor, a.assessment_id, 1, "maybe" as never, ""),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(w.svc.assessments.get(builder, "no-such-assessment")).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(w.svc.assessments.get(builder, "../etc")).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(w.svc.assessments.get(builder, a.assessment_id, 9)).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(w.svc.assessments.history(builder, "no-such-assessment")).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(
      w.svc.assessments.create(builder, input.assessment("no-such-system")),
    ).rejects.toMatchObject({ code: "invalid", checks: ["/system_id"] });
    await expect(
      w.svc.assessments.create(
        builder,
        input.assessment(sys.system_id, { review_due: "2026-02-30" }),
      ),
    ).rejects.toMatchObject({ checks: ["/review_due"] });
    await expect(
      w.svc.assessments.create(builder, input.assessment(sys.system_id, { review_due: "soon" })),
    ).rejects.toMatchObject({ checks: ["/review_due"] });
    await expect(
      w.svc.assessments.create(
        builder,
        input.assessment(sys.system_id, { risk_rating: "extreme", intended_use: "" }),
      ),
    ).rejects.toMatchObject({ checks: expect.arrayContaining(["/risk_rating", "/intended_use"]) });
    const r = input.assessment(sys.system_id).risks[0]!;
    await expect(
      w.svc.assessments.create(builder, input.assessment(sys.system_id, { risks: [r, r] })),
    ).rejects.toMatchObject({ checks: ["/risks/1/id"] });
    await expect(
      w.svc.assessments.create(
        builder,
        input.assessment(sys.system_id, {
          risks: [{ id: "x" }, 4],
          affected_groups: [1, { group: "g" }],
        }),
      ),
    ).rejects.toMatchObject({ code: "invalid" });
    await expect(w.svc.assessments.create(builder, undefined as never)).rejects.toMatchObject({
      code: "invalid",
    });
  });

  it("lists the latest version of each assessment with filters and derived overdue flags", async () => {
    const { w, sys } = await setup();
    const sys2 = await w.svc.systems.create(builder, input.system({ system_id: "other-system" }));
    const a = await w.svc.assessments.create(
      builder,
      input.assessment(sys.system_id, { review_due: "2026-03-10" }),
    );
    const b = await w.svc.assessments.create(builder, input.assessment(sys2.system_id));
    await w.svc.assessments.submit(builder, a.assessment_id, 1);
    await w.svc.assessments.review(auditor, a.assessment_id, 1, "approve", "ok");
    await w.svc.assessments.submit(builder, b.assessment_id, 1);
    expect((await w.svc.assessments.list(auditor)).length).toBe(2);
    expect(
      (await w.svc.assessments.list(auditor, { system_id: "other-system" })).map(
        (x) => x.assessment_id,
      ),
    ).toEqual([b.assessment_id]);
    expect(
      (await w.svc.assessments.list(auditor, { state: "approved" })).map((x) => x.assessment_id),
    ).toEqual([a.assessment_id]);
    expect((await w.svc.assessments.list(auditor, { overdue: true })).length).toBe(0);
    w.clock.advance(11 * DAY); // 2026-03-12: a's review date passed; b waited 11 days (< 14)
    expect(
      (await w.svc.assessments.list(auditor, { overdue: true })).map((x) => [
        x.assessment_id,
        x.overdue_reason,
      ]),
    ).toEqual([[a.assessment_id, "review_due_passed"]]);
    w.clock.advance(5 * DAY);
    const od = await w.svc.assessments.list(auditor, { overdue: true });
    expect(od.map((x) => x.overdue_reason).sort()).toEqual([
      "review_due_passed",
      "review_pending_too_long",
    ]);
    expect((await w.svc.assessments.list(auditor, { overdue: false })).length).toBe(0);
    // a newer version replaces the older one in the list, and a superseded version is never overdue
    const v2 = await w.svc.assessments.revise(builder, a.assessment_id, 1, {
      review_due: "2027-01-01",
    });
    const l = await w.svc.assessments.list(auditor, { system_id: sys.system_id });
    expect(l.map((x) => [x.version, x.state, x.overdue])).toEqual([[2, "draft", false]]);
    expect((await w.svc.assessments.get(auditor, a.assessment_id, 1)).overdue).toBe(false);
    expect(v2.version).toBe(2);
  });

  it("is tenant-isolated for every operation", async () => {
    const { w, sys } = await setup();
    const a = await w.svc.assessments.create(builder, input.assessment(sys.system_id));
    const mallory = user(T2, "owner", "mallory");
    const rev = user(T2, "auditor", "rita");
    await expect(w.svc.assessments.get(mallory, a.assessment_id)).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(w.svc.assessments.history(mallory, a.assessment_id)).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(w.svc.assessments.revise(mallory, a.assessment_id, 1, {})).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(w.svc.assessments.submit(mallory, a.assessment_id, 1)).rejects.toMatchObject({
      code: "not_found",
    });
    await w.svc.assessments.submit(builder, a.assessment_id, 1);
    await expect(
      w.svc.assessments.review(rev, a.assessment_id, 1, "approve", ""),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      w.svc.assessments.create(mallory, input.assessment(sys.system_id)),
    ).rejects.toMatchObject({ code: "invalid" }); // the system is not hers
    expect(await w.svc.assessments.list(mallory)).toEqual([]);
    expect((await w.svc.assessments.get(auditor, a.assessment_id)).state).toBe("in_review");
  });

  it("enforces roles: write = owner/admin/builder, review = owner/admin/auditor, read = all but billing", async () => {
    const { w, sys } = await setup();
    const a = await w.svc.assessments.create(builder, input.assessment(sys.system_id));
    for (const role of ["operator", "viewer", "auditor", "billing"]) {
      await expect(
        w.svc.assessments.create(user(T1, role), input.assessment(sys.system_id)),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(
        w.svc.assessments.revise(user(T1, role), a.assessment_id, 1, {}),
      ).rejects.toMatchObject({ code: "forbidden" });
      await expect(
        w.svc.assessments.submit(user(T1, role), a.assessment_id, 1),
      ).rejects.toMatchObject({ code: "forbidden" });
    }
    await w.svc.assessments.submit(builder, a.assessment_id, 1);
    for (const role of ["builder", "operator", "viewer", "billing"])
      await expect(
        w.svc.assessments.review(user(T1, role, `x-${role}`), a.assessment_id, 1, "approve", ""),
      ).rejects.toMatchObject({ code: "forbidden" });
    for (const role of ["owner", "admin", "builder", "operator", "auditor", "viewer"])
      expect((await w.svc.assessments.list(user(T1, role))).length).toBe(1);
    await expect(w.svc.assessments.list(user(T1, "billing"))).rejects.toMatchObject({
      code: "forbidden",
    });
    await expect(
      w.svc.assessments.list({ tenantId: "", subject: "x", role: "owner" }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      w.svc.assessments.list({ tenantId: T1, subject: "", role: "owner" }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(w.svc.assessments.list(null as never)).rejects.toMatchObject({
      code: "forbidden",
    });
  });

  it("records every mutation and every refusal in the tenant's chain with a failure code", async () => {
    const { w, sys } = await setup();
    const a = await w.svc.assessments.create(builder, input.assessment(sys.system_id));
    await w.svc.assessments.submit(builder, a.assessment_id, 1);
    await w.svc.assessments.review(admin, a.assessment_id, 1, "approve", "fine");
    await w.svc.assessments.revise(builder, a.assessment_id, 9, {}).catch(() => undefined); // conflict before mutate: nothing audited
    const rows = (await w.log.read(T1, {})).map((e) => `${e.action}:${e.decision}`);
    expect(rows).toEqual(
      expect.arrayContaining([
        "compliance.assessment.create:ALLOW",
        "compliance.assessment.submit:ALLOW",
        "compliance.assessment.review:ALLOW",
        "compliance.assessment.review.done:ALLOW",
      ]),
    );
    // a store failure inside mutate is audited as DENY with the code
    const failing = world({ docs: w.docs });
    const sysDoc = await w.docs.get(T1, "systems", sys.system_id);
    expect(sysDoc).toBeTruthy();
    // the second world numbers its ids from 1 again, so it collides with the first world's assessment
    await expect(
      failing.svc.assessments.create(builder, input.assessment(sys.system_id)),
    ).rejects.toMatchObject({ code: "conflict" });
    const dup = (await failing.log.read(T1, {})).filter(
      (e) => e.action === "compliance.assessment.create.failed",
    );
    expect(dup.length).toBe(1);
    expect(dup[0]?.reason).toContain("code=conflict");
    // a failed audit append stops the mutation
    const broken = world({ docs: w.docs });
    (broken.log as unknown as { append: () => Promise<never> }).append = () =>
      Promise.reject(new Error("down"));
    await expect(broken.svc.assessments.submit(builder, "x".repeat(8), 1)).rejects.toMatchObject({
      code: "not_found",
    });
    await expect(broken.svc.systems.create(builder, input.system())).rejects.toMatchObject({
      code: "unavailable",
    });
  });
});
