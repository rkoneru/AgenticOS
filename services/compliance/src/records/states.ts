import { invalid } from "../errors.js";
import type { AssessmentRecord, AssessmentState } from "../types.js";

export type AssessmentEvent = "submit" | "withdraw" | "approve" | "reject";

const TRANSITIONS: Record<AssessmentState, Partial<Record<AssessmentEvent, AssessmentState>>> = {
  draft: { submit: "in_review" },
  in_review: { approve: "approved", reject: "rejected", withdraw: "draft" },
  approved: {},
  rejected: {},
};

/** The review state machine. Approved and rejected are final for a version: a change is a NEW version. */
export function nextState(state: AssessmentState, event: AssessmentEvent): AssessmentState {
  const to = TRANSITIONS[state]?.[event];
  if (to === undefined) throw invalid(`cannot ${event} an assessment that is ${String(state)}`);
  return to;
}

export const isFinal = (s: AssessmentState): boolean => s === "approved" || s === "rejected";

/** Why `reviewer` may not review this version (null = may). The author and every contributor are excluded. */
export function reviewerConflict(
  a: Pick<AssessmentRecord, "author" | "contributors" | "submitted_by">,
  reviewer: string,
): string | null {
  if (a.author === reviewer) return "reviewer is the author";
  if (a.contributors.includes(reviewer)) return "reviewer contributed to this version";
  if (a.submitted_by === reviewer) return "reviewer submitted this version";
  return null;
}

export type OverdueReason = "review_due_passed" | "review_pending_too_long" | null;

/** Overdue detection (derived at read time): approved past its review date, or waiting for a reviewer beyond the grace period. */
export function overdueReason(
  a: Pick<AssessmentRecord, "state" | "review_due" | "submitted_at">,
  now: Date,
  graceMs: number,
): OverdueReason {
  if (a.state === "approved" && Date.parse(`${a.review_due}T23:59:59.999Z`) < now.getTime())
    return "review_due_passed";
  if (
    a.state === "in_review" &&
    a.submitted_at !== null &&
    now.getTime() - Date.parse(a.submitted_at) > graceMs
  )
    return "review_pending_too_long";
  return null;
}
