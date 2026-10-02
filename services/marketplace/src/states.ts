import { RegistryError } from "@axis/registry";

/** Publisher verification: unverified -> pending -> verified | rejected; a rejected publisher may resubmit; a verified one may be suspended by moderation. */
export const VERIFICATION_STATES = ["unverified", "pending", "verified", "rejected"] as const;
export type VerificationState = (typeof VERIFICATION_STATES)[number];

const VERIFICATION_EDGES: Readonly<Record<VerificationState, readonly VerificationState[]>> = {
  unverified: ["pending"],
  pending: ["verified", "rejected"],
  verified: ["rejected"], // suspension by moderation
  rejected: ["pending"], // resubmission
};

/** Security review: submitted -> automated_scan -> in_review -> approved | rejected | changes_requested. The last three are terminal. */
export const REVIEW_STATES = [
  "submitted",
  "automated_scan",
  "in_review",
  "approved",
  "rejected",
  "changes_requested",
] as const;
export type ReviewState = (typeof REVIEW_STATES)[number];

const REVIEW_EDGES: Readonly<Record<ReviewState, readonly ReviewState[]>> = {
  submitted: ["automated_scan"],
  // The scan may reject outright (does not compile / critical secrets) or, only when policy allows, approve low-risk blueprints.
  automated_scan: ["in_review", "approved", "rejected"],
  in_review: ["approved", "rejected", "changes_requested"],
  approved: [],
  rejected: [],
  changes_requested: [],
};

export const isTerminalReview = (s: ReviewState): boolean => REVIEW_EDGES[s].length === 0;

export function canVerify(from: VerificationState, to: VerificationState): boolean {
  return VERIFICATION_EDGES[from]?.includes(to) ?? false;
}
export function canReview(from: ReviewState, to: ReviewState): boolean {
  return REVIEW_EDGES[from]?.includes(to) ?? false;
}

export function assertVerify(from: VerificationState, to: VerificationState): void {
  if (!canVerify(from, to))
    throw new RegistryError("conflict", `illegal publisher transition ${from} -> ${to}`);
}
export function assertReview(from: ReviewState, to: ReviewState): void {
  if (!canReview(from, to))
    throw new RegistryError("conflict", `illegal review transition ${from} -> ${to}`);
}
