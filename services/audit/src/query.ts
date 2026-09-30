import { AuditValidationError } from "./errors.js";
import { assertSeq } from "./chain.js";
import type { ListQuery } from "./types.js";

export const MAX_LIST_LIMIT = 10_000;
export const TRACE_RE = /^[0-9a-f]{32}$/;

export function assertListQuery(q: ListQuery): void {
  if (!Number.isSafeInteger(q.limit) || q.limit < 1 || q.limit > MAX_LIST_LIMIT) {
    throw new RangeError(`limit must be an integer in 1..${MAX_LIST_LIMIT}`);
  }
  assertSeq("fromSeq", q.fromSeq);
  if (q.traceId !== undefined && !TRACE_RE.test(q.traceId)) {
    throw new AuditValidationError("traceId must be 32 lowercase hex characters");
  }
}
