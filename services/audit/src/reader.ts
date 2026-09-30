// Read-only surface for AGIL (invariant 2: AGIL reads the audit log and never writes to it or governs).
// This module must stay free of write capabilities; test/reader.architecture.test.ts enforces that.
import type { AuditReader } from "./types.js";

/**
 * Wrap any source of events in an object that exposes `listEvents` and nothing else. The returned object is frozen and
 * holds no reference to the underlying store reachable by callers (the source is captured in a closure).
 */
export function createAuditReader(source: AuditReader): AuditReader {
  return Object.freeze({
    listEvents: (...args: Parameters<AuditReader["listEvents"]>) => source.listEvents(...args),
  });
}
