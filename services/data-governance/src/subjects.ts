import { randomBytes } from "node:crypto";
import type { Pseudonymiser } from "./keys.js";
import type { GovernanceStore } from "./store.js";
import { GovernanceError, type Identifier } from "./types.js";

/**
 * Map a set of identifiers to ONE subject (get-or-create). Identifiers that already belong to two different subjects are refused: the
 * officer must decide whether they are the same person. New identifiers are attached to the found subject.
 */
export async function resolveSubject(
  store: GovernanceStore,
  pseudo: Pseudonymiser,
  tenantId: string,
  ids: readonly Identifier[],
): Promise<{ subjectId: string; created: boolean }> {
  const lookups = await Promise.all(
    ids.map(async (i) => ({ hmac: await pseudo.lookup(tenantId, i), kind: i.kind })),
  );
  const found = await store.findSubjects(
    tenantId,
    lookups.map((l) => l.hmac),
  );
  if (found.length > 1)
    throw new GovernanceError(
      "conflict",
      "identifiers belong to different subjects; resolve manually",
    );
  if (found.length === 1) {
    const subjectId = found[0] as string;
    await store.addLookups(tenantId, subjectId, lookups);
    return { subjectId, created: false };
  }
  return {
    subjectId: await store.createSubject(tenantId, lookups, randomBytes(32)),
    created: true,
  };
}
