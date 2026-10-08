import type { Hold } from "./store.js";
import type { DataClass, Identifier, Protection } from "./types.js";

export interface SealedGroups {
  groups: Identifier[][];
}

const covers = (h: Hold, cls: DataClass): boolean =>
  h.dataClasses === null || h.dataClasses.includes(cls);
const active = (h: Hold): boolean => h.kind === "legal_hold" && h.releasedAt === null;

/** A hold that freezes a whole class: tenant scope, or a case hold that names no subjects. */
export function classWideHold(holds: readonly Hold[], cls: DataClass): Hold | undefined {
  return holds.find(
    (h) =>
      active(h) &&
      covers(h, cls) &&
      (h.scope === "tenant" || (h.scope === "case" && h.sealedIdentifiers === null)),
  );
}

/** Active holds that cover `cls` for subject-scoped / case-with-subjects holds (the caller opens the sealed groups). */
export function subjectScopedHolds(holds: readonly Hold[], cls: DataClass): Hold[] {
  return holds.filter(
    (h) =>
      active(h) &&
      covers(h, cls) &&
      (h.scope === "subject" || (h.scope === "case" && h.sealedIdentifiers !== null)),
  );
}

export const sameIdentifier = (a: Identifier, b: Identifier): boolean =>
  a.kind === b.kind && a.value === b.value;

/** Do two identifier sets describe overlapping people? */
export const overlaps = (a: readonly Identifier[], b: readonly Identifier[]): boolean =>
  a.some((x) => b.some((y) => sameIdentifier(x, y)));

export function toProtection(groups: Identifier[][]): Protection {
  return { subjects: groups };
}
