import { parse } from "yaml";

export const STATUSES = ["Built", "Prototype", "Designed", "Gap"] as const;
export type Status = (typeof STATUSES)[number];

export const EVIDENCE_KINDS = ["test", "make", "doc", "file", "audit_query"] as const;
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];

/** Evidence that RUNS or QUERIES something. A row may be `Built` only with at least one of these. */
export const EXECUTABLE_KINDS: readonly EvidenceKind[] = ["test", "make", "audit_query"];

export interface Evidence {
  kind: EvidenceKind;
  /** `path`, `path#needle` (the needle must appear in the file), or a make target for `make`. */
  ref: string;
}

export interface Row {
  id: string;
  requirement: string;
  mechanism: string;
  code: string[];
  config: string[];
  evidence: Evidence[];
  status: Status;
  notes: string;
}

export interface Framework {
  framework: string;
  title: string;
  version: number;
  /** Paraphrased scope statement; labelling rules apply to it too. */
  scope: string;
  rows: Row[];
}

export interface SchemaProblem {
  framework: string;
  row: string | null;
  message: string;
}

const isObj = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const FIELD_KEYS = new Set([
  "id",
  "requirement",
  "mechanism",
  "code",
  "config",
  "evidence",
  "status",
  "notes",
]);

/** Parses and shape-checks one matrix file. Never throws: every problem is returned. Unknown keys are problems (typos must not hide). */
export function parseFramework(
  text: string,
  fileName: string,
): { framework: Framework | null; problems: SchemaProblem[] } {
  const problems: SchemaProblem[] = [];
  const add = (row: string | null, message: string): void => {
    problems.push({ framework: fileName, row, message });
  };
  let raw: unknown;
  try {
    raw = parse(text);
  } catch (e) {
    add(null, `YAML does not parse: ${(e as Error).message.split("\n")[0] ?? ""}`);
    return { framework: null, problems };
  }
  if (!isObj(raw)) {
    add(null, "the file must be a YAML mapping");
    return { framework: null, problems };
  }
  for (const k of Object.keys(raw))
    if (!["framework", "title", "version", "scope", "rows"].includes(k)) add(null, `unknown key ${k}`);
  const str = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";
  if (!str(raw["framework"])) add(null, "framework must be a non-empty string");
  if (!str(raw["title"])) add(null, "title must be a non-empty string");
  if (!str(raw["scope"])) add(null, "scope must be a non-empty string");
  if (!Number.isInteger(raw["version"])) add(null, "version must be an integer");
  if (!Array.isArray(raw["rows"]) || raw["rows"].length === 0) {
    add(null, "rows must be a non-empty list");
    return { framework: null, problems };
  }
  const rows: Row[] = [];
  raw["rows"].forEach((r: unknown, i: number) => {
    if (!isObj(r)) {
      add(`#${i}`, "row must be a mapping");
      return;
    }
    const id = str(r["id"]) ? r["id"] : `#${i}`;
    if (!str(r["id"])) add(id, "id must be a non-empty string");
    for (const k of Object.keys(r)) if (!FIELD_KEYS.has(k)) add(id, `unknown key ${k}`);
    for (const k of ["requirement", "mechanism", "notes"])
      if (!str(r[k])) add(id, `${k} must be a non-empty string`);
    const strList = (k: string): string[] => {
      const v = r[k];
      if (!Array.isArray(v) || !v.every(str)) {
        add(id, `${k} must be a list of non-empty strings`);
        return [];
      }
      return v as string[];
    };
    const code = strList("code");
    const config = strList("config");
    const evidence: Evidence[] = [];
    if (!Array.isArray(r["evidence"])) add(id, "evidence must be a list");
    else
      r["evidence"].forEach((e: unknown, j: number) => {
        if (
          !isObj(e) ||
          !(EVIDENCE_KINDS as readonly string[]).includes(e["kind"] as string) ||
          !str(e["ref"])
        ) {
          add(id, `evidence #${j} must be {kind: ${EVIDENCE_KINDS.join("|")}, ref: string}`);
          return;
        }
        for (const k of Object.keys(e)) if (k !== "kind" && k !== "ref") add(id, `evidence #${j}: unknown key ${k}`);
        evidence.push({ kind: e["kind"] as EvidenceKind, ref: e["ref"] as string });
      });
    if (!(STATUSES as readonly string[]).includes(r["status"] as string))
      add(id, `status must be one of ${STATUSES.join(", ")}`);
    rows.push({
      id,
      requirement: String(r["requirement"] ?? ""),
      mechanism: String(r["mechanism"] ?? ""),
      code,
      config,
      evidence,
      status: (STATUSES as readonly string[]).includes(r["status"] as string)
        ? (r["status"] as Status)
        : "Gap",
      notes: String(r["notes"] ?? ""),
    });
  });
  if (problems.length > 0) return { framework: null, problems };
  return {
    framework: {
      framework: raw["framework"] as string,
      title: raw["title"] as string,
      version: raw["version"] as number,
      scope: raw["scope"] as string,
      rows,
    },
    problems,
  };
}
