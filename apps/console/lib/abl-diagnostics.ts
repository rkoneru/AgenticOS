/**
 * Live ABL validation. Runs on the server (the ABL package reads its JSON Schema from disk), exposed
 * through `app/api/abl/validate`. Turns schema issues and lint findings into editor markers with
 * 1-based line/column positions by walking the YAML AST.
 */
import { Document, LineCounter, isNode, parseDocument, type Node } from "yaml";

export interface Diagnostic {
  line: number;
  column: number;
  severity: "error" | "warning";
  message: string;
  code: string;
  path: string;
}

export interface AblCheck {
  ok: boolean;
  diagnostics: Diagnostic[];
  /** Parsed document (only when the YAML parsed and passed the schema), for publishing. */
  doc?: Record<string, unknown>;
  riskLevel?: string;
  name?: string;
  version?: string;
}

export interface AblEngine {
  validateAbl(
    doc: unknown,
  ):
    | { ok: true; doc: unknown }
    | { ok: false; issues: Array<{ path: string; keyword: string; message: string }> };
  lintAbl(
    doc: unknown,
  ): Array<{ code: string; severity: "error" | "warning"; path: string; message: string }>;
}

export const MAX_ABL_BYTES = 256 * 1024;

const unescapePointer = (s: string): string => s.replace(/~1/g, "/").replace(/~0/g, "~");

export function pointerToPath(p: string): Array<string | number> {
  if (p === "" || p === "/") return [];
  return p
    .split("/")
    .slice(1)
    .map(unescapePointer)
    .map((seg) => (/^(0|[1-9]\d*)$/.test(seg) ? Number(seg) : seg));
}

function position(
  doc: Document,
  lc: LineCounter,
  path: Array<string | number>,
): { line: number; column: number } {
  // Walk as deep as the document goes; a missing property is reported at its deepest existing parent.
  for (let n = path.length; n >= 0; n--) {
    const node = n === 0 ? doc.contents : doc.getIn(path.slice(0, n), true);
    if (isNode(node) && node.range) {
      const { line, col } = lc.linePos((node as Node).range![0]);
      return { line, column: col };
    }
  }
  return { line: 1, column: 1 };
}

export function checkAbl(text: string, engine: AblEngine): AblCheck {
  if (new TextEncoder().encode(text).length > MAX_ABL_BYTES) {
    return {
      ok: false,
      diagnostics: [
        {
          line: 1,
          column: 1,
          severity: "error",
          message: "Document is larger than 256 KiB",
          code: "too_large",
          path: "/",
        },
      ],
    };
  }
  const lc = new LineCounter();
  const doc = parseDocument(text, { lineCounter: lc, prettyErrors: false });
  const diagnostics: Diagnostic[] = [];
  for (const e of doc.errors) {
    const p = e.linePos?.[0];
    diagnostics.push({
      line: p?.line ?? 1,
      column: p?.col ?? 1,
      severity: "error",
      message: e.message.split("\n")[0] ?? "YAML error",
      code: `yaml.${e.code}`,
      path: "/",
    });
  }
  if (doc.errors.length > 0) return { ok: false, diagnostics };

  const js: unknown = doc.toJS();
  const v = engine.validateAbl(js);
  if (!v.ok) {
    for (const i of v.issues) {
      const pos = position(doc, lc, pointerToPath(i.path));
      diagnostics.push({
        ...pos,
        severity: "error",
        message: `${i.path === "/" ? "" : `${i.path}: `}${i.message}`,
        code: `schema.${i.keyword}`,
        path: i.path,
      });
    }
    return { ok: false, diagnostics };
  }
  for (const f of engine.lintAbl(js)) {
    const pos = position(doc, lc, pointerToPath(f.path));
    diagnostics.push({
      ...pos,
      severity: f.severity,
      message: f.message,
      code: f.code,
      path: f.path,
    });
  }
  const meta = js as {
    metadata?: { name?: string; version?: string };
    spec?: { riskClassification?: { level?: string } };
  };
  const ok = !diagnostics.some((d) => d.severity === "error");
  const out: AblCheck = { ok, diagnostics };
  if (ok) out.doc = js as Record<string, unknown>;
  const level = meta.spec?.riskClassification?.level;
  if (level) out.riskLevel = level;
  if (meta.metadata?.name) out.name = meta.metadata.name;
  if (meta.metadata?.version) out.version = String(meta.metadata.version);
  return out;
}

export const STARTER_ABL = `apiVersion: abl.axis.dev/v1
kind: Agent
metadata:
  name: hello-agent
  version: 1.0.0
spec:
  riskClassification:
    level: minimal
    rationale: Answers general product questions; no decisions about people.
  model:
    primary: { provider: anthropic, model: claude-sonnet-5-5 }
  instructions:
    system: You are a helpful assistant.
`;
