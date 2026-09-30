import type { Finding } from "./lint.js";
import type { AblIssue } from "./validate.js";

/** JSON pointer (`/spec/tools/0/name`) to a dotted path (`spec.tools[0].name`). The root is `(root)`. */
export function pointerToDotted(pointer: string): string {
  const parts = pointer.split("/").filter((p) => p !== "");
  if (parts.length === 0) return "(root)";
  return parts.reduce(
    (acc, p) => (/^\d+$/.test(p) ? `${acc}[${p}]` : acc === "" ? p : `${acc}.${p}`),
    "",
  );
}

const child = (pointer: string, prop: unknown): string =>
  pointer === "/" ? String(prop) : `${pointerToDotted(pointer)}.${String(prop)}`;

function got(value: unknown): string {
  const text = JSON.stringify(value);
  return text.length > 80 ? `${text.slice(0, 77)}...` : text;
}

const str = (v: unknown): string => String(v);

/** Human text per schema keyword. `p` is the ajv `params` object, `v` the offending value when recorded. */
const DESCRIBE: Record<string, (p: Record<string, unknown>, v: unknown) => string> = {
  enum: (p, v) =>
    `must be one of ${(p.allowedValues as unknown[]).map(str).join(", ")} (got ${got(v)})`,
  const: (p, v) => `must be ${got(p.allowedValue)} (got ${got(v)})`,
  pattern: (p, v) => `must match pattern ${str(p.pattern)} (got ${got(v)})`,
  type: (p, v) => `must be of type ${str(p.type)} (got ${got(v)})`,
  format: (p, v) => `must be a valid ${str(p.format)} (got ${got(v)})`,
  minimum: (p, v) => `must be >= ${str(p.limit)} (got ${got(v)})`,
  maximum: (p, v) => `must be <= ${str(p.limit)} (got ${got(v)})`,
  minLength: (p) => `must be at least ${str(p.limit)} characters long`,
  maxLength: (p) => `must be at most ${str(p.limit)} characters long`,
  minItems: (p) => `must have at least ${str(p.limit)} items`,
  maxItems: (p) => `must have at most ${str(p.limit)} items`,
  uniqueItems: () => "must not contain duplicate items",
};

/** One readable line per schema issue, e.g. `spec.riskClassification.level: must be one of minimal, limited, high (got "unacceptable")`. */
export function formatIssues(issues: readonly AblIssue[]): string[] {
  // ajv adds an "if" issue ("must match then schema") next to the concrete failure of a conditional; it says nothing new.
  return issues
    .filter((i) => i.keyword !== "if")
    .map((i) => {
      if (i.keyword === "required")
        return `${child(i.path, i.params.missingProperty)}: is required`;
      if (i.keyword === "additionalProperties") {
        return `${child(i.path, i.params.additionalProperty)}: unknown property`;
      }
      const describe = DESCRIBE[i.keyword];
      return `${pointerToDotted(i.path)}: ${describe ? describe(i.params, i.value) : i.message}`;
    });
}

/** One line per lint finding: `error ABL004 spec.evals: message`. */
export function formatFindings(findings: readonly Finding[]): string[] {
  return findings.map((f) => `${f.severity} ${f.code} ${pointerToDotted(f.path)}: ${f.message}`);
}
