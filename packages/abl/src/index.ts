import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Ajv2020, type ErrorObject } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse } from "yaml";

export const ABL_API_VERSION = "abl.axis.dev/v1";

const schemaPath = fileURLToPath(new URL("../schema/abl-v1.schema.json", import.meta.url));
export const ablSchema: object = JSON.parse(readFileSync(schemaPath, "utf8"));

const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats.default(ajv);
const validateFn = ajv.compile(ablSchema);

export interface AblIssue {
  path: string;
  keyword: string;
  message: string;
}

export type AblResult = { ok: true; doc: unknown } | { ok: false; issues: AblIssue[] };

function toIssues(errors: ErrorObject[]): AblIssue[] {
  return errors.map((e) => ({
    path: e.instancePath === "" ? "/" : e.instancePath,
    keyword: e.keyword,
    message: String(e.message),
  }));
}

/** Validate an already-parsed ABL document against the v1 schema. */
export function validateAbl(doc: unknown): AblResult {
  return validateFn(doc)
    ? { ok: true, doc }
    : { ok: false, issues: toIssues(validateFn.errors as ErrorObject[]) };
}

/** Parse YAML text and validate it. YAML syntax errors are reported as a single issue. */
export function validateAblYaml(text: string): AblResult {
  let doc: unknown;
  try {
    doc = parse(text);
  } catch (err) {
    return { ok: false, issues: [{ path: "/", keyword: "yaml", message: String(err) }] };
  }
  return validateAbl(doc);
}
