import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse } from "yaml";

const load = (name: string): object =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../schemas/${name}`, import.meta.url)), "utf8"));

const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats.default(ajv);

export const policySchema = load("policy-v1.schema.json");
export const auditEventSchema = load("audit-event-v1.schema.json");
export const ipcEnvelopeSchema = load("ipc-envelope-v1.schema.json");

export const validatePolicy = ajv.compile(policySchema);
export const validateAuditEvent = ajv.compile(auditEventSchema);
export const validateIpcEnvelope = ajv.compile(ipcEnvelopeSchema);

export function parsePolicyYaml(text: string): unknown {
  return parse(text);
}
