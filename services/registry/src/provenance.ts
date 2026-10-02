import type { KeyObject } from "node:crypto";
import { canonicalJson, compileAbl } from "@axis/abl";
import { createRequire } from "node:module";
import { decodeB64, signDetached, verifyDetached } from "./signing.js";
import type { DsseEnvelope } from "./types.js";

export const PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const PREDICATE_TYPE = "https://axis.dev/blueprint-provenance/v1";

const require = createRequire(import.meta.url);
/** Version of the ABL compiler that this registry links (what a verifier can reproduce). */
export const COMPILER_VERSION: string = (require("@axis/abl/package.json") as { version: string })
  .version;
export const COMPILER_NAME = "@axis/abl";

export interface ProvenancePredicate {
  builder: { id: string };
  source: { ref: string; digest?: string };
  abl: { sha256: string };
  compiler: { name: string; version: string };
  lint: { errors: number; warnings: number; codes: string[] };
  evals?: { resultsUrl: string };
  buildFinishedOn: string;
}

export interface ProvenanceStatement {
  _type: string;
  subject: { name: string; digest: { sha256: string } }[];
  predicateType: string;
  predicate: ProvenancePredicate;
}

/** DSSE pre-authentication encoding: what is actually signed (binds the payload type, defeating type confusion). */
export function pae(payloadType: string, payload: Uint8Array): Buffer {
  const t = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${t.length} `, "utf8"),
    t,
    Buffer.from(` ${payload.length} `, "utf8"),
    Buffer.from(payload),
  ]);
}

export const subjectName = (namespace: string, name: string, version: string): string =>
  `${namespace}/${name}@${version}`;

export interface BuildProvenanceInput {
  namespace: string;
  name: string;
  version: string;
  abl: unknown;
  builderId: string;
  sourceRef: string;
  sourceDigest?: string;
  evalsUrl?: string;
  now?: Date;
}

/** Runs the real compiler/linter, so lint results in the attestation are what a verifier can reproduce. */
export function buildStatement(i: BuildProvenanceInput, contentHash: string): ProvenanceStatement {
  const res = compileAbl(i.abl);
  const findings = res.findings;
  return {
    _type: STATEMENT_TYPE,
    subject: [
      { name: subjectName(i.namespace, i.name, i.version), digest: { sha256: contentHash } },
    ],
    predicateType: PREDICATE_TYPE,
    predicate: {
      builder: { id: i.builderId },
      source: { ref: i.sourceRef, ...(i.sourceDigest ? { digest: i.sourceDigest } : {}) },
      abl: { sha256: contentHash },
      compiler: { name: COMPILER_NAME, version: COMPILER_VERSION },
      lint: {
        errors: findings.filter((f) => f.severity === "error").length,
        warnings: findings.filter((f) => f.severity === "warning").length,
        codes: findings.map((f) => f.code).sort(),
      },
      ...(i.evalsUrl ? { evals: { resultsUrl: i.evalsUrl } } : {}),
      buildFinishedOn: (i.now ?? new Date()).toISOString(),
    },
  };
}

export function signStatement(
  statement: ProvenanceStatement,
  key: { keyId: string; privateKey: KeyObject },
): DsseEnvelope {
  const body = Buffer.from(canonicalJson(statement), "utf8");
  return {
    payloadType: PAYLOAD_TYPE,
    payload: body.toString("base64"),
    signatures: [{ keyid: key.keyId, sig: signDetached(key.privateKey, pae(PAYLOAD_TYPE, body)) }],
  };
}

export const isEnvelope = (e: unknown): e is DsseEnvelope => {
  if (typeof e !== "object" || e === null) return false;
  const o = e as Record<string, unknown>;
  return (
    typeof o["payloadType"] === "string" &&
    typeof o["payload"] === "string" &&
    Array.isArray(o["signatures"]) &&
    o["signatures"].every(
      (s) =>
        typeof s === "object" &&
        s !== null &&
        typeof (s as Record<string, unknown>)["keyid"] === "string" &&
        typeof (s as Record<string, unknown>)["sig"] === "string",
    )
  );
};

/** Decodes the statement of an envelope. Requires the payload to be canonical JSON (one byte string per statement). */
export function decodeStatement(env: DsseEnvelope): ProvenanceStatement | undefined {
  const body = decodeB64(env.payload);
  if (!body) return undefined;
  try {
    const text = body.toString("utf8");
    const parsed: unknown = JSON.parse(text);
    if (canonicalJson(parsed) !== text) return undefined;
    return parsed as ProvenanceStatement;
  } catch {
    return undefined;
  }
}

/** Signature check of an envelope against ONE key. The key's validity window is the caller's concern (see verify.ts). */
export function envelopeSignedBy(env: DsseEnvelope, keyId: string, publicKey: string): boolean {
  const body = decodeB64(env.payload);
  if (!body || env.payloadType !== PAYLOAD_TYPE) return false;
  const msg = pae(env.payloadType, body);
  return env.signatures.some((s) => s.keyid === keyId && verifyDetached(publicKey, msg, s.sig));
}
