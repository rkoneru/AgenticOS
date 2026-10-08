import type { KeyObject } from "node:crypto";
import { canonicalJson } from "@axis/abl";
import { PAYLOAD_TYPE, pae } from "./provenance.js";
import { decodeB64, signDetached, verifyDetached } from "./signing.js";
import type { DsseEnvelope } from "./types.js";

// ---------------------------------------------------------------- the gate port

export interface EvalGateSuite {
  ref: string;
  threshold: number;
}
export interface EvalGateBlueprint {
  namespace: string;
  name: string;
  version: string;
  contentHash: string;
}
export interface EvalGateInput {
  /** The OWNER tenant of the blueprint (the eval history lives there). */
  tenantId: string;
  blueprint: EvalGateBlueprint;
  /** `spec.evals.suites` of the stored ABL. Read by the registry from the blueprint itself, never taken from a caller. */
  suites: EvalGateSuite[];
  actor: string;
  purpose: "release" | "marketplace_submit";
}
export interface EvalGateReason {
  code: string;
  suite_ref?: string;
  message: string;
}
export interface EvalGateResult {
  allowed: boolean;
  reasons: EvalGateReason[];
}

/**
 * The Eval Hub as the registry and the marketplace see it. The default (`DENY_ALL_EVAL_GATE`) refuses: a service that was not wired to
 * a gate cannot release a blueprint that declares required evals. A port that throws is a refusal too (fail-closed).
 */
export interface EvalGatePort {
  check(input: EvalGateInput): Promise<EvalGateResult>;
  /** Best effort, after a release went through: lets the hub promote the released run to the baseline. */
  released?(input: EvalGateInput): Promise<void>;
}

export const DENY_ALL_EVAL_GATE: EvalGatePort = {
  check: () =>
    Promise.resolve({
      allowed: false,
      reasons: [{ code: "gate_unavailable", message: "no eval gate is configured" }],
    }),
};

// ---------------------------------------------------------------- eval-result attestations

export const EVAL_PREDICATE_TYPE = "https://axis.dev/eval-result/v1";
export const EVAL_STATEMENT_TYPE = "https://in-toto.io/Statement/v1";

export interface EvalPredicate {
  run_id: string;
  suite_ref: string;
  suite_hash: string;
  dataset_hash: string;
  mode: string;
  status: "passed" | "failed";
  overall: number;
  per_grader: Record<string, number>;
  pass_threshold: number;
  sample_size: number;
  runner_id: string;
  finished_at: string;
  record_hash: string;
}
export interface EvalStatement {
  _type: string;
  subject: { name: string; digest: { sha256: string } }[];
  predicateType: string;
  predicate: EvalPredicate;
}

export function signEvalStatement(
  statement: EvalStatement,
  key: { keyId: string; privateKey: KeyObject },
): DsseEnvelope {
  const body = Buffer.from(canonicalJson(statement), "utf8");
  return {
    payloadType: PAYLOAD_TYPE,
    payload: body.toString("base64"),
    signatures: [{ keyid: key.keyId, sig: signDetached(key.privateKey, pae(PAYLOAD_TYPE, body)) }],
  };
}

export interface TrustedHubKey {
  keyId: string;
  /** base64url raw Ed25519 public key. */
  publicKey: string;
}

export type EvalAttestationVerdict =
  | { ok: true; statement: EvalStatement }
  | { ok: false; reason: string };

/** Verifies an envelope against the trusted hub keys, and that it is a well-formed eval statement. Never throws. */
export function verifyEvalAttestation(
  env: DsseEnvelope,
  trusted: readonly TrustedHubKey[],
): EvalAttestationVerdict {
  const body = decodeB64(env?.payload);
  if (!body || env.payloadType !== PAYLOAD_TYPE) return { ok: false, reason: "malformed envelope" };
  const msg = pae(env.payloadType, body);
  const signed = env.signatures.some((s) =>
    trusted.some((k) => k.keyId === s.keyid && verifyDetached(k.publicKey, msg, s.sig)),
  );
  if (!signed) return { ok: false, reason: "not signed by a trusted eval hub key" };
  try {
    const text = body.toString("utf8");
    const st = JSON.parse(text) as EvalStatement;
    if (canonicalJson(st) !== text) return { ok: false, reason: "payload is not canonical" };
    if (
      st._type !== EVAL_STATEMENT_TYPE ||
      st.predicateType !== EVAL_PREDICATE_TYPE ||
      !Array.isArray(st.subject) ||
      st.subject.length !== 1 ||
      typeof st.predicate?.run_id !== "string"
    )
      return { ok: false, reason: "not an eval-result statement" };
    return { ok: true, statement: st };
  } catch {
    return { ok: false, reason: "payload is not JSON" };
  }
}
