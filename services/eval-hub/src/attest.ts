import type { KeyObject } from "node:crypto";
import {
  EVAL_PREDICATE_TYPE,
  EVAL_STATEMENT_TYPE,
  signEvalStatement,
  type DsseEnvelope,
  type EvalStatement,
} from "@axis/registry";
import type { EvalRunDoc, Suite } from "./types.js";

/** Where signed summaries go (the registry's `attachEvalAttestation`). */
export interface AttestationSink {
  attach(
    tenantId: string,
    ref: { namespace: string; name: string; version: string },
    envelope: DsseEnvelope,
  ): Promise<void>;
}

export interface HubSigningKey {
  keyId: string;
  privateKey: KeyObject;
}

/** The signed summary of one FINISHED, non-errored run. */
export function buildEvalStatement(run: EvalRunDoc, suite: Suite): EvalStatement {
  const b = run.blueprint;
  return {
    _type: EVAL_STATEMENT_TYPE,
    subject: [
      {
        name: `${b.namespace ?? "-"}/${b.name}@${b.version}`,
        digest: { sha256: b.content_hash },
      },
    ],
    predicateType: EVAL_PREDICATE_TYPE,
    predicate: {
      run_id: run.id,
      suite_ref: run.suite_ref,
      suite_hash: run.suite_hash,
      dataset_hash: run.dataset_hash,
      mode: run.mode,
      status: run.status === "passed" ? "passed" : "failed",
      overall: (run.scores as NonNullable<EvalRunDoc["scores"]>).overall as number,
      per_grader: (run.scores as NonNullable<EvalRunDoc["scores"]>).per_grader,
      pass_threshold: suite.pass_threshold,
      sample_size: run.sample_size,
      runner_id: run.runner_id as string,
      finished_at: run.finished_at as string,
      record_hash: run.record_hash as string,
    },
  };
}

export function attestationFor(run: EvalRunDoc, suite: Suite, key: HubSigningKey): DsseEnvelope {
  return signEvalStatement(buildEvalStatement(run, suite), key);
}
