import { canonicalJson, compileAbl, contentHash, validateAbl, type AblDocument } from "@axis/abl";
import {
  COMPILER_NAME,
  PREDICATE_TYPE,
  STATEMENT_TYPE,
  decodeStatement,
  envelopeSignedBy,
  isEnvelope,
  subjectName,
} from "./provenance.js";
import { MAX_SKEW_MS, keyTrustedAt, signedMessage, verifyDetached } from "./signing.js";
import { compareVersions, parseVersion } from "./semver.js";
import type { PublisherKey, VersionRecord } from "./types.js";

export interface VerifyOptions {
  /** Provenance must come from a compiler at least this version (default: any). */
  minCompilerVersion?: string;
}

export type Verdict =
  | { ok: true; keyId: string; builder: string; sourceRef: string; compilerVersion: string }
  | { ok: false; failures: string[] };

/**
 * Full verification of a stored/received version. PURE (keys are passed in). FAIL-CLOSED: every check must pass; any thrown
 * exception, malformed field or unknown shape is a failure. Nothing here trusts a client-supplied hash, name or timestamp:
 * the content hash is recomputed from the ABL text, and the signed message is rebuilt from the record.
 */
export function verifyVersion(
  rec: VersionRecord,
  keys: ReadonlyMap<string, PublisherKey>,
  opts: VerifyOptions = {},
): Verdict {
  const failures: string[] = [];
  const fail = (code: string): void => {
    if (!failures.includes(code)) failures.push(code);
  };
  try {
    return verifyInner(rec, keys, opts, fail, failures);
  } catch {
    fail("internal_error");
    return { ok: false, failures };
  }
}

function verifyInner(
  rec: VersionRecord,
  keys: ReadonlyMap<string, PublisherKey>,
  opts: VerifyOptions,
  fail: (c: string) => void,
  failures: string[],
): Verdict {
  // 1. The blueprint itself: canonical text, schema, hash, identity.
  let doc: unknown;
  try {
    doc = JSON.parse(rec.abl);
  } catch {
    fail("abl_not_json");
    return { ok: false, failures };
  }
  if (canonicalJson(doc) !== rec.abl) fail("abl_not_canonical");
  const v = validateAbl(doc);
  if (!v.ok) {
    fail("abl_schema");
    return { ok: false, failures };
  }
  const abl = v.doc as AblDocument;
  const hash = contentHash(abl);
  if (hash !== rec.contentHash) fail("content_hash_mismatch");
  if (abl.metadata.name !== rec.name) fail("name_mismatch");
  if (abl.metadata.version !== rec.version) fail("version_mismatch");
  if (abl.spec.riskClassification.level !== rec.riskLevel) fail("risk_level_mismatch");
  const compiled = compileAbl(abl);
  if (!compiled.ok) fail("abl_lint_errors");

  // 2. Detached signature over (content hash + metadata + key id + signed-at), by a key trusted at publish time.
  const sig = rec.signature;
  const key = keys.get(sig.keyId);
  const signedAt = new Date(sig.signedAt);
  if (!key || key.namespace !== rec.namespace) {
    fail("signing_key_unknown");
  } else if (Number.isNaN(signedAt.getTime()) || signedAt.toISOString() !== sig.signedAt) {
    fail("signed_at_malformed");
  } else {
    if (signedAt.getTime() > rec.publishedAt.getTime() + MAX_SKEW_MS) fail("signed_after_publish");
    if (!keyTrustedAt(key, rec.publishedAt).ok || !keyTrustedAt(key, signedAt).ok)
      fail("signing_key_not_trusted");
    const msg = signedMessage({
      v: 1,
      namespace: rec.namespace,
      name: rec.name,
      version: rec.version,
      contentHash: hash,
      riskLevel: rec.riskLevel,
      keyId: sig.keyId,
      signedAt: sig.signedAt,
    });
    if (!verifyDetached(key.publicKey, msg, sig.sig)) fail("signature_invalid");
  }

  // 3. Provenance attestation: signed, bound to THIS content, reproducible lint results.
  const env = rec.provenance;
  let builder = "";
  let sourceRef = "";
  let compilerVersion = "";
  if (!isEnvelope(env)) {
    fail("provenance_malformed");
  } else {
    const st = decodeStatement(env);
    if (!st) {
      fail("provenance_payload_invalid");
    } else {
      const p = st.predicate;
      if (st._type !== STATEMENT_TYPE || st.predicateType !== PREDICATE_TYPE)
        fail("provenance_type");
      const subj = st.subject;
      if (
        !Array.isArray(subj) ||
        subj.length !== 1 ||
        subj[0]?.name !== subjectName(rec.namespace, rec.name, rec.version) ||
        subj[0]?.digest?.sha256 !== hash
      )
        fail("provenance_subject_mismatch");
      if (!p || p.abl?.sha256 !== hash) fail("provenance_abl_hash_mismatch");
      if (!p || typeof p.builder?.id !== "string" || p.builder.id === "")
        fail("provenance_builder");
      else builder = p.builder.id;
      if (!p || typeof p.source?.ref !== "string" || p.source.ref === "") fail("provenance_source");
      else sourceRef = p.source.ref;
      if (p?.compiler?.name !== COMPILER_NAME || typeof p.compiler.version !== "string") {
        fail("provenance_compiler");
      } else {
        compilerVersion = p.compiler.version;
        if (opts.minCompilerVersion) {
          try {
            if (
              compareVersions(
                parseVersion(compilerVersion),
                parseVersion(opts.minCompilerVersion),
              ) < 0
            )
              fail("provenance_compiler_too_old");
          } catch {
            fail("provenance_compiler");
          }
        }
      }
      if (compiled.ok) {
        const warn = compiled.findings.filter((f) => f.severity === "warning");
        const codes = compiled.findings.map((f) => f.code).sort();
        if (
          p?.lint?.errors !== 0 ||
          p.lint.warnings !== warn.length ||
          JSON.stringify(p.lint.codes) !== JSON.stringify(codes)
        )
          fail("provenance_lint_mismatch");
      }
      // At least one signature by a key trusted at publish time. An unknown/untrusted extra signature is ignored.
      const good = env.signatures.some((s) => {
        const k = keys.get(s.keyid);
        return (
          k !== undefined &&
          k.namespace === rec.namespace &&
          keyTrustedAt(k, rec.publishedAt).ok &&
          envelopeSignedBy(env, s.keyid, k.publicKey)
        );
      });
      if (!good) fail("provenance_signature_invalid");
    }
  }
  if (failures.length > 0) return { ok: false, failures };
  return { ok: true, keyId: sig.keyId, builder, sourceRef, compilerVersion };
}
