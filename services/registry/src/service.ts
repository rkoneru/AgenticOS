import { canonicalJson, compileAbl, contentHash, validateAbl, type AblDocument } from "@axis/abl";
import type { ServiceAudit } from "./audit.js";
import { requirePlatform, requireTenant } from "./authz.js";
import { RegistryError, conflict, forbidden, invalid, notFound } from "./errors.js";
import {
  DENY_ALL_EVAL_GATE,
  verifyEvalAttestation,
  type EvalGatePort,
  type EvalGateReason,
  type TrustedHubKey,
} from "./eval-gate.js";
import { isEnvelope } from "./provenance.js";
import {
  compareVersions,
  maxSatisfying,
  parseRange,
  parseVersion,
  tryParseVersion,
} from "./semver.js";
import { decodeB64u, keyIdOf } from "./signing.js";
import { StoreConflict, StoreForbidden, type RegistryStore } from "./store.js";
import {
  NAMESPACE_RE,
  NAME_RE,
  RESERVED_NAMESPACES,
  normalizeName,
  type BlueprintSignature,
  type DsseEnvelope,
  type EvalAttestationRecord,
  type EventKind,
  type NamespaceRecord,
  type PlatformPrincipal,
  type PublisherKey,
  type RevokeReason,
  type TenantPrincipal,
  type VersionRecord,
  type VersionRow,
  type VersionState,
  type Viewer,
} from "./types.js";
import { verifyVersion, type VerifyOptions, type Verdict } from "./verify.js";

export interface RegistryDeps {
  store: RegistryStore;
  audit: ServiceAudit;
  now?: () => Date;
  verify?: VerifyOptions;
  /** The Eval Hub gate. Default: refuses (a registry that was not wired to a gate cannot release a blueprint that declares evals). */
  evalGate?: EvalGatePort;
  /** Public keys of the Eval Hub whose signed attestations the registry attaches to versions. */
  evalHubKeys?: TrustedHubKey[];
}

export interface PublishInput {
  abl: unknown;
  signature: BlueprintSignature;
  provenance: DsseEnvelope;
}

export interface ResolvedBlueprint {
  namespace: string;
  name: string;
  version: string;
  contentHash: string;
  riskLevel: VersionRecord["riskLevel"];
  abl: AblDocument;
  record: VersionRecord;
  state: VersionState;
  statusReason: string | null;
  verification: Extract<Verdict, { ok: true }>;
}

export interface ResolveOptions {
  /** Default false: a yanked version is never resolved. */
  allowYanked?: boolean;
  /** Rollback guard: refuse to resolve below this version (a lock-file's pinned version). */
  notBelow?: string;
}

const REF_RE = /^([a-z][a-z0-9-]{1,62})\/([a-z][a-z0-9-]{1,62})@(.+)$/;
const MAX_ABL_BYTES = 1_000_000;
const MAX_DEPTH = 8;
const MAX_CLOSURE = 64;
const MAX_REASON = 500;
const MAX_FUTURE_MS = 30 * 24 * 3_600_000;

export interface ParsedRef {
  namespace: string;
  name: string;
  range: string;
}

/**
 * Registry references are ALWAYS namespace-qualified (`ns/name@range`). An unqualified reference is refused, never searched
 * across namespaces: that is the dependency-confusion defence (docs/security/registry-threat-model.md).
 */
export function parseRef(ref: string): ParsedRef {
  const m = REF_RE.exec(typeof ref === "string" ? ref : "");
  if (!m) throw invalid("reference must be namespace-qualified: <namespace>/<name>@<range>");
  parseRange(m[3] as string);
  return { namespace: m[1] as string, name: m[2] as string, range: m[3] as string };
}

const SYNTAX_REF_RE = /^(?:[a-z][a-z0-9-]{1,62}\/)?[a-z][a-z0-9-]{1,62}@(.+)$/;

/** Every dependency-like reference of an ABL document: where it came from and the reference text. */
export function collectReferences(
  abl: AblDocument,
): { path: string; ref: string; registry: boolean }[] {
  const out: { path: string; ref: string; registry: boolean }[] = [];
  (abl.spec.tools ?? []).forEach((t, i) => {
    if (t.ref !== undefined)
      out.push({ path: `/spec/tools/${i}/ref`, ref: t.ref, registry: t.kind === "agent" });
  });
  (abl.spec.policy?.packs ?? []).forEach((p, i) =>
    out.push({ path: `/spec/policy/packs/${i}`, ref: p, registry: false }),
  );
  (abl.spec.evals?.suites ?? []).forEach((s, i) =>
    out.push({ path: `/spec/evals/suites/${i}/ref`, ref: s.ref, registry: false }),
  );
  return out;
}

export class RegistryService {
  private readonly store: RegistryStore;
  private readonly audit: ServiceAudit;
  private readonly now: () => Date;
  private readonly verifyOpts: VerifyOptions;
  private readonly evalGate: EvalGatePort;
  /** True when the composition wired a hub. Only then is a blueprint that declares NO suites still asked about (tenant-required suites). */
  private readonly evalGateWired: boolean;
  private readonly hubKeys: TrustedHubKey[];
  constructor(d: RegistryDeps) {
    this.evalGate = d.evalGate ?? DENY_ALL_EVAL_GATE;
    this.evalGateWired = d.evalGate !== undefined;
    this.hubKeys = d.evalHubKeys ?? [];
    this.store = d.store;
    this.audit = d.audit;
    this.now = d.now ?? (() => new Date());
    this.verifyOpts = d.verify ?? {};
  }

  // ---------------------------------------------------------------- audit wrapper
  /**
   * authorize (caller) -> audit the decision -> perform -> audit the outcome. A decision that cannot be written is not performed.
   * Failures of `fn` are audited as DENY with the failure code, then rethrown unchanged.
   */
  private async mutate<T>(
    tenantId: string,
    actor: string,
    action: string,
    detail: Record<string, unknown>,
    fn: () => Promise<T>,
  ): Promise<T> {
    await this.audit.record({
      tenantId,
      actor: { type: "human", id: actor },
      action,
      decision: "ALLOW",
      reason: "authorized",
      inputs: detail,
    });
    try {
      const out = await fn();
      await this.audit
        .record({
          tenantId,
          actor: { type: "human", id: actor },
          action: `${action}.done`,
          decision: "ALLOW",
          reason: "ok",
          inputs: detail,
        })
        .catch(() => undefined);
      return out;
    } catch (err) {
      const code = err instanceof RegistryError ? err.code : "error";
      const checks = err instanceof RegistryError ? err.checks.join(",") : "";
      await this.audit
        .record({
          tenantId,
          actor: { type: "human", id: actor },
          action: `${action}.failed`,
          decision: "DENY",
          reason: `code=${code} checks=${checks}`,
          inputs: detail,
        })
        .catch(() => undefined);
      throw err;
    }
  }

  private async deny(p: TenantPrincipal, action: string, err: RegistryError): Promise<never> {
    await this.audit
      .record({
        tenantId: p.tenantId,
        actor: { type: "human", id: p.subject },
        action,
        decision: "DENY",
        reason: `code=${err.code}`,
      })
      .catch(() => undefined);
    throw err;
  }

  // ---------------------------------------------------------------- namespaces
  async claimNamespace(p: TenantPrincipal, namespace: string): Promise<NamespaceRecord> {
    try {
      requireTenant(p, "registry.namespace.claim");
    } catch (e) {
      return this.deny(p, "registry.namespace.claim", e as RegistryError);
    }
    if (
      typeof namespace !== "string" ||
      !NAMESPACE_RE.test(namespace) ||
      namespace.endsWith("-") ||
      namespace.includes("--")
    )
      throw invalid(
        "namespace must match [a-z][a-z0-9-]{1,62} without trailing or doubled hyphens",
      );
    // (the folded comparison also covers the exact name)
    if (RESERVED_NAMESPACES.some((r) => normalizeName(r) === normalizeName(namespace)))
      throw forbidden("namespace is reserved");
    return this.mutate(
      p.tenantId,
      p.subject,
      "registry.namespace.claim",
      { namespace },
      async () => {
        try {
          return await this.store.claimNamespace({
            namespace,
            tenantId: p.tenantId,
            normalized: normalizeName(namespace),
            createdAt: this.now(),
            createdBy: p.subject,
          });
        } catch (e) {
          if (e instanceof StoreConflict) throw conflict(e.message);
          throw e;
        }
      },
    );
  }

  async listNamespaces(p: TenantPrincipal): Promise<NamespaceRecord[]> {
    requireTenant(p, "registry.read");
    return this.store.listNamespaces(p.tenantId);
  }

  /** Marketplace only: the namespace becomes readable by every tenant and by anonymous catalog readers. */
  async setNamespacePublic(p: PlatformPrincipal, namespace: string): Promise<void> {
    requirePlatform(p);
    const owner = await this.store.ownerOf(namespace);
    if (!owner) throw notFound("namespace not found");
    await this.mutate(owner, p.subject, "registry.namespace.publish", { namespace }, () =>
      this.store.setPublic(owner, namespace, p.subject, this.now()),
    );
  }

  /**
   * Marketplace only: one reviewed version becomes readable by every tenant (and the namespace, with its keys, so a reader can verify
   * it). Nothing else in the namespace is released: other blueprints and later versions stay private until they are released too.
   */
  async setVersionPublic(
    p: PlatformPrincipal,
    namespace: string,
    name: string,
    version: string,
  ): Promise<void> {
    requirePlatform(p);
    const owner = await this.store.ownerOf(namespace);
    if (!owner) throw notFound("namespace not found");
    if (!(await this.store.getVersion({ tenantId: owner }, namespace, name, version)))
      throw notFound("version not found");
    // The eval gate runs BEFORE anything becomes public. With a hub wired it is asked even when the blueprint declares no suites.
    await this.requireEvalGate({
      tenantId: owner,
      namespace,
      name,
      version,
      purpose: "release",
      actor: p.subject,
    });
    await this.setNamespacePublic(p, namespace);
    await this.mutate(
      owner,
      p.subject,
      "registry.version.publish",
      { namespace, name, version },
      () => this.store.setVersionPublic(owner, namespace, name, version, p.subject, this.now()),
    );
    await this.afterRelease({
      tenantId: owner,
      namespace,
      name,
      version,
      purpose: "release",
      actor: p.subject,
    });
  }

  private async gateInput(g: {
    tenantId: string;
    namespace: string;
    name: string;
    version: string;
    purpose: "release" | "marketplace_submit";
    actor: string;
  }): Promise<import("./eval-gate.js").EvalGateInput | undefined> {
    const row = await this.store.getVersion(
      { tenantId: g.tenantId },
      g.namespace,
      g.name,
      g.version,
    );
    if (!row) throw notFound("version not found");
    let suites: { ref: string; threshold: number }[] = [];
    try {
      const abl = JSON.parse(row.record.abl) as {
        spec?: { evals?: { suites?: { ref: string; threshold: number }[] } };
      };
      suites = abl.spec?.evals?.suites ?? [];
    } catch {
      throw invalid("stored blueprint is not readable"); // fail closed: an unreadable ABL cannot be shown to declare no suites
    }
    // The rule (ADR 0058): with a hub wired the gate is ALWAYS asked, because the tenant may require suites the blueprint did not
    // declare (`required_for_release`); the hub adds them and allows when nothing is required. Without a wired hub there is nothing
    // that could know of a requirement, so a blueprint that declares no suites is not gated (as before).
    if (suites.length === 0 && !this.evalGateWired) return undefined;
    return {
      tenantId: g.tenantId,
      blueprint: {
        namespace: g.namespace,
        name: g.name,
        version: g.version,
        contentHash: row.record.contentHash,
      },
      suites: suites.map((x) => ({ ref: x.ref, threshold: x.threshold })),
      actor: g.actor,
      purpose: g.purpose,
    };
  }

  /**
   * Refuses (`evals_gate_failed`, 409, with the gate's reasons) unless the Eval Hub allows this version. The declared suites come from
   * the STORED blueprint; the hub adds the tenant's required ones. No declared suites and no wired hub: allowed without asking. A gate that errors, times out or is absent refuses.
   */
  async requireEvalGate(g: {
    tenantId: string;
    namespace: string;
    name: string;
    version: string;
    purpose: "release" | "marketplace_submit";
    actor: string;
  }): Promise<void> {
    const input = await this.gateInput(g);
    if (!input) return;
    let reasons: EvalGateReason[];
    try {
      const r = await this.evalGate.check(input);
      if (r && r.allowed === true) return;
      reasons =
        Array.isArray(r?.reasons) && r.reasons.length > 0
          ? r.reasons
          : [{ code: "not_allowed", message: "the eval gate did not allow this version" }];
    } catch {
      reasons = [{ code: "gate_unavailable", message: "the eval gate could not be reached" }];
    }
    await this.audit
      .record({
        tenantId: g.tenantId,
        actor: { type: "system", id: g.actor },
        action: `registry.evals_gate.${g.purpose}`,
        decision: "DENY",
        reason: `code=evals_gate_failed reasons=${reasons.map((x) => x.code).join(",")}`,
        inputs: { namespace: g.namespace, name: g.name, version: g.version },
      })
      .catch(() => undefined);
    throw new RegistryError(
      "evals_gate_failed",
      "the eval gate did not allow this version",
      reasons.map((x) => x.code),
      reasons,
    );
  }

  private async afterRelease(g: Parameters<RegistryService["requireEvalGate"]>[0]): Promise<void> {
    try {
      const input = await this.gateInput(g);
      if (input && this.evalGate.released) await this.evalGate.released(input);
    } catch {
      /* best effort: the baseline can be promoted by an admin */
    }
  }

  // ---------------------------------------------------------------- eval attestations
  /**
   * Eval Hub only. Attaches a signed eval-result summary to a version. The envelope must verify against a trusted hub key, be about
   * THIS version (subject name and content hash), and is append-only (one per run).
   */
  async attachEvalAttestation(
    p: PlatformPrincipal,
    ref: { namespace: string; name: string; version: string },
    envelope: DsseEnvelope,
  ): Promise<EvalAttestationRecord> {
    requirePlatform(p, "eval-hub");
    const owner = await this.store.ownerOf(ref.namespace);
    if (!owner) throw notFound("namespace not found");
    const row = await this.store.getVersion(
      { tenantId: owner },
      ref.namespace,
      ref.name,
      ref.version,
    );
    if (!row) throw notFound("version not found");
    if (!isEnvelope(envelope)) throw invalid("attestation is not a DSSE envelope");
    const v = verifyEvalAttestation(envelope, this.hubKeys);
    if (!v.ok) throw new RegistryError("verification_failed", v.reason, ["attestation_signature"]);
    const subj = v.statement.subject[0];
    if (
      subj?.name !== `${ref.namespace}/${ref.name}@${ref.version}` ||
      subj.digest.sha256 !== row.record.contentHash
    )
      throw new RegistryError("verification_failed", "attestation is about a different blueprint", [
        "attestation_subject",
      ]);
    const rec: EvalAttestationRecord = {
      tenantId: owner,
      ...ref,
      runId: v.statement.predicate.run_id,
      suiteRef: v.statement.predicate.suite_ref,
      contentHash: row.record.contentHash,
      overall: v.statement.predicate.overall,
      envelope,
      attachedAt: this.now(),
      attachedBy: p.subject,
    };
    return this.mutate(
      owner,
      p.subject,
      "registry.eval_attestation.attach",
      { ...ref, run: rec.runId },
      async () => {
        try {
          await this.store.addAttestation(rec);
        } catch (e) {
          if (e instanceof StoreConflict) throw conflict(e.message);
          throw e;
        }
        return rec;
      },
    );
  }

  /** Attestations of one version (same visibility as the version). */
  async evalAttestations(
    viewer: Viewer,
    ns: string,
    name: string,
    version: string,
  ): Promise<EvalAttestationRecord[]> {
    return this.store.attestations(viewer, ns, name, version);
  }

  // ---------------------------------------------------------------- keys
  private async ownedNamespace(p: TenantPrincipal, namespace: string): Promise<NamespaceRecord> {
    const ns = await this.store.getNamespace({ tenantId: p.tenantId }, namespace);
    // Not owned = not visible = not found (an own-tenant read; a PUBLIC namespace of another tenant is visible but not owned).
    if (!ns || ns.tenantId !== p.tenantId) throw forbidden("namespace not owned by this tenant");
    return ns;
  }

  private parseKey(publicKey: string): string {
    const raw = decodeB64u(publicKey, 32);
    if (!raw) throw invalid("public key must be a base64url Ed25519 key (32 bytes)");
    return keyIdOf(raw);
  }

  private checkTime(at: Date, now: Date): void {
    if (Number.isNaN(at.getTime())) throw invalid("bad timestamp");
    if (at.getTime() > now.getTime() + MAX_FUTURE_MS)
      throw invalid("effective time too far in the future");
  }

  async addKey(
    p: TenantPrincipal,
    namespace: string,
    input: { publicKey: string; validFrom?: Date },
  ): Promise<PublisherKey> {
    requireTenant(p, "registry.keys.manage");
    await this.ownedNamespace(p, namespace);
    const keyId = this.parseKey(input.publicKey);
    const now = this.now();
    const validFrom = input.validFrom ?? now;
    this.checkTime(validFrom, now);
    const key: PublisherKey = {
      namespace,
      keyId,
      tenantId: p.tenantId,
      publicKey: input.publicKey,
      validFrom,
      validUntil: null,
      revokedAt: null,
      revokeReason: null,
      createdAt: now,
      createdBy: p.subject,
    };
    return this.mutate(
      p.tenantId,
      p.subject,
      "registry.key.add",
      { namespace, keyId },
      async () => {
        try {
          await this.store.addKey(key);
        } catch (e) {
          if (e instanceof StoreConflict) throw conflict(e.message);
          throw e;
        }
        return key;
      },
    );
  }

  /** Ends the old key at `effectiveAt` and starts the new one at the same instant: no overlap, no gap. */
  async rotateKey(
    p: TenantPrincipal,
    namespace: string,
    oldKeyId: string,
    input: { newPublicKey: string; effectiveAt?: Date },
  ): Promise<{ oldKey: PublisherKey; newKey: PublisherKey }> {
    requireTenant(p, "registry.keys.manage");
    await this.ownedNamespace(p, namespace);
    const newKeyId = this.parseKey(input.newPublicKey);
    const now = this.now();
    const at = input.effectiveAt ?? now;
    this.checkTime(at, now);
    return this.mutate(
      p.tenantId,
      p.subject,
      "registry.key.rotate",
      { namespace, oldKeyId, newKeyId },
      async () => {
        const keys = await this.store.getKeys({ tenantId: p.tenantId }, namespace);
        if (!keys.some((k) => k.keyId === oldKeyId)) throw notFound("key not found");
        if (newKeyId === oldKeyId) throw invalid("the new key must differ from the old key");
        const newKey: PublisherKey = {
          namespace,
          keyId: newKeyId,
          tenantId: p.tenantId,
          publicKey: input.newPublicKey,
          validFrom: at,
          validUntil: null,
          revokedAt: null,
          revokeReason: null,
          createdAt: now,
          createdBy: p.subject,
        };
        try {
          const oldKey = await this.store.updateKey(p.tenantId, namespace, oldKeyId, {
            validUntil: at,
          });
          await this.store.addKey(newKey);
          return { oldKey, newKey };
        } catch (e) {
          if (e instanceof StoreConflict) throw conflict(e.message);
          throw e;
        }
      },
    );
  }

  async revokeKey(
    p: TenantPrincipal,
    namespace: string,
    keyId: string,
    input: { reason: RevokeReason; effectiveAt?: Date },
  ): Promise<PublisherKey> {
    requireTenant(p, "registry.keys.manage");
    await this.ownedNamespace(p, namespace);
    if (input.reason !== "retired" && input.reason !== "compromised")
      throw invalid("reason must be retired or compromised");
    const now = this.now();
    const at = input.effectiveAt ?? now;
    this.checkTime(at, now);
    return this.mutate(
      p.tenantId,
      p.subject,
      "registry.key.revoke",
      { namespace, keyId, reason: input.reason },
      async () => {
        try {
          return await this.store.updateKey(p.tenantId, namespace, keyId, {
            revoke: { at, reason: input.reason },
          });
        } catch (e) {
          if (e instanceof StoreConflict) throw conflict(e.message);
          if (e instanceof StoreForbidden) throw notFound("key not found");
          throw e;
        }
      },
    );
  }

  async listKeys(p: TenantPrincipal, namespace: string): Promise<PublisherKey[]> {
    requireTenant(p, "registry.read");
    return this.store.getKeys({ tenantId: p.tenantId }, namespace);
  }

  // ---------------------------------------------------------------- publish
  async publish(
    p: TenantPrincipal,
    namespace: string,
    input: PublishInput,
  ): Promise<VersionRecord> {
    try {
      requireTenant(p, "registry.publish");
    } catch (e) {
      return this.deny(p, "registry.publish", e as RegistryError);
    }
    const ns = await this.ownedNamespace(p, namespace).catch((e: unknown) =>
      this.deny(p, "registry.publish", e as RegistryError),
    );

    // Shape + schema + lint. Nothing below trusts any client-computed value.
    if (typeof input.abl !== "object" || input.abl === null) throw invalid("abl must be an object");
    const text = canonicalJson(input.abl);
    if (Buffer.byteLength(text) > MAX_ABL_BYTES) throw invalid("blueprint too large");
    const v = validateAbl(input.abl);
    if (!v.ok)
      throw invalid(
        `ABL schema violations: ${v.issues
          .slice(0, 5)
          .map((i) => `${i.path} ${i.message}`)
          .join("; ")}`,
      );
    const abl = v.doc as AblDocument;
    const compiled = compileAbl(abl);
    if (!compiled.ok)
      throw invalid(
        `ABL lint errors: ${compiled.findings
          .filter((f) => f.severity === "error")
          .map((f) => f.code)
          .join(", ")}`,
      );
    const { name, version } = abl.metadata;
    if (!NAME_RE.test(name)) throw invalid("bad blueprint name");
    const sv = tryParseVersion(version);
    if (!sv) throw invalid("version must be strict semver");
    if (sv.build.length > 0) throw invalid("build metadata is not allowed in published versions");
    if (!isEnvelope(input.provenance)) throw invalid("provenance must be a DSSE envelope");
    if (typeof input.signature !== "object" || input.signature === null)
      throw invalid("signature is required");

    const hash = contentHash(abl);
    const now = this.now();
    const rec: VersionRecord = {
      namespace,
      name,
      version,
      tenantId: p.tenantId,
      abl: text,
      contentHash: hash,
      riskLevel: abl.spec.riskClassification.level,
      signature: {
        keyId: input.signature.keyId,
        signedAt: input.signature.signedAt,
        sig: input.signature.sig,
      },
      provenance: input.provenance,
      publishedAt: now,
      publishedBy: p.subject,
    };
    const detail = { namespace, name, version, contentHash: hash };

    return this.mutate(p.tenantId, p.subject, "registry.publish", detail, async () => {
      await this.checkReferences(p.tenantId, ns, abl);
      const keys = new Map(
        (await this.store.getKeys({ tenantId: p.tenantId }, namespace)).map((k) => [k.keyId, k]),
      );
      const verdict = verifyVersion(rec, keys, this.verifyOpts);
      if (!verdict.ok)
        throw new RegistryError(
          "verification_failed",
          "signature or provenance verification failed",
          verdict.failures,
        );
      try {
        await this.store.insertVersion(rec, normalizeName(name));
      } catch (e) {
        if (e instanceof StoreConflict)
          throw conflict(
            e.what === "version" ? "version already published (versions are immutable)" : e.message,
          );
        if (e instanceof StoreForbidden) throw forbidden("namespace not owned by this tenant");
        throw e;
      }
      return rec;
    });
  }

  /** Reference checks: syntax of every ref, registry-resolvable agent refs (verified), no cycles, public namespaces depend on public ones. */
  private async checkReferences(
    tenantId: string,
    ns: NamespaceRecord,
    abl: AblDocument,
  ): Promise<void> {
    const self = `${ns.namespace}/${abl.metadata.name}`;
    for (const r of collectReferences(abl)) {
      if (r.registry) {
        const dep = parseRef(r.ref);
        if (`${dep.namespace}/${dep.name}` === self)
          throw invalid(`${r.path}: a blueprint cannot depend on itself`);
        const closure = new Set<string>();
        await this.walk({ tenantId }, dep, ns.public, self, closure, 1);
      } else {
        const m = SYNTAX_REF_RE.exec(r.ref);
        if (!m) throw invalid(`${r.path}: malformed reference`);
        try {
          parseRange(m[1] as string);
        } catch {
          throw invalid(`${r.path}: malformed version range`);
        }
      }
    }
  }

  private async walk(
    viewer: Viewer,
    dep: ParsedRef,
    needPublic: boolean,
    self: string,
    seen: Set<string>,
    depth: number,
  ): Promise<void> {
    if (depth > MAX_DEPTH) throw invalid("dependency chain too deep");
    const key = `${dep.namespace}/${dep.name}`;
    if (key === self) throw invalid(`dependency cycle through ${self}`);
    if (seen.has(key)) return;
    seen.add(key);
    if (seen.size > MAX_CLOSURE) throw invalid("too many transitive dependencies");
    let res: ResolvedBlueprint;
    try {
      res = await this.resolve(viewer, dep);
    } catch (e) {
      if (
        e instanceof RegistryError &&
        (e.code === "not_found" || e.code === "verification_failed")
      )
        throw invalid(`dependency ${key}@${dep.range} cannot be resolved and verified (${e.code})`);
      throw e;
    }
    if (needPublic) {
      // What an anonymous reader would resolve for this range must be the very version the publisher resolved (a released one).
      const anon = await this.resolve({ tenantId: null }, dep).catch(() => undefined);
      if (anon?.version !== res.version)
        throw invalid(`dependency ${key} is not in a public namespace (no released version)`);
    }
    for (const r of collectReferences(res.abl))
      if (r.registry) await this.walk(viewer, parseRef(r.ref), needPublic, self, seen, depth + 1);
  }

  // ---------------------------------------------------------------- yank / deprecate
  private async setStatus(
    p: TenantPrincipal,
    kind: EventKind,
    ns: string,
    name: string,
    version: string,
    reason: string,
  ): Promise<void> {
    requireTenant(p, "registry.yank");
    await this.ownedNamespace(p, ns);
    this.checkReason(reason);
    const row = await this.store.getVersion({ tenantId: p.tenantId }, ns, name, version);
    if (!row) throw notFound("version not found");
    if (row.status.state === "yanked") throw conflict("version is already yanked");
    await this.mutate(
      p.tenantId,
      p.subject,
      `registry.${kind}`,
      { ns, name, version, reason },
      () =>
        this.store.appendEvent({
          namespace: ns,
          name,
          version,
          tenantId: p.tenantId,
          kind,
          reason,
          actor: p.subject,
          at: this.now(),
        }),
    );
  }
  private checkReason(reason: string): void {
    if (typeof reason !== "string" || reason.trim().length < 3 || reason.length > MAX_REASON)
      throw invalid("a reason of 3-500 characters is required");
  }
  yank(
    p: TenantPrincipal,
    ns: string,
    name: string,
    version: string,
    reason: string,
  ): Promise<void> {
    return this.setStatus(p, "yank", ns, name, version, reason);
  }
  deprecate(
    p: TenantPrincipal,
    ns: string,
    name: string,
    version: string,
    reason: string,
  ): Promise<void> {
    return this.setStatus(p, "deprecate", ns, name, version, reason);
  }

  /** Marketplace moderation: yanks a version of any public namespace (the owner tenant's chain records it). */
  async platformYank(
    p: PlatformPrincipal,
    ns: string,
    name: string,
    version: string,
    reason: string,
  ): Promise<void> {
    requirePlatform(p);
    this.checkReason(reason);
    const owner = await this.store.ownerOf(ns);
    if (!owner) throw notFound("namespace not found");
    const row = await this.store.getVersion({ tenantId: owner }, ns, name, version);
    if (!row) throw notFound("version not found");
    if (row.status.state === "yanked") return;
    await this.mutate(
      owner,
      p.subject,
      "registry.platform_yank",
      { ns, name, version, reason },
      () =>
        this.store.appendEvent({
          namespace: ns,
          name,
          version,
          tenantId: owner,
          kind: "yank",
          reason,
          actor: p.subject,
          at: this.now(),
        }),
    );
  }

  // ---------------------------------------------------------------- reads
  async listVersions(viewer: Viewer, ns: string, name: string): Promise<VersionRow[]> {
    const rows = await this.store.listVersions(viewer, ns, name);
    return rows.sort((a, b) =>
      compareVersions(parseVersion(a.record.version), parseVersion(b.record.version)),
    );
  }

  /** Verifies a stored row (fail-closed) and audits a failure into the viewer's tenant chain. */
  private async verifiedRow(viewer: Viewer, row: VersionRow): Promise<ResolvedBlueprint> {
    const rec = row.record;
    const keys = new Map(
      (await this.store.getKeys(viewer, rec.namespace)).map((k) => [k.keyId, k]),
    );
    const verdict = verifyVersion(rec, keys, this.verifyOpts);
    if (!verdict.ok) {
      if (viewer.tenantId !== null)
        await this.audit
          .record({
            tenantId: viewer.tenantId,
            actor: { type: "system", id: "registry" },
            action: "registry.verify",
            decision: "DENY",
            reason: `target=${rec.namespace}/${rec.name}@${rec.version} checks=${verdict.failures.join(",")}`,
          })
          .catch(() => undefined);
      throw new RegistryError(
        "verification_failed",
        `verification failed for ${rec.namespace}/${rec.name}@${rec.version}`,
        verdict.failures,
      );
    }
    return {
      namespace: rec.namespace,
      name: rec.name,
      version: rec.version,
      contentHash: rec.contentHash,
      riskLevel: rec.riskLevel,
      abl: JSON.parse(rec.abl) as AblDocument,
      record: rec,
      state: row.status.state,
      statusReason: row.status.reason,
      verification: verdict,
    };
  }

  /** One exact version, verified. A yanked version is returned only with `allowYanked` (pinned installs). */
  async getVersion(
    viewer: Viewer,
    ns: string,
    name: string,
    version: string,
    opts: { allowYanked?: boolean } = {},
  ): Promise<ResolvedBlueprint> {
    const row = await this.store.getVersion(viewer, ns, name, version);
    if (!row) throw notFound("version not found");
    if (row.status.state === "yanked" && !opts.allowYanked) throw notFound("version is yanked");
    return this.verifiedRow(viewer, row);
  }

  /**
   * `ns/name@range` -> the highest satisfying, non-yanked version, VERIFIED (blueprint hash, signature, key validity at publish time,
   * provenance). Fails closed: if the best candidate does not verify, resolution FAILS; it never silently falls back to an older
   * version (that would let an attacker steer you to a stale one).
   */
  async resolve(
    viewer: Viewer,
    ref: string | ParsedRef,
    opts: ResolveOptions = {},
  ): Promise<ResolvedBlueprint> {
    const r = typeof ref === "string" ? parseRef(ref) : ref;
    const range = parseRange(r.range);
    const ns = await this.store.getNamespace(viewer, r.namespace);
    if (!ns) throw notFound("blueprint not found");
    const rows = await this.store.listVersions(viewer, r.namespace, r.name);
    const live = rows.filter((x) => opts.allowYanked === true || x.status.state !== "yanked");
    const best = maxSatisfying(
      live.map((x) => x.record.version),
      range,
    );
    if (best === undefined) throw notFound("no version satisfies the range");
    const row = live.find((x) => x.record.version === best) as VersionRow;
    if (
      opts.notBelow !== undefined &&
      compareVersions(parseVersion(best), parseVersion(opts.notBelow)) < 0
    )
      throw new RegistryError(
        "verification_failed",
        "resolved version is older than the pinned lock (rollback)",
        ["rollback"],
      );
    return this.verifiedRow(viewer, row);
  }
}
