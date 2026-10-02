/* global console, process */
// Mutation check for the control plane's safety logic: apply one mutant (one or more coordinated edits) at a time, run the suite,
// and require a FAILURE. A surviving mutant means a safety property is untested. Mutants that disable a redundant layer (service
// check AND the store/policy check behind it) are listed as one mutant so defence in depth is not mistaken for an equivalent mutant.
// Usage (from services/control-plane, needs PG via infra/scripts/with-pg.sh): node scripts-mutation.mjs [filter]
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const M = [
  // ---- authorization (fail-closed, tenant, ceiling, scopes)
  ["authz: skip tenant check (code and policy attribute)", [
    ["src/authz.ts", 'if (!sameTenant) return DENY("resource belongs to another tenant", version);', ""],
    ["src/authz.ts", "same_tenant: sameTenant,", "same_tenant: true,"],
  ]],
  ["authz: skip role ceiling (code and policy attribute)", [
    ["src/authz.ts", 'if (!ceiling) return DENY("role above the caller\'s own", version);', ""],
    ["src/authz.ts", "within_ceiling: ceiling,", "within_ceiling: true,"],
  ]],
  ["roles: ceiling always true", [["src/roles.ts", "ROLE_RANK[target] <= ROLE_RANK[actor]", "true"]]],
  ["authz: ignore API key scopes", [["src/authz.ts", 'if (p.credential === "api_key" && !scopeAllows(p.scopes, req.action))', "if (false)"]]],
  ["authz: accept non-ALLOW decisions", [["src/authz.ts", 'if (r.decision !== "ALLOW") return', "if (false) return"]]],
  ["authz: ignore evaluation time budget", [["src/authz.ts", 'if (this.clock() - t0 > this.timeoutMs) return DENY("policy evaluation exceeded its time budget", version);', ""]]],
  ["authz: ALLOW on evaluation error", [["src/authz.ts", 'return DENY("policy evaluation error", version);', 'return { allowed: true, decision: "ALLOW", reason: "", policyVersion: version, winners: [] };']]],
  ["authz: ALLOW when no policy is loaded", [["src/authz.ts", 'if (!this.o) return DENY("no policy loaded", version);', 'if (!this.o) return { allowed: true, decision: "ALLOW", reason: "", policyVersion: version, winners: [] };']]],
  ["authz: malformed result allowed", [["src/authz.ts", 'if (typeof raw !== "object" || raw === null) return DENY("malformed policy result", version);', 'if (typeof raw !== "object" || raw === null) return { allowed: true, decision: "ALLOW", reason: "", policyVersion: version, winners: [] };']]],
  ["crypto: constant-time compare always true", [["src/crypto.ts", "return timingSafeEqual(a, b);", "return true;"]]],
  ["crypto: accept bad token signature", [["src/crypto.ts", "if (!safeEqual(want, fromB64u(sig))) return undefined;", ""]]],
  ["crypto: token purpose not bound", [["src/crypto.ts", 'const want = hmac(k.key, purpose, "\\0", kid, ".", body);', 'const want = hmac(k.key, "p", "\\0", kid, ".", body);'], ["src/crypto.ts", 'b64u(hmac(k.key, purpose, "\\0", k.kid, ".", body))', 'b64u(hmac(k.key, "p", "\\0", k.kid, ".", body))']]],
  // ---- admin service
  ["admin: ignore the authorization decision", [["src/admin.ts", "if (!dec.allowed) return this.deniedAudit(p, action, dec, detail);", "if (false) return this.deniedAudit(p, action, dec, detail);"]]],
  ["admin: do not audit allowed mutations", [["src/admin.ts", "    if (mutation) {\n      await this.d.audit.record({", "    if (false) {\n      await this.d.audit.record({"]]],
  ["admin: no region pin on writes", [["src/admin.ts", "if (mutation) await this.d.region.assertWritable(p.tenantId);", ""]]],
  ["admin: last owner can be demoted/removed (service and both stores)", [
    ["src/admin.ts", 'if (cur.role === "owner" && role !== "owner") await this.assertNotLastOwner(p.tenantId, cur.id);', ""],
    ["src/admin.ts", 'if (cur.role === "owner") await this.assertNotLastOwner(p.tenantId, cur.id);', ""],
    ["src/memory-store.ts", "if (others.length === 0) return Promise.reject(new LastOwnerError());", ""],
    ["src/pg-store.ts", "if ((o.rows[0] as { n: number }).n === 0) throw new LastOwnerError();", ""],
  ]],
  ["admin: removed member keeps sessions", [["src/admin.ts", 'const sessions = await this.d.sessions.revokeAllOfMember(p.tenantId, mid, "member_removed");', "const sessions = 0;"]]],
  ["admin: removed member keeps API keys", [["src/admin.ts", "const keys = await this.d.store.revokeApiKeysOfMember(p.tenantId, mid, this.now());\n      return { result: undefined, outputs: { member: mid, sessions, keys } };", "const keys = 0;\n      return { result: undefined, outputs: { member: mid, sessions, keys } };"]]],
  ["admin: ids are not validated as UUIDs", [["src/admin.ts", "if (typeof v !== \"string\" || !UUID.test(v)) throw notFound();", "if (typeof v !== \"string\") throw notFound();"]]],
  ["admin: missing resource answers 404 before authorizing", [["src/admin.ts", "if (!dec.allowed) return this.deniedAudit(p, action, dec, detail);\n    if (opts.missing) throw notFound();", "if (opts.missing) throw notFound();\n    if (!dec.allowed) return this.deniedAudit(p, action, dec, detail);"]]],
  ["admin: audit retention can be shortened", [["src/admin.ts", "if (audit !== undefined && audit < cur.retentionAuditDays) throw conflict", "if (false) throw conflict"]]],
  ["admin: JIT can create owners", [["src/admin.ts", 'if (!isExternalRole(role)) throw invalid("JIT can never create an owner");', ""]]],
  // ---- stores: tenant scoping
  ["memory store: getMember ignores tenant", [["src/memory-store.ts", "const m = this.members.get(k(t, id));\n    return Promise.resolve(m && { ...m });", "const m = [...this.members.values()].find((x) => x.id === id);\n    return Promise.resolve(m && { ...m });"]]],
  ["memory store: getApiKey ignores tenant", [["src/memory-store.ts", "const x = this.keys.get(k(t, id));\n    return Promise.resolve(x && { ...x });", "const x = [...this.keys.values()].find((y) => y.id === id);\n    return Promise.resolve(x && { ...x });"]]],
  ["memory store: refresh rotation not compare-and-set", [["src/memory-store.ts", "if (!s || s.revokedAt || !safeEqual(s.refreshHash, expected)) return Promise.resolve(false);", "if (!s || s.revokedAt) return Promise.resolve(false);"]]],
  ["pg store: refresh rotation not compare-and-set", [["src/pg-store.ts", "WHERE tenant_id = $1 AND id = $2 AND refresh_hash = $3 AND revoked_at IS NULL", "WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL"]]],
  // ---- sessions
  ["sessions: accept expired access token", [["src/sessions.ts", "if (exp * 1000 <= now.getTime()) return undefined;", ""]]],
  ["sessions: accept revoked session", [["src/sessions.ts", "if (!sess || sess.memberId !== m || sess.revokedAt || sess.expiresAt.getTime() <= now.getTime()) return undefined;", "if (!sess || sess.memberId !== m || sess.expiresAt.getTime() <= now.getTime()) return undefined;"]]],
  ["sessions: accept past absolute lifetime", [["src/sessions.ts", "if (!sess || sess.memberId !== m || sess.revokedAt || sess.expiresAt.getTime() <= now.getTime()) return undefined;", "if (!sess || sess.memberId !== m || sess.revokedAt) return undefined;"]]],
  ["sessions: accept inactive member", [["src/sessions.ts", 'if (!member || member.status !== "active") return undefined;', "if (!member) return undefined;"]]],
  ["sessions: no refresh-reuse detection", [["src/sessions.ts", "if (sess.prevRefreshHash && safeEqual(sess.prevRefreshHash, presented)) {", "if (false) {"]]],
  ["sessions: refresh ignores revocation", [["src/sessions.ts", "if (!sess || sess.revokedAt || sess.expiresAt.getTime() <= now.getTime()) throw unauthenticated(\"invalid refresh token\");", "if (!sess) throw unauthenticated(\"invalid refresh token\");"]]],
  ["sessions: access token outlives the session", [["src/sessions.ts", "return new Date(Math.min(now.getTime() + this.accessTtl * 1000, sessionExpiresAt.getTime()));", "return new Date(now.getTime() + this.accessTtl * 1000);"]]],
  ["sessions: issue to inactive member", [["src/sessions.ts", 'if (member.status !== "active") throw unauthenticated("member is not active");', ""]]],
  // ---- API keys
  ["apikeys: plaintext key stored", [["src/apikeys.ts", "keyHash: this.hash(full),", "keyHash: Buffer.from(full),"], ["src/apikeys.ts", 'return hmac(this.o.pepper, "apikey\\0", fullKey);', "return Buffer.from(fullKey);"]]],
  ["apikeys: unkeyed hash", [["src/apikeys.ts", 'return hmac(this.o.pepper, "apikey\\0", fullKey);', "return sha256(fullKey);"]]],
  ["apikeys: skip constant-time hash check (and store filter)", [
    ["src/apikeys.ts", "if (!rec || !safeEqual(rec.keyHash, hash)) return undefined;", "if (!rec) return undefined;"],
    ["src/memory-store.ts", "x.prefix === prefix && safeEqual(x.keyHash, hash)", "x.prefix === prefix"],
  ]],
  ["apikeys: accept revoked", [["src/apikeys.ts", "if (rec.revokedAt) return undefined;", ""]]],
  ["apikeys: accept expired", [["src/apikeys.ts", "if (rec.expiresAt && rec.expiresAt.getTime() <= now.getTime()) return undefined;", ""]]],
  ["apikeys: accept key of inactive owner", [["src/apikeys.ts", 'if (!owner || owner.status !== "active") return undefined;', "if (!owner) return undefined;"]]],
  ["apikeys: rotate keeps the old key alive", [["src/apikeys.ts", "await this.o.store.updateApiKey(p.tenantId, old.id, { revokedAt: this.now() });\n    return created;", "return created;"]]],
  ["apikeys: key format not enforced", [["src/apikeys.ts", "if (!m) return undefined;\n    const hash", "if (!m) return undefined;\n    void 0;\n    const hash"], ["src/apikeys.ts", "const KEY_RE = /^axk_([0-9a-f]{16})_([A-Za-z0-9_-]{43})$/;", "const KEY_RE = /^axk_([0-9a-f]{16})_(.*)$/;"]]],
  // ---- SCIM / directory
  ["scim: deprovision keeps sessions", [["src/directory.ts", 'const sessions = await this.o.sessions.revokeAllOfMember(ctx.tenantId, m.id, "deprovisioned");', "const sessions = 0;"]]],
  ["scim: deprovision keeps API keys", [["src/directory.ts", "const keys = await this.o.store.revokeApiKeysOfMember(ctx.tenantId, m.id, this.now());", "const keys = 0;"]]],
  ["scim: directory sees users it did not provision", [["src/directory.ts", "return m && m.directoryId === ctx.directory.id ? m : undefined;", "return m;"]]],
  ["scim: roles of owners recomputed", [["src/directory.ts", 'if (m.role === "owner" || m.directoryId !== ctx.directory.id) return m;', "if (false) return m;"]]],
  ["scim: group may map to owner", [["src/directory.ts", 'if (role !== undefined && !isExternalRole(role)) throw invalid("a directory group can never map to owner");', ""]]],
  ["scim: revoked directory still authenticates", [["src/directory.ts", 'if (!d || d.status !== "active") return undefined;\n    await', "if (!d) return undefined;\n    await"]]],
  ["scim: token not required to match lookup (any bearer shape)", [["src/directory.ts", "if (!m || !tm) return undefined;", "if (!m) return undefined;"]]],
  ["scim: unsupported filter attributes accepted", [["src/scim.ts", "if (!FILTER_ATTRS.has(attr)) throw", "if (false) throw"]]],
  ["scim: filter 'or' accepted as a single term", [["src/scim.ts", 'if (!m) throw new ScimFail(400, `unsupported filter expression: ${p.trim().slice(0, 60)}`, "invalidFilter");', 'if (!m) return { attr: "id", op: "pr" };']]],
  ["scim: non-owner external role cap removed from default role", [["src/directory.ts", 'if (!isExternalRole(defaultRole)) throw invalid("defaultRole must be an external role (never owner)");', ""]]],
  ["scim: foreign member ids accepted into a group", [["src/directory.ts", 'if (!m) throw invalid(`unknown member ${id}`);', "if (!m) continue;"]]],
  // ---- SSO
  ["sso: state not compared", [["src/sso.ts", 'if (!safeEqual(sha256(q.state), sha256(c.s))) throw unauthenticated("state mismatch"); // login CSRF', ""]]],
  ["sso: expired attempt accepted", [["src/sso.ts", 'if (c.exp <= now) throw unauthenticated("login attempt expired");', ""]]],
  ["sso: attempt replay accepted", [["src/sso.ts", 'if (this.spent.has(c.s)) throw unauthenticated("login attempt already used");', ""]]],
  ["sso: nonce not checked", [["src/sso.ts", 'if (!safeEqual(sha256(profile.nonce), sha256(c.n))) return this.deny(tenantId, "nonce_mismatch", profile.id);', ""]]],
  ["sso: OIDC without nonce accepted", [["src/sso.ts", '} else if (profile.connectionType === "oidc") return this.deny(tenantId, "nonce_missing", profile.id);', "}"]]],
  ["sso: IdP organization not matched to the request", [["src/sso.ts", "if (!conn || profile.organizationId !== c.o) throw", "if (!conn) throw"]]],
  ["sso: login cookie is unsigned", [
    ["src/sso.ts", "const cookie = b64u(seal(this.o.cookieKey, Buffer.from(JSON.stringify(payload)), COOKIE_AAD));", "const cookie = b64u(Buffer.from(JSON.stringify(payload)));"],
    ["src/sso.ts", 'JSON.parse(open(this.o.cookieKey, fromB64u(cookie), COOKIE_AAD).toString("utf8"))', 'JSON.parse(fromB64u(cookie).toString("utf8"))'],
  ]],
  ["sso: open redirect (absolute path passthrough)", [["src/sso.ts", 'if (raw.startsWith("/")) return raw.startsWith("//") ? "/" : raw;', 'if (raw.startsWith("/")) return raw;']]],
  ["sso: open redirect (any origin)", [["src/sso.ts", "return allowedOrigins.includes(u.origin) ? u.toString() : \"/\";", "return u.toString();"]]],
  ["sso: JIT without verified domain", [["src/sso.ts", 'if (!d || d.status !== "verified") return this.deny(tenantId, "domain_not_verified", p.id);', ""]]],
  ["sso: JIT without verified e-mail", [["src/sso.ts", 'if (!p.emailVerified) return this.deny(tenantId, "email_unverified", p.id);', ""]]],
  ["sso: JIT when disabled", [["src/sso.ts", 'if (!enabled) return this.deny(tenantId, "jit_disabled", p.id);', ""]]],
  ["sso: deprovisioned member signs in", [["src/sso.ts", 'if (member.status !== "active") return this.deny(tenantId, "member_deprovisioned", member.id);', ""]]],
  ["sso: unverified e-mail claims existing member", [["src/sso.ts", "if (!member && profile.emailVerified)", "if (!member)"]]],
  ["sso: PKCE not enforced by the IdP fake binding", [["src/sso.ts", "codeVerifier: c.v,", 'codeVerifier: "x",']]],
  // ---- domains
  ["domains: verification does not check the proof", [["src/domains.ts", "if (!ok) throw invalid(\"verification record not found\");", ""]]],
  ["domains: public mail domains claimable", [["src/domains.ts", "if (FORBIDDEN.has(d)) throw invalid(\"this domain cannot be claimed\");", ""]]],
  // ---- BYO keys
  ["modelkeys: secret stored in plaintext", [["src/modelkeys.ts", 'const box = seal(dek, Buffer.from(value, "utf8"), aad(p.tenantId, provider, label));', 'const box = Buffer.concat([Buffer.alloc(12), Buffer.from(value, "utf8")]);'], ["src/modelkeys.ts", 'return open(dek, rec.nonceAndCiphertext, aad(tenantId, provider, label)).toString("utf8");', 'return rec.nonceAndCiphertext.subarray(12).toString("utf8");']]],
  ["modelkeys: ciphertext not bound to tenant/provider/label", [["src/modelkeys.ts", "`axis-byo:${tenantId}:${provider}:${label}`", '"axis-byo"']]],
  ["kms: wrapped key not bound to tenant", [["src/kms.ts", "`axis-kms:${tenantId}:${this.activeKeyId}`", "`axis-kms:${this.activeKeyId}`"], ["src/kms.ts", "`axis-kms:${tenantId}:${keyId}`", "`axis-kms:${keyId}`"]]],
  ["modelkeys: secret returned to the admin caller", [["src/modelkeys.ts", "  id: r.id,\n  provider: r.provider,", "  id: r.id,\n  secret: r.nonceAndCiphertext.toString('utf8'),\n  provider: r.provider,"]]],
  // ---- policies / provisioning
  ["policies: baseline-deny can be deactivated", [["src/policies.ts", "if (packName === BASELINE_PACK) throw conflict(", "if (false) throw conflict("]]],
  ["policies: activation does not re-validate the set", [["src/policies.ts", "const r = this.validate(docs);\n    if (!r.ok) throw issuesToError(r.issues);\n    await this.o.store.activatePackVersion", "const r = { ok: true as const, policyVersion: 'x', rego: '' };\n    await this.o.store.activatePackVersion"]]],
  ["policies: publish does not validate", [["src/policies.ts", "const v = this.validate([doc]);\n    if (!v.ok) throw issuesToError(v.issues);", "const v = { ok: true as const, policyVersion: 'x', rego: '' };"]]],
  ["provisioning: baseline-deny not required", [["src/provisioning.ts", 'if (!packs.some((p) => p.name === BASELINE_PACK)) throw new CpError("unavailable", "the baseline-deny pack is required");', ""]]],
  ["provisioning: any region accepted", [["src/provisioning.ts", "if (i.region !== this.o.region)", "if (false)"]]],
  // ---- tenancy router / region
  ["tenancy: missing placement falls through", [["src/tenancy.ts", 'if (!placement) throw new CpError("unavailable", "tenant has no placement");', "if (!placement) return { tier: \"shared_rls\", pool: this.o.shared, poolKey: undefined };"]]],
  ["tenancy: dedicated tenant without pool uses shared", [["src/tenancy.ts", 'if (!pool) throw new CpError("unavailable", `no pool is configured for ${placement.isolationTier} tenant placement`);', "if (!pool) return { tier: placement.isolationTier, pool: this.o.shared, poolKey: placement.poolKey };"]]],
  ["tenancy: dedicated may alias the shared pool", [["src/tenancy.ts", 'if (pool === this.o.shared) throw new CpError("unavailable", "a dedicated placement must not resolve to the shared pool");', ""]]],
  ["tenancy: placement errors fall through to shared", [["src/tenancy.ts", 'throw new CpError("unavailable", "tenant placement unavailable");', "return { tier: \"shared_rls\", pool: this.o.shared, poolKey: undefined };"]]],
  ["tenancy: region guard disabled", [["src/tenancy.ts", "if (t.region !== this.region)", "if (false)"]]],
  // ---- HTTP
  ["http: no CSRF check for cookie auth", [["src/http.ts", 'if (unsafe && !equalToken(c[COOKIE_CSRF], req.headers["x-axis-csrf"] as string | undefined)) throw forbidden("CSRF token missing or wrong");', ""]]],
  ["http: tenant_id accepted in bodies", [["src/http.ts", "if (/^tenant[_-]?id$/i.test(k)) throw invalid(", "if (false) throw invalid("]]],
  ["http: cookies not Secure", [["src/http.ts", '${secure ? "; Secure" : ""}', ""]]],
  ["http: cookies not HttpOnly", [["src/http.ts", '${httpOnly ? "; HttpOnly" : ""}', ""]]],
  ["http: session cookies SameSite=None-ish (Lax)", [["src/http.ts", '${COOKIE_ACCESS}=${sess.accessToken}; ${flags(accessAge, "Strict")}', '${COOKIE_ACCESS}=${sess.accessToken}; ${flags(accessAge, "Lax")}']]],
  ["http: 500 leaks internals", [["src/http.ts", 'return problem(res, 500, "internal", "internal error");', "return problem(res, 500, \"internal\", String(err));"]]],
  ["http: platform token not checked", [["src/http.ts", "if (!d.platformToken || !equalToken(m?.[1], d.platformToken)) throw unauthenticated();", ""]]],
  ["http: dev token not checked", [["src/http.ts", "if (!d.devToken || !equalToken(m?.[1], d.devToken)) throw unauthenticated();", ""]]],
  ["http: body size unlimited", [["src/http.ts", "if (size > MAX_BODY) big = true;", "if (false) big = true;"]]],
  ["http: refresh via cookie without CSRF", [["src/http.ts", 'if (!equalToken(c[COOKIE_CSRF], req.headers["x-axis-csrf"] as string | undefined)) throw forbidden("CSRF token missing or wrong");\n      }', "}"]]],
  ["http: IdP webhook signature unchecked", [["src/http.ts", 'ev = d.idp.parseDirectoryEvent(raw, req.headers["x-idp-signature"] as string | undefined);', "ev = JSON.parse(raw);"]]],
  ["idp fake: webhook signature accepted when wrong", [["src/idp.ts", "if (!signature || !safeEqual(Buffer.from(this.signWebhook(rawBody)), Buffer.from(signature))) throw new Error(\"bad webhook signature\");", ""]]],
];

const only = process.argv[2];
let survived = 0;
let ran = 0;
for (const [name, edits] of M) {
  if (only && !name.includes(only)) continue;
  ran++;
  const origs = new Map();
  let missing = false;
  for (const [file, from] of edits) {
    if (!origs.has(file)) origs.set(file, readFileSync(file, "utf8"));
    if (!origs.get(file).includes(from)) {
      console.log(`SKIP (pattern gone): ${name}: ${from.slice(0, 60)}`);
      missing = true;
    }
  }
  if (missing) {
    survived++;
    continue;
  }
  const work = new Map(origs);
  for (const [file, from, to] of edits) work.set(file, work.get(file).replace(from, to));
  for (const [file, text] of work) writeFileSync(file, text);
  const r = spawnSync("bash", ["../../infra/scripts/with-pg.sh", "pnpm", "exec", "vitest", "run", "--bail", "1"], { encoding: "utf8" });
  for (const [file, text] of origs) writeFileSync(file, text);
  const killed = r.status !== 0;
  if (!killed) survived++;
  console.log(`${killed ? "killed  " : "SURVIVED"} ${name}`);
}
console.log(`${ran - survived}/${ran} mutants killed`);
process.exit(survived ? 1 : 0);
