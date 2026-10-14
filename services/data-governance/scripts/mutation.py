#!/usr/bin/env python3
# ruff: noqa: E501, S603, S607, T201
"""Mutation check of the safety logic: each mutant edits one source line, the relevant tests MUST fail, the file is restored.
Run: uv run python services/data-governance/scripts/mutation.py   (needs PostgreSQL 16 via infra/scripts/with-pg.sh)"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATEWAY = ROOT.parents[1] / "apps/api-gateway"
# A mutant is (name, path, old, new, tests) or (..., tests, cwd): `path` is relative to the service, `cwd` is where vitest runs
# (the gateway's governance adapter has no database, so its tests need none).
MUTANTS = [
    (
        "skip the verification pass",
        "src/dsar.ts",
        "if (residual.length > 0) {",
        "if (false as boolean) {",
        ["test/dsar.test.ts"],
    ),
    (
        "purge held data (class-wide hold ignored)",
        "src/retention.ts",
        "const wide = classWideHold(holds, cls);",
        "const wide = undefined as ReturnType<typeof classWideHold>;",
        ["test/retention.test.ts"],
    ),
    (
        "purge held subjects (protection list dropped)",
        "src/retention.ts",
        "protect: { subjects: protect },",
        "protect: { subjects: [] },",
        ["test/retention.test.ts"],
    ),
    (
        "request lookup ignores the tenant (cross-tenant erase)",
        "src/store.ts",
        "const r = this.requests.get(`${t}|${id}`);\n    return r && clone(r);",
        "const r = [...this.requests.values()].find((x) => x.id === id);\n    return r && clone(r);",
        ["test/dsar.test.ts"],
    ),
    (
        "raw PII into audit (guard off + identifier in reason)",
        "src/dsar.ts",
        "reason: `kind=${i.kind}`,",
        "reason: `kind=${i.kind} ${ids[0]?.value ?? ''}`,",
        ["test/dsar.test.ts"],
    ),
    (
        "audit PII guard disabled",
        "src/audit.ts",
        "if (needle.length >= MIN_SCAN && text.includes(needle))",
        "if (false as boolean)",
        ["test/dsar.test.ts"],
    ),
    (
        "residency default-allow for unknown tenant",
        "src/residency.ts",
        'if (!t || canon(t.homeRegion) === "") return [];',
        'if (!t || canon(t.homeRegion) === "") return ["*", canon("")];',
        ["test/residency.test.ts"],
    ),
    (
        "residency permits everything",
        "src/residency.ts",
        'if (region === undefined || canon(region) === "") return false;\n    return (await this.allowedRegions(tenantId)).includes(canon(region));',
        "return true;",
        ["test/residency.test.ts"],
    ),
    (
        "export egress check skipped",
        "src/dsar.ts",
        "await this.d.residency.assertEgress(r.tenantId, dest);",
        "void dest;",
        ["test/dsar.test.ts"],
    ),
    (
        "retention floor not enforced",
        "src/retention.ts",
        'if (requestedDays < min) return { days: min, clamped: "min" };',
        "if (requestedDays < min) return { days: requestedDays, clamped: null };",
        ["test/retention.test.ts"],
    ),
    (
        "crypto-shred skipped",
        "src/dsar.ts",
        "await this.d.store.shredSubject(r.tenantId, r.subjectId, this.now());",
        "",
        ["test/dsar.test.ts"],
    ),
    (
        "erase allowed before requester verification",
        "src/dsar.ts",
        'if (r.status === "received")\n      throw new GovernanceError("not_verified", "requester is not verified");\n    if (r.status !== "verified" && r.status !== "processing")',
        'if (r.status !== "verified" && r.status !== "processing" && r.status !== "received")',
        ["test/dsar.test.ts"],
    ),
    (
        "subject hold ignored on erase",
        "src/dsar.ts",
        "const sub = subjectScopedHolds(holds, cls).find(",
        "const sub = ([] as typeof holds).find(",
        ["test/dsar.test.ts"],
    ),
    (
        "sole owner can be erased",
        "src/providers/members.ts",
        "if (Number((o.rows[0] as { n: string }).n) === 0)",
        "if (false as boolean)",
        ["test/pg.test.ts"],
    ),
    (
        "verifier: the opener may attest its own request (dual control off)",
        "src/verifier.ts",
        "if (attest.m === req.requestedBy || attest.m === req.verifiedBy)",
        "if (false as boolean)",
        ["test/verifier.test.ts"],
    ),
    (
        "verifier: the attester is not looked up in the tenant's admins",
        "src/verifier.ts",
        'if (!(await this.directory.isTenantAdmin(req.tenantId, attest.m))) return refuse("attester");',
        "",
        ["test/verifier.test.ts"],
    ),
    (
        "verifier: expired tokens accepted",
        "src/verifier.ts",
        "c.exp * 1000 <= this.now().getTime()",
        "false as boolean",
        ["test/verifier.test.ts"],
    ),
    (
        "verifier: the requester token is not bound to the subject",
        "src/verifier.ts",
        "requester.s !== req.subjectRef",
        "false as boolean",
        ["test/verifier.test.ts"],
    ),
    (
        "verifier: a directory failure lets the request through",
        "src/verifier.ts",
        '      return refuse("error");',
        '      return { ok: true, method: "error" };',
        ["test/verifier.test.ts"],
    ),
    (
        "attester directory ignores deprovisioned members",
        "src/pg-ports.ts",
        "WHERE id = $1 AND status = 'active' AND role IN ('owner', 'admin')",
        "WHERE id = $1 AND role IN ('owner', 'admin')",
        ["test/kit.pg.test.ts"],
    ),
    (
        "attester directory accepts any role",
        "src/pg-ports.ts",
        "WHERE id = $1 AND status = 'active' AND role IN ('owner', 'admin')",
        "WHERE id = $1 AND status = 'active'",
        ["test/kit.pg.test.ts"],
    ),
    (
        "audit sink failure is swallowed (not fail-closed)",
        "src/audit.ts",
        'throw new GovernanceError("unavailable", "audit append failed; refusing to proceed");',
        "return undefined as never;",
        ["test/dsar.test.ts"],
    ),
    (
        "gateway adapter: any role may write",
        "../../apps/api-gateway/src/adapters/governance.ts",
        "if (!GOVERNANCE_WRITE_ROLES.has(p.role))",
        "if (false as boolean)",
        ["test/governance.test.ts"],
        GATEWAY,
    ),
    (
        "gateway adapter: any role may read",
        "../../apps/api-gateway/src/adapters/governance.ts",
        "if (!GOVERNANCE_READ_ROLES.has(p.role))",
        "if (false as boolean)",
        ["test/governance.test.ts"],
        GATEWAY,
    ),
    (
        "gateway adapter: the unconfigured gateway answers an empty success instead of 503",
        "../../apps/api-gateway/src/adapters/governance.ts",
        'throw new PortUnavailable("the data-governance service is not configured on this gateway");',
        "return undefined as never;",
        ["test/governance.test.ts"],
        GATEWAY,
    ),
    (
        "gateway adapter: an unresolved region is an empty success",
        "../../apps/api-gateway/src/adapters/governance.ts",
        'if (!t) throw new GovernanceError("unavailable", "the tenant\'s residency policy is unavailable");',
        "",
        ["test/governance.test.ts"],
        GATEWAY,
    ),
    (
        "gateway: a residency refusal is an internal error, not a 403",
        "../../apps/api-gateway/src/server.ts",
        '(e as { code?: unknown }).code === "region_mismatch"',
        "false as boolean",
        ["test/governance.test.ts"],
        GATEWAY,
    ),
]


def run(tests, cwd=ROOT):
    pg = ["bash", str(ROOT.parents[1] / "infra/scripts/with-pg.sh")] if cwd == ROOT else []
    r = subprocess.run(
        [*pg, "npx", "vitest", "run", *tests],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return r.returncode


survivors = []
for name, path, old, new, tests, *rest in MUTANTS:
    cwd = rest[0] if rest else ROOT
    f = ROOT / path
    src = f.read_text()
    if old not in src:
        print(f"SKIP (pattern not found): {name}")
        survivors.append(name + " [pattern missing]")
        continue
    f.write_text(src.replace(old, new, 1))
    try:
        rc = run(tests, cwd)
    finally:
        f.write_text(src)
    print(("killed   " if rc != 0 else "SURVIVED ") + name)
    if rc == 0:
        survivors.append(name)
print(f"{len(MUTANTS) - len(survivors)}/{len(MUTANTS)} killed")
sys.exit(1 if survivors else 0)
