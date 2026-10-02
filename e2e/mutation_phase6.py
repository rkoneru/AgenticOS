"""Mutation check for the Phase 6 wiring (run by hand: ``uv run python e2e/mutation_phase6.py [name-substring ...]``; needs PG like `make e2e-phase6`).

Each mutant breaks ONE safety or accuracy property of the new wiring in the working tree, rebuilds the TS packages when a TS file
changed, runs ``test_phase6_saas.py`` (a stateful scenario: it stops at the first failure) and requires a FAILURE of a real test
(a stack that fails to start does not count). Sources are restored afterwards. Exit code 0 only if every mutant was killed.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
E2E = "e2e/test_phase6_saas.py"


@dataclass(frozen=True)
class Mutant:
    name: str
    edits: tuple[tuple[str, str, str], ...]  # (file, old, new)


MUTANTS = [
    Mutant(
        "tenant policy not loaded: activation does not publish the bundle for the kernel",
        (
            (
                "services/control-plane/src/admin.ts",
                "      const r = await this.d.policies.activate(p, vid);\n      await this.d.bundles?.publish(p.tenantId);\n",
                "      const r = await this.d.policies.activate(p, vid);\n",
            ),
        ),
    ),
    Mutant(
        "no baseline floor published at signup",
        (
            (
                "services/control-plane/src/wire.ts",
                "    ...(bundles ? { afterProvision: (t: string) => bundles.publish(t).then(() => undefined) } : {}),\n",
                "",
            ),
        ),
    ),
    Mutant(
        "kernel serves a tenant with no bundle from another tenant's file (no fail-closed)",
        (
            (
                "services/risk-kernel/src/tenant-engine.ts",
                '      this.cache.delete(tenant);\n      return Promise.reject(new Error("no policy bundle for this tenant"));',
                "      return this.engineFor(Object.keys(Object.fromEntries(this.cache))[0] ?? tenant);",
            ),
        ),
    ),
    Mutant(
        "denied actions are billed (the ALLOW join is skipped)",
        (
            (
                "services/billing/src/emitters.ts",
                '        const id = str(d["action_id"]);\n        if (!id || !BILLABLE.has(decisions.get(id) ?? "")) {\n          skip(e, "no ALLOW decision for this action");\n          break;\n        }\n        const input',
                '        const id = str(d["action_id"]);\n        const input',
            ),
            (
                "services/billing/src/emitters.ts",
                '        const id = str(d["action_id"]);\n        const point = str(d["enforcement_point"]);\n        if (!id || !BILLABLE.has(decisions.get(id) ?? "")) {\n          skip(e, "no ALLOW decision for this action");\n          break;\n        }\n',
                '        const point = str(d["enforcement_point"]);\n',
            ),
        ),
    ),
    Mutant(
        "tenant taken from the request body instead of the credential",
        (
            (
                "services/billing/src/dev-server.ts",
                '    const t = auth.tenantId;\n    if (b["tenant_id"] !== undefined && b["tenant_id"] !== t) throw new Forbidden();\n    if (path === "run-events") {',
                '    const t = typeof b["tenant_id"] === "string" ? b["tenant_id"] : auth.tenantId;\n    if (path === "run-events") {',
            ),
        ),
    ),
    Mutant(
        "usage dedupe skipped (a replay inserts again)",
        (
            (
                "services/billing/src/emitters.ts",
                "idempotencyKey: `run:${runId}:${e.seq}:${meter}`,",
                "idempotencyKey: `run:${runId}:${e.seq}:${meter}:${Math.random()}`,",
            ),
        ),
    ),
    Mutant(
        "a live Stripe key is accepted",
        (
            (
                "services/billing/src/stripe.ts",
                "const TEST_KEY_RE = /^(sk|rk)_test_[A-Za-z0-9]{8,}$/;",
                "const TEST_KEY_RE = /^(sk|rk)_(test|live)_[A-Za-z0-9]{8,}$/;",
            ),
        ),
    ),
    Mutant(
        "metering sent inside the cancellation (runs stopped by a budget or a kill are never billed)",
        (
            (
                "runtime/src/axis_runtime/run.py",
                "    task = asyncio.ensure_future(send())\n    cancelled = False\n    while not task.done():\n        try:\n            await asyncio.shield(task)\n        except asyncio.CancelledError:\n            cancelled = True  # honoured once the (bounded) send is over\n    if cancelled:\n        raise asyncio.CancelledError\n",
                "    await send()\n",
            ),
        ),
    ),
    Mutant(
        "the run never emits its usage (RunDeps.usage hook dropped)",
        (
            (
                "runtime/src/axis_runtime/run.py",
                "            if deps.usage is not None:\n                await emit_usage(deps.usage, deps.log, run_id)\n",
                "",
            ),
        ),
    ),
    Mutant(
        "the control plane's tenant budgets are not applied to the TKI ledger",
        (
            (
                "runtime/src/axis_runtime/tenant_budgets.py",
                "        ledger.ensure_account(key, None, self.tenant_limits())\n        ledger.set_limits(\n            key, self.tenant_limits()\n        )  # the control plane's current config is authoritative\n",
                "        ledger.ensure_account(key, None, {})\n",
            ),
        ),
    ),
    Mutant(
        "a tenant budget can raise what the blueprint declares (merge takes the looser cap)",
        (
            (
                "runtime/src/axis_runtime/tenant_budgets.py",
                "            if lim is not None and lim.hard is not None:\n                hards.append(lim.hard)\n        hard = min(hards) if hards else None\n        soft = min(softs) if softs else None\n",
                "            if lim is not None and lim.hard is not None:\n                hards.append(lim.hard)\n        hard = max(hards) if hards else None\n        soft = max(softs) if softs else None\n",
            ),
        ),
    ),
    Mutant(
        "audit hashes integers only again (fractional budgets refused as 'audit unavailable')",
        (
            (
                "services/control-plane/src/audit.ts",
                "inputs_hash: hashJson(e.inputs ?? {}),",
                "inputs_hash: sha256Hex(canonicalize(e.inputs ?? {})),",
            ),
            (
                "services/control-plane/src/audit.ts",
                'import { hashJson, type AuditEvent, type AuditSink } from "@axis/contracts";',
                'import { canonicalize, sha256Hex, hashJson, type AuditEvent, type AuditSink } from "@axis/contracts";',
            ),
        ),
    ),
    Mutant(
        "dedicated placement falls back to the shared database",
        (
            (
                "services/control-plane/src/tenancy.ts",
                '    if (!pool)\n      throw new CpError(\n        "unavailable",\n        `no pool is configured for ${placement.isolationTier} tenant placement`,\n      );\n',
                "    if (!pool) return { tier: placement.isolationTier, pool: this.o.shared, poolKey: placement.poolKey };\n",
            ),
        ),
    ),
]


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)


def rebuild() -> None:
    out = run(["pnpm", "build"])
    if out.returncode != 0:
        raise RuntimeError(f"build failed:\n{out.stdout}\n{out.stderr}")


def main() -> int:
    only = sys.argv[1:]
    mutants = [m for m in MUTANTS if not only or any(o in m.name for o in only)]
    survived: list[str] = []
    for m in mutants:
        originals: dict[str, str] = {}
        try:
            for rel, old, new in m.edits:
                path = ROOT / rel
                originals.setdefault(rel, path.read_text())
                text = path.read_text()
                if old not in text:
                    raise RuntimeError(f"{m.name}: pattern not found in {rel}")
                path.write_text(text.replace(old, new, 1))
            if any(rel.startswith("services/") for rel in originals):
                rebuild()
            out = run(
                ["bash", "infra/scripts/with-pg.sh", "uv", "run", "pytest", E2E]
                + ["-p", "no:cacheprovider", "--no-cov", "-q", "-x"]
            )
            tail = (out.stdout + out.stderr).strip().splitlines()[-1]
            # killed = a test FAILED; an ERROR (the stack did not start) or no tests selected is not a kill
            killed = out.returncode != 0 and " failed" in tail and "error" not in tail
            print(f"{'KILLED  ' if killed else 'SURVIVED'} {m.name}  [{tail}]", flush=True)
            if not killed:
                survived.append(m.name)
        finally:
            for rel, text in originals.items():
                (ROOT / rel).write_text(text)
            if any(rel.startswith("services/") for rel in originals):
                rebuild()
    print(f"\n{len(mutants) - len(survived)}/{len(mutants)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
