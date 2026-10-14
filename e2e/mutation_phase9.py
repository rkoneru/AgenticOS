"""Mutation check for the Phase 9 wiring (run by hand: ``uv run python e2e/mutation_phase9.py [name-substring ...]``; needs PG like
`make e2e-phase9`).

Each mutant breaks ONE safety property of the compliance / governance / hardening work in the working tree, rebuilds if TypeScript changed,
runs the scenario tests that must notice (``test_phase9_hardening.py -k ...``) and requires a FAILURE of a real test (a stack that fails to
start is not a kill). Sources are restored afterwards (also on Ctrl-C); if the process is killed hard, ``git checkout -- .`` restores them.
Exit code 0 only if every mutant was killed.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = ["bash", "infra/scripts/with-pg.sh", "uv", "run", "pytest", "e2e/test_phase9_hardening.py"]
PY_ARGS = ["-p", "no:cacheprovider", "--no-cov", "-q", "-x"]


@dataclass(frozen=True)
class Mutant:
    name: str
    edits: tuple[tuple[str, str, str], ...]  # (file, old, new)
    k: str  # pytest -k expression: the scenario tests that must notice


DSAR = "services/data-governance/src/dsar.ts"
MUTANTS = [
    Mutant(
        "residual verification is skipped (the pass counts nothing and reports zero)",
        (
            (
                DSAR,
                "      const c = await prov.count(ctx, ids);\n      o.verify = c;",
                "      const c = { residual: 0, retained: 0, pseudonymised: 0 };\n      o.verify = c;",
            ),
        ),
        "test_a2",
    ),
    Mutant(
        "an erasure that leaves the memory behind AND a blind verification (the report says 'done')",
        (
            (
                DSAR,
                "      const c = await prov.count(ctx, ids);\n      o.verify = c;",
                "      const c = { residual: 0, retained: 0, pseudonymised: 0 };\n      o.verify = c;",
            ),
            (
                "services/data-governance/src/providers/memory.ts",
                'const ch = await c.query("DELETE FROM memory_chunks WHERE subject = ANY($1)", [s]);',
                'const ch = await c.query("DELETE FROM memory_chunks WHERE false AND subject = ANY($1)", [s]);',
            ),
        ),
        "test_a2",
    ),
    Mutant(
        "a retention purge ignores the legal hold and deletes held data",
        (
            (
                "services/data-governance/src/retention.ts",
                '      if (wide) {\n        base.status = "skipped_hold";',
                '      if (wide && Date.now() < 0) {\n        base.status = "skipped_hold";',
            ),
        ),
        "test_b2",
    ),
    Mutant(
        "the governance audit writes the raw subject identifiers into the chain (and its guard is off)",
        (
            (
                "services/data-governance/src/audit.ts",
                "    assertNoRawPii(event, s.raw ?? []);",
                '    (event as { reason?: string }).reason = (s.raw ?? []).join(",");',
            ),
        ),
        "test_a2",
    ),
    Mutant(
        "residency default-allow: the Eval Hub store does not ask the guard on insert",
        (
            (
                "services/eval-hub/src/docstore.ts",
                "  async insert<T>(tenantId: string, coll: string, key: string, data: T): Promise<Doc<T>> {\n    await this.o.residency?.assertWrite(tenantId);",
                "  async insert<T>(tenantId: string, coll: string, key: string, data: T): Promise<Doc<T>> {",
            ),
        ),
        "test_d2",
    ),
    Mutant(
        "residency default-allow: the billing ledger does not ask the guard",
        (
            (
                "services/billing/src/pg-ledger.ts",
                "    await this.o.residency?.assertWrite(v.tenantId);\n",
                "",
            ),
        ),
        "test_d3",
    ),
    Mutant(
        "residency default-allow: the registry does not ask the guard on insertVersion",
        (
            (
                "services/registry/src/pg-store.ts",
                "    await this.o.residency?.assertWrite(rec.tenantId);\n",
                "",
            ),
        ),
        "test_d1",
    ),
    Mutant(
        "residency default-allow: the policy permits every region",
        (
            (
                "services/data-governance/src/residency.ts",
                "    return (await this.allowedRegions(tenantId)).includes(canon(region));",
                "    return true;",
            ),
        ),
        "test_d1 or test_d2 or test_d3",
    ),
    Mutant(
        "residency default-allow: the model gateway skips the region check",
        (
            (
                "runtime/src/axis_runtime/models/gateway.py",
                "        allowed = self._policy(tenant_id).allowed_regions\n        if allowed is None:\n            return",
                "        return\n        allowed = self._policy(tenant_id).allowed_regions\n        if allowed is None:\n            return",
            ),
        ),
        "test_d4",
    ),
    Mutant(
        "redaction-net bypass: the run log keeps free text in a PHI run",
        (
            (
                "runtime/src/axis_runtime/phi_net.py",
                "    return {k: _scrub(v, str(k)) for k, v in data.items()}",
                "    return dict(data)",
            ),
        ),
        "test_c5",
    ),
    Mutant(
        "redaction-net bypass: the channels transcript net is a no-op",
        (
            (
                "services/channels/src/redact.ts",
                "export function redactPatterns(text: string): string {\n  let t = text;",
                'export function redactPatterns(text: string): string {\n  if (text !== "\\u0000") return text;\n  let t = text;',
            ),
        ),
        "test_c2",
    ),
    Mutant(
        "redaction-net bypass: memory writes are not redacted in PHI mode",
        (
            (
                "services/memory/src/redact.ts",
                "export function redactForPhi(doc: Redactable, extraPaths: readonly string[] = []): Redactable {",
                "export function redactForPhi(doc: Redactable, extraPaths: readonly string[] = []): Redactable {\n  if (extraPaths.length >= 0) return doc;",
            ),
        ),
        "test_c3",
    ),
    Mutant(
        "redaction-net bypass: a PHI eval dataset is stored as ingested",
        (
            (
                "services/eval-hub/src/catalog.ts",
                "const stored = phi ? (redactJson(cases, this.c.redact) as EvalCase[]) : cases;",
                "const stored = cases;",
            ),
        ),
        "test_c4",
    ),
    Mutant(
        "red-team gate default-allow: the Hub's release gate allows whatever it finds",
        (
            (
                "services/eval-hub/src/gate.ts",
                "      allowed: reasons.length === 0,",
                "      allowed: true,",
            ),
        ),
        "test_f2",
    ),
]


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)


def rebuild() -> None:
    out = run(["pnpm", "build"])
    if out.returncode != 0:
        raise RuntimeError(f"build failed:\n{out.stdout[-3000:]}\n{out.stderr[-3000:]}")


def main() -> int:
    only = sys.argv[1:]
    mutants = [m for m in MUTANTS if not only or any(o in m.name for o in only)]
    survived: list[str] = []
    for m in mutants:
        originals: dict[str, str] = {}
        rebuilt = False
        try:
            for rel, old, new in m.edits:
                path = ROOT / rel
                originals.setdefault(rel, path.read_text())
                text = path.read_text()
                if old not in text:
                    raise RuntimeError(f"{m.name}: pattern not found in {rel}")
                path.write_text(text.replace(old, new, 1))
            if any(rel.endswith((".ts", ".tsx", ".mjs")) for rel in originals):
                rebuild()
                rebuilt = True
            out = run(PY + PY_ARGS + ["-k", m.k])
            lines = (out.stdout + out.stderr).strip().splitlines()
            tail = lines[-1] if lines else ""
            killed = out.returncode != 0 and " failed" in tail and "error" not in tail
            print(f"{'KILLED  ' if killed else 'SURVIVED'} {m.name}  [{tail}]", flush=True)
            if not killed:
                survived.append(m.name)
        finally:
            for rel, text in originals.items():
                (ROOT / rel).write_text(text)
            if rebuilt:
                rebuild()
    print(f"\n{len(mutants) - len(survived)}/{len(mutants)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
