"""Mutation check for the Phase 7 wiring (run by hand: ``uv run python e2e/mutation_phase7.py [name-substring ...]``; needs PG like `make e2e-phase7`).

Each mutant breaks ONE safety property of the interfaces wiring in the working tree, rebuilds, runs ``test_phase7_interfaces.py`` (or, for
the console mutant, the real-stack Playwright suite) and requires a FAILURE of a real test (a stack that fails to start is not a kill).
Sources are restored afterwards. Exit code 0 only if every mutant was killed.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = ["bash", "infra/scripts/with-pg.sh", "uv", "run", "pytest", "e2e/test_phase7_interfaces.py"]
PY_ARGS = ["-p", "no:cacheprovider", "--no-cov", "-q", "-x"]
CONSOLE = [
    "bash", "-c",
    "cd apps/console && NEXT_PUBLIC_DEV_LOGIN=1 NEXT_TELEMETRY_DISABLED=1 pnpm exec next build >/dev/null 2>&1 && cd ../.. && "
    "bash infra/scripts/with-pg.sh uv run python e2e/interfaces_stack.py --out /tmp/axis-mut-stack.json -- "
    "bash -c 'cd apps/console && pnpm exec playwright test -c playwright.real.config.ts --max-failures=1'",
]  # fmt: skip


@dataclass(frozen=True)
class Mutant:
    name: str
    edits: tuple[tuple[str, str, str], ...]  # (file, old, new)
    suite: str = "py"


MUTANTS = [
    Mutant(
        "gateway wiring: the per-tenant run-service credential is not derived from the tenant (first table entry wins)",
        (
            (
                "apps/api-gateway/src/standalone.ts",
                "    return Object.prototype.hasOwnProperty.call(this.data, tenantId)\n      ? this.data[tenantId]\n      : undefined;",
                "    return Object.values(this.data)[0];",
            ),
        ),
    ),
    Mutant(
        "API key scopes are ignored (every key may do everything its role may)",
        (
            (
                "services/control-plane/src/authz.ts",
                '  return scopes.some((s) => s === "*" || s === need || s === `${res}:*`);',
                "  return true;",
            ),
        ),
    ),
    Mutant(
        "registry served unverified (resolve skips signature/provenance/hash verification)",
        (
            (
                "services/registry/src/service.ts",
                "    if (!verdict.ok) {",
                "    if (!verdict.ok && false) {",
            ),
        ),
    ),
    Mutant(
        "marketplace install skips the consent digest check",
        (
            (
                "services/marketplace/src/installs.ts",
                "    if (digest !== pv.consentDigest)",
                "    if (false as boolean)",
            ),
        ),
    ),
    Mutant(
        "approval gate bypassed on resume (runtime accepts any outcome AND the kernel accepts any presented record)",
        (
            (
                "runtime/src/axis_runtime/executor.py",
                '        if outcome != "APPROVED":',
                "        if False:",
            ),
            (
                "services/risk-kernel/src/kernel.ts",
                "        if (!(await verifier.verify(presented, expected))) {",
                "        if (false) {",
            ),
        ),
    ),
    Mutant(
        "console BFF forwards a client-supplied tenant header to the gateway",
        (
            (
                "apps/console/lib/bff.ts",
                '  "idempotency-key",\n',
                '  "idempotency-key",\n  "x-tenant-id",\n',
            ),
        ),
        suite="console",
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
            if any(rel.endswith((".ts", ".tsx")) for rel in originals):
                rebuild()
            out = run(PY + PY_ARGS) if m.suite == "py" else run(CONSOLE)
            tail = (out.stdout + out.stderr).strip().splitlines()[-1]
            if m.suite == "py":
                killed = out.returncode != 0 and " failed" in tail and "error" not in tail
            else:
                killed = out.returncode != 0 and "failed" in (out.stdout + out.stderr)
            print(f"{'KILLED  ' if killed else 'SURVIVED'} {m.name}  [{tail}]", flush=True)
            if not killed:
                survived.append(m.name)
        finally:
            for rel, text in originals.items():
                (ROOT / rel).write_text(text)
            if any(rel.endswith((".ts", ".tsx")) for rel in originals):
                rebuild()
    print(f"\n{len(mutants) - len(survived)}/{len(mutants)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
