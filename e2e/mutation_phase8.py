"""Mutation check for the Phase 8 wiring (run by hand: ``uv run python e2e/mutation_phase8.py [name-substring ...]``; needs PG like `make e2e-phase8`).

Each mutant breaks ONE safety property of the evals integration in the working tree, rebuilds if TypeScript changed, runs
``test_phase8_evals.py`` (or, for the console mutant, the real-stack evals Playwright suite) and requires a FAILURE of a real test (a
stack that fails to start is not a kill). Sources are restored afterwards. Exit code 0 only if every mutant was killed.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = ["bash", "infra/scripts/with-pg.sh", "uv", "run", "pytest", "e2e/test_phase8_evals.py"]
PY_ARGS = ["-p", "no:cacheprovider", "--no-cov", "-q", "-x"]
CONSOLE = [
    "bash", "-c",
    "cd apps/console && NEXT_PUBLIC_DEV_LOGIN=1 NEXT_TELEMETRY_DISABLED=1 pnpm exec next build >/dev/null 2>&1 && cd ../.. && "
    "bash infra/scripts/with-pg.sh uv run python e2e/interfaces_stack.py --out /tmp/axis-mut8-stack.json -- "
    "bash -c 'cd apps/console && pnpm exec playwright test -c playwright.real.config.ts evals.spec.ts --max-failures=1'",
]  # fmt: skip


@dataclass(frozen=True)
class Mutant:
    name: str
    edits: tuple[tuple[str, str, str], ...]  # (file, old, new)
    suite: str = "py"


MUTANTS = [
    Mutant(
        "gate port default allow (the staff-side registry is not wired to the hub AND an unwired registry allows)",
        (
            ("e2e/scripts/interfaces-stack.mjs", "  evalGate: evalHub.gatePort,\n", ""),
            (
                "services/registry/src/eval-gate.ts",
                'export const DENY_ALL_EVAL_GATE: EvalGatePort = {\n  check: () =>\n    Promise.resolve({\n      allowed: false,\n      reasons: [{ code: "gate_unavailable", message: "no eval gate is configured" }],\n    }),\n};',
                "export const DENY_ALL_EVAL_GATE: EvalGatePort = {\n  check: () => Promise.resolve({ allowed: true, reasons: [] }),\n};",
            ),
        ),
    ),
    Mutant(
        "the gate accepts a run of OTHER blueprint content (stale run)",
        (
            (
                "services/eval-hub/src/gate.ts",
                "const forHash = sameSuite.filter((r) => r.content_hash === bp.content_hash);",
                "const forHash = sameSuite;",
            ),
        ),
    ),
    Mutant(
        "the gate accepts a run of an unregistered or revoked runner",
        (
            (
                "services/eval-hub/src/gate.ts",
                "if (r.runner_id !== null && (await this.runs.runnerActive(tenantId, r.runner_id)))",
                "if (r.runner_id !== null)",
            ),
        ),
    ),
    Mutant(
        "the hub trusts the runner's aggregate (no recomputation check)",
        (
            (
                "services/eval-hub/src/runs.ts",
                "      if (bad.length > 0)\n        throw integrityFailed(",
                "      if (bad.length > 0 && false)\n        throw integrityFailed(",
            ),
        ),
    ),
    Mutant(
        "a reviewer may be the blueprint's publisher or the run's starter",
        (
            (
                "services/eval-hub/src/runs.ts",
                '      const conflicts = [\n        ...new Set(\n          [run.requested_by, run.publisher].filter((x): x is string => typeof x === "string"),\n        ),\n      ];',
                "      const conflicts: string[] = [];",
            ),
        ),
    ),
    Mutant(
        "an online result changes release state (good online scores clear a gate verdict)",
        (
            (
                "services/eval-hub/src/gate.ts",
                "    return { reasons, run: summary };\n  }\n}\n\nfunction emptyRun",
                '    const on = await this.c.docs.find<{ score: number | null }>(tenantId, "online");\n    if (on.some((o) => (o.data.score ?? 0) >= 0.9)) reasons.length = 0;\n    return { reasons, run: summary };\n  }\n}\n\nfunction emptyRun',
            ),
        ),
    ),
    Mutant(
        "the gateway gate route forgets the suites the stored ABL declares",
        (
            (
                "apps/api-gateway/src/routes.ts",
                "    suites = [\n      ...declared.map((d) => ({ ref: d.ref, threshold: d.threshold })),\n      ...(body.suites ?? []),\n    ];",
                "    void declared;\n    suites = body.suites;",
            ),
        ),
    ),
    Mutant(
        "personal data reaches the review queue and the judge (runner redaction and the hub's second pass off)",
        (
            (
                "runtime/src/axis_runtime/evals/redact.py",
                "    return redact_transcript(out, names) if phi else out",
                "    return out",
            ),
            ("services/eval-hub/src/online.ts", "        ? redactPatterns(v)", "        ? v"),
            (
                "services/eval-hub/src/online.ts",
                "output === null ? null : redactPatterns(output as string)",
                "output",
            ),
        ),
    ),
    Mutant(
        "the judge's data block is not defanged (a forged end marker closes it)",
        (
            (
                "runtime/src/axis_runtime/evals/judge.py",
                '    out = defang_fence(out).replace(nonce, "")',
                '    out = out.replace(nonce, "")',
            ),
        ),
    ),
    Mutant(
        "eval mode opens a real approval request",
        (
            (
                "services/risk-kernel/src/kernel.ts",
                'if (req.context["eval_mode"] === true)',
                "if (false as boolean)",
            ),
        ),
    ),
    Mutant(
        "eval mode lets a code/MCP/browser action through to the kernel",
        (
            (
                "runtime/src/axis_runtime/evals/isolation.py",
                '        return f"eval_mode_side_effect_denied:{point.value}"',
                "        return None",
            ),
        ),
    ),
    Mutant(
        "a runner may read the manifest of a blueprint it is not executing",
        (
            (
                "services/eval-hub/src/dev-server.ts",
                "if (!(await h.runs.runnerHoldsBlueprint(p, { name, version })))",
                "if (false as boolean)",
            ),
        ),
    ),
    Mutant(
        "console renders a case output as HTML",
        (
            (
                "apps/console/app/(app)/evals/runs/[id]/page.tsx",
                '            {c.output ?? "(no output)"}',
                '            <span dangerouslySetInnerHTML={{ __html: c.output ?? "(no output)" }} />',
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
            if any(rel.endswith((".ts", ".tsx", ".mjs")) for rel in originals):
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
            if any(rel.endswith((".ts", ".tsx", ".mjs")) for rel in originals):
                rebuild()
    print(f"\n{len(mutants) - len(survived)}/{len(mutants)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
