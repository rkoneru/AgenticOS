"""Mutation check for the eval runner's safety logic (run by hand:
``uv run python runtime/tests/mutation_evals.py``).

Each mutation breaks one safety property in the source; the eval tests MUST fail. The source is
restored afterwards. Exit code 0 only if every mutant was killed.

Covered: judge output delimiting and verdict parsing, fail-closed on malformed/unavailable
verdicts, anchor drift, eval-mode write denial and its fall-through, case isolation (fresh ids,
logs, no NEXUS/memory carry-over, tenant check), no retry-for-score, caps never loosen,
deterministic seeds and sampling, the hourly cap and dedupe, redaction before persist/grade,
failure containment, stale-input refusal, aggregation (ungraded = 0, errored cannot pass,
pending holds the run) and request signing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "runtime/src/axis_runtime/evals"
TESTS = ["runtime/tests/test_evals_*.py"]

MUTANTS: list[tuple[str, str, str, str]] = [
    # --- judge prompt delimiting
    (
        "output not defanged",
        "judge.py",
        'out = defang_fence(out).replace(nonce, "")',
        'out = out.replace(nonce, "")',
    ),
    (
        "control/zero-width chars kept",
        "judge.py",
        'out = CONTROL_CHARS.sub("", text)',
        "out = text",
    ),
    (
        "nonce not stripped from output",
        "judge.py",
        'out = defang_fence(out).replace(nonce, "")',
        "out = defang_fence(out)",
    ),
    ("output not truncated", "judge.py", "    if len(out) > limit:", "    if False:"),
    # --- verdict parsing, fail closed
    (
        "extra/missing verdict keys accepted",
        "judge.py",
        'if not isinstance(doc, dict) or set(doc) != {"score", "rationale"}:',
        "if not isinstance(doc, dict):",
    ),
    (
        "out-of-range score accepted",
        "judge.py",
        "if not 0.0 <= float(score) <= 1.0 or not isinstance(rationale, str):",
        "if not isinstance(rationale, str):",
    ),
    (
        "boolean score accepted",
        "judge.py",
        "if isinstance(score, bool) or not isinstance(score, int | float):",
        "if not isinstance(score, int | float):",
    ),
    (
        "duplicate JSON keys accepted",
        "graders.py",
        "            if k in out:",
        "            if False:",
    ),
    ("NaN/Infinity accepted", "graders.py", "parse_constant=_reject_constant, ", ""),
    (
        "malformed verdict scores as a pass",
        "judge.py",
        'return Grade(spec.id, "model", "ungraded", 0.0, why, prov)',
        'return Grade(spec.id, "model", "scored", 1.0, why, prov)',
    ),
    (
        "unavailable judge scores as a pass",
        "judge.py",
        'return None, None, f"judge_unavailable:{exc.reason}"[:120]',
        "return Verdict(1.0, ''), None, 'ok'",
    ),
    (
        "expected answer always shown to the judge",
        "judge.py",
        "if config.include_expected else None",
        "if True else None",
    ),
    (
        "input always shown to the judge",
        "judge.py",
        "if config.include_input else None",
        "if True else None",
    ),
    (
        "anchor drift ignored",
        "judge.py",
        "if not anchor.min_score <= score <= anchor.max_score:",
        "if False:",
    ),
    (
        "vote needs no majority",
        "judge.py",
        "if len(scores) * 2 <= config.samples:",
        "if len(scores) == 0:",
    ),
    (
        "judge output not redacted",
        "judge.py",
        "out = redact_text(trace.output, phi=phi, names=names)",
        "out = trace.output",
    ),
    (
        "judge may call tools",
        "judge.py",
        "tool_calls=Budget(None, 0.0),",
        "tool_calls=Budget(None, 5.0),",
    ),
    # --- eval-mode lockdown
    (
        "MCP/code tool kinds treated as safe",
        "isolation.py",
        "if point is EnforcementPoint.TOOL_CALL and kind in SAFE_TOOL_KINDS:",
        "if point is EnforcementPoint.TOOL_CALL:",
    ),
    (
        "side-effect actions not denied",
        "isolation.py",
        'return f"eval_mode_side_effect_denied:{point.value}"',
        "return None",
    ),
    (
        "eval gate ignores its own denial",
        "isolation.py",
        "        if reason is not None:\n            return deny(reason)",
        "        if False:\n            return deny(reason)",
    ),
    (
        "any action allowed by name",
        "isolation.py",
        "if request.action in self.allow_sandboxed:",
        "if True:",
    ),
    # --- case isolation
    (
        "event log shared between cases",
        "isolation.py",
        "        log=InMemoryRunEventLog(),",
        "        log=base.log,",
    ),
    (
        "NEXUS cache carried into evals",
        "isolation.py",
        "        nexus_factory=None,",
        "        nexus_factory=base.nexus_factory,",
    ),
    (
        "memory without a declared session",
        "isolation.py",
        "memory=base.memory if session_id is not None else None,",
        "memory=base.memory,",
    ),
    (
        "session id inherited from production",
        "isolation.py",
        "        session_id=session_id,",
        "        session_id=base.session_id,",
    ),
    (
        "approvals wait for humans in evals",
        "isolation.py",
        "        approvals=None,",
        "        approvals=base.approvals,",
    ),
    (
        "deps of another tenant accepted",
        "isolation.py",
        "    if base.tenant_id != tenant_id:",
        "    if False:",
    ),
    (
        "run id reused across cases",
        "runner.py",
        "run_id, trace_id = self._ids.run_id(), self._ids.trace_id()",
        'run_id, trace_id = "run_shared", self._ids.trace_id()',
    ),
    # --- retries and caps
    (
        "every outcome retried (score buying)",
        "runner.py",
        "            if is_infra_failure(result):",
        "            if True:",
    ),
    (
        "completed runs classified as infra",
        "runner.py",
        "    if result.exit_reason not in (ExitReason.FAILED, ExitReason.POLICY_DENIED):\n        return False",
        "    if False:\n        return False",
    ),
    (
        "caps loosen the blueprint's own",
        "runner.py",
        "hard = cap if current.hard is None else min(current.hard, cap)",
        "hard = cap",
    ),
    (
        "per-case seed ignores the case",
        "runner.py",
        'hashlib.sha256(f"{run_seed}:{case_id}".encode()).digest()',
        'hashlib.sha256(f"{run_seed}".encode()).digest()',
    ),
    # --- sampler
    (
        "hourly cap ignored",
        "sampler.py",
        "if self._hour_counts.get(bucket, 0) >= self.config.max_per_hour:",
        "if False:",
    ),
    (
        "cap keeps arrival order, not hash order",
        "sampler.py",
        "picked.sort(key=lambda r: (sample_position(r.run_id, salt), r.run_id))",
        "picked.sort(key=lambda r: r.completed_at)",
    ),
    (
        "sampling salt dropped",
        "sampler.py",
        "        salt = self.config.suite_ref",
        '        salt = ""',
    ),
    (
        "runs graded twice",
        "sampler.py",
        "fresh = [r for r in runs if r.run_id not in self._seen]",
        "fresh = list(runs)",
    ),
    (
        "sampler output persisted unredacted",
        "sampler.py",
        "run.trace, output=None if out is None else redact_text(out, phi=phi, names=names)",
        "run.trace, output=out",
    ),
    (
        "online failures escape",
        "sampler.py",
        "            except Exception:  # noqa: BLE001 - sampling must never affect anything else",
        "            except ZeroDivisionError:",
    ),
    (
        "reader failures escape",
        "sampler.py",
        "        except Exception:  # noqa: BLE001\n            self.stats.reader_errors += 1",
        "        except ZeroDivisionError:\n            self.stats.reader_errors += 1",
    ),
    (
        "other tenants' runs graded",
        "sampler.py",
        "r.tenant_id == self.tenant_id and r.blueprint == self.config.blueprint",
        "True",
    ),
    # --- persistence and refusal
    (
        "case output persisted unredacted",
        "suite.py",
        "else redact_text(\n                        t.output,\n                        phi=dataset.phi,\n                        names=names_in(o.case.input_text) if dataset.phi else (),\n                    )[:MAX_PERSISTED_OUTPUT_CHARS],",
        "else t.output[:MAX_PERSISTED_OUTPUT_CHARS],",
    ),
    (
        "stale blueprint hash accepted",
        "suite.py",
        "if manifest.content_hash != bp.content_hash:",
        "if False:",
    ),
    (
        "altered dataset accepted",
        "suite.py",
        "if dataset.computed_hash() != dataset.version_hash:",
        "if False:",
    ),
    (
        "run of another tenant executed (suite)",
        "suite.py",
        "if run.tenant_id != self._tenant_id:",
        "if False:",
    ),
    (
        "run of another tenant executed (worker)",
        "worker.py",
        "if run.tenant_id != self._config.tenant_id:",
        "if False:",
    ),
    (
        "submissions unsigned",
        "hubclient.py",
        '            headers["x-axis-runner-signature"] = self._identity.sign(content)',
        "            pass",
    ),
    # --- aggregation
    (
        "ungraded counts as a pass",
        "aggregation.py",
        "                ungraded += 1\n                s = 0.0",
        "                ungraded += 1\n                s = 1.0",
    ),
    (
        "errored cases can pass",
        "aggregation.py",
        "    if errored:\n        failures.append",
        "    if False:\n        failures.append",
    ),
    (
        "pending human grade ignored",
        "aggregation.py",
        'if any(row[g].status == "pending" for row in grades.values() for g in row):',
        "if False:",
    ),
    (
        "human grader scores itself",
        "grading.py",
        'Grade(spec.id, "human", "pending", 0.0, "awaiting_human_review")',
        'Grade(spec.id, "human", "scored", 1.0, "auto")',
    ),
    (
        "no_output scores as a pass",
        "graders.py",
        '        return scored(spec, False, "no_output")\n    if isinstance(want, str):',
        '        return scored(spec, True, "no_output")\n    if isinstance(want, str):',
    ),
    (
        "unsafe regex executed",
        "graders.py",
        "        compile_safe(pattern)  # linear-time guard",
        "        pass  # linear-time guard",
    ),
]


def main() -> int:
    only = sys.argv[1:]  # optional name filters (substrings)
    mutants = [m for m in MUTANTS if not only or any(o in m[0] for o in only)]
    survived: list[str] = []
    for name, fname, old, new in mutants:
        path = SRC / fname
        original = path.read_text()
        if old not in original:
            print(f"STALE    {name}: pattern not found in {fname}")
            survived.append(name)
            continue
        path.write_text(original.replace(old, new, 1))
        try:
            tests = sorted(str(p) for p in ROOT.glob(TESTS[0]))
            cmd = ["uv", "run", "pytest", *tests, "-x", "-q", "--no-cov", "-p", "no:cacheprovider"]  # noqa: S607
            proc = subprocess.run(  # noqa: S603
                cmd, cwd=ROOT, capture_output=True, text=True, timeout=600, check=False
            )
        finally:
            path.write_text(original)
        killed = proc.returncode != 0
        print(f"{'KILLED  ' if killed else 'SURVIVED'} {name}", flush=True)
        if not killed:
            survived.append(name)
    print(f"{len(mutants) - len(survived)}/{len(mutants)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
