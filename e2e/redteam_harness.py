"""Red-team campaign on the REAL stack (``make redteam`` / ``make redteam-selfcheck``).

Boots the Phase 7/8 interfaces stack (Postgres 16 with RLS, the Risk Kernel over gRPC with per-tenant bundles, control plane,
registry, run service, standalone gateway hosting the Eval Hub), provisions a tenant with the red-team policy pack, publishes the
red-team blueprints, creates the datasets and suites of ``evals/redteam`` in the Hub, starts a REAL eval runner process (scripted
GULLIBLE model, ``e2e/scripts/redteam_runner.py``), queues the suites (mode=ci, so the results are recorded in the Hub and usable
as a release gate), reads the per-case results back through the public API, adds the execution-sink check, and applies the
thresholds. See docs/security/redteam.md.

    python e2e/redteam_harness.py --report out.json            # the campaign; exit 1 below the thresholds
    python e2e/redteam_harness.py --selfcheck --report out.json  # each mutant must make the suite FAIL
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent
RT = ROOT / "evals" / "redteam"
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(RT))

import interfaces_stack as istack  # noqa: E402
import mutants as mutants_mod  # noqa: E402
import oracle  # noqa: E402
import redteam_probes  # noqa: E402
from evals_clients import PySdk  # noqa: E402
from evals_world import bp_dict, publish_version, ref_of, setup_publisher, yaml_json  # noqa: E402

ALL = [
    "redteam-core",
    "redteam-phi",
    "redteam-kill-tenant",
    "redteam-kill-tool",
    "redteam-kill-agent",
    "redteam-mislabel",
]
PACK = yaml_json(str(RT / "policy" / "pack.yaml"))
ABL = {
    "redteam-agent": yaml_json(str(RT / "blueprint" / "redteam-agent.abl.yaml")),
    "redteam-phi-agent": yaml_json(str(RT / "blueprint" / "redteam-phi-agent.abl.yaml")),
    "redteam-mislabel-agent": yaml_json(str(RT / "blueprint" / "redteam-mislabel-agent.abl.yaml")),
}
THRESHOLDS = json.loads((RT / "thresholds.json").read_text())


class _W:
    """The duck-typed world ``publish_version`` needs."""

    def __init__(self, stack: istack.Stack, ns: str) -> None:
        self.stack, self.ns, self.state = stack, ns, {}


def switch(stack: istack.Stack, key: str, ks: dict[str, Any], engaged: bool) -> None:
    body: dict[str, Any] = {"scope": ks["scope"], "engaged": engaged, "reason": "red-team drill"}
    if ks.get("target"):
        body["target"] = ks["target"]
    r = httpx.put(
        f"{stack.gateway}/kill-switches", headers={"x-axis-api-key": key}, json=body, timeout=60
    )
    assert r.status_code == 200, (r.status_code, r.text)
    time.sleep(1.2)  # "effective < 1 s"


def campaign(
    stack: istack.Stack,
    *,
    pack: dict[str, Any],
    datasets: list[str],
    gate_bypass: tuple[str, ...] = (),
    tool_catalog: tuple[str, ...] = (),
    label: str = "control",
    timeout_s: int = 900,
    probes: bool = False,
) -> dict[str, Any]:
    slug = "rt" + secrets.token_hex(3)
    tenant = stack.provision(slug, pack=pack)
    key = stack.api_key(tenant["tenant_id"], tenant["owner_member_id"])
    catalog_file = stack.work / "tool-catalog.json"
    catalog_file.write_text(
        json.dumps({tenant["tenant_id"]: dict.fromkeys(tool_catalog, "read")} if tool_catalog else {})
    )
    w = _W(stack, f"rt-{slug}")
    w.owner_key = key  # type: ignore[attr-defined]
    setup_publisher(w)  # type: ignore[arg-type]
    sdk = PySdk(stack, key)
    published: dict[str, dict[str, Any]] = {}
    for name in {
        json.loads((RT / "datasets" / f"{d}.json").read_text())["blueprint"] for d in datasets
    }:
        published[name] = publish_version(w, ABL[name], local=True)  # type: ignore[arg-type]
    sink = stack.work / f"sink-{slug}.jsonl"
    sink.write_text("")
    env = {"REDTEAM_SINK": str(sink)}
    if gate_bypass:
        env["REDTEAM_MUTATION"] = "gate-bypass:" + ",".join(gate_bypass)
    creds = stack.runner_credentials(tenant, "rt-runner")
    sdk.call("evalsRunnersRegister", id="rt-runner", description=f"red-team runner ({label})")
    runner = stack.start_runner(
        tenant, "rt-runner", creds=creds, script="e2e/scripts/redteam_runner.py", extra_env=env
    )
    verdicts: list[dict[str, Any]] = []
    runs: dict[str, Any] = {}
    gates: dict[str, Any] = {}
    try:
        time.sleep(2.0)
        for d in datasets:
            ds = json.loads((RT / "datasets" / f"{d}.json").read_text())
            suite = json.loads((RT / "suites" / f"{d}.json").read_text())
            created = sdk.call(
                "evalsDatasetCreate",
                body={"name": ds["name"], "cases": ds["cases"], "description": ds["description"]},
            )
            assert created["ref"] == suite["dataset_ref"], created["ref"]
            sdk.call("evalsSuiteCreate", body=suite)
            v = published[ds["blueprint"]]
            ks = ds.get("kill_switch")
            if ks:
                switch(stack, key, ks, True)
            try:
                run = sdk.call("evalsRunStart", suite=suite["ref"], blueprint=ref_of(w, v))  # type: ignore[arg-type]
                fin = sdk.call("evalsRunWait", id=run["id"], timeout_ms=timeout_s * 1000)
            finally:
                if ks:
                    switch(stack, key, ks, False)
            runs[d] = {k: fin.get(k) for k in ("id", "status", "score", "mode", "scores")}
            by_case = {c["case_id"]: c for c in fin.get("case_results", [])}
            entries: dict[str, list[dict[str, Any]]] = {}
            for line in sink.read_text().splitlines():
                e = json.loads(line)
                entries.setdefault(e["case"], []).append(e)
            for case in ds["cases"]:
                verdicts.append(
                    oracle.verdict(case, by_case.get(case["id"]), entries.get(case["id"], []))
                )
            gates[d] = sdk.call(
                "evalsGate",
                blueprint=bp_dict(w, v),  # type: ignore[arg-type]
                suites=[{"ref": suite["ref"], "threshold": 1.0}],
            )
    finally:
        err = runner.stderr()
        runner.stop()
    if probes:
        other = stack.provision("rt" + secrets.token_hex(3), pack=pack)
        key_b = stack.api_key(other["tenant_id"], other["owner_member_id"])
        narrow = stack.api_key(tenant["tenant_id"], tenant["owner_member_id"], scopes=["runs:read"])
        first = datasets[0]
        ds0 = json.loads((RT / "datasets" / f"{first}.json").read_text())
        verdicts.extend(
            redteam_probes.run_probes(
                stack.gateway,
                key_a=key,
                key_b=key_b,
                narrow_a=narrow,
                tenant_a=tenant["tenant_id"],
                tenant_b=other["tenant_id"],
                run_id_a=runs[first]["id"],
                suite_ref=ds0["suite"],
                dataset=(ds0["name"], 1),
            )
        )
    summary = oracle.summarise(verdicts, THRESHOLDS)
    return {
        "label": label,
        "summary": summary,
        "verdicts": verdicts,
        "hub_runs": runs,
        "release_gate": {
            k: {"allowed": g.get("allowed"), "reasons": g.get("reasons")} for k, g in gates.items()
        },
        "runner_stderr_tail": err[-1500:],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("--only", help="selfcheck: a single mutant name")
    args = ap.parse_args()
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise SystemExit("PG_ADMIN_URL is required: run via `make redteam`")
    work = Path(tempfile.mkdtemp(prefix="redteam-"))
    out: dict[str, Any] = {}
    code = 0
    (work / "tool-catalog.json").write_text("{}")
    with istack.boot(
        work, admin, kernel_env={"AXIS_RK_TOOL_CATALOG_FILE": str(work / "tool-catalog.json")}
    ) as stack:
        if not args.selfcheck:
            rep = campaign(stack, pack=PACK, datasets=ALL, probes=True)
            out = rep
            s = rep["summary"]
            print(
                f"redteam: {s['cases']} counted cases, containment {s['containment']:.4f}, unsafe {len(s['unsafe'])}, "
                f"known-open {len(s['known_open'])}"
            )
            for f in s["failures"]:
                print(
                    f"  UNSAFE {f['id']} [{f['category']}/{f['severity']}] {f['technique']}: {'; '.join(f['reasons'])}"
                )
                print(f"         evidence: {f.get('evidence')}")
            for p in s["problems"]:
                print("  PROBLEM:", p)
            for k, g in rep["release_gate"].items():
                print(f"  release gate {k}: allowed={g['allowed']}")
            code = (
                0 if s["passed"] and all(g["allowed"] for g in rep["release_gate"].values()) else 1
            )
        else:
            results: list[dict[str, Any]] = []
            control = campaign(stack, pack=PACK, datasets=["redteam-core"], label="control")
            ok_control = control["summary"]["passed"]
            print(f"selfcheck control: passed={ok_control}")
            results.append(
                {"mutant": "control", "expected": "pass", "passed": ok_control, "ok": ok_control}
            )
            for m in mutants_mod.MUTANTS:
                if args.only and m.name != args.only:
                    continue
                pack = m.pack(PACK) if m.pack else PACK
                rep = campaign(
                    stack,
                    pack=pack,
                    datasets=list(m.datasets),
                    gate_bypass=m.gate_bypass,
                    tool_catalog=m.tool_catalog,
                    label=m.name,
                )
                s = rep["summary"]
                cats = {f["category"] for f in s["failures"]}
                detected = (not s["passed"]) and all(c in cats for c in m.must_fail)
                print(
                    f"selfcheck {m.name}: suite passed={s['passed']} unsafe={len(s['unsafe'])} categories={sorted(cats)} detected={detected}"
                )
                results.append(
                    {
                        "mutant": m.name,
                        "expected": "fail",
                        "passed": s["passed"],
                        "unsafe": len(s["unsafe"]),
                        "categories": sorted(cats),
                        "must_fail": list(m.must_fail),
                        "ok": detected,
                    }
                )
            out = {"selfcheck": results}
            code = 0 if all(r["ok"] for r in results) else 1
    Path(args.report).write_text(json.dumps(out, indent=1))
    return code


if __name__ == "__main__":
    sys.exit(main())
