"""Phase 8 exit check: blueprint releases are BLOCKED when evals regress, and eval history is visible per version, on the REAL stack.

The stack (e2e/interfaces_stack.py) is the Phase 7 interfaces stack plus the Eval Hub: Postgres 16 with RLS, the real Risk Kernel
over gRPC (per-tenant policy bundles), the control plane, the registry/marketplace, the Python run service, the API gateway as a
standalone process hosting the Eval Hub (tenant API on the gateway port, runner surface on a second loopback port), and a REAL eval
runner process per tenant (``runtime/scripts/eval_runner.py``) that polls the hub, fetches the compiled manifest of the queued
blueprint version from the hub, runs every case through the real run path with the kernel gating every call, grades, and posts a
signed result. Fakes: the IdP, KMS, DNS, the marketplace provers and the MODEL (a scripted provider answering for the agent under
test and for the model judge; see ``e2e/scripts/eval_runner_e2e.py``: it is deterministic, persona-driven and gullible in one way a
real judge can be, so the injection test has teeth).

Scenarios (the docstring of each test says which):
  1 dataset + suite (deterministic + model-graded + human-graded) -> v1 run through the kernel -> human grades -> hub recomputes ->
    gate ALLOWS -> registry release succeeds -> attestation visible on the version
  2 v2 regresses -> gate BLOCKS (regression) from the TS SDK, the Python SDK and the CLI (exit 4); registry release and marketplace
    submit refused with evals_gate_failed
  3 fail-closed: no run, a run for other content, a revoked runner, an unregistered runner, a tampered score, a replayed run, an
    unmet threshold
  4 human grading: reviewer != publisher, double grade + adjudication
  5 online sampling of production runs: deterministic selection, PHI redacted, history only, never changes a release
  6 a judge prompt injection does not raise the score
  7 cross-tenant isolation from every client
  8 eval mode never lets a side effect happen, and never changes what production would decide

Run with:  make e2e-phase8
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).parent))
import interfaces_stack as istack  # noqa: E402
from axis_runtime.evals.aggregation import aggregate  # noqa: E402
from axis_runtime.evals.sampler import is_selected  # noqa: E402
from axis_runtime.evals.types import (  # noqa: E402
    EvalCase,
    Grade,
    GraderSpec,
    canonical,
    dataset_content_hash,
)
from evals_clients import CLIENTS, ApiFail, Cli, EvalClient, PySdk, TsSdk  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def yaml_json(path: str) -> Any:
    return json.loads(istack.sh(["node", "scripts/yaml-to-json.mjs", path], cwd=ROOT / "e2e"))


PACK = yaml_json("policies/phase8-evals/pack.yaml")
SHIPPED_JUDGE_PACK = yaml_json("../policies/eval-judge/pack.yaml")
ABL_V1 = yaml_json("agents/answer8.v1.abl.yaml")
ABL_V2 = yaml_json("agents/answer8.v2.abl.yaml")
ABL_PROBE = yaml_json("agents/probe8.abl.yaml")

SUITE_REF = "answers@1.0.0"
FAST_REF = "answers-fast@1.0.0"
CASES = [
    {
        "id": f"q{i}",
        "input": f"What is the status of claim {1000 + i}?",
        "expected": {"contains": [f"claim {1000 + i}", "2 days"]},
        "tags": ["status"],
    }
    for i in range(1, 5)
]
TONE_RUBRIC = "The answer is polite, says what happens next, and thanks the customer."
GOOD_ANCHOR = (
    "Claim 7 is open. A specialist will contact you within 2 days. Thank you for your patience."
)
DETERMINISTIC = [
    {
        "id": "has-facts",
        "kind": "deterministic",
        "weight": 1,
        "config": {"type": "contains", "mode": "all", "normalize": ["casefold"]},
    },
    {
        "id": "no-guessing",
        "kind": "deterministic",
        "weight": 1,
        "config": {
            "type": "not_contains",
            "values": ["I do not know", "cannot help"],
            "normalize": ["casefold"],
        },
    },
]
TONE = {
    "id": "tone",
    "kind": "model",
    "weight": 1,
    "config": {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "rubric": TONE_RUBRIC,
        "include_input": True,
        "anchors": [
            {"output": GOOD_ANCHOR, "min_score": 0.8, "max_score": 1.0},
            {"output": "Open.", "min_score": 0.0, "max_score": 0.4},
        ],
    },
}
HUMAN = {
    "id": "reviewer",
    "kind": "human",
    "weight": 1,
    "config": {"rubric": "Would you send this answer to a customer as it is?", "sla_hours": 24},
}
SUITE = {
    "ref": SUITE_REF,
    "dataset_ref": "answer-cases@1",
    "graders": [*DETERMINISTIC, TONE, HUMAN],
    "pass_threshold": 0.5,
    "tolerance": 0.05,
}
FAST_SUITE = {**SUITE, "ref": FAST_REF, "graders": [*DETERMINISTIC, TONE]}


# ---- small helpers -----------------------------------------------------------------------------------------------------------


def short() -> str:
    return secrets.token_hex(3)


def until(fn: Callable[[], Any], what: str, timeout: float = 90.0, every: float = 0.4) -> Any:
    deadline = time.time() + timeout
    last: Any = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(every)
    raise AssertionError(f"timed out waiting for {what} (last: {last!r})")


def audit_rows(stack: istack.Stack, tenant: str) -> list[dict[str, Any]]:
    out = json.loads(
        istack.sh(["node", "scripts/verify-audit.mjs", stack.db_url, tenant], cwd=ROOT / "e2e")
    )
    return out["events"]  # type: ignore[no-any-return]


def codes(gate: dict[str, Any]) -> list[str]:
    return [r["code"] for r in gate["reasons"]]


def variant(
    abl: dict[str, Any],
    version: str,
    *,
    suites: list[dict[str, Any]] | None = None,
    tweak: str = "",
) -> dict[str, Any]:
    d = copy.deepcopy(abl)
    d["metadata"]["version"] = version
    if suites is not None:
        d["spec"]["evals"] = {"suites": suites}
    if tweak:
        d["spec"]["instructions"]["system"] += " " + tweak
    return d


class Hub:
    """A runner talking to the Eval Hub's runner surface directly (what a rogue or buggy runner could send): bearer token + HMAC body."""

    def __init__(self, base: str, runner_id: str, token: str) -> None:
        self.base, self.runner_id, self.token = base, runner_id, token

    def req(
        self, method: str, path: str, body: Any = None, *, sign: bool = True, key: str | None = None
    ) -> httpx.Response:
        raw = (
            b""
            if body is None
            else json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        )
        headers = {"authorization": f"Bearer {self.token}", "x-axis-runner-id": self.runner_id}
        if body is not None:
            headers["content-type"] = "application/json"
            if sign:
                mac = hmac.new((key or self.token).encode(), raw, hashlib.sha256).hexdigest()
                headers["x-axis-runner-signature"] = f"v1={mac}"
        return httpx.request(
            method, f"{self.base}/v1/evals{path}", headers=headers, content=raw or None, timeout=60
        )


class World:
    """Tenant A (the team shipping a blueprint), tenant B (the neighbour / attacker), the people and the processes."""

    def __init__(self, stack: istack.Stack) -> None:
        self.stack = stack
        slug = short()
        self.a = stack.provision(f"ea{slug}", pack=PACK)
        self.b = stack.provision(f"eb{slug}", pack=PACK)
        self.owner_key = stack.api_key(self.a["tenant_id"], self.a["owner_member_id"])
        self.key_b = stack.api_key(self.b["tenant_id"], self.b["owner_member_id"])
        self.reviewer = stack.member(self.a["tenant_id"], "operator")
        self.reviewer2 = stack.member(self.a["tenant_id"], "operator")
        self.adjudicator = stack.member(self.a["tenant_id"], "admin")
        self.reviewer_key = stack.api_key(self.a["tenant_id"], self.reviewer["member_id"])
        self.reviewer2_key = stack.api_key(self.a["tenant_id"], self.reviewer2["member_id"])
        self.adjudicator_key = stack.api_key(self.a["tenant_id"], self.adjudicator["member_id"])
        self.ns = f"pub-{slug}"
        self.judge_log = stack.work / "judge-prompts.jsonl"
        self.state: dict[str, Any] = {}
        self.runners: dict[str, istack.EvalRunner] = {}
        self.runner_creds: dict[str, dict[str, Any]] = {}

    def client(self, cls: type[EvalClient], key: str | None = None) -> EvalClient:
        return cls(self.stack, key or self.owner_key)

    @property
    def owner(self) -> PySdk:
        return PySdk(self.stack, self.owner_key)

    def start_runner(
        self, runner_id: str, *, register: bool = True, online: bool = False
    ) -> istack.EvalRunner:
        creds = self.runner_creds.get(runner_id) or self.stack.runner_credentials(self.a, runner_id)
        self.runner_creds[runner_id] = creds
        if register and not online:
            self.owner.call("evalsRunnersRegister", id=runner_id, description="e2e runner")
        r = self.stack.start_runner(
            self.a, runner_id, online=online, judge_log=self.judge_log, creds=creds
        )
        self.runners[f"{runner_id}{'/online' if online else ''}"] = r
        return r

    def hub(self, runner_id: str) -> Hub:
        return Hub(self.stack.eval_hub, runner_id, self.runner_creds[runner_id]["runner_token"])


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[istack.Stack]:
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise RuntimeError("PG_ADMIN_URL is required: run via `make e2e-phase8`")
    work = tmp_path_factory.mktemp("e2e8")
    with istack.boot(work, admin) as st:
        yield st


@pytest.fixture(scope="module")
def world(stack: istack.Stack) -> Iterator[World]:
    w = World(stack)
    yield w
    for r in w.runners.values():
        r.stop()


# ---- publishing (registry, signed) -------------------------------------------------------------------------------------------


def setup_publisher(w: World) -> None:
    """Publisher tooling (the CLI, offline): claim a namespace, make a key (private half stays in a local PEM), register it."""
    cli = Cli(w.stack, w.owner_key)
    w.state["publisher_cli"] = cli
    assert cli.j("registry", "claim", w.ns)["namespace"] == w.ns
    kg = cli.j("registry", "keygen", "--out", str(cli.tmp / "publisher.pem"))
    cli.j(
        "registry", "add-key", w.ns, f"--public-key={kg['public_key']}"
    )  # base64url keys may start with "-"
    time.sleep(1.1)  # a signature is only trusted from the moment its key became valid


def publish_version(w: World, abl: dict[str, Any], *, local: bool = False) -> dict[str, Any]:
    """Sign + publish ``abl`` to the registry namespace of the world (and, with ``local``, as the tenant's own blueprint)."""
    cli: Cli = w.state["publisher_cli"]
    name, version = abl["metadata"]["name"], abl["metadata"]["version"]
    f = cli.file(f"{name}-{version}.json", abl)
    signed = cli.run(
        "registry", "sign", f, "--namespace", w.ns, "--key", str(cli.tmp / "publisher.pem")
    ).stdout
    sf = cli.tmp / f"{name}-{version}.signed.json"
    sf.write_text(signed)
    v = cli.j("registry", "publish", str(sf))
    if local:
        cli.j("blueprints", "publish", f)
    return v  # type: ignore[no-any-return]


def bp_dict(w: World, v: dict[str, Any]) -> dict[str, Any]:
    return {
        "namespace": w.ns,
        "name": v["name"],
        "version": v["version"],
        "content_hash": v["content_hash"],
    }


def ref_of(w: World, v: dict[str, Any]) -> str:
    return f"{w.ns}/{v['name']}@{v['version']}"


def start_and_wait(
    w: World, cls: type[EvalClient], suite: str, v: dict[str, Any], *, mode: str | None = None
) -> dict[str, Any]:
    c = w.client(cls)
    run = c.call(
        "evalsRunStart", suite=suite, blueprint=ref_of(w, v), **({"mode": mode} if mode else {})
    )
    assert run["status"] in ("queued", "running")
    return run  # type: ignore[no-any-return]


def wait_final(w: World, run_id: str, timeout_ms: int = 180000) -> dict[str, Any]:
    return w.owner.call("evalsRunWait", id=run_id, timeout_ms=timeout_ms)  # type: ignore[no-any-return]


def grade_all(
    w: World,
    run_id: str,
    scores: dict[str, float],
    *,
    clients: list[type[EvalClient]] | None = None,
) -> list[dict[str, Any]]:
    """The reviewer (an operator who neither started the run nor published the blueprint) claims and grades every open task of the run,
    rotating through the three clients. ``scores`` maps case id -> score."""
    clients = clients or [TsSdk, PySdk, Cli]
    rv = lambda cls: w.client(cls, w.reviewer_key)  # noqa: E731
    tasks = until(
        lambda: [t for t in rv(PySdk).call("evalsReviewTasks", params={"run_id": run_id})["items"]],
        f"review tasks of run {run_id}",
    )
    done = []
    for i, t in enumerate(sorted(tasks, key=lambda t: t["case_id"])):
        c = rv(clients[i % len(clients)])
        claimed = c.call("evalsReviewClaim", id=t["id"])
        assert claimed["claimed_by"] == w.reviewer["member_id"] or claimed["state"] == "claimed"
        done.append(
            c.call(
                "evalsReviewGrade",
                id=t["id"],
                score=scores[t["case_id"]],
                comment=f"graded by {c.name}",
            )
        )
    return done


def recompute(run: dict[str, Any], suite: dict[str, Any]) -> dict[str, Any]:
    """An independent recomputation of the run's score from its per-case grades, with the runner's own aggregation module."""
    graders = [
        GraderSpec(
            g["id"], g["kind"], float(g.get("weight", 1)), g.get("config", {}), g.get("min_mean")
        )
        for g in suite["graders"]
    ]
    grid = {
        c["case_id"]: {
            g["grader_id"]: Grade(
                g["grader_id"], g["kind"], g["status"], float(g["score"]), g.get("detail", "")
            )
            for g in c["grades"]
        }
        for c in run["case_results"]
    }
    agg = aggregate(graders, grid, pass_threshold=suite["pass_threshold"])
    return agg.to_wire()  # type: ignore[no-any-return]


# ==== 0. the world ===================================================================================================


def test_00_the_tenant_policy_carries_the_shipped_judge_rule() -> None:
    """The judge bootstrap: the tenant pack of this suite contains, verbatim, the rule shipped as policies/eval-judge (a tenant that
    denies by default must add it, or every model-graded case is ungraded: see test_11)."""
    shipped = next(
        r for r in SHIPPED_JUDGE_PACK["spec"]["rules"] if r["id"] == "allow-eval-judge-model-calls"
    )
    mine = next(r for r in PACK["spec"]["rules"] if r["id"] == "allow-eval-judge-model-calls")
    assert mine == shipped


def test_01_dataset_and_suite_through_the_three_clients(world: World) -> None:
    """Scenario 1 (setup): a dataset version by the TS SDK, a suite by the CLI, reads by the Python SDK; the hub's dataset hash is the
    hash the runner computes (a cross-language canonical JSON contract); a human, a model and two deterministic graders."""
    setup_publisher(world)
    ds = world.client(TsSdk).call(
        "evalsDatasetCreate",
        body={"name": "answer-cases", "cases": CASES, "description": "claim status questions"},
    )
    assert ds["ref"] == "answer-cases@1" and ds["case_count"] == 4
    got = world.client(PySdk).call("evalsDatasetGet", name="answer-cases", version=1)
    expect = dataset_content_hash([EvalCase.from_wire({**c, "metadata": {}}) for c in CASES])
    assert got["content_hash"] == expect == ds["content_hash"], (
        "dataset hash differs between the hub (JS) and the runner (Python)"
    )
    suite = world.client(Cli).call("evalsSuiteCreate", body=SUITE)
    assert suite["ref"] == SUITE_REF and suite["dataset_hash"] == ds["content_hash"]
    assert [g["kind"] for g in suite["graders"]] == [
        "deterministic",
        "deterministic",
        "model",
        "human",
    ]
    fast = world.owner.call("evalsSuiteCreate", body=FAST_SUITE)
    assert fast["ref"] == FAST_REF
    # immutability: the same suite ref is a conflict, never a silent replacement
    with pytest.raises(ApiFail):
        world.owner.call("evalsSuiteCreate", body={**SUITE, "pass_threshold": 0.1})
    assert [d["ref"] for d in world.client(TsSdk).call("evalsDatasetList")["items"]] == [
        "answer-cases@1"
    ]


def test_02_the_real_runner_starts_registered_and_the_policy_allows_the_judge(world: World) -> None:
    r = world.start_runner("runner-a")
    time.sleep(2.0)
    assert r.alive(), r.stderr()
    listed = world.client(Cli).call("evalsRunnersList")["items"]
    assert [x["runner_id"] for x in listed] == ["runner-a"] and listed[0]["revoked_at"] is None


# ==== 1. blueprint v1: evals through the real kernel, human grades, the gate allows, the release succeeds =============================


def test_03_the_gate_is_closed_before_any_run(world: World) -> None:
    """Fail closed at the start: v1 is published (signed, in the registry) but has no run. The gate, the marketplace submit and the
    registry release all refuse, with the same reason, from every client."""
    s = world.stack
    v1 = publish_version(world, ABL_V1, local=True)
    world.state["v1"] = v1
    assert v1["version"] == "1.0.0" and len(v1["content_hash"]) == 64
    for cls in CLIENTS:
        g = world.client(cls).call(
            "evalsGate", blueprint=bp_dict(world, v1), suites=[{"ref": SUITE_REF, "threshold": 0.5}]
        )
        assert g["allowed"] is False and codes(g) == ["missing_run"], (cls.name, g)
        assert g["reasons"][0]["suite_ref"] == SUITE_REF
    cli = world.client(Cli)
    assert isinstance(cli, Cli)
    assert cli.last_exit("evals", "gate", ref_of(world, v1)) == 4  # DENIED
    s.ops("mp/publisher-verify", tenant_id=world.a["tenant_id"])
    status, body = s.ops_raw(
        "mp/submit",
        tenant_id=world.a["tenant_id"],
        namespace=world.ns,
        name="answer-agent",
        version="1.0.0",
    )
    assert status == 500 and body["code"] == "evals_gate_failed", body
    assert [r["code"] for r in body["reasons"]] == ["missing_run"]
    status, body = s.ops_raw(
        "registry/release", namespace=world.ns, name="answer-agent", version="1.0.0"
    )
    assert status == 500 and body["code"] == "evals_gate_failed", body
    # nothing became public
    pub = httpx.get(
        f"{s.gateway}/registry/resolve",
        params={"ref": f"{world.ns}/answer-agent@^1"},
        headers={"x-axis-api-key": world.key_b},
    )
    assert pub.status_code == 404


def test_04_a_run_executes_through_the_kernel_and_waits_for_the_human(world: World) -> None:
    """Scenario 1: queue the suite against v1 from the CLI. The REAL runner claims it, fetches v1's compiled manifest from the hub,
    runs the four cases through the real run path (every model call gated by the kernel, the judge included) and submits; the human
    grader holds the run until a reviewer has graded."""
    v1 = world.state["v1"]
    run = start_and_wait(world, Cli, SUITE_REF, v1)
    world.state["run1"] = run
    assert (
        run["suite"] == SUITE_REF
        and run["blueprint"]["content_hash"] == v1["content_hash"]
        and run["mode"] == "ci"
    )

    def waiting() -> Any:
        r = world.owner.call("evalsRunGet", id=run["id"])
        return r if r["pending_human"] == 4 else None

    r = until(waiting, "the run to reach the human review", timeout=120)
    assert r["status"] == "running" and r["runner_id"] == "runner-a" and r["score"] is None
    assert [c["case_id"] for c in r["case_results"]] == ["q1", "q2", "q3", "q4"]
    # a run waiting for a human is not a pass: the gate says so
    g = world.owner.call("evalsGate", blueprint=bp_dict(world, v1))
    assert g["allowed"] is False and "run_in_progress" in codes(g)
    # per-case drill-down: the agent's real output, the grader results, the kernel decisions of the trace
    q1 = next(c for c in r["case_results"] if c["case_id"] == "q1")
    assert "Claim 1001 is open" in q1["output"]
    by = {g["grader_id"]: g for g in q1["grades"]}
    assert by["has-facts"]["status"] == "scored" and by["has-facts"]["score"] == 1.0
    assert by["tone"]["status"] == "scored" and by["tone"]["score"] == 0.95
    assert (
        by["tone"]["provenance"]["judge"]["model"] == "gpt-4o-mini"
        and by["tone"]["provenance"]["judge"]["prompt_sha256"]
    )
    assert by["reviewer"]["status"] == "pending"
    decisions = q1["trace"]["gate_decisions"]
    assert decisions and all(
        d["decision"] == "ALLOW" for d in decisions if d["enforcement_point"] == "model_call"
    )


def test_05_the_human_review_is_independent_of_the_publisher(world: World) -> None:
    """Scenario 4 (first half): the owner started the run AND published the blueprint, so the owner never sees these tasks and cannot
    claim or grade one. The reviewer (an operator) can."""
    run = world.state["run1"]
    for cls in CLIENTS:
        assert (
            world.client(cls).call("evalsReviewTasks", params={"run_id": run["id"]})["items"] == []
        ), cls.name
    reviewer = world.client(PySdk, world.reviewer_key)
    tasks = until(
        lambda: reviewer.call("evalsReviewTasks", params={"run_id": run["id"]})["items"],
        "open review tasks",
    )
    assert len(tasks) == 4 and all(
        t["state"] == "open" and t["grader_id"] == "reviewer" for t in tasks
    )
    t = tasks[0]
    assert t["case_output"] and t["rubric"].startswith("Would you send")
    for cls in CLIENTS:  # reviewer == publisher/starter: refused by every client
        with pytest.raises(ApiFail) as e:
            world.client(cls).call("evalsReviewClaim", id=t["id"])
        assert e.value.status in (403, 404, None), (cls.name, e.value)
    with pytest.raises(ApiFail):
        world.client(PySdk).call(
            "evalsReviewGrade", id=t["id"], score=1.0, comment="I wrote it, it is perfect"
        )
    # the reviewer grades all four, one through each client in turn
    graded = grade_all(world, run["id"], {"q1": 0.9, "q2": 0.9, "q3": 0.9, "q4": 0.9})
    assert [g["state"] for g in graded] == ["resolved"] * 4
    final = wait_final(world, run["id"])
    world.state["run1_final"] = final
    assert final["status"] == "passed" and final["pending_human"] == 0


def test_06_the_hub_recomputes_the_scores_and_the_gate_allows(world: World) -> None:
    """Scenario 1: the stored scores equal an independent recomputation from the per-case grades; human scores came from the review
    queue (the runner cannot submit one); the gate allows from all three clients (CLI exit 0)."""
    run = world.state["run1"]
    detail = world.owner.call("evalsRunGet", id=run["id"])
    mine = recompute(detail, SUITE)
    assert (
        detail["scores"]["overall"] == mine["overall"]
        and detail["scores"]["per_case"] == mine["per_case"]
    )
    assert detail["scores"]["per_grader"] == mine["per_grader"]
    # (1 + 1 + 0.95 + 0.9) / 4
    assert abs(detail["score"] - 0.9625) < 1e-9, detail["scores"]
    human = [g for c in detail["case_results"] for g in c["grades"] if g["grader_id"] == "reviewer"]
    assert len(human) == 4 and all(
        g["status"] == "scored" and g["detail"].startswith("human_review") for g in human
    )
    v1 = world.state["v1"]
    for cls in CLIENTS:
        g = world.client(cls).call(
            "evalsGate", blueprint=bp_dict(world, v1), suites=[{"ref": SUITE_REF, "threshold": 0.5}]
        )
        assert g["allowed"] is True and g["reasons"] == [], (cls.name, g)
        assert g["runs"][0]["run_id"] == run["id"] and abs(g["runs"][0]["overall"] - 0.9625) < 1e-9
    assert world.client(Cli).last_exit("evals", "gate", ref_of(world, v1)) == 0
    # every model call of the run (the agent AND the judge) was decided by the real kernel and is in the tenant's audit chain
    rows = audit_rows(world.stack, world.a["tenant_id"])
    traces = {c["trace"]["trace_id"] for c in detail["case_results"]}
    mine_rows = [r for r in rows if r["trace_id"] in traces]
    assert any(
        r["enforcement_point"] == "model_call" and r["decision"] == "ALLOW" for r in mine_rows
    )
    judge_rows = [r for r in rows if (r.get("blueprint") or {}).get("name") == "eval-judge"]
    assert judge_rows and all(
        r["decision"] == "ALLOW" and r["enforcement_point"] == "model_call" for r in judge_rows
    )
    world.state["audit_judge_rows"] = len(judge_rows)


def test_07_release_succeeds_and_the_baseline_and_attestation_follow(world: World) -> None:
    """Scenario 1: marketplace submit passes the gate, the reviewer approves, the registry releases v1 (the gate is asked again), the run
    becomes the baseline, and the signed eval-result attestation is attached to the released version."""
    s = world.stack
    out = s.ops(
        "mp/review-and-list",
        tenant_id=world.a["tenant_id"],
        namespace=world.ns,
        name="answer-agent",
        version="1.0.0",
    )
    assert out["state"] in ("approved", "in_review", "listed") or out["state"]
    # v1 is now readable by every tenant
    r = httpx.get(
        f"{s.gateway}/registry/resolve",
        params={"ref": f"{world.ns}/answer-agent@^1"},
        headers={"x-axis-api-key": world.key_b},
    )
    assert r.status_code == 200 and r.json()["version"] == "1.0.0"
    base = world.owner.call("evalsBaselineList", blueprint="answer-agent", suite=SUITE_REF)["items"]
    assert [b["run_id"] for b in base] == [world.state["run1"]["id"]]
    assert base[0]["set_by"].startswith("release:")  # promoted by the release, not set by a person
    # the baseline run has nothing to be compared with
    assert world.owner.call("evalsCompare", id=world.state["run1"]["id"]) is None


# ==== 2. blueprint v2 regresses: the gate BLOCKS the release ===========================================================================


def test_08_v2_regresses_and_the_release_is_blocked(world: World) -> None:
    """Scenario 2: v2 (a cost-cutting prompt rewrite) is evaluated by the same suite. The runner runs it, the reviewer grades it; the run
    PASSES the suite's own bar (0.5) but drops far below the baseline v1 set, so the gate blocks with `regression`: from the TS SDK,
    the Python SDK and the CLI (exit 4), the registry release and the marketplace submit are refused with evals_gate_failed, and v2 stays
    private."""
    s = world.stack
    v2 = publish_version(world, ABL_V2, local=True)
    world.state["v2"] = v2
    run = start_and_wait(world, TsSdk, SUITE_REF, v2)
    world.state["run2"] = run
    until(
        lambda: world.owner.call("evalsRunGet", id=run["id"])["pending_human"] == 4,
        "v2 to reach human review",
        timeout=120,
    )
    # the reviewer sees the answers the terse prompt produced and grades them accordingly
    grade_all(world, run["id"], {"q1": 0.9, "q2": 0.9, "q3": 0.4, "q4": 0.4})
    final = wait_final(world, run["id"])
    assert final["status"] == "passed"  # above the suite's own bar of 0.5 ...
    assert final["score"] < 0.7 and final["scores"]["per_grader"]["has-facts"] == 0.5
    detail = world.owner.call("evalsRunGet", id=run["id"])
    assert recompute(detail, SUITE)["overall"] == detail["scores"]["overall"]
    # ... and still the release is blocked, from every client, with the reason
    for cls in CLIENTS:
        g = world.client(cls).call("evalsGate", blueprint=bp_dict(world, v2))
        assert g["allowed"] is False and codes(g) == ["regression"], (cls.name, g)
        assert g["runs"][0]["delta"] < -0.25 and g["runs"][0]["regression"] is True
    cli = world.client(Cli)
    assert isinstance(cli, Cli)
    assert cli.last_exit("evals", "gate", ref_of(world, v2)) == 4
    text = cli.run("evals", "gate", ref_of(world, v2), expect=(4,)).stdout
    assert "BLOCKED" in text and "regression" in text
    # the comparison with the baseline (v1's run) is explicit about it
    cmp_ = world.client(PySdk).call("evalsCompare", id=run["id"])
    assert (
        cmp_["regression"] is True
        and cmp_["blocking"] is True
        and cmp_["baseline_run_id"] == world.state["run1"]["id"]
    )
    assert cmp_["delta"] < -0.25 and cmp_["significance"] is not None
    assert cli.last_exit("evals", "compare", run["id"]) == 4
    # marketplace submit and registry release are refused with evals_gate_failed (the reasons travel with the refusal)
    status, body = s.ops_raw(
        "mp/submit",
        tenant_id=world.a["tenant_id"],
        namespace=world.ns,
        name="answer-agent",
        version="1.1.0",
    )
    assert (
        status == 500
        and body["code"] == "evals_gate_failed"
        and [r["code"] for r in body["reasons"]] == ["regression"]
    ), body
    status, body = s.ops_raw(
        "registry/release", namespace=world.ns, name="answer-agent", version="1.1.0"
    )
    assert status == 500 and body["code"] == "evals_gate_failed", body
    # v2 is not public: another tenant resolves v1 only
    r = httpx.get(
        f"{s.gateway}/registry/resolve",
        params={"ref": f"{world.ns}/answer-agent@^1"},
        headers={"x-axis-api-key": world.key_b},
    )
    assert r.status_code == 200 and r.json()["version"] == "1.0.0"
    # every refusal is in the tenant's audit chain
    rows = audit_rows(s, world.a["tenant_id"])
    denied = [
        r for r in rows if r["action"].startswith("registry.evals_gate") and r["decision"] == "DENY"
    ]
    assert len(denied) >= 4 and any("regression" in (r["reason"] or "") for r in denied)
    # the baseline is still v1's run: a regression does not move it
    base = world.owner.call("evalsBaselineList", blueprint="answer-agent", suite=SUITE_REF)["items"]
    assert [b["run_id"] for b in base] == [world.state["run1"]["id"]]


def test_09_eval_history_is_visible_per_version(world: World) -> None:
    """The history of a version: every run bound to its content hash, newest first, with score, runner, status and the gate verdict."""
    v1, v2 = world.state["v1"], world.state["v2"]
    for cls in CLIENTS:
        h1 = world.client(cls).call(
            "evalsRunList", params={"blueprint": "answer-agent", "suite": SUITE_REF}
        )["items"]
        assert {r["id"] for r in h1} == {world.state["run1"]["id"], world.state["run2"]["id"]}, (
            cls.name
        )
    only1 = world.owner.call("evalsRunList", params={"content_hash": v1["content_hash"]})["items"]
    assert [r["id"] for r in only1] == [world.state["run1"]["id"]]
    only2 = world.owner.call("evalsRunList", params={"content_hash": v2["content_hash"]})["items"]
    assert [r["id"] for r in only2] == [world.state["run2"]["id"]] and only2[0]["score"] < only1[0][
        "score"
    ]
