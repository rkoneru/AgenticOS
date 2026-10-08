"""Shared world of the Phase 8 suites: the policy pack, blueprints, dataset and suite definitions, the tenants and people, the
runner processes, signed publishing and human grading. Used by the end-to-end test (``test_phase8_evals.py``) and by the seed of the
console's real-stack suite (``seed_console_evals.py``)."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).parent))
import interfaces_stack as istack  # noqa: E402
from axis_runtime.evals.aggregation import aggregate  # noqa: E402
from axis_runtime.evals.types import Grade, GraderSpec  # noqa: E402
from evals_clients import ApiFail, Cli, EvalClient, PySdk, TsSdk  # noqa: E402,F401

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
