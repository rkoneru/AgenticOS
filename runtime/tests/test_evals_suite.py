"""Suite execution end to end (agent via the real run path, deterministic + model + human graders),
the submission payload, refusals, the worker loop and the hub HTTP client."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from axis_runtime.evals.aggregation import aggregate
from axis_runtime.evals.hubclient import HttpEvalHubClient, HubError, RunnerIdentity
from axis_runtime.evals.judge import JUDGE_SYSTEM_PROMPT
from axis_runtime.evals.judge_backend import RunPathJudgeBackend
from axis_runtime.evals.suite import RunRefused, SuiteExecutor, eval_policy, runner_config
from axis_runtime.evals.types import (
    BlueprintRef,
    Dataset,
    EvalCase,
    Grade,
    GraderSpec,
    OnlineConfig,
    QueuedRun,
    Suite,
    WireError,
    dataset_content_hash,
)
from axis_runtime.evals.worker import EvalWorker, OnlineWorker, WorkerConfig
from conftest import TENANT, ScriptedGate, allow
from evals_helpers import FakeHub, FnTransport, SeqIds, det, make_base_deps, make_manifest, text_body, user_text

WIRE = json.loads((Path(__file__).parent / "fixtures" / "eval-hub-wire-examples.json").read_text())
IDENT = RunnerIdentity("runner-1", "tok-secret-1")
HASH = "a" * 64


def dataset(cases: list[EvalCase], *, phi: bool = False) -> Dataset:
    return Dataset("refund-cases@3", dataset_content_hash(cases), tuple(cases), phi)


def suite(*graders: GraderSpec, threshold: float = 0.8, **kw: Any) -> Suite:
    return Suite("refunds@1.0.0", "refund-cases@3", graders, threshold, **kw)


def queued(seed: int = 7, **over: Any) -> QueuedRun:
    base: dict[str, Any] = {
        "id": "evr_01",
        "tenant_id": TENANT,
        "suite_ref": "refunds@1.0.0",
        "seed": seed,
        "blueprint": BlueprintRef("claims-triage", "1.0.0", HASH),
    }
    return QueuedRun(**{**base, **over})


def refund_agent(answers: dict[str, str]) -> Any:
    def fn(messages: list[dict[str, Any]], n: int) -> dict[str, Any]:
        system = messages[0]["content"] if messages and messages[0]["role"] == "system" else ""
        text = user_text(messages)
        if system == JUDGE_SYSTEM_PROMPT:  # the judge: polite & mentions amount -> 1, else 0
            body = text.split("<<<BEGIN_UNTRUSTED_OUTPUT")[1]
            return text_body('{"score": %s, "rationale": "graded"}' % ("1.0" if "$5" in body else "0.0"))
        for key, answer in answers.items():
            if key in text:
                return text_body(answer)
        return text_body("I do not know")

    return fn


def executor(fn: Any, gate: ScriptedGate | None = None, *, judge: bool = True) -> tuple[SuiteExecutor, FnTransport]:
    transport = FnTransport(fn)
    base = make_base_deps(transport, gate)
    return (
        SuiteExecutor(
            base_deps=base,
            tenant_id=TENANT,
            identity=IDENT,
            judge_backend=RunPathJudgeBackend(base, tenant_id=TENANT, ids=SeqIds()) if judge else None,
            ids=SeqIds(),
            nonce=lambda: "n0nce1234567890a",
        ),
        transport,
    )


CASES = [
    EvalCase("c1", "refund for order 7?", {"contains": ["$5"]}),
    EvalCase("c2", "refund for order 8?", {"contains": ["$9"]}),
    EvalCase("c3", "refund for order 9?", {"contains": ["$5"]}),
]
RUBRIC = {"provider": "openai", "model": "gpt-4o", "rubric": "States the correct refund politely."}
GRADERS = (
    GraderSpec("amount", "deterministic", 2.0, {"type": "contains"}),
    GraderSpec("tone", "model", 1.0, RUBRIC),
)
MANIFEST = make_manifest(blueprint={"name": "claims-triage", "version": "1.0.0", "content_hash": HASH})


async def test_scores_come_only_from_executed_graders() -> None:
    ex, _ = executor(refund_agent({"order 7": "It is $5.", "order 8": "It is $5.", "order 9": "no idea"}))
    res = await ex.execute(queued(), suite(*GRADERS), dataset(CASES), MANIFEST)
    # c1: $5 expected, $5 given -> contains 1, judge 1; c2: expects $9, got $5 -> contains 0, judge 1; c3: 0, 0
    assert res.aggregate.per_grader == {"amount": 0.333333, "tone": 0.666667}
    assert res.aggregate.per_case == {"c1": 1.0, "c2": 0.333333, "c3": 0.0}
    assert res.aggregate.overall == 0.444444 and res.aggregate.passed is False
    # the same suite against a better agent gets a better score: nothing is canned
    ex2, _ = executor(refund_agent({"order 7": "It is $5.", "order 8": "It is $9", "order 9": "It is $5 sir"}))
    res2 = await ex2.execute(queued(), suite(*GRADERS), dataset(CASES), MANIFEST)
    assert res2.aggregate.per_grader["amount"] == 1.0
    assert res2.aggregate.overall > res.aggregate.overall


async def test_payload_shape_provenance_and_hub_recompute() -> None:
    ex, _ = executor(refund_agent({"order 7": "It is $5.", "order 8": "It is $5.", "order 9": "no idea"}))
    s, ds = suite(*GRADERS), dataset(CASES)
    res = await ex.execute(queued(), s, ds, MANIFEST)
    p = res.payload
    ex_keys = WIRE["results_request"]
    assert sorted(p) == ex_keys["body_keys"] and sorted(p["scores"]) == ex_keys["scores_keys"]
    assert sorted(p["cost"]) == ex_keys["cost_keys"] and sorted(p["provenance"]) == ex_keys["provenance_keys"]
    cr = p["case_results"][0]
    assert sorted(cr) == ex_keys["case_result_keys"] and sorted(cr["trace"]) == ex_keys["trace_keys"]
    assert sorted(cr["grades"][0]) == ex_keys["grade_keys"]
    prov = p["provenance"]
    assert prov["seed"] == 7 and prov["runner_version"] == "1.0.0" and prov["runner_id"] == "runner-1"
    assert prov["blueprint_content_hash"] == HASH and prov["dataset_version_hash"] == ds.version_hash
    assert prov["suite_ref"] == "refunds@1.0.0" and prov["model_ids"] == ["openai/gpt-4o-2024-08-06"]
    assert prov["judges"]["tone"]["prompt_sha256"] and prov["aggregation_version"] == 1
    assert p["status"] == "completed" and p["mode"] == "ci" and p["started_at"] <= p["finished_at"]
    assert float(p["cost"]["total_usd"]) > 0 and p["cost"]["tokens"] > 0 and p["cost"]["judge_tokens"] > 0
    # the hub recomputes the scores from the per-case grades and must get the same numbers
    grades = {
        c["case_id"]: {g["grader_id"]: Grade(g["grader_id"], g["kind"], g["status"], g["score"]) for g in c["grades"]}
        for c in p["case_results"]
    }
    again = aggregate(s.graders, grades, pass_threshold=s.pass_threshold, min_case_score=s.min_case_score)
    assert again.to_wire() == p["scores"]
    json.dumps(p)  # JSON-serialisable


async def test_a_run_is_refused_when_its_inputs_are_not_what_was_queued() -> None:
    ex, transport = executor(refund_agent({}))
    s, ds = suite(*GRADERS), dataset(CASES)
    stale = make_manifest(blueprint={"name": "claims-triage", "version": "1.0.0", "content_hash": "b" * 64})
    with pytest.raises(RunRefused, match="blueprint_hash_mismatch"):
        await ex.execute(queued(), s, ds, stale)
    with pytest.raises(RunRefused, match="blueprint_mismatch"):
        await ex.execute(queued(blueprint=BlueprintRef("other", "1.0.0", HASH)), s, ds, MANIFEST)
    with pytest.raises(RunRefused, match="tenant_mismatch"):
        await ex.execute(queued(tenant_id="22222222-2222-4222-8222-222222222222"), s, ds, MANIFEST)
    with pytest.raises(RunRefused, match="suite_or_dataset_mismatch"):
        await ex.execute(queued(suite_ref="other@1"), s, ds, MANIFEST)
    tampered = Dataset(ds.ref, ds.version_hash, ds.cases[:2], False)
    with pytest.raises(RunRefused, match="dataset_hash_mismatch"):
        await ex.execute(queued(), s, tampered, MANIFEST)
    assert transport.calls == []  # nothing ran


async def test_phi_datasets_are_redacted_before_persisting_and_before_the_judge() -> None:
    seen: list[str] = []

    def fn(messages: list[dict[str, Any]], n: int) -> dict[str, Any]:
        system = messages[0]["content"] if messages[0]["role"] == "system" else ""
        if system == JUDGE_SYSTEM_PROMPT:
            seen.append(user_text(messages))
            return text_body('{"score": 1, "rationale": "ok"}')
        return text_body("Patient SSN 123-45-6789 owes $5, key sk-abcdefghijklmnop1234")

    ex, _ = executor(fn)
    res = await ex.execute(queued(), suite(GRADERS[1]), dataset(CASES[:1], phi=True), MANIFEST)
    out = res.payload["case_results"][0]["output"]
    assert "123-45-6789" not in out and "sk-abcdefghijklmnop1234" not in out and "[REDACTED]" in out
    assert "123-45-6789" not in seen[0]
    # without PHI only credentials are scrubbed from what is persisted
    res2 = await ex.execute(queued(), suite(GRADERS[1]), dataset(CASES[:1], phi=False), MANIFEST)
    out2 = res2.payload["case_results"][0]["output"]
    assert "123-45-6789" in out2 and "sk-abcdefghijklmnop1234" not in out2


async def test_human_graders_leave_the_run_pending_and_produce_review_tasks() -> None:
    human = GraderSpec("review", "human", 1.0, {"rubric": "Is the tone ok?", "include_expected": True})
    ex, _ = executor(refund_agent({"order": "It is $5."}), judge=False)
    ds = dataset([EvalCase("c1", "order 1 refund?", {"output": "$5"}), EvalCase("c2", "order 2 refund?")])
    res = await ex.execute(queued(), suite(GRADERS[0], human), ds, MANIFEST)
    assert res.payload["status"] == "pending_human"
    assert res.payload["scores"]["status"] == "pending_human" and res.payload["scores"]["overall"] is None
    assert res.payload["scores"]["passed"] is None
    assert [(t.case_id, t.grader_id) for t in res.review_tasks] == [("c1", "review"), ("c2", "review")]
    assert res.review_tasks[0].expected == {"output": "$5"} and res.review_tasks[1].expected is None


async def test_model_graders_without_a_judge_backend_are_ungraded() -> None:
    ex, _ = executor(refund_agent({"order": "It is $5."}), judge=False)
    res = await ex.execute(queued(), suite(GRADERS[1]), dataset(CASES[:1]), MANIFEST)
    assert res.aggregate.overall == 0.0 and res.aggregate.ungraded == 1 and res.aggregate.passed is False


async def test_an_infrastructure_error_case_cannot_pass_the_run() -> None:
    class Dead:
        async def evaluate(self, request: Any) -> Any:
            raise RuntimeError("kernel down")

    ex, _ = executor(refund_agent({}), Dead(), judge=False)  # type: ignore[arg-type]
    res = await ex.execute(queued(), suite(GRADERS[0], threshold=0.0), dataset(CASES[:1]), MANIFEST)
    assert res.payload["case_results"][0]["status"] == "error" and res.payload["case_results"][0]["trace"] is None
    assert res.aggregate.passed is False and "errored_cases:c1" in res.aggregate.failures


async def test_suite_settings_drive_the_runner_and_the_eval_policy() -> None:
    s = suite(GRADERS[0], settings={"concurrency": 1, "case_timeout_seconds": 9, "max_tokens": 50, "allow_sandboxed_targets": ["run_python", 3]})
    cfg = runner_config(s)
    assert (cfg.concurrency, cfg.case_timeout_seconds, cfg.max_tokens) == (1, 9.0, 50)
    assert eval_policy(s).allow_sandboxed == frozenset({"run_python"})
    weird = suite(GRADERS[0], settings={"concurrency": True, "allow_sandboxed_targets": "all"})
    assert runner_config(weird).concurrency == 4 and eval_policy(weird).allow_sandboxed == frozenset()


async def test_same_seed_same_scores_end_to_end() -> None:
    answers = {"order 7": "It is $5.", "order 8": "It is $5.", "order 9": "no idea"}
    r1 = await executor(refund_agent(answers))[0].execute(queued(), suite(*GRADERS), dataset(CASES), MANIFEST)
    r2 = await executor(refund_agent(answers))[0].execute(queued(), suite(*GRADERS), dataset(CASES), MANIFEST)
    assert r1.payload["scores"] == r2.payload["scores"]
    assert [c["seed"] for c in r1.payload["case_results"]] == [c["seed"] for c in r2.payload["case_results"]]
    r3 = await executor(refund_agent(answers))[0].execute(queued(seed=8), suite(*GRADERS), dataset(CASES), MANIFEST)
    assert [c["seed"] for c in r3.payload["case_results"]] != [c["seed"] for c in r1.payload["case_results"]]


# ---- worker ---------------------------------------------------------------------------------------


def hub_with(run: QueuedRun | None = None, *graders: GraderSpec) -> FakeHub:
    hub = FakeHub()
    s = suite(*(graders or (GRADERS[0],)))
    hub.suites[s.ref] = s
    hub.datasets["refund-cases@3"] = dataset(CASES)
    if run:
        hub.queue.append(run)
    return hub


class Manifests:
    def __init__(self, m: Any = MANIFEST) -> None:
        self.m = m

    async def manifest(self, blueprint: BlueprintRef) -> Any:
        return self.m


def worker(hub: FakeHub, fn: Any = None, manifests: Any = None, **kw: Any) -> EvalWorker:
    ex, _ = executor(fn or refund_agent({"order": "It is $5."}), judge=False)
    sleeps: list[float] = []

    async def nosleep(s: float) -> None:
        sleeps.append(s)

    w = EvalWorker(hub, ex, manifests or Manifests(), WorkerConfig(TENANT, poll_interval=0.01), sleep=nosleep, **kw)
    w.sleeps = sleeps  # type: ignore[attr-defined]
    return w


async def test_worker_claims_executes_and_submits() -> None:
    hub = hub_with(queued())
    w = worker(hub)
    assert await w.run_once() is True
    ((run_id, payload),) = hub.submissions
    assert run_id == "evr_01" and payload["status"] == "completed" and payload["scores"]["overall"] is not None
    assert await w.run_once() is False  # queue empty


async def test_worker_hands_human_work_to_the_hub() -> None:
    human = GraderSpec("review", "human", 1.0, {"rubric": "ok?"})
    hub = hub_with(queued(), GRADERS[0], human)
    await worker(hub).run_once()
    assert hub.submissions[0][1]["status"] == "pending_human"
    ((rid, tasks),) = hub.tasks
    assert rid == "evr_01" and sorted(tasks[0]) == WIRE["review_tasks_request"]["task_keys"] and len(tasks) == 3


async def test_worker_reports_a_refused_run_as_failed_without_scores() -> None:
    stale = make_manifest(blueprint={"name": "claims-triage", "version": "1.0.0", "content_hash": "c" * 64})
    hub = hub_with(queued())
    await worker(hub, manifests=Manifests(stale)).run_once()
    ((_, payload),) = hub.submissions
    assert payload["status"] == "failed" and payload["reason"] == "refused:blueprint_hash_mismatch"
    assert "scores" not in payload and sorted(payload) == WIRE["failed_request"]["body_keys"]


async def test_worker_survives_hub_and_manifest_failures() -> None:
    hub = hub_with(queued(suite_ref="missing@1"))
    await worker(hub).run_once()
    assert hub.submissions[0][1]["reason"].startswith("internal:")

    class Boom:
        async def manifest(self, b: BlueprintRef) -> Any:
            raise FileNotFoundError("no such manifest")

    hub2 = hub_with(queued())
    await worker(hub2, manifests=Boom()).run_once()
    assert hub2.submissions[0][1]["reason"] == "internal:FileNotFoundError"


async def test_worker_ignores_a_run_of_another_tenant() -> None:
    hub = hub_with(queued(tenant_id="22222222-2222-4222-8222-222222222222"))
    assert await worker(hub).run_once() is True
    assert hub.submissions == []


async def test_worker_retries_submission_and_never_resubmits_a_conflict() -> None:
    hub = hub_with(queued())
    hub.fail_submits = 2
    w = worker(hub)
    await w.run_once()
    assert len(hub.submissions) == 1 and len(w.sleeps) == 2  # type: ignore[attr-defined]

    class Conflict(FakeHub):
        async def submit_results(self, run_id: str, payload: Any) -> Any:
            self.submissions.append((run_id, payload))
            raise HubError("conflict")

    hub2 = Conflict()
    hub2.suites, hub2.datasets, hub2.queue = hub.suites, hub.datasets, [queued()]
    await worker(hub2).run_once()
    assert len(hub2.submissions) == 1


async def test_worker_survives_a_dead_hub_and_stops_on_request() -> None:
    class Dead(FakeHub):
        async def claim_run(self) -> QueuedRun | None:
            raise HubError("transport:ConnectError")

    w = worker(Dead())
    assert await w.run_once() is False
    stop = asyncio.Event()
    task = asyncio.create_task(w.run_forever(stop))
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, 2)


async def test_review_task_handoff_failure_is_logged_not_fatal() -> None:
    class NoTasks(FakeHub):
        async def create_review_tasks(self, run_id: str, tasks: Any) -> Any:
            raise HubError("http_500")

    human = GraderSpec("review", "human", 1.0, {"rubric": "ok?"})
    hub = NoTasks()
    s = suite(GRADERS[0], human)
    hub.suites[s.ref], hub.datasets["refund-cases@3"], hub.queue = s, dataset(CASES), [queued()]
    assert await worker(hub).run_once() is True
    assert len(hub.submissions) == 1


# ---- types ----------------------------------------------------------------------------------------


def test_wire_examples_parse_and_hash() -> None:
    s = Suite.from_wire(WIRE["suite"])
    assert [g.kind for g in s.graders] == ["deterministic", "model"] and s.graders[1].min_mean == 0.5
    d = Dataset.from_wire(WIRE["dataset"])
    assert d.computed_hash() == d.version_hash
    r = QueuedRun.from_wire(WIRE["claim_response"]["run"])
    assert r.seed == 7 and r.blueprint.name == "claims-triage"
    assert OnlineConfig.from_wire(WIRE["online_configs_response"]["configs"][0]).rate == 0.1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(graders=[]),
        lambda s: s.update(pass_threshold=1.5),
        lambda s: s.update(pass_threshold="high"),
        lambda s: s.update(ref="no-version"),
        lambda s: s["graders"][0].update(weight=0),
        lambda s: s["graders"][0].update(kind="vibes"),
        lambda s: s["graders"][0].update(id="bad id"),
        lambda s: s["graders"].append(dict(s["graders"][0])),
        lambda s: s.update(settings=[]),
        lambda s: s.update(min_case_score=2),
        lambda s: s["graders"][0].update(config=[]),
        lambda s: s["graders"][0].update(weight=float("nan")),
    ],
)
def test_malformed_suites_are_refused(mutate: Any) -> None:
    raw = json.loads(json.dumps(WIRE["suite"]))
    mutate(raw)
    with pytest.raises(WireError):
        Suite.from_wire(raw)


def test_malformed_datasets_and_runs_are_refused() -> None:
    for bad in (
        {**WIRE["dataset"], "cases": "x"},
        {**WIRE["dataset"], "version_hash": "short"},
        {**WIRE["dataset"], "cases": [WIRE["dataset"]["cases"][0], WIRE["dataset"]["cases"][0]]},
        {**WIRE["dataset"], "cases": [{"id": "ok"}]},
        {**WIRE["dataset"], "cases": [{"id": "bad id", "input": "x"}]},
        {**WIRE["dataset"], "cases": [{"id": "a", "input": "x", "tags": [1]}]},
        {**WIRE["dataset"], "cases": [{"id": "a", "input": "x", "metadata": []}]},
        [],
    ):
        with pytest.raises(WireError):
            Dataset.from_wire(bad)
    run = WIRE["claim_response"]["run"]
    for bad in ({**run, "mode": "x"}, {**run, "seed": -1}, {**run, "seed": True}, {**run, "blueprint": {"name": "x"}}, {**run, "id": ""}):
        with pytest.raises(WireError):
            QueuedRun.from_wire(bad)
    for bad in ({"blueprint": "b", "suite_ref": "s@1", "rate": 0.1, "max_per_hour": -1}, {"blueprint": "b", "suite_ref": "s@1", "rate": 2, "max_per_hour": 1}, {"blueprint": "b", "suite_ref": "s@1", "rate": 0.1, "max_per_hour": 1, "redaction": "none"}):
        with pytest.raises(WireError):
            OnlineConfig.from_wire(bad)
    assert EvalCase.from_wire({"id": "a", "input": {"k": 1}}).input_text == '{"k":1}'


# ---- HTTP client ----------------------------------------------------------------------------------


def http_client(handler: Any) -> tuple[HttpEvalHubClient, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return handler(req)

    client = HttpEvalHubClient("http://hub.test/", IDENT, client=httpx.AsyncClient(transport=httpx.MockTransport(wrapped)))
    return client, seen


async def test_http_client_authenticates_and_signs_the_exact_body() -> None:
    client, seen = http_client(lambda r: httpx.Response(200, json={"ok": True}))
    payload = {"b": 1, "a": [1, 2], "z": {"y": None}}
    await client.submit_results("evr_01", payload)
    (req,) = seen
    assert req.url.path == "/v1/evals/runs/evr_01/results" and req.method == "POST"
    assert req.headers["authorization"] == "Bearer tok-secret-1" and req.headers["x-axis-runner-id"] == "runner-1"
    expected = "v1=" + hmac.new(b"tok-secret-1", req.content, hashlib.sha256).hexdigest()
    assert req.headers["x-axis-runner-signature"] == expected
    assert json.loads(req.content) == payload
    assert sorted(WIRE["results_request"]["headers"]) == sorted(
        ["authorization", "x-axis-runner-id", "x-axis-runner-version", "x-axis-runner-signature", "content-type"]
    )
    assert all(h in req.headers for h in WIRE["results_request"]["headers"])
    keyed = RunnerIdentity("r", "tok", b"separate-signing-key")
    assert keyed.sign(b"x") == "v1=" + hmac.new(b"separate-signing-key", b"x", hashlib.sha256).hexdigest()
    await client.aclose()


async def test_http_client_claim_and_fetch() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/evals/runner/claim":
            assert json.loads(req.content) == WIRE["claim_request"]["body"]
            return httpx.Response(200, json=WIRE["claim_response"])
        if req.url.path.startswith("/v1/evals/suites/"):
            return httpx.Response(200, json=WIRE["suite"])
        if req.url.path.startswith("/v1/evals/datasets/"):
            return httpx.Response(200, json=WIRE["dataset"])
        if req.url.path == "/v1/evals/online/configs":
            return httpx.Response(200, json=WIRE["online_configs_response"])
        return httpx.Response(404)

    client, seen = http_client(handler)
    run = await client.claim_run()
    assert run is not None and run.id == "evr_01"
    assert (await client.get_suite("refunds@1.0.0")).pass_threshold == 0.8
    assert seen[-1].url.raw_path.decode() == "/v1/evals/suites/refunds%401.0.0"
    assert (await client.get_dataset("refund-cases@3")).cases[0].id == "c1"
    assert (await client.online_configs())[0].max_per_hour == 20


async def test_http_client_empty_claims_and_errors() -> None:
    c1, _ = http_client(lambda r: httpx.Response(204))
    assert await c1.claim_run() is None
    c2, _ = http_client(lambda r: httpx.Response(200, json={"run": None}))
    assert await c2.claim_run() is None
    c3, _ = http_client(lambda r: httpx.Response(200, json={"run": {"id": "x"}}))
    with pytest.raises(HubError, match="malformed_run"):
        await c3.claim_run()
    for status, kind in ((409, "conflict"), (500, "http_500"), (401, "http_401")):
        c, _ = http_client(lambda r, s=status: httpx.Response(s))  # type: ignore[misc]
        with pytest.raises(HubError, match=kind):
            await c.submit_results("evr_01", {})

    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused http://hub.test/?key=secret")

    c4, _ = http_client(boom)
    with pytest.raises(HubError) as ei:
        await c4.claim_run()
    assert ei.value.kind == "transport:ConnectError" and "secret" not in str(ei.value)
    c5, _ = http_client(lambda r: httpx.Response(200, content=b"not json"))
    for call in (c5.get_suite("a@1"), c5.get_dataset("a@1"), c5.online_configs()):
        with pytest.raises(HubError, match="malformed"):
            await call
    c6, _ = http_client(lambda r: httpx.Response(200, json={"name": "wrong"}))
    with pytest.raises(HubError, match="malformed_suite"):
        await c6.get_suite("a@1")
    with pytest.raises(HubError, match="malformed_dataset"):
        await c6.get_dataset("a@1")
    c7, _ = http_client(lambda r: httpx.Response(200, json={"configs": [{"blueprint": "b"}]}))
    with pytest.raises(HubError, match="malformed_online_config"):
        await c7.online_configs()
    c8, _ = http_client(lambda r: httpx.Response(200, json={"configs": 3}))
    with pytest.raises(HubError, match="malformed_response"):
        await c8.online_configs()
    c9, seen = http_client(lambda r: httpx.Response(201, json={"created": 1}))
    assert await c9.create_review_tasks("evr_01", [{"case_id": "c1"}]) == {"created": 1}
    assert json.loads(seen[0].content) == {"tasks": [{"case_id": "c1"}]}
    assert await c9.post_online_results({"mode": "online"}) == {"created": 1}
    c10, _ = http_client(lambda r: httpx.Response(200, json=[1]))
    assert await c10.submit_results("evr_01", {}) == {}


async def test_online_worker_builds_one_sampler_per_config_and_drops_removed_ones() -> None:
    built: list[OnlineConfig] = []

    class Stub:
        def __init__(self, config: OnlineConfig) -> None:
            self.config = config
            self.polls = 0

        async def poll_once(self) -> int:
            self.polls += 1
            return 2

        async def drain(self) -> None:
            return None

    def build(cfg: OnlineConfig) -> Any:
        built.append(cfg)
        return Stub(cfg)

    hub = FakeHub()
    cfg = OnlineConfig("claims-triage", "refunds@1.0.0", 0.5, 10)
    hub.online = [cfg]
    ow = OnlineWorker(hub, build, poll_interval=0.01)
    assert await ow.poll_once() == 2 and await ow.poll_once() == 2 and len(built) == 1
    hub.online = [OnlineConfig("claims-triage", "refunds@1.0.0", 0.9, 10)]
    await ow.poll_once()
    assert len(built) == 2  # a changed configuration rebuilds the sampler
    hub.online = []
    assert await ow.poll_once() == 0
    stop = asyncio.Event()
    task = asyncio.create_task(ow.run_forever(stop))
    await asyncio.sleep(0.03)
    stop.set()
    await asyncio.wait_for(task, 2)

    class Failing(FakeHub):
        async def online_configs(self) -> list[OnlineConfig]:
            raise HubError("http_500")

    assert await OnlineWorker(Failing(), build).poll_once() == 0
