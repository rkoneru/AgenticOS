from __future__ import annotations

import inspect
import json
from pathlib import Path

import httpx
import pytest
from axis_mock_server import MODEL, MockServer, sample_params
from axis_sdk import OPERATIONS, AsyncAxis, Axis
from axis_sdk._generated.client import GeneratedApi

KEY = "axk_test_key_123456"
RUN = "3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f"


def sync_client(server: MockServer, **kw: object) -> Axis:
    return Axis(
        KEY,
        base_url=server.base_url,
        http_client=httpx.Client(transport=server.transport()),
        sleep=lambda _s: None,
        **kw,
    )  # type: ignore[arg-type]


def snake(op_id: str) -> str:
    import re

    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", op_id).lower()


def _kwargs(op_id: str) -> dict[str, object]:
    spec = OPERATIONS[op_id]
    params = sample_params(op_id)
    out: dict[str, object] = {}
    for name in (*spec.path_params, *spec.query_params):
        if name in params:
            py = "from_" if name == "from" else snake(name)
            out[py] = params[name]
    if "body" in params:
        out["body"] = params["body"]
    return out


def test_operation_table_equals_the_spec() -> None:
    assert sorted(OPERATIONS) == sorted(o["operationId"] for o in MODEL["operations"])
    assert len(OPERATIONS) >= 19


def test_every_operation_has_a_generated_method() -> None:
    methods = {n for n, _ in inspect.getmembers(GeneratedApi, inspect.isfunction)}
    assert {snake(i) for i in OPERATIONS} <= methods


@pytest.mark.parametrize("op_id", sorted(OPERATIONS))
def test_generated_sync_method_sends_spec_valid_request(op_id: str) -> None:
    server = MockServer()
    ax = sync_client(server)
    out = getattr(ax.api, snake(op_id))(**_kwargs(op_id))
    assert server.violations == []
    assert [c.operation_id for c in server.calls] == [op_id]
    assert server.calls[0].method == OPERATIONS[op_id].method
    assert out is not None


@pytest.mark.parametrize("op_id", sorted(OPERATIONS))
async def test_generated_async_method_sends_spec_valid_request(op_id: str) -> None:
    server = MockServer()

    async def noop(_s: float) -> None:
        return None

    async with AsyncAxis(
        KEY,
        base_url=server.base_url,
        http_client=httpx.AsyncClient(transport=server.transport()),
        sleep=noop,
    ) as ax:
        out = await getattr(ax.api, snake(op_id))(**_kwargs(op_id))
    assert server.violations == []
    assert [c.operation_id for c in server.calls] == [op_id]
    assert out is not None


ERGONOMIC = {
    "listBlueprints": lambda ax: ax.blueprints.list(),
    "publishBlueprintVersion": lambda ax: ax.blueprints.publish({"apiVersion": "abl.axis.dev/v1"}),
    "getBlueprintVersion": lambda ax: ax.blueprints.get("agent-one", "1.0.0"),
    "listRuns": lambda ax: ax.runs.list(state="running"),
    "startRun": lambda ax: ax.runs.start("agent-one@1.0.0", {"q": 1}),
    "getRun": lambda ax: ax.runs.get(RUN),
    "signalRun": lambda ax: ax.runs.signal(RUN, "PAUSE"),
    "listRunEvents": lambda ax: ax.runs.events(RUN),
    "listApprovals": lambda ax: ax.approvals.list(status="pending"),
    "decideApproval": lambda ax: ax.approvals.approve(RUN, "ok"),
    "listPolicyPacks": lambda ax: ax.policies.list(),
    "publishPolicyPack": lambda ax: ax.policies.publish({"policy_version": "1"}),
    "testPolicy": lambda ax: ax.policies.test(
        {}, {"enforcement_point": "tool_call", "context": {}}
    ),
    "explainRun": lambda ax: ax.runs.explain(RUN),
    "explainAuditEvent": lambda ax: ax.audit.explain_event(7),
    "listAuditEvents": lambda ax: ax.audit.events(from_seq=1),
    "verifyAuditChain": lambda ax: ax.audit.verify(from_seq=1, to_seq=9),
    "listKillSwitches": lambda ax: ax.kill_switches.list(),
    "setKillSwitch": lambda ax: ax.kill_switches.engage("agent", "agent-one", "drill"),
    "getUsage": lambda ax: ax.usage.get(
        "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", group_by="day"
    ),
    "startEvalRun": lambda ax: ax.evals.start("smoke@1.0.0", "agent-one@1.0.0"),
    "listEvalRuns": lambda ax: ax.evals.list(suite="smoke@1.0.0", status="passed"),
    "getEvalRun": lambda ax: ax.evals.get(RUN),
    "getEvalRunComparison": lambda ax: ax.evals.comparison(RUN),
    "gateEvalRelease": lambda ax: ax.evals.gate(
        {"name": "agent-one", "version": "1.0.0", "content_hash": "a" * 64},
        [{"ref": "smoke@1.0.0", "threshold": 0.8}],
    ),
    "listEvalDatasets": lambda ax: ax.evals.datasets.list(name="qa"),
    "createEvalDataset": lambda ax: ax.evals.datasets.create(
        "qa", [{"id": "c1", "input": "q", "expected": "a"}]
    ),
    "getEvalDatasetVersion": lambda ax: ax.evals.datasets.get("qa", 1),
    "listEvalSuites": lambda ax: ax.evals.suites.list(),
    "createEvalSuite": lambda ax: ax.evals.suites.create(
        {
            "ref": "smoke@1.0.0",
            "dataset_ref": "qa@1",
            "graders": [{"id": "exact", "kind": "deterministic", "config": {"type": "exact"}}],
            "pass_threshold": 0.8,
        }
    ),
    "getEvalSuite": lambda ax: ax.evals.suites.get("smoke@1.0.0"),
    "listEvalBaselines": lambda ax: ax.evals.baselines.list("agent-one", "smoke@1.0.0"),
    "setEvalBaseline": lambda ax: ax.evals.baselines.set(RUN),
    "listEvalReviewTasks": lambda ax: ax.evals.review.tasks(state="open"),
    "claimEvalReviewTask": lambda ax: ax.evals.review.claim("rt-1"),
    "gradeEvalReviewTask": lambda ax: ax.evals.review.grade("rt-1", score=0.9, comment="clear"),
    "skipEvalReviewTask": lambda ax: ax.evals.review.skip("rt-1", "not my area"),
    "listEvalSamplingConfigs": lambda ax: ax.evals.sampling.list(),
    "putEvalSamplingConfig": lambda ax: ax.evals.sampling.put(
        "prod", blueprint="agent-one", suite="smoke@1.0.0", rate=0.1, max_per_hour=10
    ),
    "getEvalOnlineSummary": lambda ax: ax.evals.sampling.summary(blueprint="agent-one"),
    "listEvalRunners": lambda ax: ax.evals.runners.list(),
    "registerEvalRunner": lambda ax: ax.evals.runners.register("ci-1", "CI worker"),
    "revokeEvalRunner": lambda ax: ax.evals.runners.revoke("ci-1"),
    "getMe": lambda ax: ax.me(),
    "getApproval": lambda ax: ax.approvals.get(RUN),
    "activatePolicyPack": lambda ax: ax.policies.activate(RUN),
    "listRegistryNamespaces": lambda ax: ax.registry.namespaces(),
    "claimRegistryNamespace": lambda ax: ax.registry.claim("acme"),
    "listRegistryKeys": lambda ax: ax.registry.keys("acme"),
    "addRegistryKey": lambda ax: ax.registry.add_key("acme", "k" * 43),
    "publishRegistryBlueprint": lambda ax: ax.registry.publish(
        "acme",
        {
            "abl": {"apiVersion": "abl.axis.dev/v1"},
            "signature": {"key_id": "k1", "signed_at": "2026-01-01T00:00:00Z", "sig": "s"},
            "provenance": {
                "payloadType": "t",
                "payload": "p",
                "signatures": [{"keyid": "k1", "sig": "s"}],
            },
        },
    ),
    "listRegistryVersions": lambda ax: ax.registry.versions("acme", "agent-one"),
    "listRegistryEvalAttestations": lambda ax: ax.registry.eval_attestations(
        "acme", "agent-one", "1.0.0"
    ),
    "yankRegistryVersion": lambda ax: ax.registry.yank("acme", "agent-one", "1.0.0", "bad"),
    "resolveRegistryBlueprint": lambda ax: ax.registry.resolve("acme/agent-one@^1"),
    "listMarketplaceListings": lambda ax: ax.marketplace.listings(q="x"),
    "getMarketplaceListing": lambda ax: ax.marketplace.listing("acme", "agent-one"),
    "previewMarketplaceInstall": lambda ax: ax.marketplace.preview("acme", "agent-one", "^1"),
    "listMarketplaceInstalls": lambda ax: ax.marketplace.installs(),
    "installMarketplaceListing": lambda ax: ax.marketplace.install(
        "acme", "agent-one", "1.0.0", "a" * 64, "digest"
    ),
    "uninstallMarketplaceListing": lambda ax: ax.marketplace.uninstall("acme", "agent-one"),
    "listComplianceSystems": lambda ax: ax.compliance.systems.list(risk_level="high"),
    "createComplianceSystem": lambda ax: ax.compliance.systems.create(
        {
            "name": "Claims triage",
            "purpose": "Routes claims",
            "owner": "owner@example.test",
            "risk_level": "high",
        }
    ),
    "getComplianceSystem": lambda ax: ax.compliance.systems.get("claims-triage", version=1),
    "updateComplianceSystem": lambda ax: ax.compliance.systems.update(
        "claims-triage", 1, {"lifecycle_stage": "deployed"}
    ),
    "listComplianceImpactAssessments": lambda ax: ax.compliance.assessments.list(
        system_id="claims-triage", overdue=True
    ),
    "createComplianceImpactAssessment": lambda ax: ax.compliance.assessments.create(
        {
            "system_id": "claims-triage",
            "title": "Impact",
            "risk_rating": "high",
            "intended_use": "Routing",
            "review_due": "2027-01-01",
        }
    ),
    "getComplianceImpactAssessment": lambda ax: ax.compliance.assessments.get(
        "assessment-1", version=2
    ),
    "reviseComplianceImpactAssessment": lambda ax: ax.compliance.assessments.revise(
        "assessment-1", 1, {"title": "Retitled"}
    ),
    "submitComplianceImpactAssessment": lambda ax: ax.compliance.assessments.submit(
        "assessment-1", 1
    ),
    "withdrawComplianceImpactAssessment": lambda ax: ax.compliance.assessments.withdraw(
        "assessment-1", 1
    ),
    "reviewComplianceImpactAssessment": lambda ax: ax.compliance.assessments.review(
        "assessment-1", 1, "approve", "reviewed"
    ),
    "listComplianceDocuments": lambda ax: ax.compliance.documents.list(
        blueprint_name="agent-one", blueprint_version="1.0.0"
    ),
    "generateComplianceDocument": lambda ax: ax.compliance.documents.generate("agent-one@1.0.0"),
    "getComplianceDocument": lambda ax: ax.compliance.documents.get("cdoc-abc"),
}


def test_ergonomic_table_covers_the_whole_spec() -> None:
    assert sorted(ERGONOMIC) == sorted(OPERATIONS)


@pytest.mark.parametrize("op_id", sorted(ERGONOMIC))
def test_ergonomic_sync_layer_reaches_every_operation(op_id: str) -> None:
    server = MockServer()
    ERGONOMIC[op_id](sync_client(server))
    assert server.violations == []
    assert [c.operation_id for c in server.calls] == [op_id]


@pytest.mark.parametrize("op_id", sorted(ERGONOMIC))
async def test_ergonomic_async_layer_reaches_every_operation(op_id: str) -> None:
    server = MockServer()

    async def noop(_s: float) -> None:
        return None

    async with AsyncAxis(
        KEY,
        base_url=server.base_url,
        http_client=httpx.AsyncClient(transport=server.transport()),
        sleep=noop,
    ) as ax:
        await ERGONOMIC[op_id](ax)
    assert server.violations == []
    assert [c.operation_id for c in server.calls] == [op_id]


def test_generated_files_are_current() -> None:
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed")
    root = Path(__file__).resolve().parents[3]
    r = subprocess.run(  # noqa: S603
        [node, "scripts/generate-sdks.mjs", "--check"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )  # noqa: S603
    assert r.returncode == 0, r.stderr


def test_idempotency_key_is_generated_or_passed_through() -> None:
    server = MockServer()
    ax = sync_client(server)
    ax.runs.start("a-b@1")
    ax.runs.start("a-b@1", idempotency_key="my-own-key-1")
    assert len(server.calls[0].headers["idempotency-key"]) == 36
    assert server.calls[1].headers["idempotency-key"] == "my-own-key-1"
    assert json.loads(json.dumps(server.calls[0].body)) == {
        "blueprint": {"name": "a-b", "version": "1"}
    }
