"""Memory backend + RAG retriever: gating through the executor, wire contract, tenant/principal binding."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from axis_runtime import Decision
from axis_runtime.actions import Backends, MemoryWrite
from axis_runtime.executor import ActionExecutor, Completed, Denied, Failed
from axis_runtime.gate import GateDecision
from axis_runtime.memory import HttpMemoryBackend, MemoryRagRetriever, MemoryUnavailable
from axis_runtime.nexus import Hit, Miss, RagStage
from axis_runtime.redaction import REDACTED, redact_paths
from conftest import TENANT, FakeClock, ScriptedGate, allow, deny
from helpers import PID, identity, running_recorder
from nexus_helpers import req

ROOT = Path(__file__).resolve().parents[2]
WIRE = json.loads((ROOT / "services/memory/contract/wire-v1.json").read_text())
VECTORS = json.loads((ROOT / "services/memory/test/redaction-vectors.json").read_text())

Handler = Callable[[httpx.Request], httpx.Response]


class Wire:
    def __init__(self, handler: Handler | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler

    def client(self) -> httpx.AsyncClient:
        def respond(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            if self._handler is not None:
                return self._handler(request)
            return httpx.Response(200, json={"id": "m1", "deduped": False})

        return httpx.AsyncClient(transport=httpx.MockTransport(respond))

    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.content) for r in self.requests]


def backend(wire: Wire, **kw: Any) -> HttpMemoryBackend:
    kw.setdefault("owner_refs", {"run": "run_1", "session": "s1", "agent": "support-bot"})
    return HttpMemoryBackend(
        "http://mem",
        token="tok",
        tenant_id=TENANT,
        principal="agent:support-bot",
        groups=["agents"],
        client=wire.client(),
        **kw,
    )


# ---- gating: a memory write is an Action, so the gate decides ---------------------------------
async def _executor(gate: ScriptedGate, mem: HttpMemoryBackend) -> ActionExecutor:
    clock = FakeClock()
    return ActionExecutor(
        gate=gate,
        recorder=await running_recorder(clock),
        identity=identity(),
        backends=Backends(memory=mem),
        gate_timeout=0.2,
    )


async def test_allowed_write_reaches_the_service_as_a_gated_action() -> None:
    wire = Wire()
    gate = ScriptedGate(allow())
    ex = await _executor(gate, backend(wire))
    out = await ex.run(
        MemoryWrite(name="remember", scope="long_term", args={"content": "likes tea"}), pid=PID
    )
    assert isinstance(out, Completed) and out.result == {"id": "m1", "deduped": False}
    assert [r.enforcement_point for r in gate.requests] == ["memory_write"]
    body = wire.bodies()[0]
    assert body["scope"] == "agent" and body["owner_ref"] == "support-bot"
    assert body["tenant_id"] == TENANT and body["principal"] == {
        "id": "agent:support-bot",
        "groups": ["agents"],
    }


async def test_denied_write_never_calls_the_service() -> None:
    wire = Wire()
    ex = await _executor(ScriptedGate(deny()), backend(wire))
    out = await ex.run(
        MemoryWrite(name="remember", scope="long_term", args={"content": "x"}), pid=PID
    )
    assert isinstance(out, Denied)
    assert wire.requests == []


async def test_gate_redaction_is_applied_before_the_service_sees_the_write() -> None:
    wire = Wire()
    gate = ScriptedGate(
        GateDecision(Decision.ALLOW_WITH_REDACTION, "phi", redact_fields=("args.metadata.mrn",))
    )
    ex = await _executor(gate, backend(wire))
    await ex.run(
        MemoryWrite(
            name="remember",
            scope="session",
            args={"content": "c", "metadata": {"mrn": "998877"}, "phi": True},
        ),
        pid=PID,
    )
    body = wire.bodies()[0]
    assert body["metadata"] == {"mrn": REDACTED} and "998877" not in json.dumps(body)
    assert body["phi"] is True and body["scope"] == "session" and body["owner_ref"] == "s1"


async def test_service_failure_is_a_failed_action_not_a_success() -> None:
    wire = Wire(lambda _r: httpx.Response(500, json={"error": {"code": "INTERNAL"}}))
    ex = await _executor(ScriptedGate(allow()), backend(wire))
    out = await ex.run(MemoryWrite(name="remember", scope="run", args={"content": "x"}), pid=PID)
    assert isinstance(out, Failed) and "MemoryUnavailable" in out.error


# ---- backend behaviour -------------------------------------------------------------------------
async def test_scope_mapping_owner_refs_and_passthrough() -> None:
    wire = Wire()
    b = backend(wire)
    full = {
        "content": "c",
        "metadata": {"a": 1},
        "acl": {"tenant": True},
        "subject": "s",
        "ttl_seconds": 5,
        "phi": False,
        "junk": 1,
    }
    await b.write("run", full)
    await b.write("longTerm", {"content": "c"})
    await b.write("tenant", {"content": "c"})
    run, lt, tenant = wire.bodies()
    assert run["scope"] == "run" and run["owner_ref"] == "run_1"
    assert run["metadata"] == {"a": 1} and run["acl"] == {"tenant": True} and run["subject"] == "s"
    assert run["ttl_seconds"] == 5 and run["phi"] is False and "junk" not in run
    assert lt["scope"] == "agent" and "metadata" not in lt
    assert tenant["scope"] == "tenant" and "owner_ref" not in tenant
    assert wire.requests[0].headers["authorization"] == "Bearer tok"
    assert str(wire.requests[0].url) == "http://mem/v1/memory/write"


async def test_write_validation() -> None:
    b = backend(Wire(), owner_refs={})
    for scope, args in (
        ("bogus", {"content": "x"}),
        ("run", {"content": "x"}),
        ("tenant", {}),
        ("tenant", {"content": 3}),
        ("tenant", {"content": ""}),
    ):
        with pytest.raises(ValueError):
            await b.write(scope, args)
    with pytest.raises(ValueError):
        HttpMemoryBackend("http://m", token="t", tenant_id=TENANT, principal="")
    with pytest.raises(ValueError):
        HttpMemoryBackend("http://m", token="t", tenant_id="", principal="p")


async def test_recall_and_errors() -> None:
    wire = Wire(lambda _r: httpx.Response(200, json=WIRE["exchanges"][2]["response"]))
    b = backend(wire)
    entries = await b.recall("long_term", limit=10)
    assert entries[0]["content"] == "Customer prefers email."
    assert wire.bodies()[0]["owner_ref"] == "support-bot" and wire.bodies()[0]["scope"] == "agent"
    with pytest.raises(ValueError):
        await b.recall("bogus")
    for bad in (
        httpx.Response(200, json={"entries": "x"}),
        httpx.Response(200, content=b"nope"),
        httpx.Response(200, json=[1]),
        httpx.Response(403),
    ):
        with pytest.raises(MemoryUnavailable):
            await backend(Wire(lambda _r, bad=bad: bad)).recall("run")

    def boom(_r: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(MemoryUnavailable):
        await backend(Wire(boom)).recall("run")
    await b.aclose()


# ---- wire contract shared with services/memory/test/server.test.ts ----------------------------
async def test_client_requests_equal_the_shared_wire_contract() -> None:
    for ex in WIRE["exchanges"]:
        wire = Wire(lambda _r, ex=ex: httpx.Response(200, json=ex["response"]))
        b = backend(wire)
        args = ex["request"]
        if ex["route"] == "write":
            await b.write(
                "long_term", {k: args[k] for k in ("content", "metadata", "subject", "ttl_seconds")}
            )
        elif ex["route"] == "recall":
            await b.recall("long_term", limit=args["limit"])
        else:
            r = MemoryRagRetriever(
                "http://mem",
                token="tok",
                tenant_id=TENANT,
                client=wire.client(),
                groups_for=lambda _p: ["agents"],
            )
            await r.retrieve(
                tenant_id=TENANT,
                principal="agent:support-bot",
                query=args["query"],
                limit=args["limit"],
            )
        assert wire.bodies()[0] == json.loads(json.dumps(args).replace("{tenant}", TENANT)), ex[
            "name"
        ]
        assert str(wire.requests[0].url).endswith("/v1/memory/" + ex["route"])


def test_redaction_matches_shared_vectors_with_the_typescript_implementation() -> None:
    for v in VECTORS["vectors"]:
        assert redact_paths(v["doc"], v["paths"]) == v["expected"], v["name"]


# ---- RAG adapter -------------------------------------------------------------------------------
def retriever(handler: Handler, **kw: Any) -> tuple[MemoryRagRetriever, Wire]:
    wire = Wire(handler)
    return MemoryRagRetriever(
        "http://mem", token="tok", tenant_id=TENANT, client=wire.client(), **kw
    ), wire


def hits(*scores: float) -> Handler:
    body = {
        "hits": [
            {"id": f"c{i}", "content": f"passage {i}", "score": s} for i, s in enumerate(scores)
        ]
    }
    return lambda _r: httpx.Response(200, json=body)


async def test_retriever_maps_hits_to_passages_with_tenant_and_principal() -> None:
    r, wire = retriever(hits(1.2, 0.4, -0.3), kbs=["handbook"], groups_for=lambda p: ["g-" + p])
    out = await r.retrieve(tenant_id=TENANT, principal="user-1", query="q", limit=3)
    assert [(p.id, p.tenant_id, p.score) for p in out] == [
        ("c0", TENANT, 1.0),
        ("c1", TENANT, 0.4),
        ("c2", TENANT, 0.0),
    ]
    assert all(p.allowed_principals == frozenset({"user-1"}) for p in out)
    body = wire.bodies()[0]
    assert body["principal"] == {"id": "user-1", "groups": ["g-user-1"]}
    assert body["kbs"] == ["handbook"] and body["scopes"] == ["kb"] and body["limit"] == 3
    await r.aclose()


async def test_retriever_without_kbs_or_groups_searches_everything_readable() -> None:
    r, wire = retriever(hits(0.5))
    await r.retrieve(tenant_id=TENANT, principal="u", query="q", limit=1)
    body = wire.bodies()[0]
    assert body["principal"]["groups"] == [] and "kbs" not in body and "scopes" not in body


async def test_retriever_refuses_mismatched_tenant_or_missing_identity() -> None:
    r, wire = retriever(hits(0.5))
    with pytest.raises(ValueError):
        await r.retrieve(tenant_id="other-tenant", principal="u", query="q", limit=1)
    with pytest.raises(ValueError):
        await r.retrieve(tenant_id="", principal="u", query="q", limit=1)
    with pytest.raises(ValueError):
        await r.retrieve(tenant_id=TENANT, principal="", query="q", limit=1)
    assert wire.requests == []


async def test_retriever_rejects_malformed_service_output() -> None:
    for bad in (
        httpx.Response(200, json={"hits": "x"}),
        httpx.Response(200, json={"hits": [1]}),
        httpx.Response(200, json={"hits": [{"id": "a"}]}),
        httpx.Response(200, json={"hits": [{"id": "a", "content": "t", "score": "nan-ish"}]}),
        httpx.Response(401),
    ):
        r, _ = retriever(lambda _r, bad=bad: bad)
        with pytest.raises(MemoryUnavailable):
            await r.retrieve(tenant_id=TENANT, principal="u", query="q", limit=1)


async def test_rag_stage_answers_from_memory_and_a_low_score_rides_along_as_context() -> None:
    r, _ = retriever(hits(0.95))
    out = await RagStage(r).run(req("what is the refund window"), None)  # type: ignore[arg-type]
    assert isinstance(out, Hit) and out.answer == "passage 0"
    low, _ = retriever(hits(0.3))
    out2 = await RagStage(low).run(req("q"), None)  # type: ignore[arg-type]
    assert isinstance(out2, Miss) and out2.context  # type: ignore[attr-defined]
