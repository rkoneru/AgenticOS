"""Compliance records and sealed technical documentation against the REAL stack, through the TypeScript SDK, the Python SDK and the CLI.

Same stack as the Phase 7 suite (e2e/interfaces_stack.py): Postgres 16 with forced RLS, the standalone API gateway with the compliance
service on the Postgres store, the registry, the Eval Hub and the hash-chained audit log. Fakes: the IdP, KMS, DNS and the model provider.

What it proves, per client: an AI system is inventoried and versioned; an impact assessment goes draft -> submitted -> reviewed by
SOMEONE ELSE (the author, as owner, is refused, and the refusal is in the audit chain); overdue assessments are found; technical
documentation is generated from the tenant's real records, verifies on read, is idempotent for unchanged sources, changes after unrelated
activity, and FAILS verification when a stored byte is altered behind the service's back; another tenant sees none of it; an API key
limited to `compliance:read` cannot write.

Run with:  make e2e-compliance
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from axis_sdk import Axis

sys.path.insert(0, str(Path(__file__).parent))
import interfaces_stack as istack  # noqa: E402
from test_phase7_interfaces import ApiFail, Cli, PySdk, TsSdk, yaml_json  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CLAIMS_ABL = yaml_json("agents/claims7.abl.yaml")


class PyC(PySdk):
    name = "py-sdk"

    def _dispatch(self, ax: Axis, op: str, a: dict[str, Any]) -> Any:  # noqa: C901
        c = ax.compliance
        match op:
            case "systemCreate":
                return c.systems.create(a["body"])
            case "systemGet":
                return c.systems.get(a["id"], version=a.get("version"))
            case "assessmentCreate":
                return c.assessments.create(a["body"])
            case "assessmentGet":
                return c.assessments.get(a["id"], version=a.get("version"))
            case "assessmentList":
                return c.assessments.list(**a.get("params", {}))
            case "assessmentSubmit":
                return c.assessments.submit(a["id"], a["expected"])
            case "assessmentReview":
                return c.assessments.review(a["id"], a["expected"], a["decision"], a.get("comment"))
            case "docGenerate":
                return c.documents.generate(a["blueprint"])
            case "docGet":
                return c.documents.get(a["id"])
            case "docList":
                return c.documents.list(**a.get("params", {}))
        return super()._dispatch(ax, op, a)


class TsC(TsSdk):
    name = "ts-sdk"


class CliC(Cli):
    name = "cli"

    def call(self, op: str, **a: Any) -> Any:  # noqa: C901
        j = self.j
        match op:
            case "systemCreate":
                return j(
                    "compliance", "systems", "create", "--file", self.file("system.json", a["body"])
                )
            case "systemGet":
                return j("compliance", "systems", "get", a["id"])
            case "assessmentCreate":
                return j(
                    "compliance",
                    "assessments",
                    "create",
                    "--file",
                    self.file("assessment.json", a["body"]),
                )
            case "assessmentGet":
                extra = ["--revision", str(a["version"])] if a.get("version") else []
                return j("compliance", "assessments", "get", a["id"], *extra)
            case "assessmentList":
                p = a.get("params", {})
                extra = (["--system", p["system_id"]] if "system_id" in p else []) + (
                    ["--overdue"] if p.get("overdue") else []
                )
                return j("compliance", "assessments", "list", *extra)
            case "assessmentSubmit":
                return j(
                    "compliance",
                    "assessments",
                    "submit",
                    a["id"],
                    "--expected-version",
                    str(a["expected"]),
                )
            case "assessmentReview":
                extra = ["--comment", a["comment"]] if a.get("comment") else []
                return j(
                    "compliance", "assessments", "review", a["id"],
                    "--expected-version", str(a["expected"]), "--decision", a["decision"], *extra,
                )  # fmt: skip
            case "docGenerate":
                b = a["blueprint"]
                return j("compliance", "documents", "generate", f"{b['name']}@{b['version']}")
            case "docGet":
                # exit 1 when the document does not verify: the JSON is still printed
                r = self.run("--json", "compliance", "documents", "get", a["id"], expect=None)
                if not r.stdout.strip():
                    raise ApiFail(
                        404 if "not found" in r.stderr.lower() else None, r.stderr.strip()
                    )
                return json.loads(r.stdout)
            case "docList":
                return j("compliance", "documents", "list")
        return super().call(op, **a)


CLIENTS = [TsC, PyC, CliC]


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[istack.Stack]:
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise RuntimeError("PG_ADMIN_URL is required: run via `make e2e-compliance`")
    with istack.boot(tmp_path_factory.mktemp("e2ec"), admin) as st:
        yield st


class World:
    """Tenant A with an owner, a builder and an auditor (one client each), and tenant B (the attacker)."""

    def __init__(self, stack: istack.Stack, cls: type[Any]) -> None:
        self.stack = stack
        slug = f"{cls.name.replace('-', '')}{secrets.token_hex(3)}"
        self.a = stack.provision(f"a{slug}")
        self.b = stack.provision(f"b{slug}")
        tid = self.a["tenant_id"]
        self.owner = cls(stack, stack.api_key(tid, self.a["owner_member_id"]))
        builder = stack.ops("member", tenant_id=tid, role="builder")
        auditor = stack.ops("member", tenant_id=tid, role="auditor")
        self.builder = cls(stack, stack.api_key(tid, builder["member_id"]))
        self.auditor = cls(stack, stack.api_key(tid, auditor["member_id"]))
        self.owner_b = cls(stack, stack.api_key(self.b["tenant_id"], self.b["owner_member_id"]))
        self.reader = cls(
            stack, stack.api_key(tid, builder["member_id"], scopes=["compliance:read"])
        )
        self.system = f"claims-{secrets.token_hex(3)}"
        self.state: dict[str, Any] = {}


@pytest.fixture(scope="module", params=CLIENTS, ids=[c.name for c in CLIENTS])
def world(request: pytest.FixtureRequest, stack: istack.Stack) -> World:
    w = World(stack, request.param)
    # the blueprint is published with the Python SDK whatever client is under test: the subject here is the compliance API
    ax = Axis(w.owner.key, base_url=stack.gateway, allow_insecure=True, max_retries=0)
    ax.blueprints.publish(CLAIMS_ABL)
    return w


def assessment_body(system: str, **over: Any) -> dict[str, Any]:
    return {
        "system_id": system,
        "title": "Claims triage impact",
        "risk_rating": "high",
        "intended_use": "Recommend a routing queue; an adjuster decides",
        "blueprints": [{"name": "claims-agent", "version": "1.0.0"}],
        "affected_groups": [{"group": "claimants", "impact": "delay or misrouting of a claim"}],
        "risks": [
            {
                "id": "R1",
                "description": "Urgent claims routed late",
                "likelihood": "medium",
                "severity": "high",
                "mitigation": "An adjuster reviews every routing",
                "residual": "low",
            }
        ],
        "review_due": "2099-01-01",
        **over,
    }


def test_01_inventory_is_versioned_and_attributed(world: World) -> None:
    b = world.builder
    s = b.call(
        "systemCreate",
        body={
            "system_id": world.system,
            "name": "Claims triage",
            "purpose": "Routes inbound claims",
            "owner": "claims@example.test",
            "risk_level": "limited",
            "blueprints": [{"name": "claims-agent", "version": "1.0.0"}],
        },
    )
    assert s["system_id"] == world.system and s["version"] == 1
    assert s["created_by"] == world.state.setdefault("builder_id", s["created_by"])
    got = world.auditor.call("systemGet", id=world.system)
    assert got["version"] == 1 and got["risk_level"] == "limited"
    with pytest.raises(ApiFail) as e:  # an auditor reads; it does not write
        world.auditor.call(
            "systemCreate",
            body={"name": "x", "purpose": "x", "owner": "x", "risk_level": "minimal"},
        )
    assert e.value.status in (403, None)


def test_02_the_author_cannot_review_their_own_assessment_and_someone_else_can(
    world: World,
) -> None:
    b, o, a = world.builder, world.owner, world.auditor
    mine = b.call("assessmentCreate", body=assessment_body(world.system))
    assert mine["state"] == "draft" and mine["version"] == 1
    sub = b.call("assessmentSubmit", id=mine["assessment_id"], expected=1)
    assert sub["state"] == "in_review"
    # a builder may not review at all (role); the auditor (independent) may
    with pytest.raises(ApiFail):
        b.call(
            "assessmentReview",
            id=mine["assessment_id"],
            expected=1,
            decision="approve",
            comment="mine",
        )
    done = a.call(
        "assessmentReview",
        id=mine["assessment_id"],
        expected=1,
        decision="approve",
        comment="independent review",
    )
    assert done["state"] == "approved" and done["reviewed_by"] != done["author"]
    # the owner authors one and submits it: the owner role may review, but not this one
    own = o.call("assessmentCreate", body=assessment_body(world.system, title="Owner's assessment"))
    o.call("assessmentSubmit", id=own["assessment_id"], expected=1)
    with pytest.raises(ApiFail) as e:
        o.call(
            "assessmentReview",
            id=own["assessment_id"],
            expected=1,
            decision="approve",
            comment="self",
        )
    assert e.value.status in (403, None)
    still = o.call("assessmentGet", id=own["assessment_id"])
    assert still["state"] == "in_review" and still["reviewed_by"] is None
    # a reviewed version is frozen: reviewing again is refused
    with pytest.raises(ApiFail):
        a.call(
            "assessmentReview",
            id=mine["assessment_id"],
            expected=1,
            decision="reject",
            comment="changed my mind",
        )
    world.state["approved"] = mine["assessment_id"]
    world.state["own"] = own["assessment_id"]


def test_03_overdue_assessments_are_found(world: World) -> None:
    b, a = world.builder, world.auditor
    old = b.call(
        "assessmentCreate",
        body=assessment_body(world.system, title="Old review date", review_due="2020-01-01"),
    )
    b.call("assessmentSubmit", id=old["assessment_id"], expected=1)
    a.call(
        "assessmentReview", id=old["assessment_id"], expected=1, decision="approve", comment="ok"
    )
    rows = a.call("assessmentList", params={"overdue": True})
    items = rows["items"] if isinstance(rows, dict) else rows
    ids = {x["assessment_id"]: x for x in items}
    assert (
        old["assessment_id"] in ids
        and ids[old["assessment_id"]]["overdue_reason"] == "review_due_passed"
    )
    assert world.state["approved"] not in ids


def test_04_documentation_from_real_records_is_sealed_idempotent_and_changes_with_activity(
    world: World,
) -> None:
    b, a = world.builder, world.auditor
    bp = {"name": "claims-agent", "version": "1.0.0"}
    first = b.call("docGenerate", blueprint=bp)
    assert first["created"] is True
    doc = first["document"]
    body = doc["body"]
    assert body["sections"]["general"]["data"]["origin"] == "tenant"
    assert body["sections"]["record_keeping"]["status"] == "complete"
    assert body["sections"]["record_keeping"]["data"]["chain_verified"] is True
    assert body["sections"]["record_keeping"]["data"]["event_count"] > 0
    items = {(g["section"], g["item"]) for g in body["gaps"]}
    assert (
        "development",
        "registry_provenance",
    ) in items  # tenant-local: no signature or provenance to show
    assert ("general", "hardware_and_deployer_instructions") in items
    assert {c["point"]: c["status"] for c in body["annex_iv_coverage"]}["7"] == "gap"
    assert "certified" not in json.dumps(body).lower().replace("not certified", "")
    got = a.call("docGet", id=doc["meta"]["document_id"])
    assert got["verification"] == {"ok": True, "failed": []}
    again = b.call("docGenerate", blueprint=bp)
    assert again["created"] is False and again["document"]["content_hash"] == doc["content_hash"]
    # unrelated activity changes the audit statistics, so the next document is the next version
    ax = Axis(world.owner.key, base_url=world.stack.gateway, allow_insecure=True, max_retries=0)
    ax.blueprints.publish(
        {**CLAIMS_ABL, "metadata": {**CLAIMS_ABL["metadata"], "name": "claims-agent-two"}}
    )
    third = b.call("docGenerate", blueprint=bp)
    assert (
        third["created"] is True
        and third["document"]["meta"]["doc_version"] == doc["meta"]["doc_version"] + 1
    )
    world.state["doc_id"] = doc["meta"]["document_id"]
    listed = a.call("docList")
    rows = listed["items"] if isinstance(listed, dict) else listed
    assert [r["doc_version"] for r in rows if r["blueprint"]["name"] == "claims-agent"] == [1, 2]
    # an unknown blueprint is a document made of gaps, not an error
    ghost = b.call("docGenerate", blueprint={"name": "no-such-agent", "version": "1.0.0"})
    assert ghost["document"]["body"]["sections"]["general"]["status"] == "gap"


def test_05_a_document_altered_behind_the_service_fails_verification(world: World) -> None:
    doc_id = world.state["doc_id"]
    assert world.auditor.call("docGet", id=doc_id)["verification"]["ok"] is True
    url = world.stack.db_url
    # the database forbids this for every role; the owner of the table has to switch the guard off to simulate an attacker with storage access
    istack.psql(url, "ALTER TABLE compliance_docs DISABLE TRIGGER compliance_docs_guard")
    try:
        istack.psql(
            url,
            "UPDATE compliance_docs SET data = jsonb_set(data, '{document,body,sections,general,status}', '\"complete\"') "
            f"WHERE coll = 'documents' AND key = '{doc_id}'",
        )
    finally:
        istack.psql(url, "ALTER TABLE compliance_docs ENABLE TRIGGER compliance_docs_guard")
    got = world.auditor.call("docGet", id=doc_id)
    assert got["verification"]["ok"] is False and "content_hash" in got["verification"]["failed"]


def test_06_another_tenant_sees_nothing_and_cannot_act(world: World) -> None:
    ob = world.owner_b
    with pytest.raises(ApiFail) as e:
        ob.call("systemGet", id=world.system)
    assert e.value.status in (404, None)
    with pytest.raises(ApiFail):
        ob.call("assessmentGet", id=world.state["approved"])
    with pytest.raises(ApiFail):
        ob.call("docGet", id=world.state["doc_id"])
    with pytest.raises(ApiFail):
        ob.call(
            "assessmentReview",
            id=world.state["own"],
            expected=1,
            decision="approve",
            comment="not mine",
        )
    rows = ob.call("assessmentList", params={})
    assert (rows["items"] if isinstance(rows, dict) else rows) == []
    # tenant B's own document for the same name is about B's records, not A's
    g = ob.call("docGenerate", blueprint={"name": "claims-agent", "version": "1.0.0"})
    assert g["document"]["body"]["sections"]["general"]["status"] == "gap"
    assert g["document"]["meta"]["tenant_id"] == world.b["tenant_id"]


def test_07_a_read_scoped_key_cannot_write(world: World) -> None:
    r = world.reader
    assert r.call("systemGet", id=world.system)["system_id"] == world.system
    with pytest.raises(ApiFail) as e:
        r.call("assessmentCreate", body=assessment_body(world.system))
    assert e.value.status in (403, None)


def test_08_the_audit_chain_holds_every_step_including_the_refusal(world: World) -> None:
    ax = Axis(world.owner.key, base_url=world.stack.gateway, allow_insecure=True, max_retries=0)
    rows: list[dict[str, Any]] = []
    from_seq = 1
    while True:
        page = ax.audit.events(from_seq=from_seq, limit=200)["items"]
        if not page:
            break
        rows += page
        from_seq = page[-1]["seq"] + 1
    actions = {(r["action"], r["decision"]) for r in rows}
    for want in [
        ("compliance.system.create", "ALLOW"),
        ("compliance.assessment.create", "ALLOW"),
        ("compliance.assessment.submit", "ALLOW"),
        ("compliance.assessment.review", "ALLOW"),
        ("compliance.assessment.review", "DENY"),  # the author's own review
        ("compliance.document.generate", "ALLOW"),
    ]:
        assert want in actions, want
    assert ax.audit.verify()["ok"] is True
