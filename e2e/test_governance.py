"""Data governance (DSAR, legal holds, retention, residency) against the REAL stack: the standalone gateway with the governance kit on
Postgres 16 (forced RLS, the ``axis_governance`` role), the tenant's hash-chained audit log, the real requester verifier with dual control.
Fakes: the IdP, KMS, DNS and the model provider; the identity-proofing step is simulated by the ``governance/evidence`` ops hook, which
signs the tokens with the same governance master key as the gateway (in production this is the tenant's proofing tooling).

What it proves: only the privacy officer writes (owner, admin, auditor read; builder is refused); a request cannot be verified by the
member who opened it nor by a non-admin, only by an independent active owner/admin with a signed token; an export contains the
subject's member record and is signed; an erasure scrubs the member row (a second export finds nothing); a tenant-wide legal hold stops
an erasure (outcome ``held``) until released; a retention dry run is stored and listed and purges nothing; another tenant sees nothing
(404); the audit chain still verifies and carries no raw identifier.

Run with:  make e2e-governance
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from axis_sdk import Axis, AxisError

sys.path.insert(0, str(Path(__file__).parent))
import interfaces_stack as istack  # noqa: E402
from test_phase7_interfaces import Cli  # noqa: E402


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[istack.Stack]:
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise RuntimeError("PG_ADMIN_URL is required: run via `make e2e-governance`")
    with istack.boot(tmp_path_factory.mktemp("e2eg"), admin) as st:
        yield st


class World:
    def __init__(self, stack: istack.Stack) -> None:
        self.stack = stack
        slug = f"g{secrets.token_hex(3)}"
        self.a = stack.provision(f"a{slug}")
        self.b = stack.provision(f"b{slug}")
        self.tid = self.a["tenant_id"]
        self.owner_id = self.a["owner_member_id"]
        mk = lambda role, email=None: stack.ops(  # noqa: E731
            "member", tenant_id=self.tid, role=role, **({"email": email} if email else {})
        )
        self.po = mk("privacy_officer")
        self.po2 = mk("privacy_officer")
        self.admin = mk("admin")
        self.auditor = mk("auditor")
        self.builder = mk("builder")
        self.jane_email = f"jane-{secrets.token_hex(4)}@subject.example"
        self.jane = mk("viewer", self.jane_email)
        self.key = lambda m, **kw: stack.api_key(
            self.tid, m["member_id"] if isinstance(m, dict) else m, **kw
        )
        self.k_po = self.key(self.po)
        self.k_po2 = self.key(self.po2)
        self.k_owner = self.key(self.owner_id)
        self.k_admin = self.key(self.admin)
        self.k_auditor = self.key(self.auditor)
        self.k_builder = self.key(self.builder)
        self.k_other = stack.api_key(
            self.b["tenant_id"],
            stack.ops("member", tenant_id=self.b["tenant_id"], role="privacy_officer")["member_id"],
        )

    def ax(self, key: str) -> Axis:
        return Axis(key, base_url=self.stack.gateway, allow_insecure=True, max_retries=0)

    def evidence(self, request: dict[str, Any], attester: str) -> dict[str, Any]:
        return self.stack.ops(
            "governance/evidence",
            tenant_id=self.tid,
            request_id=request["id"],
            subject_ref=request["subject_ref"],
            attester_member_id=attester,
        )

    def verified(self, kind: str, email: str, ident: str | None = None) -> dict[str, Any]:
        po = self.ax(self.k_po)
        req = po.governance.requests.create(
            {"kind": kind, "identifiers": [{"kind": "email", "value": email}]}
        )
        out = self.ax(self.k_po2).governance.requests.verify(
            req["id"], self.evidence(req, self.owner_id)
        )
        assert out["status"] == "verified", out
        return req


@pytest.fixture(scope="module")
def world(stack: istack.Stack) -> World:
    return World(stack)


def rest(w: World, key: str, method: str, path: str, body: Any = None) -> httpx.Response:
    return httpx.request(
        method, f"{w.stack.gateway}{path}", headers={"x-axis-api-key": key}, json=body, timeout=60
    )


def test_01_role_matrix_over_the_real_gateway(world: World) -> None:
    w = world
    for key in (w.k_po, w.k_owner, w.k_admin, w.k_auditor):
        assert rest(w, key, "GET", "/governance/holds").status_code == 200
        assert rest(w, key, "GET", "/governance/residency").status_code == 200
    assert rest(w, w.k_builder, "GET", "/governance/holds").status_code == 403
    body = {"scope": "tenant", "reason": "x"}
    for key in (w.k_owner, w.k_admin, w.k_auditor, w.k_builder):
        assert rest(w, key, "POST", "/governance/holds", body).status_code == 403
    assert httpx.get(f"{w.stack.gateway}/governance/holds", timeout=30).status_code == 401
    res = rest(w, w.k_owner, "GET", "/governance/residency").json()
    assert res["home_region"] == "us-east-1"


def test_02_export_is_gated_by_dual_control_and_signed(world: World) -> None:
    w = world
    po, po2 = w.ax(w.k_po), w.ax(w.k_po2)
    req = po.governance.requests.create(
        {"kind": "export", "identifiers": [{"kind": "email", "value": w.jane_email}]}
    )
    assert w.jane_email not in json.dumps(req), "the identifier must never be echoed"
    # nothing is exported before verification
    with pytest.raises(AxisError) as e:
        po.governance.requests.export(req["id"])
    assert e.value.status == 409
    # the member who OPENED the request cannot attest, a builder is not an admin, garbage is refused
    for evidence in (
        w.evidence(req, w.po["member_id"]),
        w.evidence(req, w.builder["member_id"]),
        {"requester_token": "x.y", "admin_attestation": "x.y"},
    ):
        out = po2.governance.requests.verify(req["id"], evidence)
        assert out["status"] == "received", out
    # a token minted for ANOTHER request does not verify this one
    other = po.governance.requests.create(
        {"kind": "export", "identifiers": [{"kind": "email", "value": w.jane_email}]}
    )
    assert (
        po2.governance.requests.verify(req["id"], w.evidence(other, w.owner_id))["status"]
        == "received"
    )
    ok = po2.governance.requests.verify(req["id"], w.evidence(req, w.owner_id))
    assert ok["status"] == "verified" and ok["verified_method"] == "signed-token+admin-attestation"
    bundle = po.governance.requests.export(req["id"])
    assert bundle["signature"]["alg"] == "Ed25519"
    assert w.jane_email in json.dumps(bundle["records"]), "the export holds the subject's own data"


def test_03_erasure_scrubs_the_member_and_a_legal_hold_blocks_it_until_released(
    world: World,
) -> None:
    w = world
    po = w.ax(w.k_po)
    hold = po.governance.holds.place({"scope": "tenant", "reason": "litigation hold"})
    req = w.verified("erase", w.jane_email)
    held = po.governance.requests.erase(req["id"])
    assert held["status"] == "held", held
    probe = w.verified("export", w.jane_email)
    assert w.jane_email in json.dumps(po.governance.requests.export(probe["id"])["records"])
    released = po.governance.holds.release(hold["id"])
    assert released["released_at"] is not None
    done = po.governance.requests.erase(req["id"])
    assert done["status"] == "completed", done
    after = w.verified("export", w.jane_email)
    assert w.jane_email not in json.dumps(po.governance.requests.export(after["id"])["records"])
    assert w.jane_email not in json.dumps(po.governance.requests.list())


def test_04_retention_dry_run_is_stored_and_purges_nothing(world: World) -> None:
    w = world
    po = w.ax(w.k_po)
    periods = po.governance.retention.get()["items"]
    assert {p["data_class"] for p in periods} >= {"memory", "audit"}
    rep = po.governance.retention.run({"classes": ["memory"]})
    assert rep["dry_run"] is True and rep["classes"][0]["purged"] == 0
    runs = w.ax(w.k_auditor).governance.retention.runs()["items"]
    assert any(r["run_id"] == rep["run_id"] for r in runs)
    cli = Cli(w.stack, w.k_po)
    out = cli.j("governance", "retention", "run", "--class", "memory")
    assert out["dry_run"] is True
    assert cli.j("governance", "residency")["home_region"] == "us-east-1"


def test_05_another_tenant_sees_and_touches_nothing(world: World) -> None:
    w = world
    mine = w.ax(w.k_po).governance.requests.list()["items"]
    assert mine
    rid = mine[0]["id"]
    other = w.ax(w.k_other)
    assert other.governance.requests.list()["items"] == []
    assert other.governance.holds.list(all=True)["items"] == []
    for method, path in (
        ("GET", f"/governance/dsar-requests/{rid}"),
        ("POST", f"/governance/dsar-requests/{rid}/export"),
        ("POST", f"/governance/dsar-requests/{rid}/erase"),
    ):
        assert rest(w, w.k_other, method, path).status_code == 404


def test_06_the_audit_chain_verifies_and_holds_no_raw_identifier(world: World) -> None:
    w = world
    ax = w.ax(w.k_owner)
    assert ax.audit.verify()["ok"] is True
    events = list(ax.audit.iterate())
    gov = [
        e
        for e in events
        if "dsar" in json.dumps(e) or "retention" in json.dumps(e) or "hold" in json.dumps(e)
    ]
    assert gov, "governance actions must be in the tenant's audit chain"
    assert w.jane_email not in json.dumps(events)
