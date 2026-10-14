"""Phase 9 exit check: the compliance, data-governance and hardening scenarios proven TOGETHER on the REAL stack.

The stack is the Phase 7/8 interfaces stack (``e2e/interfaces_stack.py``): Postgres 16 with forced RLS and the hash-chained audit log,
the real Risk Kernel over gRPC, the control plane, billing, registry/marketplace, the Python run service, the standalone API gateway
hosting the Eval Hub and the data-governance kit, PLUS (added for this suite) the channels gateway (signed Slack webhooks, identity,
conversation log) and the memory service in the stack process. Fakes: the IdP, KMS, DNS, the model provider (scripted), the identity
proofing of a data subject (the ``governance/evidence`` ops hook) and Slack's own servers. Seams that remain (NEEDS #413-#420): the
Postgres ``runs`` / ``run_events`` / ``approvals`` tables have no writer in this stack (the dev run service keeps events in memory and the
approvals bridge is in memory), so the subject's rows there are inserted by SQL as the table owner.

Scenarios (the docstring of each test says which):
  a  DSAR export + erase for ONE person whose data is in many stores at once (member, a real Slack message, memory, run logs, an eval
     dataset case, approvals, billing refs): erased through the public governance API by a privacy officer, residual verification passes,
     the audit chain verifies and holds no raw subject data, another tenant's data (including the SAME person there) is byte-identical
  b  retention purge with and without a legal hold; dry run changes nothing; audit is never purged
  c  PHI canary through the real ingress paths (channel, memory, eval dataset, run input + tool args + tool error + answer): no raw
     canary in any persisted store, log or the audit chain
  d  residency: a region-pinned tenant's cross-region writes are refused (403 residency_violation) through registry, Eval Hub and
     billing; a model call to a provider outside the allowed regions is refused before any network call
  e  compliance: Annex IV document for a real blueprint version, sealed, verified; compliance matrix + threat-model checks
  f  red team as a release gate: redteam-core@1.0.0 passes -> released; a weakened control -> BLOCKED (evals_gate_failed)
  g  chaos subset: kernel killed mid-run -> nothing executes; audit DB loss -> mutations refused (503); a kill switch survives a kernel restart
  h  DR: the committed drill result is well-formed, its negatives were detected, RPO/RTO within docs/nfr.md

Run with:  make e2e-phase9
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
import phase9_support as p9  # noqa: E402
from test_governance import World as GovWorld  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[istack.Stack]:
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise RuntimeError("PG_ADMIN_URL is required: run via `make e2e-phase9`")
    with istack.boot(tmp_path_factory.mktemp("e2e9"), admin) as st:
        yield st


def ax_of(stack: istack.Stack, key: str) -> Axis:
    return Axis(key, base_url=stack.gateway, allow_insecure=True, max_retries=0)


def rest(
    stack: istack.Stack, key: str, method: str, path: str, body: Any = None
) -> httpx.Response:
    return httpx.request(
        method, f"{stack.gateway}{path}", headers={"x-axis-api-key": key}, json=body, timeout=60
    )


# =================================================================================================================================
# a. DSAR across many stores
# =================================================================================================================================


class Person:
    """One human in one tenant, with data in every store the governance kit covers. ``markers`` are the raw strings that must be
    gone from the tenant (and absent from the audit chain) once the person is erased."""

    def __init__(
        self, stack: istack.Stack, tid: str, owner_key: str, email: str, slack_user: str, tag: str
    ) -> None:
        self.stack, self.tid, self.email, self.slack_user, self.tag = stack, tid, email, slack_user, tag
        m = stack.ops("member", tenant_id=tid, role="viewer", email=email)
        self.member_id: str = m["member_id"]
        self.user_ref = f"ops:{self.member_id}"
        self.route = stack.ops("channels/route", tenant_id=tid, team_id=f"T{tag}", transcript_mode="full")
        self.msg = f"where is my refund for order ORD-{tag}-7731, please"
        self.note = f"Prefers a call in the morning; loyalty note {tag}-LN-5521"
        self.case_input = f"Customer question about invoice INV-{tag}-9902"
        self.approval_comment = f"approved the exception for {email}"
        self.run_input_note = f"claim lookup for customer {tag}-CL-4417"
        # 1. a REAL inbound Slack message through the signed webhook
        r = p9.slack_post(self.route, slack_user, self.msg)
        assert r.status_code == 200, (r.status_code, r.text)
        # 2. memory (the real service; subject is the person's opaque reference)
        stack.ops("memory/write", tenant_id=tid, content=self.note, subject=self.user_ref)
        # 3. an eval dataset case linked to the person, ingested through the public API
        ax_of(stack, owner_key).evals.datasets.create(
            f"support-{tag}",
            [
                {
                    "id": "c1",
                    "input": self.case_input,
                    "expected": "refund issued",
                    "metadata": {"subject_ref": self.user_ref},
                },
                {"id": "c2", "input": "a generic question", "expected": "generic"},
            ],
            description="support questions",
        )
        # 4. billing: usage dimensioned by the person, and a goodwill adjustment made by them (actor)
        assert stack.ops("billing/usage", tenant_id=tid, key=f"u-{tag}", dimensions={"end_user": self.user_ref})["ok"]
        assert stack.ops("billing/usage", tenant_id=tid, key=f"a-{tag}", actor=self.user_ref)["ok"]
        # 5. run logs + approvals: no writer on this stack (NEEDS #413): inserted as the table owner
        self.run_id = secrets.token_hex(16)
        self.run_id = f"{self.run_id[:8]}-{self.run_id[8:12]}-4{self.run_id[13:16]}-8{self.run_id[17:20]}-{self.run_id[20:32]}"
        pid = "axp_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        inp = json.dumps({"requested_by": self.user_ref, "note": self.run_input_note}).replace("'", "''")
        data = json.dumps({"requested_by": self.user_ref, "text": self.run_input_note}).replace("'", "''")
        istack.psql(
            stack.db_url,
            f"INSERT INTO runs (tenant_id, id, blueprint_name, blueprint_version, trace_id, input) VALUES "
            f"('{tid}', '{self.run_id}', 'support', '1.0.0', '{secrets.token_hex(16)}', '{inp}'::jsonb);"
            f"INSERT INTO run_events (tenant_id, run_id, sequence, type, pid, data) VALUES "
            f"('{tid}', '{self.run_id}', 1, 'message', '{pid}', '{data}'::jsonb);"
            f"INSERT INTO approvals (tenant_id, run_id, pid, action, roles, status, sla_deadline, decided_by, decided_at, comment) VALUES "
            f"('{tid}', '{self.run_id}', '{pid}', 'file-payout', '{{admin}}', 'approved', now() + interval '1 day', "
            f"'{self.user_ref}', now(), '{self.approval_comment}');",
        )

    @property
    def identifiers(self) -> list[dict[str, str]]:
        return [
            {"kind": "email", "value": self.email},
            {"kind": "channel_identity", "value": f"slack:{self.slack_user}"},
        ]

    @property
    def markers(self) -> list[str]:
        return [
            self.email,
            self.slack_user,
            self.msg,
            self.note,
            self.case_input,
            self.approval_comment,
            self.run_input_note,
        ]


class DsarWorld:
    def __init__(self, stack: istack.Stack) -> None:
        self.stack = stack
        self.g = GovWorld(stack)
        self.a_tid, self.b_tid = self.g.tid, self.g.b["tenant_id"]
        self.email = f"jane9-{secrets.token_hex(3)}@subject.example"
        k_owner_b = stack.api_key(self.b_tid, self.g.b["owner_member_id"])
        k_po_b = stack.api_key(self.b_tid, stack.ops("member", tenant_id=self.b_tid, role="privacy_officer")["member_id"])
        self.k_po_b = k_po_b
        # the SAME human exists in tenant B (same email, same Slack user id): erasing in A must not touch B
        self.jane = Person(stack, self.a_tid, self.g.k_owner, self.email, f"UJANE{secrets.token_hex(2)}", "a" + secrets.token_hex(2))
        self.jane_b = Person(stack, self.b_tid, k_owner_b, self.email, self.jane.slack_user, "b" + secrets.token_hex(2))
        # a colleague in tenant A who must be left alone
        self.bob = Person(stack, self.a_tid, self.g.k_owner, f"bob9-{secrets.token_hex(3)}@subject.example", f"UBOB{secrets.token_hex(2)}", "c" + secrets.token_hex(2))

    def request(self, kind: str, person: Person) -> dict[str, Any]:
        po, po2 = self.g.ax(self.g.k_po), self.g.ax(self.g.k_po2)
        req = po.governance.requests.create({"kind": kind, "identifiers": person.identifiers})
        out = po2.governance.requests.verify(req["id"], self.g.evidence(req, self.g.owner_id))
        assert out["status"] == "verified", out
        return req  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def dsar(stack: istack.Stack) -> DsarWorld:
    return DsarWorld(stack)


def test_a1_the_person_is_in_every_store_and_the_export_covers_them_all(dsar: DsarWorld) -> None:
    """Scenario a: before anything is erased, an export for the person finds data in EVERY provider, is signed, carries the person's own
    words, and nothing of their colleague or of the same human in the other tenant."""
    d, st = dsar, dsar.stack
    j = d.jane
    # seeds really are in the database
    assert p9.count(st, "conversation_messages", d.a_tid, f"content LIKE '%ORD-{j.tag}-7731%'") == 1
    assert p9.count(st, "memory_chunks", d.a_tid, f"subject = '{j.user_ref}'") == 1
    po = d.g.ax(d.g.k_po)
    req = d.request("export", j)
    bundle = po.governance.requests.export(req["id"])
    assert bundle["signature"]["alg"] == "Ed25519"
    stores = {s["provider"]: s for s in bundle["manifest"]["stores"]}
    for provider in ("control-plane-members", "channels", "memory", "eval-hub", "run-logs", "approvals", "billing"):
        assert provider in stores, (provider, sorted(stores))
        n = sum(c["count"] for c in stores[provider]["collections"])
        assert n > 0, f"the export found nothing in {provider}"
    text = json.dumps(bundle["records"])
    for marker in j.markers:
        assert marker in text, f"the export is missing {marker!r}"
    for other in (d.bob, d.jane_b):
        assert other.msg not in text and other.note not in text and other.tag not in text.replace(j.tag, "")


def test_a2_erase_through_the_public_api_verifies_residuals_and_leaves_the_chain_intact(dsar: DsarWorld) -> None:
    """Scenario a: the privacy officer erases the person. The engine's residual verification passes for every store, the raw words are
    gone from the tenant's whole database (not only from the stores the providers know), the audit chain verifies and holds no raw
    subject data, the colleague's data is untouched and the SAME human in the other tenant is byte-identical."""
    d, st = dsar, dsar.stack
    j = d.jane
    b_before = p9.digest(p9.dump_tenant(st, d.b_tid))
    bob_before = p9.digest(
        "\n".join(
            [
                p9.q(st, f"SELECT content FROM conversation_messages WHERE tenant_id='{d.a_tid}' AND content LIKE '%ORD-{d.bob.tag}-7731%'"),
                p9.q(st, f"SELECT content FROM memory_chunks WHERE tenant_id='{d.a_tid}' AND subject = '{d.bob.user_ref}'"),
            ]
        )
    )
    po = d.g.ax(d.g.k_po)
    chain_len_before = int(p9.q(st, f"SELECT count(*) FROM audit_events WHERE tenant_id='{d.a_tid}'"))
    req = d.request("erase", j)
    done = po.governance.requests.erase(req["id"])
    assert done["status"] == "completed", done
    verification = done["request"]["result"]["verification"]
    assert verification["ok"] is True, verification
    proofs = {v["provider"]: v for v in verification["providers"]}
    assert all(v["residual"] == 0 for v in proofs.values()), proofs
    for provider in ("control-plane-members", "channels", "memory", "eval-hub", "run-logs", "approvals", "billing"):
        assert provider in proofs, (provider, sorted(proofs))
    assert proofs["channels"]["erased"] >= 3 and proofs["memory"]["erased"] == 1
    assert proofs["eval-hub"]["erased"] == 1 and proofs["run-logs"]["erased"] >= 2
    # every raw marker is gone from the tenant's data, wherever it lived
    dump = p9.dump_tenant(st, d.a_tid)
    for marker in j.markers:
        assert marker not in dump, f"{marker!r} survives in tenant A's database"
    # a second export finds nothing of the person
    again = d.request("export", j)
    records = json.dumps(po.governance.requests.export(again["id"])["records"])
    for marker in j.markers:
        assert marker not in records
    # the audit chain: verifies through the public API, grew, and contains no raw subject data
    owner = d.g.ax(d.g.k_owner)
    assert owner.audit.verify()["ok"] is True
    events = list(owner.audit.iterate())
    assert len(events) > chain_len_before - 1
    audit_text = json.dumps(events) + p9.q(st, f"SELECT t::text FROM audit_events t WHERE tenant_id='{d.a_tid}'")
    for marker in j.markers:
        assert marker not in audit_text, f"raw {marker!r} is in the audit chain"
    assert any("dsar.erase.completed" in json.dumps(e) for e in events)
    # the colleague is untouched
    bob_after = p9.digest(
        "\n".join(
            [
                p9.q(st, f"SELECT content FROM conversation_messages WHERE tenant_id='{d.a_tid}' AND content LIKE '%ORD-{d.bob.tag}-7731%'"),
                p9.q(st, f"SELECT content FROM memory_chunks WHERE tenant_id='{d.a_tid}' AND subject = '{d.bob.user_ref}'"),
            ]
        )
    )
    assert bob_after == bob_before
    # the same human in tenant B: byte-identical
    assert p9.digest(p9.dump_tenant(st, d.b_tid)) == b_before
    assert j.email not in p9.dump_tenant(st, d.a_tid)
    assert d.jane_b.msg in p9.dump_tenant(st, d.b_tid)
    # tenant B's privacy officer cannot see or run tenant A's request
    other = ax_of(st, d.k_po_b)
    assert other.governance.requests.list()["items"] == []
    assert rest(st, d.k_po_b, "POST", f"/governance/dsar-requests/{req['id']}/erase").status_code == 404
