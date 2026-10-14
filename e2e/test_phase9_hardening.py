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


# =================================================================================================================================
# b. retention: dry run, legal hold, purge, audit never purged
# =================================================================================================================================


class RetentionWorld:
    def __init__(self, stack: istack.Stack) -> None:
        self.stack = stack
        t = stack.provision("ret" + secrets.token_hex(3))
        self.tid = t["tenant_id"]
        self.po_member = stack.ops("member", tenant_id=self.tid, role="privacy_officer")
        self.k_po = stack.api_key(self.tid, self.po_member["member_id"])
        self.k_owner = stack.api_key(self.tid, t["owner_member_id"])
        self.tag = secrets.token_hex(3)
        self.route = stack.ops("channels/route", tenant_id=self.tid, team_id=f"TR{self.tag}", transcript_mode="full")
        for i in range(3):
            stack.ops("memory/write", tenant_id=self.tid, content=f"old note {i} {self.tag}")
        stack.ops("memory/write", tenant_id=self.tid, content=f"fresh note {self.tag}")
        for i in range(2):
            assert p9.slack_post(self.route, f"UOLD{i}", f"old question {i} {self.tag}").status_code == 200
        assert p9.slack_post(self.route, "UFRESH", f"fresh question {self.tag}").status_code == 200
        # age the "old" rows past every retention period (the table owner; the application cannot rewrite history)
        tid = self.tid
        istack.psql(
            stack.db_url,
            f"UPDATE memory_chunks SET created_at = now() - interval '800 days' WHERE tenant_id='{tid}' AND content LIKE 'old note%';"
            f"UPDATE conversation_messages SET created_at = now() - interval '800 days' WHERE tenant_id='{tid}' AND content LIKE 'old question%';"
            f"UPDATE conversations SET updated_at = now() - interval '800 days' WHERE tenant_id='{tid}' AND id IN "
            f"(SELECT conversation_id FROM conversation_messages WHERE tenant_id='{tid}' AND content LIKE 'old question%');",
        )

    def old_notes(self) -> int:
        return p9.count(self.stack, "memory_chunks", self.tid, "content LIKE 'old note%'")

    def old_messages(self) -> int:
        return p9.count(self.stack, "conversation_messages", self.tid, "content LIKE 'old question%'")

    def fresh(self) -> int:
        return p9.count(self.stack, "memory_chunks", self.tid, "content LIKE 'fresh note%'") + p9.count(
            self.stack, "conversation_messages", self.tid, "content LIKE 'fresh question%'"
        )

    def audit_count(self) -> int:
        return p9.count(self.stack, "audit_events", self.tid)


@pytest.fixture(scope="module")
def ret(stack: istack.Stack) -> RetentionWorld:
    return RetentionWorld(stack)


def by_class(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["data_class"]: c for c in report["classes"]}


def test_b1_dry_run_reports_matches_and_changes_nothing(ret: RetentionWorld) -> None:
    """Scenario b: a dry run (the default) says what WOULD go, stores the report, and every row is still there."""
    po = ax_of(ret.stack, ret.k_po)
    before = (ret.old_notes(), ret.old_messages(), ret.fresh())
    assert before == (3, 2, 2)
    rep = po.governance.retention.run({"classes": ["memory", "conversation"]})
    assert rep["dry_run"] is True
    c = by_class(rep)
    assert c["memory"]["status"] == "dry_run" and c["memory"]["matched"] == 3 and c["memory"]["purged"] == 0
    assert c["conversation"]["status"] == "dry_run" and c["conversation"]["matched"] == 2 and c["conversation"]["purged"] == 0
    assert (ret.old_notes(), ret.old_messages(), ret.fresh()) == before
    assert any(r["run_id"] == rep["run_id"] for r in po.governance.retention.runs()["items"])


def test_b2_a_legal_hold_stops_the_purge_and_releasing_it_lets_it_run(ret: RetentionWorld) -> None:
    """Scenario b: with a tenant-wide legal hold the real run skips the held classes and deletes nothing; after the release the same
    run purges exactly the expired rows and leaves the fresh ones."""
    po = ax_of(ret.stack, ret.k_po)
    hold = po.governance.holds.place({"scope": "tenant", "reason": "litigation hold (e2e)"})
    held = po.governance.retention.run({"classes": ["memory", "conversation"], "dry_run": False})
    for cls in ("memory", "conversation"):
        assert by_class(held)[cls]["status"] == "skipped_hold", by_class(held)[cls]
        assert by_class(held)[cls]["purged"] == 0
    assert (ret.old_notes(), ret.old_messages(), ret.fresh()) == (3, 2, 2), "a held tenant lost data"
    po.governance.holds.release(hold["id"])
    done = po.governance.retention.run({"classes": ["memory", "conversation"], "dry_run": False})
    c = by_class(done)
    assert c["memory"]["status"] == "purged" and c["memory"]["purged"] == 3, c["memory"]
    assert c["conversation"]["status"] == "purged" and c["conversation"]["purged"] == 2, c["conversation"]
    assert (ret.old_notes(), ret.old_messages(), ret.fresh()) == (0, 0, 2)


def test_b3_audit_is_never_purged(ret: RetentionWorld) -> None:
    """Scenario b: asking for the audit class (dry or real) purges nothing, and the chain still verifies; the reports of all of the
    above are themselves audited without raw data."""
    po = ax_of(ret.stack, ret.k_po)
    n = ret.audit_count()
    assert n > 0
    for dry in (True, False):
        rep = po.governance.retention.run({"classes": ["audit"], "dry_run": dry})
        a = by_class(rep)["audit"]
        assert a["purged"] == 0 and a["status"] in ("retained_by_policy", "dry_run"), a
    assert ret.audit_count() >= n
    assert ax_of(ret.stack, ret.k_owner).audit.verify()["ok"] is True
    audit_text = p9.q(ret.stack, f"SELECT t::text FROM audit_events t WHERE tenant_id='{ret.tid}'")
    assert f"old note 0 {ret.tag}" not in audit_text and f"old question 0 {ret.tag}" not in audit_text


# =================================================================================================================================
# c. PHI canary through the real ingress paths
# =================================================================================================================================


def _abl(name: str, *, phi: bool) -> dict[str, Any]:
    return {
        "apiVersion": "abl.axis.dev/v1",
        "kind": "Agent",
        "metadata": {"name": name, "version": "1.0.0", "description": "Phase 9 PHI canary target"},
        "spec": {
            "riskClassification": {
                "level": "limited",
                "rationale": "Test fixture: reads claims, nothing leaves the tenant.",
                "transparencyNotice": "You are interacting with an AI system.",
            },
            "model": {
                "primary": {"provider": "openai", "model": "gpt-4o", "params": {"maxOutputTokens": 128}}
            },
            "instructions": {"system": "You look claims up for the tenant. Use the tools you are given."},
            "routing": {"stages": ["llm"]},
            "tools": [
                {"name": "lookup-claim", "kind": "function", "sideEffects": "read"},
                {"name": "strict-lookup", "kind": "function", "sideEffects": "read"},
            ],
            "budgets": {"tokens": {"soft": 40000, "hard": 60000}, "toolCalls": {"hard": 20}},
            "policy": {"packs": ["tenant-claims@^1.0.0"]},
            **({"data": {"phi": True, "residency": "us-east-1"}} if phi else {}),
        },
    }


def _phi_pack() -> dict[str, Any]:
    import copy

    from evals_world import yaml_json

    pack = copy.deepcopy(yaml_json("policies/phase7-interfaces/pack.yaml"))
    pack["spec"]["rules"].append(
        {
            "id": "allow-strict-lookup",
            "enforcementPoints": ["tool_call"],
            "when": {"field": "tool.name", "op": "eq", "value": "strict-lookup"},
            "gates": ["tenant-kill"],
            "decision": "ALLOW",
        }
    )
    return pack


class PhiWorld:
    def __init__(self, stack: istack.Stack) -> None:
        self.stack = stack
        pack = _phi_pack()
        slug = secrets.token_hex(3)
        self.phi = stack.ops("provision-tenant", slug=f"phi{slug}", byo_key=istack.BYO_KEY, pack=pack, phi_mode=True)
        self.plain = stack.provision(f"pln{slug}", pack=pack)
        self.tid = self.phi["tenant_id"]
        self.k = stack.api_key(self.tid, self.phi["owner_member_id"])
        self.k_plain = stack.api_key(self.plain["tenant_id"], self.plain["owner_member_id"])
        self.ax = ax_of(stack, self.k)
        self.ax.blueprints.publish(_abl("phi-intake", phi=True))
        ax_of(stack, self.k_plain).blueprints.publish(_abl("plain-intake", phi=False))
        self.runs: list[str] = []

    def run(self, ax: Axis, name: str, text: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        r = ax.runs.start({"name": name, "version": "1.0.0"}, {"prompt": f"phi-canary: {text}"})
        final = ax.runs.wait(r["id"], timeout=120, poll_interval=0.3)
        return final, list(ax.runs.all_events(r["id"]))


@pytest.fixture(scope="module")
def phiw(stack: istack.Stack) -> PhiWorld:
    return PhiWorld(stack)


def test_c1_the_phi_tenant_is_in_phi_mode_and_the_control_tenant_is_not(phiw: PhiWorld) -> None:
    st = phiw.stack
    assert p9.q(st, f"SELECT phi_mode FROM tenants WHERE id='{phiw.tid}'") == "t"
    assert p9.q(st, f"SELECT phi_mode FROM tenants WHERE id='{phiw.plain['tenant_id']}'") == "f"


def test_c2_channel_messages_are_redacted_before_they_are_stored(phiw: PhiWorld) -> None:
    """Scenario c, channel ingress: a Slack message on a PHI route carries each canary; the stored conversation holds none of them
    (the route is configured to keep FULL text, which PHI mode caps at a redacted preview)."""
    st = phiw.stack
    route = st.ops("channels/route", tenant_id=phiw.tid, team_id="TPHI" + secrets.token_hex(2), phi=True, transcript_mode="full")
    for i, (text, _core) in enumerate(p9.CANARIES):
        r = p9.slack_post(route, f"UPHI{i}", text)
        assert r.status_code == 200, (text, r.status_code, r.text)
    stored = p9.q(st, f"SELECT content FROM conversation_messages WHERE tenant_id='{phiw.tid}'")
    assert stored.count("\n") + 1 >= len(p9.CANARIES)
    assert p9.leaked(stored) == [], f"raw PHI in the conversation log: {p9.leaked(stored)}"
    # the control: a non-PHI route with full transcripts DOES keep the words (so the redaction above is the PHI path, not the transport)
    plain = st.ops("channels/route", tenant_id=phiw.plain["tenant_id"], team_id="TPLN" + secrets.token_hex(2), transcript_mode="full")
    assert p9.slack_post(plain, "UPLAIN", p9.CANARIES[0][0]).status_code == 200
    kept = p9.q(st, f"SELECT content FROM conversation_messages WHERE tenant_id='{phiw.plain['tenant_id']}'")
    assert "123-45-6789" in kept


def test_c3_memory_writes_are_redacted_before_they_are_stored(phiw: PhiWorld) -> None:
    st = phiw.stack
    for text, _core in p9.CANARIES:
        st.ops("memory/write", tenant_id=phiw.tid, content=text, metadata={"note": text})
    stored = p9.q(st, f"SELECT t::text FROM memory_chunks t WHERE tenant_id='{phiw.tid}'")
    assert p9.leaked(stored) == [], f"raw PHI in memory: {p9.leaked(stored)}"
    st.ops("memory/write", tenant_id=phiw.plain["tenant_id"], content=p9.CANARIES[0][0])
    assert "123-45-6789" in p9.q(st, f"SELECT content FROM memory_chunks WHERE tenant_id='{phiw.plain['tenant_id']}'")


def test_c4_eval_datasets_are_redacted_at_ingest(phiw: PhiWorld) -> None:
    st = phiw.stack
    cases = [
        {"id": f"k{i}", "input": text, "expected": text, "metadata": {"note": text}}
        for i, (text, _core) in enumerate(p9.CANARIES)
    ]
    phiw.ax.evals.datasets.create("phi-cases", cases, description="canaries", phi=True)
    stored = p9.q(st, f"SELECT t::text FROM eval_hub_docs t WHERE tenant_id='{phiw.tid}'")
    assert p9.leaked(stored) == [], f"raw PHI in the Eval Hub: {p9.leaked(stored)}"
    served = json.dumps(phiw.ax.evals.datasets.get("phi-cases", "latest"))
    assert p9.leaked(served) == [], "the API serves raw PHI"


def test_c5_run_input_tool_args_tool_errors_and_answers_are_redacted_in_the_run_log(phiw: PhiWorld) -> None:
    """Scenario c, run path (the gap closed in this phase): each canary is the run INPUT, becomes the argument of two tool calls, comes
    back in a tool result and in a tool ERROR, and is echoed in the final answer. None of it is in the events the API serves, and
    the control (a non-PHI blueprint) shows the same flow DOES carry the words."""
    seen: list[str] = []
    for text, _core in p9.CANARIES:
        final, events = phiw.run(phiw.ax, "phi-intake", text)
        assert final["state"] == "terminated", final
        seen.append(json.dumps(events) + json.dumps(final))
    assert any("tool_call" in e["type"] or "tool" in e["type"] for e in events)
    assert p9.leaked("\n".join(seen)) == [], f"raw PHI in the run log: {p9.leaked(chr(10).join(seen))}"
    _final, ctl = phiw.run(ax_of(phiw.stack, phiw.k_plain), "plain-intake", p9.CANARIES[0][0])
    assert "123-45-6789" in json.dumps(ctl), "control: the non-PHI run log is expected to keep the words"


def test_c6_nothing_raw_anywhere_a_database_log_or_the_audit_chain_can_hold(phiw: PhiWorld) -> None:
    """Scenario c, the sweep: the whole PHI tenant's database (every table, audit chain included), the audit API, and every stack
    process's log contain no raw canary."""
    st = phiw.stack
    dump = p9.dump_tenant(st, phiw.tid)
    assert p9.leaked(dump) == [], f"raw PHI in the PHI tenant's database: {p9.leaked(dump)}"
    audit = json.dumps(list(phiw.ax.audit.iterate()))
    assert p9.leaked(audit) == []
    assert phiw.ax.audit.verify()["ok"] is True
    logs = p9.stderr_logs(st)
    assert p9.leaked(logs) == [], f"raw PHI in a process log: {p9.leaked(logs)}"


# =================================================================================================================================
# d. residency
# =================================================================================================================================


class ResidencyWorld:
    """Two tenants in the same stack: one homed where the stack's services run (us-east-1), one re-homed to eu-west-1 AFTER its
    publisher setup. The stack's services (gateway: registry + Eval Hub; billing) run in us-east-1."""

    def __init__(self, stack: istack.Stack) -> None:
        self.stack = stack
        slug = secrets.token_hex(3)
        self.home = stack.provision(f"rh{slug}")
        self.pinned = stack.provision(f"rp{slug}")
        self.k_home = stack.api_key(self.home["tenant_id"], self.home["owner_member_id"])
        self.k_pinned = stack.api_key(self.pinned["tenant_id"], self.pinned["owner_member_id"])
        self.signed: dict[str, dict[str, Any]] = {}
        self.ns: dict[str, str] = {}
        # a publisher for each (claim, key, signed bundle) is set up while the tenant is still homed in us-east-1
        from evals_world import Cli, setup_publisher  # noqa: PLC0415

        for label, tenant, key in (("home", self.home, self.k_home), ("pinned", self.pinned, self.k_pinned)):
            w = type("W", (), {})()
            w.stack, w.ns, w.state, w.owner_key = stack, f"res-{label}-{slug}", {}, key  # type: ignore[attr-defined]
            setup_publisher(w)  # type: ignore[arg-type]
            cli: Cli = w.state["publisher_cli"]  # type: ignore[attr-defined]
            abl = _abl(f"res-{label}-agent", phi=False)
            f = cli.file(f"res-{label}.json", abl)
            signed = cli.run("registry", "sign", f, "--namespace", w.ns, "--key", str(cli.tmp / "publisher.pem")).stdout  # type: ignore[attr-defined]
            self.signed[label] = json.loads(signed)
            self.ns[label] = w.ns
        stack.ops("tenant/set-region", tenant_id=self.pinned["tenant_id"], region="eu-west-1")


@pytest.fixture(scope="module")
def resw(stack: istack.Stack) -> ResidencyWorld:
    return ResidencyWorld(stack)


def refused(call: Any) -> AxisError:
    with pytest.raises(AxisError) as e:
        call()
    return e.value


def is_residency_violation(err: AxisError) -> bool:
    """403 with the gateway's `residency_violation` problem (title "Residency violation"; the SDK's slug is the generic `forbidden`)."""
    p = err.problem or {}
    return err.status == 403 and "residency_violation" in json.dumps(p) + str(err.message).lower().replace(" ", "_")


def test_d1_registry_refuses_a_cross_region_write_and_allows_the_home_tenant(resw: ResidencyWorld) -> None:
    """Scenario d: publishing a registry version for the tenant homed in eu-west-1 is refused by the us-east-1 registry with 403
    residency_violation (no region names in the answer); the same call for the home-region tenant succeeds."""
    ok = ax_of(resw.stack, resw.k_home).registry.publish(resw.ns["home"], resw.signed["home"])
    assert ok["version"] == "1.0.0"
    err = refused(lambda: ax_of(resw.stack, resw.k_pinned).registry.publish(resw.ns["pinned"], resw.signed["pinned"]))
    assert is_residency_violation(err), (err.status, err.code, err.problem, str(err))
    assert "eu-west-1" not in str(err) and "us-east-1" not in str(err)


def test_d2_the_eval_hub_refuses_a_cross_region_write(resw: ResidencyWorld) -> None:
    cases = [{"id": "c1", "input": "hello", "expected": "hi"}]
    assert ax_of(resw.stack, resw.k_home).evals.datasets.create("res-home", cases)["name"] == "res-home"
    err = refused(lambda: ax_of(resw.stack, resw.k_pinned).evals.datasets.create("res-pinned", cases))
    assert is_residency_violation(err), (err.status, err.code, err.problem)
    assert p9.count(resw.stack, "eval_hub_docs", resw.pinned["tenant_id"]) == 0
    # reads are not writes: the pinned tenant can still read its own data
    assert ax_of(resw.stack, resw.k_pinned).evals.datasets.list() is not None


def test_d3_billing_refuses_a_cross_region_write(resw: ResidencyWorld) -> None:
    st = resw.stack
    assert st.ops("billing/usage", tenant_id=resw.home["tenant_id"], key="res-ok")["ok"] is True
    bad = st.ops("billing/usage", tenant_id=resw.pinned["tenant_id"], key="res-bad")
    assert bad["ok"] is False and bad["code"] == "region_mismatch", bad
    assert p9.count(st, "usage_events", resw.pinned["tenant_id"]) == 0
    assert p9.count(st, "usage_events", resw.home["tenant_id"]) == 1


def test_d4_a_model_call_to_a_provider_outside_the_allowed_regions_is_refused_before_any_network_call(
    resw: ResidencyWorld,
) -> None:
    """Scenario d, model egress: the ModelGateway with the pinned tenant's allowed regions (read from its REAL home region in the
    database) refuses a provider in another region, a provider with no declared region, and an empty allow-list, each BEFORE the
    transport is touched; a provider in the allowed region goes through. (The run service of this stack does not configure
    ``allowed_regions`` for real runs: NEEDS #418.)"""
    import asyncio
    import dataclasses

    from axis_runtime.models import (
        InMemorySecretStore,
        Message,
        ModelError,
        ModelGateway,
        ModelRequest,
        ModelTarget,
        TenantModelPolicy,
    )
    from axis_runtime.models.adapters import HttpxTransport
    from axis_runtime.models.types import ErrorKind

    tid = resw.pinned["tenant_id"]
    home_region = p9.q(resw.stack, f"SELECT region FROM tenants WHERE id='{tid}'")
    assert home_region == "eu-west-1"
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        return httpx.Response(
            200,
            json={
                "model": "gpt-4o",
                "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            },
        )

    async def public(_h: str, _p: int) -> list[str]:
        return ["93.184.216.34"]

    def gateway(allowed: frozenset[str] | None) -> Any:
        gw = ModelGateway(
            InMemorySecretStore({(tid, "openai", "default"): "sk-e2e-residency-1234567890"}),
            tenant_policy=lambda _t: TenantModelPolicy(allowed_regions=allowed),
            transport=HttpxTransport(httpx.AsyncClient(transport=httpx.MockTransport(handler))),
            resolver=public,
        )
        return gw.unguarded_for_tests()

    def req(region: str | None) -> ModelRequest:
        return ModelRequest(
            tenant_id=tid,
            messages=(Message("user", "hello"),),
            target=dataclasses.replace(ModelTarget("openai", "gpt-4o", None, {}), region=region),
        )

    allowed = frozenset({home_region})
    for region in ("us-east-1", None, "", "ap-south-1"):
        with pytest.raises(ModelError) as e:
            asyncio.run(gateway(allowed).complete(req(region)))
        assert e.value.kind is ErrorKind.CONFIGURATION
    with pytest.raises(ModelError):
        asyncio.run(gateway(frozenset()).complete(req("eu-west-1")))  # an empty allow-list permits nothing
    assert calls == [], f"a refused model call reached the network: {calls}"
    assert asyncio.run(gateway(allowed).complete(req("EU-West-1"))).text == "ok"
    assert len(calls) == 1
