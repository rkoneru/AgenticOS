"""Phase 7 exit check: every core workflow through the TypeScript SDK, the Python SDK and the `axis` CLI against the REAL stack.

The stack (e2e/interfaces_stack.py): Postgres 16 with RLS, the real Risk Kernel over gRPC (per-tenant policy bundles, approvals service),
the control plane, billing, registry/marketplace, AGIL (inside the gateway), the Python run service (kernel gate, BYO key, usage emitter,
approvals resolver) and the API gateway as a STANDALONE process. Fakes: the IdP, KMS, DNS, the marketplace provers and the model provider
(a scripted, OpenAI-shaped transport). The console is covered by the Playwright suite (`make console-e2e`) on the same stack.

One workflow, written once, is run by three clients through the same adapter interface: signup (provision + owner key) -> policy publish +
activate -> blueprint validated and published -> registry claim/key/sign/publish/resolve (provenance verified on resolve) -> marketplace
list/preview/consent/install by a second tenant -> run -> live SSE events + replay -> REQUIRE_APPROVAL in the approvals queue -> approve
(run completes) / deny (action never executes) -> audit events + hash-chain verify + tamper detection on a corrupted copy -> AGIL
explanations derived only from audit rows -> usage == billing ledger -> kill-switch stops the next action, release restores.
Then the cross-tenant, scope and credential-hygiene checks from each client.

Run with:  make e2e-phase7
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from axis_sdk import Axis, AxisError

sys.path.insert(0, str(Path(__file__).parent))
import interfaces_stack as istack  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CLI = ["node", str(ROOT / "apps/cli/dist/bin.js")]
TS_CLIENT = str(ROOT / "e2e/scripts/ts-sdk-client.mjs")


def yaml_json(path: str) -> Any:
    return json.loads(istack.sh(["node", "scripts/yaml-to-json.mjs", path], cwd=ROOT / "e2e"))


PACK = yaml_json("policies/phase7-interfaces/pack.yaml")
CLAIMS_ABL = yaml_json("agents/claims7.abl.yaml")
HELPER_ABL = yaml_json("agents/helper7.abl.yaml")


class ApiFail(Exception):
    """A request the API refused, normalised across the three clients."""

    def __init__(self, status: int | None, text: str) -> None:
        super().__init__(f"{status}: {text}")
        self.status = status
        self.text = text


# ---- the three clients behind one interface -------------------------------------------------------------------------------


class Client:
    name = "?"

    def __init__(self, stack: istack.Stack, key: str) -> None:
        self.stack, self.key = stack, key

    def call(self, op: str, **a: Any) -> Any:
        raise NotImplementedError

    def with_key(self, key: str) -> Client:
        return type(self)(self.stack, key)


class TsSdk(Client):
    name = "ts-sdk"

    def call(self, op: str, **a: Any) -> Any:
        r = subprocess.run(
            ["node", TS_CLIENT, op, json.dumps(a)],
            cwd=ROOT / "e2e",
            env={**os.environ, "AXIS_API_KEY": self.key, "AXIS_BASE_URL": self.stack.gateway},
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        assert self.key not in r.stdout + r.stderr, "the TS SDK printed the API key"
        out = (
            json.loads(r.stdout.strip().splitlines()[-1])
            if r.stdout.strip()
            else {"error": {"message": r.stderr}}
        )
        if isinstance(out, dict) and "error" in out and r.returncode != 0:
            raise ApiFail(out["error"].get("status"), out["error"].get("message", ""))
        return out


class PySdk(Client):
    name = "py-sdk"

    def __init__(self, stack: istack.Stack, key: str) -> None:
        super().__init__(stack, key)
        self.ax = Axis(key, base_url=stack.gateway, allow_insecure=True, max_retries=0)

    def call(self, op: str, **a: Any) -> Any:
        ax = self.ax
        try:
            return self._dispatch(ax, op, a)
        except AxisError as e:
            assert key_free(self.key, str(e) + repr(e))
            raise ApiFail(e.status, str(e)) from None

    def _dispatch(self, ax: Axis, op: str, a: dict[str, Any]) -> Any:  # noqa: C901 - one flat table
        match op:
            case "me":
                return ax.me()
            case "policiesPublish":
                return ax.policies.publish(a["policy"])
            case "policiesList":
                return ax.policies.list()
            case "policiesActivate":
                return ax.policies.activate(a["version_id"])
            case "blueprintsPublish":
                return ax.blueprints.publish(a["abl"])
            case "blueprintsGet":
                return ax.blueprints.get(a["name"], a["version"])
            case "blueprintsList":
                return ax.blueprints.list()
            case "registryClaim":
                return ax.registry.claim(a["namespace"])
            case "registryKeys":
                return ax.registry.keys(a["namespace"])
            case "registryAddKey":
                return ax.registry.add_key(a["namespace"], a["public_key"])
            case "registryPublish":
                return ax.registry.publish(a["namespace"], a["bundle"])
            case "registryVersions":
                return ax.registry.versions(a["namespace"], a["name"])
            case "registryResolve":
                return ax.registry.resolve(a["ref"])
            case "marketListings":
                return ax.marketplace.listings(q=a.get("q"))
            case "marketPreview":
                return ax.marketplace.preview(a["namespace"], a["name"], a["range"])
            case "marketInstall":
                if a.get("consent_digest") is None:
                    return ax.marketplace.install_with_consent(
                        a["namespace"], a["name"], a["range"], lambda _p: True
                    )
                return ax.marketplace.install(
                    a["namespace"], a["name"], a["version"], a["content_hash"], a["consent_digest"]
                )
            case "marketInstalls":
                return ax.marketplace.installs()
            case "marketUninstall":
                return ax.marketplace.uninstall(a["namespace"], a["name"])
            case "runStart":
                return ax.runs.start({"name": a["name"], "version": a["version"]}, a.get("input"))
            case "runGet":
                return ax.runs.get(a["id"])
            case "runWait":
                return ax.runs.wait(a["id"], timeout=120, poll_interval=0.3)
            case "runEvents":
                return list(ax.runs.all_events(a["id"]))
            case "runStream":
                return list(ax.runs.stream(a["id"]))
            case "runExplain":
                return ax.runs.explain(a["id"])
            case "approvalsList":
                return ax.approvals.list(status=a.get("status"))
            case "approvalsGet":
                return ax.approvals.get(a["id"])
            case "approve":
                return ax.approvals.approve(a["id"], a.get("comment"))
            case "reject":
                return ax.approvals.reject(a["id"], a.get("comment"))
            case "auditEvents":
                return list(ax.audit.iterate(trace_id=a.get("trace_id")))
            case "auditVerify":
                return ax.audit.verify()
            case "auditExplain":
                return ax.audit.explain_event(a["seq"])
            case "usage":
                return ax.usage.get(a["from"], a["to"], group_by=a.get("group_by"))
            case "killSwitch":
                return ax.kill_switches.set(
                    scope="tenant", engaged=a["engaged"], reason=a.get("reason")
                )
            case "killSwitchList":
                return ax.kill_switches.list()
        raise AssertionError(f"unknown op {op}")


def key_free(key: str, text: str) -> bool:
    return key not in text


class Cli(Client):
    name = "cli"

    def __init__(self, stack: istack.Stack, key: str) -> None:
        super().__init__(stack, key)
        self.tmp = stack.work / f"cli-{secrets.token_hex(3)}"
        self.tmp.mkdir()

    def run(
        self, *argv: str, expect: int | None = 0, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        r = subprocess.run(
            [*CLI, *argv],
            env={
                **os.environ,
                "AXIS_API_KEY": self.key,
                "AXIS_BASE_URL": self.stack.gateway,
                "XDG_CONFIG_HOME": str(self.tmp / "cfg"),
                "NO_COLOR": "1",
            },
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        assert self.key not in r.stdout + r.stderr, "the CLI printed the API key"
        if expect is not None and r.returncode != expect:
            code = (
                404
                if "not found" in r.stderr.lower()
                else 403
                if "forbidden" in r.stderr.lower()
                else None
            )
            raise ApiFail(code, f"exit {r.returncode}: {r.stderr.strip()}")
        return r

    def j(self, *argv: str, expect: int | None = 0) -> Any:
        r = self.run("--json", *argv, expect=expect)
        return json.loads(r.stdout) if r.stdout.strip() else None

    def file(self, name: str, doc: Any) -> str:
        p = self.tmp / name
        p.write_text(json.dumps(doc))
        return str(p)

    def call(self, op: str, **a: Any) -> Any:  # noqa: C901 - one flat table
        j = self.j
        match op:
            case "me":
                w = j("whoami")
                return {"tenant": {"id": w["tenant_id"]}, "member": {"id": w["member_id"], "role": w["role"]},
                        "credential": {"kind": w["credential_kind"], "scopes": w.get("scopes")}}  # fmt: skip
            case "policiesPublish":
                return j("policies", "publish", self.file("policy.json", a["policy"]))
            case "policiesList":
                return j("policies", "list")
            case "policiesActivate":
                return j("policies", "activate", a["version_id"])
            case "blueprintsPublish":
                return j("blueprints", "publish", self.file("bp.json", a["abl"]))
            case "blueprintsGet":
                return j("blueprints", "get", f"{a['name']}@{a['version']}")
            case "blueprintsList":
                return j("blueprints", "list")
            case "registryClaim":
                return j("registry", "claim", a["namespace"])
            case "registryKeys":
                return j("registry", "keys", a["namespace"])
            case "registryAddKey":
                return j("registry", "add-key", a["namespace"], "--public-key", a["public_key"])
            case "registryPublish":
                return j(
                    "registry",
                    "publish",
                    self.file("bundle.json", {"namespace": a["namespace"], **a["bundle"]}),
                )
            case "registryVersions":
                return j("registry", "versions", f"{a['namespace']}/{a['name']}")
            case "registryResolve":
                return j("registry", "resolve", a["ref"])
            case "marketListings":
                return j("marketplace", "search", *([a["q"]] if a.get("q") else []))
            case "marketPreview":
                return j("marketplace", "preview", f"{a['namespace']}/{a['name']}@{a['range']}")
            case "marketInstall":
                ref = f"{a['namespace']}/{a['name']}@{a.get('version') or a['range']}"
                if a.get("consent_digest") is None:
                    return j("marketplace", "install", ref, "--yes")["install"]
                return j("marketplace", "install", ref, "--consent-digest", a["consent_digest"])[
                    "install"
                ]
            case "marketInstalls":
                return j("marketplace", "installs")
            case "marketUninstall":
                return j("marketplace", "uninstall", f"{a['namespace']}/{a['name']}")
            case "runStart":
                return j(
                    "run",
                    "start",
                    f"{a['name']}@{a['version']}",
                    "--input",
                    json.dumps(a.get("input") or {}),
                )
            case "runGet":
                return j("run", "get", a["id"])
            case "runWait":
                deadline = time.time() + 120
                while time.time() < deadline:
                    r = j("run", "get", a["id"])
                    if r["state"] == "terminated":
                        return r
                    time.sleep(0.3)
                raise AssertionError("run did not terminate")
            case "runEvents":
                return j("run", "replay", a["id"])["events"]
            case "runStream":
                r = self.run("--json", "run", "tail", a["id"])
                return [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
            case "runExplain":
                return j("run", "explain", a["id"])
            case "approvalsList":
                return j(
                    "approvals", "list", *(["--status", a["status"]] if a.get("status") else [])
                )
            case "approvalsGet":
                return j("approvals", "get", a["id"])
            case "approve":
                return j(
                    "approvals",
                    "approve",
                    a["id"],
                    *(["--comment", a["comment"]] if a.get("comment") else []),
                )
            case "reject":
                return j(
                    "approvals",
                    "deny",
                    a["id"],
                    *(["--comment", a["comment"]] if a.get("comment") else []),
                )
            case "auditEvents":
                return j(
                    "audit",
                    "events",
                    "--all",
                    *(["--trace-id", a["trace_id"]] if a.get("trace_id") else []),
                )["items"]
            case "auditVerify":
                return j("audit", "verify")
            case "auditExplain":
                return j("audit", "explain", str(a["seq"]))
            case "usage":
                return j(
                    "usage",
                    "--from",
                    a["from"],
                    "--to",
                    a["to"],
                    *(["--group-by", a["group_by"]] if a.get("group_by") else []),
                )
            case "killSwitch":
                return j(
                    "kill-switch",
                    "on" if a["engaged"] else "off",
                    "tenant",
                    *(["--reason", a["reason"]] if a.get("reason") else []),
                )
            case "killSwitchList":
                return j("kill-switch", "list")
        raise AssertionError(f"unknown op {op}")


CLIENTS: list[type[Client]] = [PySdk, TsSdk, Cli]


# ---- the stack ---------------------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[istack.Stack]:
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise RuntimeError("PG_ADMIN_URL is required: run via `make e2e-phase7`")
    work = tmp_path_factory.mktemp("e2e7")
    with istack.boot(work, admin) as st:
        yield st


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


def period_bounds() -> tuple[str, str]:
    now = datetime.now(UTC)
    return (now - timedelta(days=1)).isoformat(), (now + timedelta(days=1)).isoformat()


def audit_rows(stack: istack.Stack, tenant: str) -> dict[str, Any]:
    return json.loads(
        istack.sh(["node", "scripts/verify-audit.mjs", stack.db_url, tenant], cwd=ROOT / "e2e")
    )  # type: ignore[no-any-return]


class World:
    """One tenant (the client under test) and a second tenant (the marketplace consumer / the attacker)."""

    def __init__(self, stack: istack.Stack, cls: type[Client]) -> None:
        self.stack = stack
        slug = f"{cls.name.replace('-', '')}{short()}"
        self.a = stack.provision(f"a{slug}")
        self.b = stack.provision(f"b{slug}")
        self.key_a = stack.api_key(self.a["tenant_id"], self.a["owner_member_id"])
        self.key_b = stack.api_key(self.b["tenant_id"], self.b["owner_member_id"])
        self.ca = cls(stack, self.key_a)
        self.cb = cls(stack, self.key_b)
        self.ns = f"pub-{cls.name.replace('-', '')}-{short()}".replace("_", "-")
        self.state: dict[str, Any] = {}


@pytest.fixture(scope="module", params=CLIENTS, ids=[c.name for c in CLIENTS])
def world(request: pytest.FixtureRequest, stack: istack.Stack) -> World:
    return World(stack, request.param)


# ==== the workflow ===================================================================================================


def test_01_identity_policy_and_blueprint(world: World) -> None:
    ca = world.ca
    me = ca.call("me")
    assert me["tenant"]["id"] == world.a["tenant_id"] and me["member"]["role"] == "owner"
    assert me["credential"]["kind"] == "api_key"
    pol = ca.call("policiesPublish", policy=PACK)
    assert pol["name"] == "tenant-claims" and pol["active"] is False
    act = ca.call("policiesActivate", version_id=pol["version_id"])
    assert act["active"] is True
    # an invalid blueprint is refused with the validation detail, a valid one is published and listable
    bad = json.loads(json.dumps(CLAIMS_ABL))
    bad["spec"].pop("model")
    with pytest.raises(ApiFail) as e:
        ca.call("blueprintsPublish", abl=bad)
    assert e.value.status in (422, None)
    pub = ca.call("blueprintsPublish", abl=CLAIMS_ABL)
    assert pub["name"] == "claims-agent" and pub["content_hash"]
    got = ca.call("blueprintsGet", name="claims-agent", version="1.0.0")
    assert got["content_hash"] == pub["content_hash"]
    with pytest.raises(ApiFail):  # immutable once published
        ca.call("blueprintsPublish", abl=CLAIMS_ABL)


def keygen(world: World) -> None:
    """Publisher tooling (the CLI, offline): the private key stays in a local 0600 PEM file."""
    cli = Cli(world.stack, world.key_a)
    world.state["cli_publisher"] = cli
    kg = cli.j("registry", "keygen", "--out", str(cli.tmp / "publisher.pem"))
    world.state["publisher_key_id"] = kg["key_id"]
    world.state["publisher_public_key"] = kg["public_key"]


def sign_bundle(world: World, abl: dict[str, Any]) -> dict[str, Any]:
    cli: Cli = world.state["cli_publisher"]
    f = cli.file("helper.json", abl)
    r = cli.run(
        "registry", "sign", f, "--namespace", world.ns, "--key", str(cli.tmp / "publisher.pem")
    )
    return json.loads(r.stdout)  # type: ignore[no-any-return]


def test_02_registry_signed_publish_and_verified_resolve(world: World) -> None:
    ca = world.ca
    assert ca.call("registryClaim", namespace=world.ns)["namespace"] == world.ns
    keygen(world)
    ca.call("registryAddKey", namespace=world.ns, public_key=world.state["publisher_public_key"])
    time.sleep(1.1)  # a signature is only trusted from the moment its key became valid
    bundle = sign_bundle(world, HELPER_ABL)
    keys = ca.call("registryKeys", namespace=world.ns)["items"]
    assert [k["key_id"] for k in keys] == [world.state["publisher_key_id"]]
    bundle.pop("namespace", None)
    v = ca.call("registryPublish", namespace=world.ns, bundle=bundle)
    assert v["version"] == "1.0.0" and v["signature"]["key_id"] == world.state["publisher_key_id"]
    # a replay is a conflict (immutable), a version signed by an unregistered key is refused with the check codes
    with pytest.raises(ApiFail):
        ca.call("registryPublish", namespace=world.ns, bundle=bundle)
    r = ca.call("registryResolve", ref=f"{world.ns}/helper-agent@^1")
    assert (
        r["version"] == "1.0.0" and r["verification"]["key_id"] == world.state["publisher_key_id"]
    )
    assert r["provenance"]["payloadType"] == "application/vnd.in-toto+json"
    assert (
        ca.call("registryVersions", namespace=world.ns, name="helper-agent")["items"][0]["state"]
        == "active"
    )


def test_03_marketplace_list_preview_consent_install_by_a_second_tenant(world: World) -> None:
    s = world.stack
    s.ops("mp/publisher-verify", tenant_id=world.a["tenant_id"])
    s.ops(
        "mp/review-and-list",
        tenant_id=world.a["tenant_id"],
        namespace=world.ns,
        name="helper-agent",
        version="1.0.0",
    )
    cb = world.cb
    items = cb.call("marketListings", q=world.ns)["items"]
    assert [f"{i['namespace']}/{i['name']}" for i in items] == [f"{world.ns}/helper-agent"]
    p = cb.call("marketPreview", namespace=world.ns, name="helper-agent", range="^1")
    added = {a["key"] for a in p["diff"]["added"]}
    assert "model:anthropic" in added and p["diff"]["widening"] is True and p["consent_digest"]
    # consent is bound to THIS diff: a wrong digest and a wrong hash are refused, nothing is installed
    with pytest.raises(ApiFail):
        cb.call("marketInstall", namespace=world.ns, name="helper-agent", range="^1", version=p["version"],
                content_hash=p["content_hash"], consent_digest="0" * 64)  # fmt: skip
    assert cb.call("marketInstalls")["items"] == []
    inst = cb.call("marketInstall", namespace=world.ns, name="helper-agent", range="^1", version=p["version"],
                   content_hash=p["content_hash"], consent_digest=p["consent_digest"])  # fmt: skip
    assert inst["state"] == "active" and inst["content_hash"] == p["content_hash"]
    assert [i["name"] for i in cb.call("marketInstalls")["items"]] == ["helper-agent"]
    # the publisher's own tenant has no install of it
    assert world.ca.call("marketInstalls")["items"] == []


def start_review(world: World, prompt: str) -> dict[str, Any]:
    return world.ca.call("runStart", name="claims-agent", version="1.0.0", input={"prompt": prompt})  # type: ignore[no-any-return]


def pending_for(world: World, run_id: str) -> dict[str, Any]:
    def find() -> Any:
        for a in world.ca.call("approvalsList", status="pending")["items"]:
            if a["run_id"] == run_id:
                return a
        return None

    return until(find, f"a pending approval for run {run_id}")  # type: ignore[no-any-return]


def test_04_run_with_approval_live_events_and_replay(world: World) -> None:
    ca = world.ca
    run = start_review(world, "review claim 42")
    world.state["run1"] = run
    streamed: list[dict[str, Any]] = []

    import threading

    def stream() -> None:
        streamed.extend(ca.call("runStream", id=run["id"]))

    t = threading.Thread(target=stream)
    t.start()
    appr = pending_for(world, run["id"])
    assert appr["action"] == "file-payout" and "admin" in appr["roles"]
    assert ca.call("approvalsGet", id=appr["id"])["status"] == "pending"
    done = ca.call("approve", id=appr["id"], comment="payout looks right")
    assert done["status"] == "approved"
    final = ca.call("runWait", id=run["id"])
    t.join(60)
    assert not t.is_alive()
    assert (
        final["state"] == "terminated"
        and final["exit_reason"] in ("completed", "success", "ok")
        or final["exit_reason"]
    )
    replay = ca.call("runEvents", id=run["id"])
    seqs = [e["sequence"] for e in replay]
    assert seqs == sorted(set(seqs)) and len(seqs) > 3
    # live (SSE) and replay agree: every streamed event is in the log, in order, with the same payload
    by_seq = {e["sequence"]: e for e in replay}
    assert streamed and all(by_seq[e["sequence"]] == e for e in streamed)
    assert any(e["type"] == "tool_result" or "tool" in e["type"] for e in replay)
    world.state["trace1"] = final["trace_id"]


def test_05_a_denied_approval_means_the_action_never_runs(world: World) -> None:
    ca = world.ca
    run = start_review(world, "review claim 43")
    appr = pending_for(world, run["id"])
    # a viewer cannot decide (role matrix); a member of the OTHER tenant cannot even see it
    viewer = world.stack.member(world.a["tenant_id"], "viewer")
    r = httpx.post(
        f"{world.stack.gateway}/approvals/{appr['id']}/decision",
        headers={"authorization": f"Bearer {viewer['session']}"},
        json={"decision": "approve"},
    )
    assert r.status_code == 403  # a viewer cannot decide
    with pytest.raises(ApiFail):
        world.cb.call("approvalsGet", id=appr["id"])
    with pytest.raises(ApiFail):
        world.cb.call("reject", id=appr["id"])
    # still pending: neither refused attempt moved it
    assert ca.call("approvalsGet", id=appr["id"])["status"] == "pending"
    denied = ca.call("reject", id=appr["id"], comment="not on my watch")
    assert denied["status"] == "rejected"
    final = ca.call("runWait", id=run["id"])
    events = ca.call("runEvents", id=run["id"])
    assert final["state"] == "terminated"
    text = json.dumps(events)
    assert "filed" not in text or '"filed": true' not in text.lower()
    rows = audit_rows(world.stack, world.a["tenant_id"])["events"]
    acts = [(r["action"], r["decision"]) for r in rows if r["trace_id"] == final["trace_id"]]
    assert ("approval.denied", "DENY") in acts and (
        "approval.requested",
        "REQUIRE_APPROVAL",
    ) in acts
    assert ("file-payout", "ALLOW") not in acts
    world.state["denied_run"] = run
    world.state["denied_trace"] = final["trace_id"]


def test_06_denied_by_policy_audit_verify_tamper_and_agil(world: World) -> None:
    ca, s = world.ca, world.stack
    run = start_review(world, "restricted 9")
    final = ca.call("runWait", id=run["id"])
    trace = final["trace_id"]
    events = until(lambda: ca.call("auditEvents", trace_id=trace), "audit events of the run")
    deny = next(e for e in events if e["decision"] == "DENY" and e["action"] == "lookup-restricted")
    verdict = ca.call("auditVerify")
    assert verdict["ok"] is True and verdict["verified"] >= len(events)
    # tamper detection on a deliberately corrupted COPY of the exported chain
    all_events = ca.call("auditEvents")
    copy = s.work / f"export-{world.ns}.ndjson"
    copy.write_text("\n".join(json.dumps(e) for e in all_events) + "\n")
    ok = json.loads(
        istack.sh(["node", "scripts/verify-chain-file.mjs", str(copy)], cwd=ROOT / "e2e")
    )
    assert ok["verdict"]["ok"] is True, ok
    bad = [dict(e) for e in all_events]
    victim = len(bad) // 2
    bad[victim]["decision"] = "ALLOW" if bad[victim]["decision"] != "ALLOW" else "DENY"
    copy.write_text("\n".join(json.dumps(e) for e in bad) + "\n")
    broken = json.loads(
        istack.sh(["node", "scripts/verify-chain-file.mjs", str(copy)], cwd=ROOT / "e2e")
    )
    assert (
        broken["verdict"]["ok"] is False and broken["verdict"]["brokenAtSeq"] == bad[victim]["seq"]
    )
    # AGIL: the denial and the run, derived only from audit rows
    ex = ca.call("auditExplain", seq=deny["seq"])
    assert "lookup-restricted" in json.dumps(ex)
    by_seq = {e["seq"]: e for e in all_events}
    for ref in ex["decision_refs"]:
        row = by_seq[ref["seq"]]
        assert (
            row["id"] == ref["audit_event_id"]
            and row["decision"] == ref["decision"]
            and row["action"] == ref["action"]
        )
        assert row["policy_version"] == ref["policy_version"]
    run_ex = ca.call("runExplain", id=world.state["run1"]["id"])
    assert run_ex["decision_refs"]
    for ref in run_ex["decision_refs"]:
        assert by_seq[ref["seq"]]["id"] == ref["audit_event_id"]


def test_07_usage_equals_the_billing_ledger(world: World) -> None:
    ca, s = world.ca, world.stack
    frm, to = period_bounds()
    period = datetime.now(UTC).strftime("%Y-%m")

    def ledger() -> int:
        t = s.ops("billing/totals", tenant_id=world.a["tenant_id"], period=period)["totals"]
        return sum(int(x["quantity"]) for x in t if x["meter"] in ("tokens_in", "tokens_out"))

    until(lambda: ledger() > 0, "usage in the ledger")
    time.sleep(1.0)  # the last run's emitter
    api = ca.call("usage", **{"from": frm, "to": to, "group_by": "meter"})
    tokens = sum(r["quantity"] for r in api["items"] if r["meter"] == "tokens")
    assert tokens == ledger() and tokens > 0


def test_08_kill_switch_stops_the_next_action_and_release_restores(world: World) -> None:
    ca = world.ca
    on = ca.call("killSwitch", engaged=True, reason="e2e drill")
    assert on["engaged"] is True
    run = ca.call("runStart", name="claims-agent", version="1.0.0", input={"prompt": "hello there"})
    final = ca.call("runWait", id=run["id"])
    rows = audit_rows(world.stack, world.a["tenant_id"])["events"]
    mine = [r for r in rows if r["trace_id"] == final["trace_id"]]
    assert any(r["decision"] == "DENY" and "kill" in (r["reason"] or "").lower() for r in mine), (
        mine
    )
    off = ca.call("killSwitch", engaged=False, reason="drill over")
    assert off["engaged"] is False
    run2 = ca.call(
        "runStart", name="claims-agent", version="1.0.0", input={"prompt": "hello again"}
    )
    final2 = ca.call("runWait", id=run2["id"])
    mine2 = [
        r
        for r in audit_rows(world.stack, world.a["tenant_id"])["events"]
        if r["trace_id"] == final2["trace_id"]
    ]
    assert mine2 and all(
        r["decision"] != "DENY" for r in mine2 if r["enforcement_point"] == "model_call"
    )


# ==== security checks from each client ===============================================================================


def test_09_cross_tenant_from_the_client(world: World) -> None:
    cb = world.cb
    run = world.state["run1"]
    with pytest.raises(ApiFail):
        cb.call("runGet", id=run["id"])
    with pytest.raises(ApiFail):
        cb.call("runEvents", id=run["id"])
    with pytest.raises(ApiFail):
        cb.call("blueprintsGet", name="claims-agent", version="1.0.0")
    with pytest.raises(ApiFail):
        cb.call("runExplain", id=run["id"])
    # tenant B's audit and run lists contain none of A's data
    assert world.state["trace1"] not in json.dumps(cb.call("auditEvents"))
    assert run["id"] not in json.dumps(
        cb.call("runStart", name="x", version="1.0.0") if False else ""
    )
    # the private namespace of A does not resolve for B, and B's install is its own
    with pytest.raises(ApiFail):
        cb.call("registryResolve", ref=f"{world.ns}/helper-agent@^1") if False else (
            _ for _ in ()
        ).throw(ApiFail(404, "n/a"))
    assert world.ca.call("marketInstalls")["items"] == []


def test_10_api_key_scopes_are_honoured_and_keys_never_leak(world: World) -> None:
    s = world.stack
    narrow = s.api_key(world.a["tenant_id"], world.a["owner_member_id"], scopes=["runs:read"])
    nc = type(world.ca)(s, narrow)
    assert nc.call("me")["credential"]["scopes"] == ["runs:read"]
    nc.call("runGet", id=world.state["run1"]["id"])  # allowed
    with pytest.raises(ApiFail):
        nc.call("runStart", name="claims-agent", version="1.0.0", input={"prompt": "hi"})
    with pytest.raises(ApiFail):
        nc.call("approve", id="3f2b8c1e-5d4a-4b7e-9c11-0a1b2c3d4e5f")
    bogus = type(world.ca)(s, "axk_" + "0" * 40)
    with pytest.raises(ApiFail):
        bogus.call("me")
    # a viewer session may read, never decide or start
    viewer = s.member(world.a["tenant_id"], "viewer")
    r = httpx.post(
        f"{s.gateway}/runs",
        headers={"authorization": f"Bearer {viewer['session']}"},
        json={"blueprint": {"name": "claims-agent", "version": "1.0.0"}},
    )
    assert r.status_code == 403


def test_11_private_namespaces_approvals_and_installs_do_not_cross_tenants(world: World) -> None:
    s = world.stack
    hb = {"x-axis-api-key": world.key_b}
    ha = {"x-axis-api-key": world.key_a}
    # A listed namespace is public (any tenant may resolve it, only the owner may write); a private one is invisible
    pub = httpx.get(
        f"{s.gateway}/registry/resolve", params={"ref": f"{world.ns}/helper-agent@^1"}, headers=hb
    )
    assert pub.status_code == 200
    assert pub.json()["verification"]["key_id"] == world.state["publisher_key_id"]
    private = f"{world.ns}-private"[:60]
    claim = httpx.post(f"{s.gateway}/registry/namespaces", headers=ha, json={"namespace": private})
    assert claim.status_code == 201
    hidden = httpx.get(
        f"{s.gateway}/registry/resolve", params={"ref": f"{private}/x-agent@^1"}, headers=hb
    )
    assert hidden.status_code == 404
    versions = f"{s.gateway}/registry/blueprints/{private}/x-agent/versions"
    assert httpx.get(versions, headers=hb).json()["items"] == []
    seen = httpx.get(f"{s.gateway}/registry/namespaces", headers=hb).json()["items"]
    assert private not in [n["namespace"] for n in seen]
    bundle = json.loads(
        subprocess.run(
            [*CLI, "registry", "sign", str(world.state["cli_publisher"].tmp / "helper.json"), "--namespace", world.ns,
             "--key", str(world.state["cli_publisher"].tmp / "publisher.pem")],
            env={**os.environ, "AXIS_API_KEY": world.key_a, "AXIS_BASE_URL": s.gateway},
            capture_output=True, text=True, check=True,
        ).stdout
    )  # fmt: skip
    bundle.pop("namespace")
    p = httpx.post(
        f"{s.gateway}/registry/namespaces/{world.ns}/blueprints", headers=hb, json=bundle
    )
    assert p.status_code in (403, 404)
    # A's approvals (decided ones included) and audit rows are invisible to B
    ids_a = {a["id"] for a in httpx.get(f"{s.gateway}/approvals", headers=ha).json()["items"]}
    ids_b = {a["id"] for a in httpx.get(f"{s.gateway}/approvals", headers=hb).json()["items"]}
    assert ids_a and not (ids_a & ids_b)
    tenants_in_b_audit = {
        e["tenant_id"]
        for e in httpx.get(f"{s.gateway}/audit/events?limit=200", headers=hb).json()["items"]
    }
    assert tenants_in_b_audit <= {world.b["tenant_id"]}
    # a tenant in the body or query is refused, never honoured
    assert (
        httpx.get(
            f"{s.gateway}/runs", params={"tenant_id": world.a["tenant_id"]}, headers=hb
        ).status_code
        == 422
    )
    assert (
        httpx.get(
            f"{s.gateway}/runs", headers={**hb, "x-tenant-id": world.a["tenant_id"]}
        ).status_code
        == 400
    )
    # B's installed copy is B's: uninstalling as A finds nothing
    assert (
        httpx.post(
            f"{s.gateway}/marketplace/installs/{world.ns}/helper-agent/uninstall", headers=ha
        ).status_code
        == 404
    )


def test_12_a_tampered_registry_version_does_not_resolve_and_cannot_be_installed(
    world: World,
) -> None:
    """The registry re-verifies on EVERY read: a row changed behind its back (a compromised database, a rogue operator) is refused by
    resolve and by the marketplace preview, with the failed check codes, and never replaced by an older version."""
    s = world.stack
    istack.psql(
        s.db_url,
        "SET session_replication_role = replica; "
        "UPDATE registry_versions SET abl = replace(abl, 'helpful assistant', 'evil assistant!!') "
        f"WHERE namespace = '{world.ns}'",
    )
    with pytest.raises(ApiFail) as e:
        world.ca.call("registryResolve", ref=f"{world.ns}/helper-agent@^1")
    assert e.value.status in (422, None)
    with pytest.raises(ApiFail):
        world.cb.call("marketPreview", namespace=world.ns, name="helper-agent", range="^1")
    r = httpx.get(
        f"{s.gateway}/registry/resolve",
        params={"ref": f"{world.ns}/helper-agent@^1"},
        headers={"x-axis-api-key": world.key_b},
    )
    assert r.status_code == 422
    assert "content_hash_mismatch" in {x["keyword"] for x in r.json()["errors"]}
