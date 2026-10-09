"""Chaos harness: the REAL Phase 7 stack (e2e/interfaces_stack.py) with a fault-injection proxy (chaos/src, in-repo) on the dependency edges
that matter, plus process kill/restart. Nothing is mocked: every assertion is about what the real kernel, gateway, run service, control
plane and Postgres did while a dependency was broken.

Edges with a proxy:  kernel (run service -> kernel, gateway -> kernel), kernel_db (kernel -> Postgres), gateway_db (gateway -> Postgres),
cp (run service -> control plane), run (gateway -> run service).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "e2e"))
import interfaces_stack as istack  # noqa: E402


def yaml_json(path: str) -> Any:
    return json.loads(istack.sh(["node", "scripts/yaml-to-json.mjs", path], cwd=ROOT / "e2e"))


PACK = yaml_json("policies/phase7-interfaces/pack.yaml")
CLAIMS_ABL = yaml_json("agents/claims7.abl.yaml")


class Toxic:
    """One running ChaosProxy process with its control port."""

    def __init__(self, name: str, upstream_port: int, work: Path) -> None:
        self.name = name
        self.proc, info = istack._spawn(
            [
                "node",
                "--import",
                "tsx",
                "chaos/src/cli.ts",
                "--upstream",
                f"127.0.0.1:{upstream_port}",
            ],
            {},
            work / f"proxy-{name}.err",
            "port",
        )
        self.port: int = info["port"]
        self.control = f"http://127.0.0.1:{info['control']}"

    def _post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        r = httpx.post(self.control + path, json=body or {}, timeout=10)
        r.raise_for_status()
        return r.json()  # type: ignore[no-any-return]

    def set(self, **toxics: Any) -> None:
        self._post("/toxics", toxics)

    def clear(self) -> None:
        self._post("/clear")

    def reset(self) -> None:
        self._post("/reset")

    def stats(self) -> dict[str, Any]:
        return httpx.get(self.control + "/stats", timeout=10).json()["stats"]  # type: ignore[no-any-return]

    def stop(self) -> None:
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            os.killpg(self.proc.pid, signal.SIGKILL)


class Chaos:
    """The stack, its proxies, and API helpers for one test run."""

    def __init__(self, stack: istack.Stack, proxies: dict[str, Toxic], kill_state: Path) -> None:
        self.stack = stack
        self.proxies = proxies
        self.kill_state = kill_state

    # ---- tenants and API calls -------------------------------------------------------------------------------------------
    def tenant(self, *, pack: bool = True, byo_key: bool = True) -> dict[str, Any]:
        slug = "ch" + os.urandom(4).hex()
        t = self.stack.provision(slug, pack=PACK if pack else None, byo_key=byo_key)
        t["key"] = self.stack.api_key(t["tenant_id"], t["owner_member_id"])
        r = self.api(t, "POST", "/blueprints", json={"abl": CLAIMS_ABL})
        assert r.status_code in (200, 201), r.text
        return t

    def api(self, t: dict[str, Any], method: str, path: str, **kw: Any) -> httpx.Response:
        headers = {"authorization": f"Bearer {t['key']}", **kw.pop("headers", {})}
        return httpx.request(
            method, self.stack.gateway + path, headers=headers, timeout=kw.pop("timeout", 30), **kw
        )

    def start_run(self, t: dict[str, Any], prompt: str) -> httpx.Response:
        return self.api(
            t,
            "POST",
            "/runs",
            json={
                "blueprint": {"name": "claims-agent", "version": "1.0.0"},
                "input": {"prompt": prompt},
            },
        )

    def wait_run(self, t: dict[str, Any], run_id: str, timeout: float = 60) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = self.api(t, "GET", f"/runs/{run_id}")
            if r.status_code == 200 and r.json()["state"] == "terminated":
                return r.json()  # type: ignore[no-any-return]
            time.sleep(0.2)
        raise AssertionError(f"run {run_id} did not terminate in {timeout}s")

    def events(self, t: dict[str, Any], run_id: str) -> list[dict[str, Any]]:
        r = self.api(t, "GET", f"/runs/{run_id}/events?limit=200")
        assert r.status_code == 200, r.text
        return r.json()["items"]  # type: ignore[no-any-return]

    def audit(self, t: dict[str, Any]) -> dict[str, Any]:
        return json.loads(  # type: ignore[no-any-return]
            istack.sh(
                ["node", "scripts/verify-audit.mjs", self.stack.db_url, t["tenant_id"]],
                cwd=ROOT / "e2e",
            )
        )

    # ---- process control -------------------------------------------------------------------------------------------------
    def kill(self, name: str) -> None:
        self.stack.kill(name)

    def restart(self, name: str, env: dict[str, str] | None = None) -> None:
        self.stack.restart(name, env)

    def heal(self) -> None:
        for p in self.proxies.values():
            p.clear()
        for name in ("kernel", "run", "gateway"):
            if self.stack.named[name].poll() is not None:
                self.restart(name)


PERFORMED = ("model_call", "tool_call_result")


def performed(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Events that record an action that actually RAN (a model call, a tool result)."""
    return [e for e in events if e["type"] in PERFORMED]


def decisions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if e["type"] == "gate_decision"]


@contextmanager
def chaos_stack(work: Path) -> Iterator[Chaos]:
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise RuntimeError("PG_ADMIN_URL is required: run via `make chaos`")
    proxies: dict[str, Toxic] = {}

    def hop(name: str, port: int) -> int:
        proxies[name] = Toxic(name, port, work)
        return proxies[name].port

    kill_state = work / "kill-switches.json"
    try:
        with istack.boot(
            work,
            admin,
            hop=hop,
            kernel_env={"AXIS_RK_KILL_STATE_FILE": str(kill_state)},
            gateway_env={"GW_RATE_BURST": "100000", "GW_RATE_PER_SEC": "100000"},
        ) as st:
            yield Chaos(st, proxies, kill_state)
    finally:
        for p in proxies.values():
            p.stop()
