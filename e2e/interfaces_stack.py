"""Boots the REAL stack the Phase 7 interfaces suites run against (NOT production).

Processes (each its own OS process, real wiring; the fakes are the IdP, KMS, DNS, the model provider and the marketplace provers):

* Postgres 16 (``PG_ADMIN_URL``; a throwaway database with every migration) - RLS, the hash-chained audit log, the usage ledger, the
  registry and marketplace stores;
* the Risk Kernel (gRPC) with the per-tenant policy bundle directory and the in-process approvals service (dev bridge);
* ``scripts/interfaces-stack.mjs``: control plane, billing ingest, publisher/staff side of the marketplace, the fake IdP page, ops;
* the Python run service (``scripts/interfaces_run_server.py``): kernel gate over gRPC, BYO key + budgets from the control plane,
  approvals resolver, usage emitter, a SCRIPTED model provider;
* the API gateway as a STANDALONE node process (``apps/api-gateway/dist/main.js``).

Used as a library by ``test_phase7_interfaces.py`` and as a command by the console suite::

    python e2e/interfaces_stack.py --out stack.json -- <command ...>      # boots, runs the command with STACK_JSON, tears down
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parent.parent
BYO_KEY = "sk-byo-e2e7-" + secrets.token_hex(12)
SPAWN_TIMEOUT = 120.0


def sh(args: list[str], *, env: dict[str, str] | None = None, cwd: Path = ROOT) -> str:
    out = subprocess.run(
        args,
        cwd=cwd,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        raise RuntimeError(
            f"{' '.join(args)} failed ({out.returncode}):\n{out.stdout}\n{out.stderr}"
        )
    return out.stdout


def psql(url: str, sql: str) -> str:
    return sh(["psql", url, "-v", "ON_ERROR_STOP=1", "-tAc", sql])


def _spawn(
    args: list[str],
    env: dict[str, str],
    err: Path,
    ready: str,
    cwd: Path = ROOT,
    *,
    append: bool = False,
) -> tuple[subprocess.Popen[str], dict[str, Any]]:
    """Start a process and wait for its one JSON readiness line (an object with a key in ``ready``)."""
    proc = subprocess.Popen(
        args,
        cwd=cwd,
        env={**os.environ, **env},
        stdout=subprocess.PIPE,
        stderr=err.open("a" if append else "w"),
        text=True,
        start_new_session=True,
    )
    assert proc.stdout is not None
    deadline = time.time() + SPAWN_TIMEOUT
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line.strip().startswith("{"):
            info = json.loads(line)
            if ready in info:
                return proc, info
        if proc.poll() is not None:
            break
    proc.kill()
    raise RuntimeError(f"{args[:3]} did not start:\n{err.read_text()}")


@dataclass
class Stack:
    admin_url: str
    db_url: str
    work: Path
    gateway: str  # http://127.0.0.1:<port>/v1
    gateway_origin: str
    cp: str
    billing: str
    ops_url: str
    idp: str
    run_service: str
    kernel_target: str
    approvals_bridge: str
    console_origin: str
    ops_token: str
    platform_token: str
    #: the Eval Hub's runner-facing surface (served by the gateway process)
    eval_hub: str = ""
    control_plane_url: str = ""
    procs: list[subprocess.Popen[str]] = field(default_factory=list)
    #: how each long-lived process was started (name -> args, env, stderr file, ready key, cwd), so chaos tests can kill and restart it
    #: on the SAME port (the kernel, the run service and the gateway have fixed ports for exactly that reason)
    specs: dict[str, tuple[list[str], dict[str, str], Path, str, Path]] = field(
        default_factory=dict
    )
    named: dict[str, subprocess.Popen[str]] = field(default_factory=dict)

    def kill(self, name: str, sig: int = signal.SIGKILL) -> None:
        """Signal a named process group (``kernel``, ``run``, ``gateway``, ``stack``) and wait for it to exit."""
        p = self.named[name]
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            return
        p.wait(30)

    def restart(self, name: str, env: dict[str, str] | None = None) -> dict[str, Any]:
        """Start a previously killed process again with its original arguments and environment (stderr is appended).
        ``env`` overrides/extends the environment for this start only."""
        args, base_env, err, ready, cwd = self.specs[name]
        proc, info = _spawn(args, {**base_env, **(env or {})}, err, ready, cwd, append=True)
        self.named[name] = proc
        self.procs.append(proc)
        return info

    def ops(self, op: str, /, **body: Any) -> dict[str, Any]:
        r = httpx.post(
            f"{self.ops_url}/ops/{op}",
            json=body,
            headers={"authorization": f"Bearer {self.ops_token}"},
            timeout=120,
        )
        assert r.status_code == 200, (op, r.status_code, r.text)
        return r.json()  # type: ignore[no-any-return]

    def ops_raw(self, op: str, /, **body: Any) -> tuple[int, dict[str, Any]]:
        """Like ``ops`` but returns the refusal (status, json) instead of asserting success."""
        r = httpx.post(
            f"{self.ops_url}/ops/{op}",
            json=body,
            headers={"authorization": f"Bearer {self.ops_token}"},
            timeout=120,
        )
        return r.status_code, r.json()

    def provision(
        self, slug: str, *, pack: dict[str, Any] | None = None, byo_key: bool = True
    ) -> dict[str, Any]:
        """Signup + SSO link + per-tenant service tokens + the BYO model key (+ an active policy pack when given)."""
        return self.ops(
            "provision-tenant", slug=slug, byo_key=BYO_KEY if byo_key else None, pack=pack
        )

    def api_key(
        self, tenant_id: str, member_id: str, scopes: list[str] | None = None, name: str = "e2e key"
    ) -> str:
        return str(
            self.ops(
                "api-key",
                tenant_id=tenant_id,
                member_id=member_id,
                scopes=scopes or ["*"],
                name=name,
            )["secret"]
        )

    def member(self, tenant_id: str, role: str) -> dict[str, Any]:
        return self.ops("member", tenant_id=tenant_id, role=role)

    def runner_credentials(self, tenant: dict[str, Any], runner_id: str) -> dict[str, Any]:
        """Runner token (hub), read token (run-service feed) and the tenant's service tokens for one runner process."""
        return self.ops(
            "eval/runner-credentials", tenant_id=tenant["tenant_id"], runner_id=runner_id
        )

    def start_runner(
        self,
        tenant: dict[str, Any],
        runner_id: str,
        *,
        online: bool = False,
        judge_log: Path | None = None,
        creds: dict[str, Any] | None = None,
        poll: float = 0.4,
    ) -> EvalRunner:
        """Start the REAL eval runner for ``tenant`` (scripted models; the kernel gates every call). It is not registered with the hub:
        registering is the tenant admin's act (``axis evals runners register``)."""
        creds = creds or self.runner_credentials(tenant, runner_id)
        tag = f"{runner_id}-{'online' if online else 'ci'}-{secrets.token_hex(2)}"
        cfg = self.work / f"runner-{tag}.json"
        cfg.write_text(
            json.dumps(
                {
                    "tenant_id": tenant["tenant_id"],
                    "hub_url": self.eval_hub,
                    "runner_id": runner_id,
                    "runner_token": creds["runner_token"],
                    "kernel_target": self.kernel_target,
                    "kernel_token": creds["kernel_token"],
                    "control_plane_url": self.control_plane_url,
                    "runtime_token": creds["runtime_token"],
                    "poll_interval": poll,
                    "online_poll_interval": poll,
                    "mode": "online" if online else "ci",
                    "run_service_url": self.run_service,
                    "run_read_token": creds.get("read_token"),
                }
            )
        )
        err = self.work / f"runner-{tag}.err"
        env = {"EVAL_RUNNER_CONFIG": str(cfg)}
        if judge_log is not None:
            env["JUDGE_LOG"] = str(judge_log)
        proc = subprocess.Popen(
            [
                "uv",
                "run",
                "python",
                "e2e/scripts/eval_runner_e2e.py",
                *(["--online"] if online else []),
            ],
            cwd=ROOT,
            env={**os.environ, **env},
            stdout=subprocess.DEVNULL,
            stderr=err.open("w"),
            text=True,
            start_new_session=True,
        )
        self.procs.append(proc)
        return EvalRunner(
            proc,
            runner_id,
            tenant["tenant_id"],
            creds["runner_token"],
            creds.get("read_token"),
            err,
            online,
        )

    @classmethod
    def from_info(cls, info: dict[str, Any], work: Path) -> Stack:
        """A handle on a stack booted by another process (``STACK_JSON``): enough to provision tenants and start runners."""
        return cls(
            admin_url="", db_url=info["db_url"], work=work, gateway=info["gateway"],
            gateway_origin=info["gateway_origin"], cp=info["cp"], billing="", ops_url=info["ops_url"],
            idp=info["idp"], run_service=info["run_service"], kernel_target=info["kernel_target"],
            approvals_bridge="", console_origin=info["console_origin"], ops_token=info["ops_token"],
            platform_token="", eval_hub=info["eval_hub"], control_plane_url=info["cp"],
        )  # fmt: skip

    def info(self) -> dict[str, Any]:
        return {
            "gateway": self.gateway,
            "gateway_origin": self.gateway_origin,
            "cp": self.cp,
            "ops_url": self.ops_url,
            "ops_token": self.ops_token,
            "idp": self.idp,
            "run_service": self.run_service,
            "console_origin": self.console_origin,
            "eval_hub": self.eval_hub,
            "kernel_target": self.kernel_target,
            "db_url": self.db_url,
            "byo_key": BYO_KEY,
        }


@dataclass
class EvalRunner:
    """A real ``eval_runner`` process of one tenant (its credentials, config and stderr)."""

    proc: subprocess.Popen[str]
    runner_id: str
    tenant_id: str
    runner_token: str
    read_token: str | None
    err: Path
    online: bool = False

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self) -> None:
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                return
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)

    def stderr(self) -> str:
        return self.err.read_text() if self.err.exists() else ""


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def boot(
    work: Path,
    admin_url: str,
    *,
    console_origin: str = "http://localhost:3100",
    gateway_env: dict[str, str] | None = None,
    hop: Callable[[str, int], int] | None = None,
    kernel_env: dict[str, str] | None = None,
) -> Iterator[Stack]:
    """``hop(name, real_port) -> port`` lets a fault-injection proxy sit on one dependency edge: ``kernel`` (the run service and the
    gateway reach the Risk Kernel through it), ``kernel_db`` / ``gateway_db`` (that process's Postgres connection) and ``cp`` (the run
    service's control-plane URL). Without it every edge is direct."""
    hop_ = hop or (lambda _name, port: port)
    suffix = secrets.token_hex(4)
    db = f"axis_e2e7_{suffix}"
    psql(admin_url, f"CREATE DATABASE {db}")
    db_url = admin_url.rsplit("/", 1)[0] + f"/{db}"
    procs: list[subprocess.Popen[str]] = []
    try:
        sh(
            ["pnpm", "--filter", "@axis/db", "exec", "tsx", "src/cli.ts"],
            env={"DATABASE_URL": db_url},
        )
        files = {n: work / f"{n}.json" for n in (
            "kernel_principals", "gw_run", "run_tokens", "gw_kernel", "run_kernel", "run_runtime", "run_ingest",
            "eval_runner", "run_read",
        )}  # fmt: skip
        for p in files.values():
            p.write_text("{}")
        bundle_dir = work / "bundles"
        bundle_dir.mkdir()
        hmac_key = secrets.token_hex(32)
        approvals_port = _free_port()
        kernel_port, run_port, gw_port = _free_port(), _free_port(), _free_port()
        specs: dict[str, tuple[list[str], dict[str, str], Path, str, Path]] = {}
        named: dict[str, subprocess.Popen[str]] = {}

        def launch(
            name: str, args: list[str], env: dict[str, str], ready: str, cwd: Path = ROOT
        ) -> dict[str, Any]:
            err = work / f"{name}.err"
            proc, info = _spawn(args, env, err, ready, cwd)
            specs[name] = (args, env, err, ready, cwd)
            named[name] = proc
            procs.append(proc)
            return info

        db_port = int(db_url.rsplit(":", 1)[1].split("/")[0])
        kernel_db_url = db_url.replace(f":{db_port}/", f":{hop_('kernel_db', db_port)}/")
        gateway_db_url = db_url.replace(f":{db_port}/", f":{hop_('gateway_db', db_port)}/")
        kinfo = launch(
            "kernel",
            ["node", "--import", "tsx", "services/risk-kernel/src/main.ts"],
            {
                "AXIS_RK_PORT": str(kernel_port),
                "AXIS_POLICY_BUNDLE_DIR": str(bundle_dir),
                "AXIS_RK_TOKENS": str(files["kernel_principals"]),
                "AXIS_AUDIT_PG_URL": kernel_db_url,
                **(kernel_env or {}),
                "AXIS_AUDIT_PG_ROLE": "axis_app",
                "AXIS_APPROVALS_HMAC_KEY": hmac_key,
                "AXIS_APPROVALS_DEV_BRIDGE": "1",
                "AXIS_APPROVALS_PORT": str(approvals_port),
            },
            "port",
        )
        kernel_target = f"127.0.0.1:{hop_('kernel', kinfo['port'])}"
        secrets_cfg = {k: secrets.token_hex(32) for k in ("pepper", "cookie_key", "signing_key")}
        ops_token = "e2e-ops-" + secrets.token_hex(8)
        platform_token = "e2e-platform-" + secrets.token_hex(8)
        seal_key = "e2e-seal-key-" + secrets.token_hex(16)
        cfg = work / "stack.json"
        cfg.write_text(
            json.dumps(
                {
                    "db_url": db_url,
                    "role": "axis_app",
                    "region": "us-east-1",
                    "bundle_dir": str(bundle_dir),
                    "platform_token": platform_token,
                    "ops_token": ops_token,
                    "seal_key": seal_key,
                    "secrets": secrets_cfg,
                    "redirect_uri": f"{console_origin}/auth/sso/callback",
                    "return_origins": [console_origin],
                    "files": {k: str(v) for k, v in files.items()},
                }
            )  # fmt: skip
        )
        sinfo = launch(
            "stack", ["node", "scripts/interfaces-stack.mjs", str(cfg)], {}, "cp", ROOT / "e2e"
        )
        cp = f"http://127.0.0.1:{sinfo['cp']}"
        billing = f"http://127.0.0.1:{sinfo['billing']}"
        run_cfg = work / "runserver.json"
        run_cfg.write_text(
            json.dumps(
                {
                    "port": run_port,
                    "tokens": {},
                    "kernel_target": kernel_target,
                    "kernel_tokens": {},
                    "control_plane_url": f"http://127.0.0.1:{hop_('cp', sinfo['cp'])}",
                    "runtime_tokens": {},
                    "billing_url": billing,
                    "ingest_tokens": {},
                    "approvals_url": f"http://127.0.0.1:{approvals_port}",
                    "approval_tokens": {},
                    "approval_poll_seconds": 0.5,
                    "approval_max_wait_seconds": 180,
                    "tokens_file": str(files["run_tokens"]),
                    "kernel_tokens_file": str(files["run_kernel"]),
                    "runtime_tokens_file": str(files["run_runtime"]),
                    "ingest_tokens_file": str(files["run_ingest"]),
                    "approval_tokens_file": str(files["run_kernel"]),
                    "read_tokens_file": str(files["run_read"]),
                }
            )  # fmt: skip
        )
        rinfo = launch(
            "run",
            ["uv", "run", "python", "e2e/scripts/interfaces_run_server.py"],
            {"RUNSERVER_CONFIG": str(run_cfg)},
            "port",
        )
        run_service = f"http://127.0.0.1:{rinfo['port']}"
        ginfo = launch(
            "gateway",
            ["node", "apps/api-gateway/dist/main.js"],
            {
                "GW_DATABASE_URL": gateway_db_url, "GW_DB_ROLE": "axis_app", "GW_PORT": str(gw_port),
                "GW_ALLOWED_ORIGINS": console_origin, "GW_PEPPER": secrets_cfg["pepper"],
                "GW_COOKIE_KEY": secrets_cfg["cookie_key"], "GW_SIGNING_KEY": secrets_cfg["signing_key"],
                "GW_SEAL_KEY": seal_key, "GW_RUN_SERVICE_URL": f"http://127.0.0.1:{hop_('run', rinfo['port'])}",
                "GW_RUN_TOKENS_FILE": str(files["gw_run"]), "GW_KERNEL_TARGET": kernel_target,
                "GW_KERNEL_TOKENS_FILE": str(files["gw_kernel"]),
                "GW_APPROVALS_URL": f"http://127.0.0.1:{approvals_port}",
                "GW_APPROVALS_TOKENS_FILE": str(files["gw_kernel"]), "GW_BUNDLE_DIR": str(bundle_dir),
                "GW_RATE_BURST": "2000", "GW_RATE_PER_SEC": "1000",
                "GW_EVAL_RUNNER_TOKENS_FILE": str(files["eval_runner"]), "GW_EVAL_RUNNER_PORT": "0",
                **(gateway_env or {}),
            },
            "port",
        )  # fmt: skip
        yield Stack(
            admin_url=admin_url, db_url=db_url, work=work,
            gateway=f"http://127.0.0.1:{ginfo['port']}/v1", gateway_origin=f"http://127.0.0.1:{ginfo['port']}",
            cp=cp, billing=billing, ops_url=f"http://127.0.0.1:{sinfo['ops']}", idp=f"http://localhost:{sinfo['idp']}",
            run_service=run_service, kernel_target=kernel_target,
            approvals_bridge=f"http://127.0.0.1:{approvals_port}", console_origin=console_origin,
            ops_token=ops_token, platform_token=platform_token, procs=procs, specs=specs, named=named,
            eval_hub=f"http://127.0.0.1:{ginfo['eval_runner_port']}", control_plane_url=cp,
        )  # fmt: skip
    finally:
        for p in reversed(procs):
            try:
                os.killpg(p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        for p in procs:
            try:
                p.wait(15)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
        psql(admin_url, f"DROP DATABASE IF EXISTS {db} WITH (FORCE)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="where to write the stack description (JSON)")
    ap.add_argument("--console-origin", default="http://localhost:3100")
    ap.add_argument(
        "--gateway-env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="extra environment for the gateway process (e.g. GW_RATE_BURST=100000 for a load test)",
    )
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise SystemExit("PG_ADMIN_URL is required: run via infra/scripts/with-pg.sh")
    import tempfile

    with (
        tempfile.TemporaryDirectory(prefix="axis-e2e7-") as d,
        boot(
            Path(d),
            admin,
            console_origin=a.console_origin,
            gateway_env=dict(kv.split("=", 1) for kv in a.gateway_env),
        ) as st,
    ):
        Path(a.out).write_text(json.dumps(st.info()))
        return subprocess.run(cmd, env={**os.environ, "STACK_JSON": a.out}, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
