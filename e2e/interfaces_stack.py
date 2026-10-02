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
from collections.abc import Iterator
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
    args: list[str], env: dict[str, str], err: Path, ready: str, cwd: Path = ROOT
) -> tuple[subprocess.Popen[str], dict[str, Any]]:
    """Start a process and wait for its one JSON readiness line (an object with a key in ``ready``)."""
    proc = subprocess.Popen(
        args,
        cwd=cwd,
        env={**os.environ, **env},
        stdout=subprocess.PIPE,
        stderr=err.open("w"),
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
    procs: list[subprocess.Popen[str]] = field(default_factory=list)

    def ops(self, op: str, /, **body: Any) -> dict[str, Any]:
        r = httpx.post(
            f"{self.ops_url}/ops/{op}",
            json=body,
            headers={"authorization": f"Bearer {self.ops_token}"},
            timeout=120,
        )
        assert r.status_code == 200, (op, r.status_code, r.text)
        return r.json()  # type: ignore[no-any-return]

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
            "db_url": self.db_url,
            "byo_key": BYO_KEY,
        }


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@contextmanager
def boot(
    work: Path, admin_url: str, *, console_origin: str = "http://localhost:3100"
) -> Iterator[Stack]:
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
        )}  # fmt: skip
        for p in files.values():
            p.write_text("{}")
        bundle_dir = work / "bundles"
        bundle_dir.mkdir()
        hmac_key = secrets.token_hex(32)
        approvals_port = _free_port()
        kernel, kinfo = _spawn(
            ["node", "--import", "tsx", "services/risk-kernel/src/main.ts"],
            {
                "AXIS_POLICY_BUNDLE_DIR": str(bundle_dir),
                "AXIS_RK_TOKENS": str(files["kernel_principals"]),
                "AXIS_AUDIT_PG_URL": db_url,
                "AXIS_AUDIT_PG_ROLE": "axis_app",
                "AXIS_APPROVALS_HMAC_KEY": hmac_key,
                "AXIS_APPROVALS_DEV_BRIDGE": "1",
                "AXIS_APPROVALS_PORT": str(approvals_port),
            },
            work / "kernel.err",
            "port",
        )
        procs.append(kernel)
        kernel_target = f"127.0.0.1:{kinfo['port']}"
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
        stack_proc, sinfo = _spawn(
            ["node", "scripts/interfaces-stack.mjs", str(cfg)],
            {},
            work / "stack.err",
            "cp",
            cwd=ROOT / "e2e",
        )
        procs.append(stack_proc)
        cp = f"http://127.0.0.1:{sinfo['cp']}"
        billing = f"http://127.0.0.1:{sinfo['billing']}"
        run_cfg = work / "runserver.json"
        run_cfg.write_text(
            json.dumps(
                {
                    "port": 0,
                    "tokens": {},
                    "kernel_target": kernel_target,
                    "kernel_tokens": {},
                    "control_plane_url": cp,
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
                }
            )  # fmt: skip
        )
        run, rinfo = _spawn(
            ["uv", "run", "python", "e2e/scripts/interfaces_run_server.py"],
            {"RUNSERVER_CONFIG": str(run_cfg)},
            work / "runserver.err",
            "port",
        )
        procs.append(run)
        run_service = f"http://127.0.0.1:{rinfo['port']}"
        gw, ginfo = _spawn(
            ["node", "apps/api-gateway/dist/main.js"],
            {
                "GW_DATABASE_URL": db_url, "GW_DB_ROLE": "axis_app", "GW_PORT": "0",
                "GW_ALLOWED_ORIGINS": console_origin, "GW_PEPPER": secrets_cfg["pepper"],
                "GW_COOKIE_KEY": secrets_cfg["cookie_key"], "GW_SIGNING_KEY": secrets_cfg["signing_key"],
                "GW_SEAL_KEY": seal_key, "GW_RUN_SERVICE_URL": run_service,
                "GW_RUN_TOKENS_FILE": str(files["gw_run"]), "GW_KERNEL_TARGET": kernel_target,
                "GW_KERNEL_TOKENS_FILE": str(files["gw_kernel"]),
                "GW_APPROVALS_URL": f"http://127.0.0.1:{approvals_port}",
                "GW_APPROVALS_TOKENS_FILE": str(files["gw_kernel"]), "GW_BUNDLE_DIR": str(bundle_dir),
                "GW_RATE_BURST": "2000", "GW_RATE_PER_SEC": "1000",
            },
            work / "gateway.err",
            "port",
        )  # fmt: skip
        procs.append(gw)
        yield Stack(
            admin_url=admin_url, db_url=db_url, work=work,
            gateway=f"http://127.0.0.1:{ginfo['port']}/v1", gateway_origin=f"http://127.0.0.1:{ginfo['port']}",
            cp=cp, billing=billing, ops_url=f"http://127.0.0.1:{sinfo['ops']}", idp=f"http://127.0.0.1:{sinfo['idp']}",
            run_service=run_service, kernel_target=kernel_target,
            approvals_bridge=f"http://127.0.0.1:{approvals_port}", console_origin=console_origin,
            ops_token=ops_token, platform_token=platform_token, procs=procs,
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
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    admin = os.environ.get("PG_ADMIN_URL")
    if not admin:
        raise SystemExit("PG_ADMIN_URL is required: run via infra/scripts/with-pg.sh")
    import tempfile

    with (
        tempfile.TemporaryDirectory(prefix="axis-e2e7-") as d,
        boot(Path(d), admin, console_origin=a.console_origin) as st,
    ):
        Path(a.out).write_text(json.dumps(st.info()))
        return subprocess.run(cmd, env={**os.environ, "STACK_JSON": a.out}, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
