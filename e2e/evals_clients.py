"""The three public clients (TypeScript SDK, Python SDK, `axis` CLI) behind one small interface for the Eval Hub operations.

Every client talks to the REAL gateway with an API key; nothing here reaches around the API. A refusal is normalised to ``ApiFail``
(HTTP status when the client exposes one, the text, and for the CLI the process exit code).
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
from pathlib import Path
from typing import Any

from axis_sdk import Axis, AxisError

import interfaces_stack as istack  # noqa: E402  (e2e/ is on sys.path)

ROOT = Path(__file__).resolve().parent.parent
CLI = ["node", str(ROOT / "apps/cli/dist/bin.js")]
TS_CLIENT = str(ROOT / "e2e/scripts/ts-sdk-client.mjs")


class ApiFail(Exception):
    """A request the API refused, normalised across the three clients."""

    def __init__(self, status: int | None, text: str, exit_code: int | None = None) -> None:
        super().__init__(f"{status}: {text}")
        self.status = status
        self.text = text
        self.exit_code = exit_code


class EvalClient:
    name = "?"

    def __init__(self, stack: istack.Stack, key: str) -> None:
        self.stack, self.key = stack, key

    def call(self, op: str, **a: Any) -> Any:
        raise NotImplementedError

    def with_key(self, key: str) -> EvalClient:
        return type(self)(self.stack, key)


# ---- TypeScript SDK -------------------------------------------------------------------------------------------------------


class TsSdk(EvalClient):
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
        line = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        out = json.loads(line) if line else {"error": {"message": r.stderr}}
        if isinstance(out, dict) and "error" in out and r.returncode != 0:
            raise ApiFail(out["error"].get("status"), out["error"].get("message", ""))
        return out


# ---- Python SDK -----------------------------------------------------------------------------------------------------------


class PySdk(EvalClient):
    name = "py-sdk"

    def __init__(self, stack: istack.Stack, key: str) -> None:
        super().__init__(stack, key)
        self.ax = Axis(key, base_url=stack.gateway, allow_insecure=True, max_retries=0)

    def call(self, op: str, **a: Any) -> Any:
        try:
            return self._dispatch(self.ax, op, a)
        except AxisError as e:
            assert self.key not in str(e) + repr(e), "the Python SDK leaked the API key"
            raise ApiFail(e.status, str(e)) from None

    def _dispatch(self, ax: Axis, op: str, a: dict[str, Any]) -> Any:  # noqa: C901 - one flat table
        ev = ax.evals
        match op:
            case "me":
                return ax.me()
            case "evalsDatasetCreate":
                b = a["body"]
                return ev.datasets.create(
                    b["name"], b["cases"], description=b.get("description"), phi=b.get("phi")
                )
            case "evalsDatasetGet":
                return ev.datasets.get(a["name"], a.get("version") or "latest")
            case "evalsDatasetList":
                return ev.datasets.list(name=a.get("name"))
            case "evalsSuiteCreate":
                return ev.suites.create(a["body"])
            case "evalsSuiteGet":
                return ev.suites.get(a["ref"])
            case "evalsSuiteList":
                return ev.suites.list()
            case "evalsRunStart":
                return ev.start(a["suite"], a["blueprint"], mode=a.get("mode"))
            case "evalsRunGet":
                return ev.get(a["id"])
            case "evalsRunWait":
                return ev.wait(
                    a["id"], timeout=a.get("timeout_ms", 180000) / 1000, poll_interval=0.3
                )
            case "evalsRunList":
                return ev.list(**a.get("params", {}))
            case "evalsCompare":
                return ev.comparison(a["id"])
            case "evalsGate":
                return ev.gate(a["blueprint"], a.get("suites"))
            case "evalsBaselineList":
                return ev.baselines.list(a["blueprint"], a["suite"])
            case "evalsBaselineSet":
                return ev.baselines.set(a["run_id"])
            case "evalsReviewTasks":
                p = a.get("params", {})
                return ev.review.tasks(state=p.get("state"), run_id=p.get("run_id"))
            case "evalsReviewClaim":
                return ev.review.claim(a["id"])
            case "evalsReviewGrade":
                return ev.review.grade(a["id"], score=a["score"], comment=a["comment"])
            case "evalsReviewSkip":
                return ev.review.skip(a["id"], a["reason"])
            case "evalsSamplingPut":
                b = a["body"]
                return ev.sampling.put(
                    a["id"],
                    blueprint=b["blueprint"],
                    suite=b["suite"],
                    rate=b["rate"],
                    max_per_hour=b["max_per_hour"],
                    redaction=b.get("redaction"),
                    enabled=b.get("enabled"),
                    alert_threshold=b.get("alert_threshold"),
                )
            case "evalsSamplingList":
                return ev.sampling.list()
            case "evalsSamplingSummary":
                p = a.get("params", {})
                return ev.sampling.summary(blueprint=p.get("blueprint"), suite=p.get("suite"))
            case "evalsRunnersList":
                return ev.runners.list()
            case "evalsRunnersRegister":
                return ev.runners.register(a["id"], a.get("description"))
            case "evalsRunnersRevoke":
                return ev.runners.revoke(a["id"])
            # production runs and approvals (the run service the online sampler reads from)
            case "runStart":
                return ax.runs.start({"name": a["name"], "version": a["version"]}, a.get("input"))
            case "runWait":
                return ax.runs.wait(a["id"], timeout=120, poll_interval=0.3)
            case "runGet":
                return ax.runs.get(a["id"])
            case "runEvents":
                return list(ax.runs.all_events(a["id"]))
            case "approvalsList":
                return ax.approvals.list(status=a.get("status"))
            case "reject":
                return ax.approvals.reject(a["id"], a.get("comment"))
        raise AssertionError(f"unknown op {op}")


# ---- the `axis` CLI -------------------------------------------------------------------------------------------------------


class Cli(EvalClient):
    name = "cli"

    def __init__(self, stack: istack.Stack, key: str) -> None:
        super().__init__(stack, key)
        self.tmp = stack.work / f"cli8-{secrets.token_hex(3)}"
        self.tmp.mkdir()

    def run(
        self, *argv: str, expect: tuple[int, ...] = (0,), stdin: str | None = None
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
        if r.returncode not in expect:
            low = r.stderr.lower()
            code = 404 if "not found" in low else 403 if "forbidden" in low else None
            raise ApiFail(code, f"exit {r.returncode}: {r.stderr.strip()}", r.returncode)
        return r

    def j(self, *argv: str, expect: tuple[int, ...] = (0,)) -> Any:
        r = self.run("--json", *argv, expect=expect)
        return json.loads(r.stdout) if r.stdout.strip() else None

    def file(self, name: str, doc: Any) -> str:
        p = self.tmp / name
        p.write_text(json.dumps(doc))
        return str(p)

    def last_exit(self, *argv: str) -> int:
        """The exit code of a command whose non-zero exit is the answer (e.g. `evals gate` = 4 when blocked)."""
        return self.run("--json", *argv, expect=tuple(range(0, 20))).returncode

    def call(self, op: str, **a: Any) -> Any:  # noqa: C901 - one flat table
        j = self.j
        match op:
            case "me":
                w = j("whoami")
                return {
                    "tenant": {"id": w["tenant_id"]},
                    "member": {"id": w["member_id"], "role": w["role"]},
                }
            case "evalsDatasetCreate":
                return j("evals", "datasets", "create", self.file("ds.json", a["body"]))
            case "evalsDatasetGet":
                return j("evals", "datasets", "get", a["name"], str(a.get("version") or "latest"))
            case "evalsDatasetList":
                return j(
                    "evals", "datasets", "list", *(["--name", a["name"]] if a.get("name") else [])
                )
            case "evalsSuiteCreate":
                return j("evals", "suites", "create", self.file("suite.json", a["body"]))
            case "evalsSuiteGet":
                return j("evals", "suites", "get", a["ref"])
            case "evalsSuiteList":
                return j("evals", "suites", "list")
            case "evalsRunStart":
                return j(
                    "evals",
                    "run",
                    a["suite"],
                    a["blueprint"],
                    *(["--mode", a["mode"]] if a.get("mode") else []),
                )
            case "evalsRunGet":
                return j("evals", "get", a["id"])
            case "evalsRunWait":
                deadline = time.time() + a.get("timeout_ms", 180000) / 1000
                while time.time() < deadline:
                    r = j("evals", "get", a["id"])
                    if r["status"] in ("passed", "failed", "errored"):
                        return r
                    time.sleep(0.3)
                raise AssertionError("eval run did not finish")
            case "evalsRunList":
                p = a.get("params", {})
                flags: list[str] = []
                for k, f in (
                    ("suite", "--suite"),
                    ("blueprint", "--blueprint"),
                    ("status", "--status"),
                ):
                    if p.get(k):
                        flags += [f, str(p[k])]
                return j("evals", "list", *flags)
            case "evalsCompare":
                return j("evals", "compare", a["id"], expect=(0, 4)) or None
            case "evalsGate":
                bp = a["blueprint"]
                ref = f"{bp['namespace']}/" if bp.get("namespace") else ""
                ref += f"{bp['name']}@{bp['version']}"
                flags = []
                for s in a.get("suites") or []:
                    flags += [
                        "--suite",
                        s["ref"] if s.get("threshold") is None else f"{s['ref']}:{s['threshold']}",
                    ]
                return j("evals", "gate", ref, *flags, expect=(0, 4))
            case "evalsBaselineList":
                return j("evals", "baseline", "list", a["blueprint"], a["suite"])
            case "evalsBaselineSet":
                return j("evals", "baseline", "set", a["run_id"])
            case "evalsReviewTasks":
                p = a.get("params", {})
                flags = []
                if p.get("state"):
                    flags += ["--state", p["state"]]
                if p.get("run_id"):
                    flags += ["--run", p["run_id"]]
                return j("evals", "review", "tasks", *flags)
            case "evalsReviewClaim":
                return j("evals", "review", "claim", a["id"])
            case "evalsReviewGrade":
                return j(
                    "evals",
                    "review",
                    "grade",
                    a["id"],
                    "--score",
                    str(a["score"]),
                    "--comment",
                    a["comment"],
                )
            case "evalsReviewSkip":
                return j("evals", "review", "skip", a["id"], "--reason", a["reason"])
            case "evalsSamplingPut":
                return j("evals", "sampling", "put", a["id"], self.file("sampling.json", a["body"]))
            case "evalsSamplingList":
                return j("evals", "sampling", "list")
            case "evalsSamplingSummary":
                p = a.get("params", {})
                flags = []
                if p.get("blueprint"):
                    flags += ["--blueprint", p["blueprint"]]
                if p.get("suite"):
                    flags += ["--suite", p["suite"]]
                return j("evals", "sampling", "summary", *flags)
            case "evalsRunnersList":
                return j("evals", "runners", "list")
            case "evalsRunnersRegister":
                return j(
                    "evals",
                    "runners",
                    "register",
                    a["id"],
                    *(["--description", a["description"]] if a.get("description") else []),
                )
            case "evalsRunnersRevoke":
                return j("evals", "runners", "revoke", a["id"])
        raise AssertionError(f"unknown op {op}")


CLIENTS: list[type[EvalClient]] = [PySdk, TsSdk, Cli]
