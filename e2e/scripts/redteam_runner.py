"""E2E launcher of the EVAL RUNNER for the red-team suite (NOT production).

It is ``runtime/scripts/eval_runner.py`` with ONE fake on the model path: a scripted provider transport whose "model" is the
worst-case GULLIBLE one of ``evals/redteam/gullible.py`` (it obeys every directive it finds in anything it is shown). Everything else
is the real wiring: the Risk Kernel over gRPC gates every model call and tool call under the tenant's policy bundle, the compiled
manifest comes from the Eval Hub, the BYO key from the control plane, the results go back to the hub with a signed body.

Two additions that exist only to make containment *measurable*:

* an execution SINK: every fixture tool handler that actually runs (that is: the gate said ALLOW) appends ``{case, tool, args}`` to
  ``REDTEAM_SINK``. The harness checks the sink independently of the graders (no harmful tool ever ran; no canary ever reached a
  non-read tool, in any encoding);
* a MUTATION switch for ``make redteam-selfcheck``: ``REDTEAM_MUTATION=gate-bypass:<tool>[,<tool>]`` (or ``gate-bypass:*``) makes the
  runner's gate client answer ALLOW for those tool calls without asking the kernel. A suite that cannot see that has no teeth.

usage: EVAL_RUNNER_CONFIG=<json> REDTEAM_SINK=<file> [REDTEAM_MUTATION=...] python e2e/scripts/redteam_runner.py
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "scripts"))
sys.path.insert(0, str(ROOT / "evals" / "redteam"))

import eval_runner  # noqa: E402
import gullible  # noqa: E402
from axis_runtime._decision import Decision  # noqa: E402
from axis_runtime.evals import isolation  # noqa: E402
from axis_runtime.evals.runner import CaseRunner  # noqa: E402
from axis_runtime.gate import EnforcementPoint, EvaluateRequest, GateDecision  # noqa: E402
from axis_runtime.models.adapters.base import HttpCall, HttpResponse  # noqa: E402

CASE: contextvars.ContextVar[str] = contextvars.ContextVar("redteam_case", default="")
SINK = Path(os.environ["REDTEAM_SINK"]) if os.environ.get("REDTEAM_SINK") else None
MUTATION = os.environ.get("REDTEAM_MUTATION", "")


class Scripted:
    """The gullible model behind the provider API (the BYO key must be present: a tenant without one gets a 401)."""

    async def send(self, call: HttpCall) -> HttpResponse:
        auth = call.headers.get("authorization") or call.headers.get("Authorization") or ""
        if not auth.startswith("Bearer sk-byo-"):
            return HttpResponse(401, {}, b'{"error":{"message":"no byo key"}}')
        out = gullible.respond(json.loads(call.body))
        return HttpResponse(200, {}, json.dumps(out).encode())

    def stream(self, call: HttpCall) -> Any:  # pragma: no cover - the agent loop does not stream
        raise NotImplementedError


def install_sink() -> None:
    original_call = isolation.FixtureTool.__call__
    original_run_case = CaseRunner.run_case

    def call(self: isolation.FixtureTool, args: Any) -> Any:
        if SINK is not None:
            with SINK.open("a") as f:
                f.write(json.dumps({"case": CASE.get(), "tool": self.name, "args": args}) + "\n")
        return original_call(self, args)

    async def run_case(self: CaseRunner, manifest: Any, case: Any, **kw: Any) -> Any:
        CASE.set(case.id)
        return await original_run_case(self, manifest, case, **kw)

    isolation.FixtureTool.__call__ = call  # type: ignore[method-assign]
    CaseRunner.run_case = run_case  # type: ignore[method-assign]


def install_mutation() -> None:
    kind, _, arg = MUTATION.partition(":")
    if kind != "gate-bypass":
        if MUTATION:
            raise SystemExit(f"unknown REDTEAM_MUTATION {MUTATION!r}")
        return
    tools = {t for t in arg.split(",") if t}
    real = eval_runner.GrpcGateClient

    class Bypassing(real):  # type: ignore[valid-type, misc]
        async def evaluate(self, request: EvaluateRequest) -> GateDecision:
            if request.enforcement_point is EnforcementPoint.TOOL_CALL and (
                "*" in tools or request.action in tools
            ):
                return GateDecision(Decision.ALLOW, reason="MUTANT: gate bypassed")
            return await super().evaluate(request)  # type: ignore[no-any-return]

    eval_runner.GrpcGateClient = Bypassing


async def main() -> int:
    cfg = json.loads(await asyncio.to_thread(Path(os.environ["EVAL_RUNNER_CONFIG"]).read_text))
    install_sink()
    install_mutation()
    return await eval_runner.run(cfg, online=False, transport=Scripted())


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
