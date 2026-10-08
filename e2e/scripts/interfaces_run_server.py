"""E2E launcher of the run service for the Phase 7 interfaces suite (NOT production).

It is ``runtime/scripts/run_server.py`` with the two things only a deterministic test needs:

* a SCRIPTED model provider (the only fake on the model path): an OpenAI-shaped transport that answers from the prompt, so a run is
  repeatable and records the BYO key and the tokens it billed;
* deterministic tools (``lookup-claim``, ``file-payout``, ``lookup-restricted``) registered by name.

Everything else is the real wiring: the kernel gate over gRPC, the BYO key and budgets from the control plane, TKI per tenant, usage to
billing, and the approvals resolver (REQUIRE_APPROVAL waits for a human decision through the approvals bridge, then the approved action
is re-gated). Config: the same JSON as ``run_server.py`` (RUNSERVER_CONFIG).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "scripts"))

from axis_runtime.models.adapters.base import HttpCall, HttpResponse  # noqa: E402
from axis_runtime.runserver import RunServer, RunServerConfig, RunService  # noqa: E402
from axis_runtime.tools import ToolRegistry  # noqa: E402
from run_server import Wiring, wired_factory  # noqa: E402

PHI_ANSWER = (
    "Patient John Smith (SSN 123-45-6789, phone 415-555-0100) has an open claim. "
    "A specialist will contact you within 2 days. Thank you for your patience."
)
XSS = '<img src=x onerror="window.__xss=1"><script>window.__xss=1</script>'


def _turn(
    text: str | None,
    calls: list[tuple[str, dict[str, Any]]] | None = None,
    *,
    prompt: int = 40,
    completion: int = 12,
) -> dict[str, Any]:
    msg: dict[str, Any] = {"role": "assistant", "content": text}
    if calls:
        msg["tool_calls"] = [
            {
                "id": f"call_{i}",
                "type": "function",
                "function": {"name": n, "arguments": json.dumps(a)},
            }
            for i, (n, a) in enumerate(calls)
        ]
    return {
        "id": "chatcmpl-e2e",
        "model": "gpt-4o",
        "choices": [
            {"index": 0, "message": msg, "finish_reason": "tool_calls" if calls else "stop"}
        ],
        "usage": {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "prompt_tokens_details": {"cached_tokens": 0},
        },
    }


def _last_user(body: dict[str, Any]) -> str:
    return next((m["content"] for m in reversed(body["messages"]) if m["role"] == "user"), "")


def _tool_results(body: dict[str, Any]) -> list[dict[str, Any]]:
    return [m for m in body["messages"] if m["role"] == "tool"]


def script(body: dict[str, Any]) -> dict[str, Any]:
    ask = _last_user(body)
    results = _tool_results(body)
    if ask.startswith("review claim"):
        claim = ask.rsplit(" ", 1)[-1]
        if not results:
            return _turn(
                None,
                [
                    ("lookup-claim", {"claim_id": claim}),
                    ("file-payout", {"claim_id": claim, "amount": 250}),
                ],
                prompt=120,
                completion=30,
            )
        return _turn(
            "claim reviewed: " + " | ".join(str(m["content"])[:60] for m in results),
            prompt=80,
            completion=20,
        )
    if ask.startswith("restricted"):
        if not results:
            return _turn(
                None,
                [("lookup-restricted", {"claim_id": ask.rsplit(" ", 1)[-1]})],
                prompt=60,
                completion=10,
            )
        return _turn(
            "restricted lookup finished: " + " | ".join(str(m["content"])[:60] for m in results)
        )
    if ask.startswith("xss"):
        return _turn(f"output: {XSS}", prompt=30, completion=15)
    if ask.startswith("slow"):
        return _turn("slow answer")
    # Phase 8: production answers the eval suite's online sampler grades
    if ask.startswith("answer claim"):
        n = ask.rsplit(" ", 1)[-1]
        return _turn(
            f"Claim {n} is open. A specialist will contact you within 2 days. Thank you for your patience."
        )
    if ask.startswith(
        "probe"
    ):  # Phase 8: what production decides for the tools the eval-safety probe tries
        claim = ask.rsplit(" ", 1)[-1]
        if not results:
            return _turn(
                None,
                [
                    ("lookup-claim", {"claim_id": claim}),
                    ("wire-funds", {"account": "ACME-1", "amount": 9000}),
                    ("file-payout", {"claim_id": claim, "amount": 250}),
                ],
            )
        return _turn("probe finished: " + " | ".join(str(m["content"])[:40] for m in results))
    if ask.startswith("terse claim"):
        return _turn("Open.")
    if ask.startswith("phi claim"):
        return _turn(PHI_ANSWER)
    return _turn(f"echo: {ask}")


class Provider:
    """The scripted model provider. ``calls`` records the credential each call used (the BYO key) and what it billed."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def send(self, call: HttpCall) -> HttpResponse:
        out = script(json.loads(call.body))
        self.calls.append(
            {
                "auth": call.headers.get("authorization") or call.headers.get("Authorization"),
                "prompt": out["usage"]["prompt_tokens"],
                "completion": out["usage"]["completion_tokens"],
            }
        )
        return HttpResponse(200, {}, json.dumps(out).encode())

    def stream(self, call: HttpCall) -> Any:  # pragma: no cover - the agent loop does not stream
        raise NotImplementedError


def tools() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(
        "lookup-claim",
        lambda a: {
            "claim": a.get("claim_id"),
            "status": "open",
            "note": XSS if a.get("claim_id") == "xss" else "ok",
        },
        description="Read a claim",
    )
    reg.register(
        "lookup-restricted",
        lambda a: {"secret": "restricted"},
        description="Read a restricted claim",
    )
    reg.register(
        "wire-funds",
        lambda a: {"wired": True, "amount": a.get("amount")},
        description="Wire funds (forbidden by every tenant pack of the suite)",
    )
    reg.register(
        "file-payout",
        lambda a: {"filed": True, "claim": a.get("claim_id"), "amount": a.get("amount")},
        description="File a payout",
    )
    return reg


async def main() -> None:
    cfg = json.loads(await asyncio.to_thread(Path(os.environ["RUNSERVER_CONFIG"]).read_text))
    wiring = Wiring(
        kernel_target=cfg["kernel_target"],
        kernel_tokens=cfg["kernel_tokens"],
        control_plane_url=cfg["control_plane_url"],
        runtime_tokens=cfg["runtime_tokens"],
        billing_url=cfg.get("billing_url"),
        ingest_tokens=cfg.get("ingest_tokens", {}),
        approvals_url=cfg.get("approvals_url"),
        approval_tokens=cfg.get("approval_tokens", {}),
        approval_poll_seconds=float(cfg.get("approval_poll_seconds", 0.5)),
        approval_max_wait_seconds=float(cfg.get("approval_max_wait_seconds", 120)),
    )
    # the token tables are files the harness rewrites as tenants are created (a tenant added after start gets credentials)
    tables = {
        k: Path(cfg[f"{k}_file"])
        for k in (
            "tokens",
            "kernel_tokens",
            "runtime_tokens",
            "ingest_tokens",
            "approval_tokens",
            "read_tokens",
        )
        if f"{k}_file" in cfg
    }

    class Live(dict[str, str]):
        def __init__(self, path: Path) -> None:
            super().__init__()
            self.path, self.m = path, (-1, -1, -1)

        def _load(self) -> None:
            try:
                st = self.path.stat()
                # mtime alone misses a rewrite inside one timestamp tick (coarse filesystems): inode and size count too
                m = (st.st_ino, st.st_size, st.st_mtime_ns)
                if m != self.m:
                    self.clear()
                    self.update(json.loads(self.path.read_text()))
                    self.m = m
            except (OSError, ValueError):
                self.clear()

        def __contains__(self, k: object) -> bool:
            self._load()
            return super().__contains__(k)

        def __getitem__(self, k: str) -> str:
            self._load()
            return super().__getitem__(k)

        def get(self, k: str, d: Any = None) -> Any:  # type: ignore[override]
            self._load()
            return super().get(k, d)

        def items(self) -> Any:
            self._load()
            return super().items()

    live = {k: Live(p) for k, p in tables.items()}
    for k in ("kernel_tokens", "runtime_tokens", "ingest_tokens", "approval_tokens"):
        if k in live:
            setattr(wiring, k, live[k])
    provider = Provider()
    factory = wired_factory(wiring, model_transport=provider, tools_factory=tools)
    server_tokens = live.get("tokens", cfg.get("tokens", {}))
    server = RunServer(
        RunService(factory),
        RunServerConfig(tokens=server_tokens, read_tokens=live.get("read_tokens", {})),
    )
    port = await server.start(port=int(cfg.get("port", 0)))
    print(json.dumps({"port": port}), flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
