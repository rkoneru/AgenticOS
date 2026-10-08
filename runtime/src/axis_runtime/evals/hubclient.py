"""Client of the Eval Hub (services/eval-hub): the runner's ONLY outbound channel.

``EvalHubClient`` is the port; ``HttpEvalHubClient`` speaks the hub's snake_case JSON API with a
runner token (``authorization: Bearer``) and an HMAC signature over the exact request body
(``x-axis-runner-signature: v1=<hex>``) so a body altered between runner and hub is rejected. The
tenant is bound by the token on the hub side; this client also refuses a queued run of another
tenant (``WorkerConfig.tenant_id`` check in ``worker``). Wire paths and shapes follow the Phase 8
plan and are pinned by ``tests/fixtures/eval-hub-wire-examples.json`` (docs/NEEDS.md notes the
re-alignment with ``services/eval-hub/contract/wire-v1.json``).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from axis_runtime.evals.types import (
    RUNNER_VERSION,
    Dataset,
    OnlineConfig,
    QueuedRun,
    Suite,
    WireError,
    canonical,
)


class HubError(RuntimeError):
    """The hub could not take or answer a request. ``kind`` is stable and secret-free."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


@dataclass(frozen=True)
class RunnerIdentity:
    """``token`` authenticates the runner; ``signing_key`` (defaults to the token) signs bodies."""

    runner_id: str
    token: str
    signing_key: bytes | None = None

    def sign(self, body: bytes) -> str:
        key = self.signing_key if self.signing_key is not None else self.token.encode("utf-8")
        return "v1=" + hmac.new(key, body, hashlib.sha256).hexdigest()


class EvalHubClient(Protocol):
    async def claim_run(self) -> QueuedRun | None: ...

    async def get_suite(self, ref: str) -> Suite: ...

    async def get_dataset(self, ref: str) -> Dataset: ...

    async def submit_results(
        self, run_id: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]: ...

    async def create_review_tasks(
        self, run_id: str, tasks: Sequence[Mapping[str, Any]]
    ) -> Mapping[str, Any]: ...

    async def online_configs(self) -> list[OnlineConfig]: ...

    async def post_online_results(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...

    async def aclose(self) -> None: ...


class HttpEvalHubClient:
    def __init__(
        self,
        base_url: str,
        identity: RunnerIdentity,
        *,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._identity = identity
        self._client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    async def _request(
        self, method: str, path: str, body: Mapping[str, Any] | None = None
    ) -> httpx.Response:
        headers = {
            "authorization": f"Bearer {self._identity.token}",
            "x-axis-runner-id": self._identity.runner_id,
            "x-axis-runner-version": RUNNER_VERSION,
        }
        content: bytes | None = None
        if body is not None:
            content = canonical(body).encode("utf-8")
            headers["content-type"] = "application/json"
            headers["x-axis-runner-signature"] = self._identity.sign(content)
        try:
            resp = await self._client.request(
                method, self._base + path, headers=headers, content=content
            )
        except httpx.HTTPError as exc:
            raise HubError(f"transport:{type(exc).__name__}") from None
        if resp.status_code == 409:
            raise HubError("conflict")
        if not 200 <= resp.status_code < 300:
            raise HubError(f"http_{resp.status_code}")
        return resp

    @staticmethod
    def _json(resp: httpx.Response) -> Any:
        try:
            return resp.json()
        except ValueError:
            raise HubError("malformed_response") from None

    async def claim_run(self) -> QueuedRun | None:
        resp = await self._request(
            "POST",
            "/v1/evals/runner/claim",
            {"runner_id": self._identity.runner_id, "runner_version": RUNNER_VERSION},
        )
        if resp.status_code == 204:
            return None
        doc = self._json(resp)
        raw = doc.get("run") if isinstance(doc, dict) else None
        if raw is None:
            return None
        try:
            return QueuedRun.from_wire(raw)
        except WireError as exc:
            raise HubError(f"malformed_run:{exc}"[:120]) from None

    async def get_suite(self, ref: str) -> Suite:
        doc = self._json(await self._request("GET", f"/v1/evals/suites/{quote(ref, safe='')}"))
        try:
            return Suite.from_wire(doc)
        except WireError as exc:
            raise HubError(f"malformed_suite:{exc}"[:120]) from None

    async def get_dataset(self, ref: str) -> Dataset:
        doc = self._json(await self._request("GET", f"/v1/evals/datasets/{quote(ref, safe='')}"))
        try:
            return Dataset.from_wire(doc)
        except WireError as exc:
            raise HubError(f"malformed_dataset:{exc}"[:120]) from None

    async def submit_results(self, run_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        resp = await self._request(
            "POST", f"/v1/evals/runs/{quote(run_id, safe='')}/results", payload
        )
        doc = self._json(resp) if resp.content else {}
        return doc if isinstance(doc, dict) else {}

    async def create_review_tasks(
        self, run_id: str, tasks: Sequence[Mapping[str, Any]]
    ) -> Mapping[str, Any]:
        resp = await self._request(
            "POST", f"/v1/evals/runs/{quote(run_id, safe='')}/review-tasks", {"tasks": list(tasks)}
        )
        doc = self._json(resp) if resp.content else {}
        return doc if isinstance(doc, dict) else {}

    async def online_configs(self) -> list[OnlineConfig]:
        doc = self._json(await self._request("GET", "/v1/evals/online/configs"))
        items = doc.get("configs") if isinstance(doc, dict) else None
        if not isinstance(items, list):
            raise HubError("malformed_response")
        try:
            return [OnlineConfig.from_wire(i) for i in items]
        except WireError as exc:
            raise HubError(f"malformed_online_config:{exc}"[:120]) from None

    async def post_online_results(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        resp = await self._request("POST", "/v1/evals/online/results", payload)
        doc = self._json(resp) if resp.content else {}
        return doc if isinstance(doc, dict) else {}

    async def aclose(self) -> None:
        await self._client.aclose()
