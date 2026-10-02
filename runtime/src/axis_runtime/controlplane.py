"""Client of the control plane's runtime bridge (DEV, non-production; docs/spec/control-plane.md
section 7).

One bearer token per tenant, issued by the control plane's operator. The control plane derives the
tenant
from the token, never from the request, so this client cannot ask for another tenant's data; it also
refuses locally to ask on behalf of a tenant other than its own (belt and braces).

Two read-only calls:
  * ``reveal_model_key``  ``POST /internal/v1/model-keys/reveal``  -> the tenant's BYO provider key
                          (plaintext on the wire: loopback + TLS termination only, NEEDS #186);
  * ``budget_config``     ``GET  /internal/v1/budget-config``      -> the tenant's budgets for TKI
                          (``tenant_budgets.TenantBudgets.from_json``).

Neither is an agent action: they run in the trusted host before and around a run. A failure raises
``ControlPlaneUnavailable``; callers fail CLOSED (no key: the model call fails; no budget config:
the run
does not start)."""

from __future__ import annotations

from typing import Any

import httpx


class ControlPlaneUnavailable(RuntimeError):  # noqa: N818 - a condition, not a hierarchy
    """The control plane could not answer. ``kind`` is a stable, secret-free reason."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


class KeyNotFound(LookupError):
    """The tenant has no such key (the control plane answered 404)."""


class ControlPlaneBridge:
    def __init__(
        self,
        base_url: str,
        *,
        tenant_id: str,
        token: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self.tenant_id = tenant_id
        self._headers = {"authorization": f"Bearer {token}"}
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def _call(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> httpx.Response:
        try:
            return await self._client.request(
                method, self._base + path, headers=self._headers, json=body
            )
        except httpx.HTTPError as exc:
            raise ControlPlaneUnavailable(f"transport:{type(exc).__name__}") from None

    async def reveal_model_key(self, tenant_id: str, provider: str, label: str) -> str:
        if tenant_id != self.tenant_id:
            raise KeyNotFound(f"{provider}/{label}")  # never ask on behalf of another tenant
        resp = await self._call(
            "POST", "/internal/v1/model-keys/reveal", {"provider": provider, "label": label}
        )
        if resp.status_code == 404:
            raise KeyNotFound(f"{provider}/{label}")
        if resp.status_code != 200:
            raise ControlPlaneUnavailable(f"http_{resp.status_code}")
        try:
            value = resp.json()["value"]
        except (ValueError, KeyError, TypeError):
            raise ControlPlaneUnavailable("malformed_response") from None
        if not isinstance(value, str) or not value:
            raise ControlPlaneUnavailable("malformed_response")
        return value

    async def budget_config(self) -> dict[str, Any]:
        resp = await self._call("GET", "/internal/v1/budget-config")
        if resp.status_code != 200:
            raise ControlPlaneUnavailable(f"http_{resp.status_code}")
        try:
            doc = resp.json()
        except ValueError:
            raise ControlPlaneUnavailable("malformed_response") from None
        if not isinstance(doc, dict):
            raise ControlPlaneUnavailable("malformed_response")
        return doc

    async def aclose(self) -> None:
        await self._client.aclose()
