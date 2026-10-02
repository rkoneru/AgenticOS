"""``HttpSecretStore``: the tenant's BYO provider keys, read from the control plane (DEV bridge).

Implements the ``SecretStore`` protocol of ``secrets.py`` over ``ControlPlaneBridge``: ``get``
returns an
opaque ``Secret`` (never logged: ``repr``/``str`` are masked). The control plane owns the keys
(envelope
encrypted, audited, RBAC-gated admin API); the runtime only reads. ``put`` is refused: a key is set
through
the admin API, never by the runtime. A key the control plane does not have is
``SecretNotFoundError``; any
other failure is ``SecretStoreError`` (fail closed: the model call does not happen without a key).

Plaintext crosses loopback in the dev bridge (docs/NEEDS.md #186); production reads through KMS."""

from __future__ import annotations

from axis_runtime.controlplane import ControlPlaneBridge, ControlPlaneUnavailable, KeyNotFound
from axis_runtime.models.secrets import Secret, SecretNotFoundError, SecretStoreError


class HttpSecretStore:
    def __init__(self, bridge: ControlPlaneBridge) -> None:
        self._bridge = bridge

    async def get(self, tenant_id: str, provider: str, label: str = "default") -> Secret:
        try:
            return Secret(await self._bridge.reveal_model_key(tenant_id, provider, label))
        except KeyNotFound:
            raise SecretNotFoundError(f"{provider}/{label}") from None
        except ControlPlaneUnavailable as exc:
            raise SecretStoreError(f"control plane unavailable: {exc.kind}") from None

    async def put(self, tenant_id: str, provider: str, label: str, value: str) -> None:
        raise SecretStoreError("keys are managed through the control plane admin API")
