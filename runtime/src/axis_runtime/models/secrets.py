"""BYO provider keys (per tenant).

``SecretStore`` implementations:
  * ``InMemorySecretStore``  - tests.
  * ``FileSecretStore``      - DEV ONLY: a single Fernet-encrypted JSON file.  The Fernet key
                               comes from the caller (e.g. an env var); it is not KMS.
  * ``KmsSecretStore``       - the production interface; NOT BUILT (raises), see docs/NEEDS.md.

Secrets are wrapped in ``Secret`` whose ``repr``/``str`` never reveal the value, so accidental
logging or exception formatting cannot leak a key.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol

from cryptography.fernet import Fernet, InvalidToken

PLATFORM_TENANT = "_platform"


class SecretNotFoundError(LookupError):
    pass


class SecretStoreError(RuntimeError):
    pass


class Secret:
    """Opaque credential holder. Use ``reveal()`` only at the point of building a request."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(***)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)

    def __reduce__(self) -> tuple[type[Secret], tuple[str]]:
        raise TypeError("Secret cannot be pickled")


def scrub(text: str, *secrets: Secret | None) -> str:
    """Remove every occurrence of the given secrets from ``text``."""
    for secret in secrets:
        if secret is not None and secret.reveal():
            text = text.replace(secret.reveal(), "***")
    return text


class SecretStore(Protocol):
    async def get(self, tenant_id: str, provider: str, label: str = "default") -> Secret:
        """Return the tenant's secret or raise SecretNotFoundError."""

    async def put(self, tenant_id: str, provider: str, label: str, value: str) -> None: ...


def _key(tenant_id: str, provider: str, label: str) -> str:
    return json.dumps([tenant_id, provider, label])


class InMemorySecretStore:
    def __init__(self, initial: Mapping[tuple[str, str, str], str] | None = None) -> None:
        self._data = {_key(*k): v for k, v in (initial or {}).items()}

    async def get(self, tenant_id: str, provider: str, label: str = "default") -> Secret:
        try:
            return Secret(self._data[_key(tenant_id, provider, label)])
        except KeyError:
            raise SecretNotFoundError(f"{provider}/{label}") from None

    async def put(self, tenant_id: str, provider: str, label: str, value: str) -> None:
        self._data[_key(tenant_id, provider, label)] = value


class FileSecretStore:
    """DEV ONLY. Whole-file Fernet encryption; not suitable for production (see KmsSecretStore)."""

    def __init__(self, path: Path, fernet_key: bytes) -> None:
        self._path = path
        self._fernet = Fernet(fernet_key)

    @staticmethod
    def generate_key() -> bytes:
        return Fernet.generate_key()

    def _load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        try:
            raw = self._fernet.decrypt(self._path.read_bytes())
            data = json.loads(raw)
        except (InvalidToken, ValueError) as exc:
            raise SecretStoreError(
                "secret file cannot be decrypted (wrong key or corrupt)"
            ) from exc
        return {str(k): str(v) for k, v in data.items()}

    async def get(self, tenant_id: str, provider: str, label: str = "default") -> Secret:
        try:
            return Secret(self._load()[_key(tenant_id, provider, label)])
        except KeyError:
            raise SecretNotFoundError(f"{provider}/{label}") from None

    async def put(self, tenant_id: str, provider: str, label: str, value: str) -> None:
        data = self._load()
        data[_key(tenant_id, provider, label)] = value
        blob = self._fernet.encrypt(json.dumps(data).encode("utf-8"))
        tmp = self._path.with_name(self._path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        os.replace(tmp, self._path)


class KmsSecretStore:
    """Production interface: envelope-encrypted secrets, data key wrapped by a per-tenant KMS key,
    tenant id bound as KMS encryption context, every read audited.

    NOT BUILT.  Construction works so wiring can be written against the interface; ``get`` and
    ``put`` raise.  Tracked in docs/NEEDS.md.
    """

    def __init__(self, key_id: str) -> None:
        self.key_id = key_id

    async def get(self, tenant_id: str, provider: str, label: str = "default") -> Secret:
        raise NotImplementedError("KmsSecretStore is not built (docs/NEEDS.md)")

    async def put(self, tenant_id: str, provider: str, label: str, value: str) -> None:
        raise NotImplementedError("KmsSecretStore is not built (docs/NEEDS.md)")
