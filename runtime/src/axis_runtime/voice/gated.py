"""STT / TTS providers that go through the ActionExecutor (production wiring).

Each ``open`` / ``synthesize`` is a gated action (``SttOpen`` / ``TtsSynthesize``) performed by the
executor, which is what lets ``ModelGateway.open_stt`` / ``synthesize`` run.  A DENY (or a pending
approval: a live call cannot wait for a human) becomes ``SpeechDeniedError``; a failure becomes
``SpeechUnavailableError``.  Nothing here touches a vendor directly.
"""

from __future__ import annotations

from axis_runtime.actions import SttOpen, TtsSynthesize
from axis_runtime.executor import ActionRunner, Completed, Denied, Failed, PendingApproval
from axis_runtime.voice.errors import SpeechDeniedError, SpeechUnavailableError
from axis_runtime.voice.interfaces import SttStream, TtsStream
from axis_runtime.voice.types import SttConfig, TtsConfig


def _unwrap(outcome: object) -> object:
    if isinstance(outcome, Completed):
        return outcome.result
    if isinstance(outcome, Denied):
        raise SpeechDeniedError(outcome.reason)
    if isinstance(outcome, PendingApproval):
        raise SpeechDeniedError("approval_pending")
    if isinstance(outcome, Failed):
        raise SpeechUnavailableError(outcome.error[:200])
    raise SpeechUnavailableError("unexpected outcome")


class GatedSttProvider:
    def __init__(
        self,
        runner: ActionRunner,
        pid: str,
        *,
        tenant_id: str,
        provider: str,
        model: str,
        key_label: str = "default",
        endpoint: str | None = None,
        consent_established: bool = False,
    ) -> None:
        self._runner, self._pid = runner, pid
        self._kw = {
            "tenant_id": tenant_id,
            "provider": provider,
            "model": model,
            "key_label": key_label,
            "endpoint": endpoint,
            "consent_established": consent_established,
        }

    async def start(self, config: SttConfig) -> SttStream:
        action = SttOpen(
            language=config.language,
            sample_rate=config.sample_rate,
            encoding=config.encoding,
            **self._kw,  # type: ignore[arg-type]
        )
        result = _unwrap(await self._runner.run(action, pid=self._pid))
        return result  # type: ignore[return-value]


class GatedTtsProvider:
    def __init__(
        self,
        runner: ActionRunner,
        pid: str,
        *,
        tenant_id: str,
        provider: str,
        model: str,
        key_label: str = "default",
        endpoint: str | None = None,
    ) -> None:
        self._runner, self._pid = runner, pid
        self._kw = {
            "tenant_id": tenant_id,
            "provider": provider,
            "model": model,
            "key_label": key_label,
            "endpoint": endpoint,
        }

    async def synthesize(self, text: str, config: TtsConfig) -> TtsStream:
        action = TtsSynthesize(
            text=text,
            voice=config.voice,
            language=config.language,
            sample_rate=config.sample_rate,
            encoding=config.encoding,
            **self._kw,  # type: ignore[arg-type]
        )
        result = _unwrap(await self._runner.run(action, pid=self._pid))
        return result  # type: ignore[return-value]
