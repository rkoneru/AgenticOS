"""Provider adapters. This package (with ``axis_runtime.tools``) is the ONLY place allowed to
import httpx: the bypass guard enforces it."""

from axis_runtime.models.adapters.anthropic import AnthropicAdapter
from axis_runtime.models.adapters.base import (
    Adapter,
    HttpCall,
    HttpResponse,
    HttpxTransport,
    ParsedResponse,
    Transport,
)
from axis_runtime.models.adapters.bedrock import BedrockAdapter
from axis_runtime.models.adapters.google import GoogleAdapter
from axis_runtime.models.adapters.openai import (
    AzureOpenAIAdapter,
    OpenAIAdapter,
    OpenAICompatibleAdapter,
)


def default_adapters() -> dict[str, Adapter]:
    adapters: list[Adapter] = [
        AnthropicAdapter(),
        OpenAIAdapter(),
        GoogleAdapter(),
        AzureOpenAIAdapter(),
        BedrockAdapter(),
        OpenAICompatibleAdapter(),
    ]
    return {a.provider: a for a in adapters}


def default_transport() -> Transport:
    return HttpxTransport()


__all__ = [
    "Adapter",
    "AnthropicAdapter",
    "AzureOpenAIAdapter",
    "BedrockAdapter",
    "GoogleAdapter",
    "HttpCall",
    "HttpResponse",
    "HttpxTransport",
    "OpenAIAdapter",
    "OpenAICompatibleAdapter",
    "ParsedResponse",
    "Transport",
    "default_adapters",
    "default_transport",
]
