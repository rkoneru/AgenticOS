"""Each adapter speaks its provider's real wire format (fixtures written from the provider docs)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import httpx
import pytest
from axis_runtime.models import CacheHints, FinishReason, Message, ModelError
from axis_runtime.models.adapters.sigv4 import sign_request, signing_key
from axis_runtime.models.types import ErrorKind
from conftest import FakeClock
from mhelpers import (
    bedrock_event,
    collect,
    event_frame,
    find,
    free,
    gateway_for,
    json_response,
    request,
    sse,
    store,
    stream_response,
    tool_round_trip_messages,
)

SEEN: list[httpx.Request] = []


def capture(resp: httpx.Response | Any) -> Any:
    def handler(req: httpx.Request) -> httpx.Response:
        SEEN.clear()
        SEEN.append(req)
        return resp() if callable(resp) else resp  # type: ignore[no-any-return]

    return handler


def body() -> dict[str, Any]:
    return json.loads(SEEN[-1].content)  # type: ignore[no-any-return]


# =============================================================================================
# Anthropic Messages API
# =============================================================================================

ANTHROPIC_TEXT = {
    "id": "msg_01",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-4-20250514",
    "content": [{"type": "text", "text": "Hi there."}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {
        "input_tokens": 100,
        "cache_creation_input_tokens": 200,
        "cache_read_input_tokens": 300,
        "output_tokens": 50,
    },
}
ANTHROPIC_TOOL = {
    **ANTHROPIC_TEXT,
    "content": [
        {"type": "text", "text": "Let me check."},
        {"type": "tool_use", "id": "toolu_01", "name": "get_weather", "input": {"city": "Paris"}},
    ],
    "stop_reason": "tool_use",
}


async def test_anthropic_request_shape_and_response_mapping() -> None:
    gw, clock = gateway_for(capture(json_response(ANTHROPIC_TEXT)))
    req = request(
        "anthropic",
        "claude-sonnet-4-20250514",
        params={"temperature": 0.2, "stop": ["END"], "top_p": 0.9},
    )
    resp = await free(gw).complete(req)
    r = SEEN[0]
    assert r.method == "POST" and str(r.url) == "https://api.anthropic.com/v1/messages"
    assert r.headers["x-api-key"] == "sk-ant-SECRET-111"
    assert (
        r.headers["anthropic-version"] == "2023-06-01"
        and r.headers["content-type"] == "application/json"
    )
    assert "authorization" not in r.headers
    assert body() == {
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 4096,
        "system": "Be brief.",
        "messages": [{"role": "user", "content": "Hello"}],
        "temperature": 0.2,
        "top_p": 0.9,
        "stop_sequences": ["END"],
    }
    assert resp.text == "Hi there." and resp.finish_reason is FinishReason.STOP
    assert resp.provider == "anthropic" and resp.model == "claude-sonnet-4-20250514"
    # usage: input_tokens is the TOTAL prompt (uncached + cache read + cache write)
    assert (
        resp.usage.input_tokens,
        resp.usage.cached_tokens,
        resp.usage.cache_write_tokens,
        resp.usage.output_tokens,
    ) == (600, 300, 200, 50)
    # 100*3 + 300*0.30 + 200*3.75 + 50*15 = 300 + 90 + 750 + 750 = 1890 per 1M
    assert resp.cost_usd == Decimal("0.001890")
    assert resp.attempts[-1].outcome == "ok" and resp.latency_ms == 0


async def test_anthropic_max_tokens_param_and_custom_endpoint() -> None:
    gw, _ = gateway_for(capture(json_response(ANTHROPIC_TEXT)))
    await free(gw).complete(
        request("anthropic", endpoint="https://proxy.corp/", params={"max_tokens": 77})
    )
    assert str(SEEN[0].url) == "https://proxy.corp/v1/messages" and body()["max_tokens"] == 77


async def test_anthropic_tool_calling_round_trip() -> None:
    gw, _ = gateway_for(capture(json_response(ANTHROPIC_TOOL)))
    resp = await free(gw).complete(request("anthropic", tools=True))
    assert body()["tools"] == [
        {
            "name": "get_weather",
            "description": "Get weather",
            "input_schema": {"type": "object", "properties": {"city": {"type": "string"}}},
        }
    ]
    assert resp.finish_reason is FinishReason.TOOL_CALLS and resp.text == "Let me check."
    assert [(c.id, c.name, dict(c.arguments)) for c in resp.tool_calls] == [
        ("toolu_01", "get_weather", {"city": "Paris"})
    ]

    await free(gw).complete(request("anthropic", tools=True, messages=tool_round_trip_messages()))
    assert body()["messages"] == [
        {"role": "user", "content": "weather in Paris and Rome?"},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Checking."},
                {"type": "tool_use", "id": "c1", "name": "get_weather", "input": {"city": "Paris"}},
                {"type": "tool_use", "id": "c2", "name": "get_weather", "input": {"city": "Rome"}},
            ],
        },
        {
            "role": "user",
            "content": [  # both results in ONE user turn, as the API requires
                {"type": "tool_result", "tool_use_id": "c1", "content": '{"temp": 21}'},
                {"type": "tool_result", "tool_use_id": "c2", "content": "boom", "is_error": True},
            ],
        },
    ]


async def test_anthropic_assistant_tool_call_without_text() -> None:
    gw, _ = gateway_for(capture(json_response(ANTHROPIC_TEXT)))
    msgs = (Message("user", "x"), Message("assistant", "", (), None), Message("user", "y"))
    from axis_runtime.models import ToolCallRequest

    msgs = (
        Message("user", "x"),
        Message("assistant", "", (ToolCallRequest("t", "f", {}),)),
        Message("tool", "r", tool_call_id="t"),
        Message("user", "y"),
    )
    await free(gw).complete(request("anthropic", messages=msgs))
    assert body()["messages"][1]["content"] == [
        {"type": "tool_use", "id": "t", "name": "f", "input": {}}
    ]
    assert body()["messages"][2]["content"][0]["type"] == "tool_result"
    assert body()["messages"][3] == {
        "role": "user",
        "content": "y",
    }  # plain user text is not merged into results


async def test_anthropic_prompt_caching_hints() -> None:
    gw, _ = gateway_for(capture(json_response(ANTHROPIC_TEXT)))
    await free(gw).complete(
        request(
            "anthropic",
            tools=True,
            cache=CacheHints(system=True, tools=True),
            messages=(Message("system", "A"), Message("system", "B"), Message("user", "q")),
        )
    )
    assert body()["system"] == [
        {"type": "text", "text": "A"},
        {"type": "text", "text": "B", "cache_control": {"type": "ephemeral"}},
    ]
    assert body()["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    await free(gw).complete(
        request("anthropic", tools=True)
    )  # no hint -> no cache_control anywhere
    assert "cache_control" not in json.dumps(body())


async def test_anthropic_structured_output_uses_a_forced_tool() -> None:
    schema = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "required": ["verdict"],
    }
    reply = {
        **ANTHROPIC_TEXT,
        "content": [
            {
                "type": "tool_use",
                "id": "t1",
                "name": "structured_output",
                "input": {"verdict": "approve"},
            }
        ],
        "stop_reason": "tool_use",
    }
    gw, _ = gateway_for(capture(json_response(reply)))
    resp = await free(gw).complete(request("anthropic", response_schema=schema))
    assert body()["tools"] == [
        {
            "name": "structured_output",
            "description": "Return the final answer as structured output.",
            "input_schema": schema,
        }
    ]
    assert body()["tool_choice"] == {"type": "tool", "name": "structured_output"}
    assert json.loads(resp.text) == {"verdict": "approve"} and resp.tool_calls == ()
    assert resp.finish_reason is FinishReason.STOP
    await free(gw).complete(request("anthropic", response_schema=schema, tools=True))
    assert body()["tool_choice"] == {"type": "any"}


@pytest.mark.parametrize(
    ("stop", "expected"),
    [
        ("max_tokens", FinishReason.LENGTH),
        ("refusal", FinishReason.CONTENT_FILTER),
        ("weird", FinishReason.OTHER),
        ("stop_sequence", FinishReason.STOP),
    ],
)
async def test_anthropic_finish_reason_mapping(stop: str, expected: FinishReason) -> None:
    gw, _ = gateway_for(capture(json_response({**ANTHROPIC_TEXT, "stop_reason": stop})))
    assert (await free(gw).complete(request("anthropic"))).finish_reason is expected


ANTHROPIC_SSE = sse(
    (
        "message_start",
        {
            "type": "message_start",
            "message": {
                "id": "msg_1",
                "model": "claude-sonnet-4-20250514",
                "usage": {"input_tokens": 25, "cache_read_input_tokens": 5, "output_tokens": 1},
            },
        },
    ),
    (
        "content_block_start",
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
    ),
    ("ping", {"type": "ping"}),
    (
        "content_block_delta",
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hel"}},
    ),
    (
        "content_block_delta",
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "lo"}},
    ),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    (
        "content_block_start",
        {
            "type": "content_block_start",
            "index": 1,
            "content_block": {
                "type": "tool_use",
                "id": "toolu_9",
                "name": "get_weather",
                "input": {},
            },
        },
    ),
    (
        "content_block_delta",
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": '{"city":'},
        },
    ),
    (
        "content_block_delta",
        {
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "input_json_delta", "partial_json": ' "Oslo"}'},
        },
    ),
    ("content_block_stop", {"type": "content_block_stop", "index": 1}),
    (
        "message_delta",
        {
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use"},
            "usage": {"output_tokens": 42},
        },
    ),
    ("message_stop", {"type": "message_stop"}),
)


@pytest.mark.parametrize("chunk", [1, 7, 64, 100_000])
async def test_anthropic_streaming_sse(chunk: int) -> None:
    gw, _ = gateway_for(capture(stream_response(ANTHROPIC_SSE, chunk)))
    events = await collect(free(gw).stream(request("anthropic", tools=True)))
    assert body()["stream"] is True
    assert "".join(e.text for e in find(events, "text")) == "Hello"
    assert [e.arguments_delta for e in find(events, "tool_call_delta")] == [
        "",
        '{"city":',
        ' "Oslo"}',
    ]
    done = events[-1].response
    assert events[-1].kind == "done" and done.text == "Hello"
    assert [(c.id, c.name, dict(c.arguments)) for c in done.tool_calls] == [
        ("toolu_9", "get_weather", {"city": "Oslo"})
    ]
    assert done.finish_reason is FinishReason.TOOL_CALLS
    assert (done.usage.input_tokens, done.usage.cached_tokens, done.usage.output_tokens) == (
        30,
        5,
        42,
    )
    assert done.cost_usd is not None and done.model == "claude-sonnet-4-20250514"


async def test_anthropic_streaming_structured_output_and_errors() -> None:
    s = sse(
        (
            "message_start",
            {"type": "message_start", "message": {"model": "m", "usage": {"input_tokens": 1}}},
        ),
        (
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": "t", "name": "structured_output"},
            },
        ),
        (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": '{"a": 1}'},
            },
        ),
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": "tool_use"},
                "usage": {"output_tokens": 2},
            },
        ),
    )
    gw, _ = gateway_for(capture(stream_response(s)))
    done = (
        await collect(free(gw).stream(request("anthropic", response_schema={"type": "object"})))
    )[-1].response
    assert json.loads(done.text) == {"a": 1} and done.tool_calls == ()

    err = sse(
        ("error", {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}})
    )
    gw, _ = gateway_for(capture(stream_response(err)))
    with pytest.raises(ModelError) as exc:
        await collect(free(gw).stream(request("anthropic")))
    assert (
        exc.value.kind is ErrorKind.SERVER
        and "overloaded_error" in str(exc.value)
        and "busy" not in str(exc.value)
    )
    err = sse(("error", {"type": "error", "error": {"type": "rate_limit_error"}}))
    gw, _ = gateway_for(
        capture(stream_response(err)),
        retry=__import__("axis_runtime.models", fromlist=["RetryPolicy"]).RetryPolicy(
            max_attempts=1
        ),
    )
    with pytest.raises(ModelError) as exc:
        await collect(free(gw).stream(request("anthropic")))
    assert exc.value.kind is ErrorKind.RATE_LIMIT


# =============================================================================================
# OpenAI chat completions (+ compatible + Azure)
# =============================================================================================

OPENAI_TEXT = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "model": "gpt-4o-2024-08-06",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "Hi!"}, "finish_reason": "stop"}
    ],
    "usage": {
        "prompt_tokens": 1000,
        "completion_tokens": 200,
        "total_tokens": 1200,
        "prompt_tokens_details": {"cached_tokens": 400},
    },
}
OPENAI_TOOL = {
    **OPENAI_TEXT,
    "choices": [
        {
            "index": 0,
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_a",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": '{"city": "Paris"}'},
                    },
                    {
                        "id": "call_b",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{not json"},
                    },
                ],
            },
        }
    ],
}


async def test_openai_request_shape_and_response_mapping() -> None:
    gw, _ = gateway_for(capture(json_response(OPENAI_TEXT)))
    schema = {"type": "object", "properties": {"a": {"type": "string"}}}
    req = request(
        "openai",
        "gpt-4o",
        tools=True,
        response_schema=schema,
        params={"temperature": 0, "max_tokens": 50, "seed": 7, "stop": ["x"], "top_p": 1},
    )
    resp = await free(gw).complete(req)
    r = SEEN[0]
    assert str(r.url) == "https://api.openai.com/v1/chat/completions"
    assert (
        r.headers["authorization"] == "Bearer sk-openai-SECRET-222" and "api-key" not in r.headers
    )
    assert body() == {
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "Hello"},
        ],
        "max_completion_tokens": 50,
        "temperature": 0,
        "seed": 7,
        "stop": ["x"],
        "top_p": 1,
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get weather",
                    "parameters": {"type": "object", "properties": {"city": {"type": "string"}}},
                },
            }
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "response", "schema": schema, "strict": True},
        },
    }
    assert resp.text == "Hi!" and resp.model == "gpt-4o-2024-08-06"
    assert (resp.usage.input_tokens, resp.usage.cached_tokens, resp.usage.output_tokens) == (
        1000,
        400,
        200,
    )
    # 600*2.5 + 400*1.25 + 200*10 = 1500 + 500 + 2000 = 4000 per 1M
    assert resp.cost_usd == Decimal("0.004000")


async def test_openai_tool_calls_and_message_conversion() -> None:
    gw, _ = gateway_for(capture(json_response(OPENAI_TOOL)))
    resp = await free(gw).complete(request("openai", tools=True))
    assert resp.finish_reason is FinishReason.TOOL_CALLS and resp.text == ""
    assert dict(resp.tool_calls[0].arguments) == {"city": "Paris"}
    assert dict(resp.tool_calls[1].arguments) == {
        "_invalid_json": "{not json"
    }  # never raises on bad model JSON
    await free(gw).complete(request("openai", messages=tool_round_trip_messages()))
    msgs = body()["messages"]
    assert msgs[1] == {
        "role": "assistant",
        "content": "Checking.",
        "tool_calls": [
            {
                "id": "c1",
                "type": "function",
                "function": {"name": "get_weather", "arguments": '{"city": "Paris"}'},
            },
            {
                "id": "c2",
                "type": "function",
                "function": {"name": "get_weather", "arguments": '{"city": "Rome"}'},
            },
        ],
    }
    assert msgs[2:] == [
        {"role": "tool", "tool_call_id": "c1", "content": '{"temp": 21}'},
        {"role": "tool", "tool_call_id": "c2", "content": "boom"},
    ]


@pytest.mark.parametrize(
    ("finish", "expected"),
    [
        ("length", FinishReason.LENGTH),
        ("content_filter", FinishReason.CONTENT_FILTER),
        ("???", FinishReason.OTHER),
    ],
)
async def test_openai_finish_reasons(finish: str, expected: FinishReason) -> None:
    body_ = {**OPENAI_TEXT, "choices": [{**OPENAI_TEXT["choices"][0], "finish_reason": finish}]}  # type: ignore[index]
    gw, _ = gateway_for(capture(json_response(body_)))
    assert (await free(gw).complete(request("openai"))).finish_reason is expected


OPENAI_SSE = sse(
    (
        None,
        {
            "id": "c",
            "model": "gpt-4o-2024-08-06",
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": ""}}],
        },
    ),
    (None, {"model": "gpt-4o-2024-08-06", "choices": [{"index": 0, "delta": {"content": "Hel"}}]}),
    (None, {"choices": [{"index": 0, "delta": {"content": "lo"}}]}),
    (
        None,
        {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_1",
                                "type": "function",
                                "function": {"name": "get_weather", "arguments": ""},
                            }
                        ]
                    },
                }
            ]
        },
    ),
    (
        None,
        {
            "choices": [
                {
                    "index": 0,
                    "delta": {"tool_calls": [{"index": 0, "function": {"arguments": '{"ci'}}]},
                }
            ]
        },
    ),
    (
        None,
        {
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [{"index": 0, "function": {"arguments": 'ty": "Rome"}'}}]
                    },
                }
            ]
        },
    ),
    (None, {"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
    (
        None,
        {
            "choices": [],
            "usage": {
                "prompt_tokens": 11,
                "completion_tokens": 7,
                "prompt_tokens_details": {"cached_tokens": 2},
            },
        },
    ),
    (None, "[DONE]"),
)


@pytest.mark.parametrize("chunk", [1, 13, 100_000])
async def test_openai_streaming_sse(chunk: int) -> None:
    gw, _ = gateway_for(capture(stream_response(OPENAI_SSE, chunk)))
    events = await collect(free(gw).stream(request("openai", "gpt-4o", tools=True)))
    assert body()["stream"] is True and body()["stream_options"] == {"include_usage": True}
    assert "".join(e.text for e in find(events, "text")) == "Hello"
    done = events[-1].response
    assert [(c.id, c.name, dict(c.arguments)) for c in done.tool_calls] == [
        ("call_1", "get_weather", {"city": "Rome"})
    ]
    assert done.finish_reason is FinishReason.TOOL_CALLS
    assert (done.usage.input_tokens, done.usage.cached_tokens, done.usage.output_tokens) == (
        11,
        2,
        7,
    )


async def test_openai_stream_malformed_event_and_error_payload() -> None:
    gw, _ = gateway_for(
        capture(stream_response(b"data: {not json\n\n")),
        retry=__import__("axis_runtime.models", fromlist=["RetryPolicy"]).RetryPolicy(
            max_attempts=1
        ),
    )
    with pytest.raises(ModelError, match="malformed stream event"):
        await collect(free(gw).stream(request("openai")))
    gw, _ = gateway_for(
        capture(stream_response(sse((None, {"error": {"message": "x"}})))),
        retry=__import__("axis_runtime.models", fromlist=["RetryPolicy"]).RetryPolicy(
            max_attempts=1
        ),
    )
    with pytest.raises(ModelError, match="stream error"):
        await collect(free(gw).stream(request("openai")))


async def test_openai_compatible_custom_endpoint_and_auth() -> None:
    gw, _ = gateway_for(capture(json_response(OPENAI_TEXT)))
    await free(gw).complete(
        request(
            "openai-compatible",
            "llama-3",
            endpoint="https://llm.internal/v1",
            params={"max_tokens": 9},
        )
    )
    assert str(SEEN[0].url) == "https://llm.internal/v1/chat/completions"
    assert SEEN[0].headers["authorization"] == "Bearer compat-SECRET-555"
    assert (
        body()["max_tokens"] == 9
        and "max_completion_tokens" not in body()
        and body()["model"] == "llama-3"
    )
    await free(gw).complete(request("openai-compatible", endpoint="https://llm.internal"))
    assert str(SEEN[0].url) == "https://llm.internal/v1/chat/completions"


async def test_openai_compatible_without_key_sends_no_auth_header() -> None:
    from axis_runtime.models import InMemorySecretStore

    gw, _ = gateway_for(capture(json_response(OPENAI_TEXT)), secrets=InMemorySecretStore())
    resp = await free(gw).complete(request("openai-compatible", endpoint="https://llm.internal/v1"))
    assert (
        "authorization" not in SEEN[0].headers and resp.cost_usd is None
    )  # unknown pricing is never guessed


async def test_endpoint_rules() -> None:
    gw, _ = gateway_for(capture(json_response(OPENAI_TEXT)))
    for provider in ("openai-compatible", "azure-openai"):
        with pytest.raises(ModelError, match="endpoint is required") as exc:
            await free(gw).complete(request(provider))
        assert exc.value.kind is ErrorKind.INVALID_REQUEST
    with pytest.raises(ModelError, match="endpoint must be https"):
        await free(gw).complete(request("openai", endpoint="http://evil.internal"))
    with pytest.raises(ModelError, match="endpoint must be https"):
        await free(gw).complete(request("openai", endpoint="file:///etc/passwd"))
    gw_http, _ = gateway_for(capture(json_response(OPENAI_TEXT)), allow_http_endpoints=True)
    await free(gw_http).complete(request("openai-compatible", endpoint="http://localhost:8000"))
    assert str(SEEN[0].url) == "http://localhost:8000/v1/chat/completions"


async def test_azure_openai_deployment_url_version_and_auth() -> None:
    gw, _ = gateway_for(capture(json_response(OPENAI_TEXT)))
    await free(gw).complete(
        request(
            "azure-openai",
            "my-gpt4o",
            endpoint="https://res.openai.azure.com/",
            tools=True,
            target_params={"max_tokens": 10, "pricing_model": "gpt-4o"},
        )
    )
    r = SEEN[0]
    assert (
        str(r.url)
        == "https://res.openai.azure.com/openai/deployments/my-gpt4o/chat/completions?api-version=2024-10-21"
    )
    assert r.headers["api-key"] == "azure-SECRET-444" and "authorization" not in r.headers
    assert "model" not in body() and body()["max_completion_tokens"] == 10
    await free(gw).complete(
        request(
            "azure-openai",
            "dep/with space",
            endpoint="https://res.openai.azure.com",
            target_params={"api_version": "2025-01-01-preview"},
        )
    )
    assert str(SEEN[0].url).endswith(
        "/deployments/dep%2Fwith%20space/chat/completions?api-version=2025-01-01-preview"
    )


async def test_azure_cost_uses_openai_family_prices_via_pricing_model() -> None:
    gw, _ = gateway_for(capture(json_response(OPENAI_TEXT)))
    priced = await free(gw).complete(
        request(
            "azure-openai",
            "prod-deployment",
            endpoint="https://r.openai.azure.com",
            target_params={"pricing_model": "gpt-4o"},
        )
    )
    assert priced.cost_usd == Decimal("0.004000")
    # the provider reports the underlying model, which is what gets priced when no hint is given
    assert (
        await free(gw).complete(
            request("azure-openai", "prod-deployment", endpoint="https://r.openai.azure.com")
        )
    ).cost_usd == Decimal("0.004000")
    gw2, _ = gateway_for(capture(json_response({**OPENAI_TEXT, "model": "my-finetune"})))
    unpriced = await free(gw2).complete(
        request("azure-openai", "prod-deployment", endpoint="https://r.openai.azure.com")
    )
    assert unpriced.cost_usd is None  # unknown model: never guessed


# =============================================================================================
# Google Gemini
# =============================================================================================

GEMINI_TEXT = {
    "candidates": [
        {
            "content": {"role": "model", "parts": [{"text": "Bonjour"}]},
            "finishReason": "STOP",
            "index": 0,
        }
    ],
    "usageMetadata": {
        "promptTokenCount": 40,
        "candidatesTokenCount": 10,
        "thoughtsTokenCount": 5,
        "cachedContentTokenCount": 8,
        "totalTokenCount": 55,
    },
    "modelVersion": "gemini-2.0-flash-001",
}
GEMINI_TOOL = {
    "candidates": [
        {
            "content": {
                "role": "model",
                "parts": [
                    {"text": "thinking...", "thought": True},
                    {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}},
                    {"functionCall": {"name": "get_weather", "args": {"city": "Rome"}}},
                ],
            },
            "finishReason": "STOP",
        }
    ],
    "usageMetadata": {"promptTokenCount": 3, "candidatesTokenCount": 1},
}


async def test_gemini_request_shape_and_response_mapping() -> None:
    gw, _ = gateway_for(capture(json_response(GEMINI_TEXT)))
    schema = {"type": "object", "properties": {"a": {"type": "string"}}}
    req = request(
        "google",
        "gemini-2.0-flash",
        tools=True,
        response_schema=schema,
        params={"temperature": 0.3, "max_tokens": 99, "top_p": 0.8, "seed": 1, "stop": ["Z"]},
    )
    resp = await free(gw).complete(req)
    r = SEEN[0]
    assert r.url.path == "/v1beta/models/gemini-2.0-flash:generateContent"
    assert (
        str(r.url)
        == "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"
    )
    assert r.headers["x-goog-api-key"] == "AIza-SECRET-333"
    assert (
        "AIza-SECRET-333" not in str(r.url) and not r.url.query
    )  # the key never travels in the URL
    assert body() == {
        "contents": [{"role": "user", "parts": [{"text": "Hello"}]}],
        "systemInstruction": {"parts": [{"text": "Be brief."}]},
        "generationConfig": {
            "temperature": 0.3,
            "topP": 0.8,
            "maxOutputTokens": 99,
            "seed": 1,
            "stopSequences": ["Z"],
            "responseMimeType": "application/json",
            "responseSchema": schema,
        },
        "tools": [
            {
                "functionDeclarations": [
                    {
                        "name": "get_weather",
                        "description": "Get weather",
                        "parameters": {
                            "type": "object",
                            "properties": {"city": {"type": "string"}},
                        },
                    }
                ]
            }
        ],
    }
    assert (
        resp.text == "Bonjour"
        and resp.finish_reason is FinishReason.STOP
        and resp.model == "gemini-2.0-flash-001"
    )
    assert (resp.usage.input_tokens, resp.usage.output_tokens, resp.usage.cached_tokens) == (
        40,
        15,
        8,
    )
    # 32*0.10 + 8*0.10 (no cache discount configured) + 15*0.40 = 3.2 + 0.8 + 6.0 = 10 per 1M
    assert resp.cost_usd == Decimal("0.000010")


async def test_gemini_function_calls_and_tool_results() -> None:
    gw, _ = gateway_for(capture(json_response(GEMINI_TOOL)))
    resp = await free(gw).complete(request("google", "gemini-2.0-flash", tools=True))
    assert (
        resp.finish_reason is FinishReason.TOOL_CALLS and resp.text == ""
    )  # thought parts are not output
    assert [(c.id, c.name, dict(c.arguments)) for c in resp.tool_calls] == [
        ("call_0", "get_weather", {"city": "Paris"}),
        ("call_1", "get_weather", {"city": "Rome"}),
    ]
    await free(gw).complete(
        request("google", "gemini-2.0-flash", messages=tool_round_trip_messages())
    )
    contents = body()["contents"]
    assert contents[1] == {
        "role": "model",
        "parts": [
            {"text": "Checking."},
            {"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}},
            {"functionCall": {"name": "get_weather", "args": {"city": "Rome"}}},
        ],
    }
    assert contents[2] == {
        "role": "user",
        "parts": [  # results merged into one turn, errors marked
            {"functionResponse": {"name": "get_weather", "response": {"temp": 21}}},
            {"functionResponse": {"name": "get_weather", "response": {"error": "boom"}}},
        ],
    }
    msgs = (
        Message("tool", "plain text", name="f", tool_call_id="x"),
        Message("tool", "[1]", name="f"),
    )
    await free(gw).complete(request("google", "gemini-2.0-flash", messages=msgs))
    parts = body()["contents"][0]["parts"]
    assert parts[0]["functionResponse"]["response"] == {"result": "plain text"}
    assert parts[1]["functionResponse"]["response"] == {"result": [1]}


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("MAX_TOKENS", FinishReason.LENGTH),
        ("SAFETY", FinishReason.CONTENT_FILTER),
        ("OTHER", FinishReason.OTHER),
    ],
)
async def test_gemini_finish_reasons(reason: str, expected: FinishReason) -> None:
    payload = {
        **GEMINI_TEXT,
        "candidates": [{**GEMINI_TEXT["candidates"][0], "finishReason": reason}],
    }  # type: ignore[index]
    gw, _ = gateway_for(capture(json_response(payload)))
    assert (
        await free(gw).complete(request("google", "gemini-2.0-flash"))
    ).finish_reason is expected


async def test_gemini_prompt_blocked_and_empty_responses() -> None:
    gw, _ = gateway_for(
        capture(
            json_response(
                {
                    "promptFeedback": {"blockReason": "SAFETY"},
                    "usageMetadata": {"promptTokenCount": 4},
                }
            )
        )
    )
    resp = await free(gw).complete(request("google", "gemini-2.0-flash"))
    assert resp.finish_reason is FinishReason.CONTENT_FILTER and resp.text == ""
    gw, _ = gateway_for(
        capture(json_response({})),
        retry=__import__("axis_runtime.models", fromlist=["RetryPolicy"]).RetryPolicy(
            max_attempts=1
        ),
    )
    with pytest.raises(ModelError, match="no candidates"):
        await free(gw).complete(request("google", "gemini-2.0-flash"))


GEMINI_SSE = sse(
    (
        None,
        {
            "candidates": [{"content": {"role": "model", "parts": [{"text": "Bon"}]}}],
            "modelVersion": "g-1",
        },
    ),
    (None, {"candidates": [{"content": {"role": "model", "parts": [{"text": "jour"}]}}]}),
    (
        None,
        {
            "candidates": [
                {
                    "content": {
                        "role": "model",
                        "parts": [
                            {"functionCall": {"name": "get_weather", "args": {"city": "Nice"}}}
                        ],
                    },
                    "finishReason": "STOP",
                }
            ],
            "usageMetadata": {"promptTokenCount": 9, "candidatesTokenCount": 4},
        },
    ),
)


@pytest.mark.parametrize("chunk", [1, 11, 100_000])
async def test_gemini_streaming_sse(chunk: int) -> None:
    gw, _ = gateway_for(capture(stream_response(GEMINI_SSE, chunk)))
    events = await collect(free(gw).stream(request("google", "gemini-2.0-flash", tools=True)))
    assert SEEN[0].url.path.endswith(":streamGenerateContent") and SEEN[0].url.query == b"alt=sse"
    assert "".join(e.text for e in find(events, "text")) == "Bonjour"
    done = events[-1].response
    assert [(c.id, c.name, dict(c.arguments)) for c in done.tool_calls] == [
        ("call_0", "get_weather", {"city": "Nice"})
    ]
    assert done.finish_reason is FinishReason.TOOL_CALLS and (
        done.usage.input_tokens,
        done.usage.output_tokens,
    ) == (9, 4)


# =============================================================================================
# AWS SigV4 + Bedrock Converse
# =============================================================================================


def test_sigv4_matches_the_aws_published_get_vanilla_vector() -> None:
    """AWS SigV4 test suite 'get-vanilla' (service 'service', us-east-1, 20150830T123600Z)."""
    signed = sign_request(
        method="GET",
        url="https://example.amazonaws.com/",
        headers={},
        body=b"",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="service",
        now=datetime(2015, 8, 30, 12, 36, 0, tzinfo=UTC),
    )
    assert signed["authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    )


def test_sigv4_signing_key_matches_the_aws_documented_derivation() -> None:
    """Key-derivation example from the AWS SigV4 documentation (iam, 20150830)."""
    key = signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
    assert key.hex() == "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"


def test_sigv4_query_ordering_token_and_double_encoding() -> None:
    now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    common: dict[str, Any] = dict(
        method="post",
        headers={"Content-Type": "application/json"},
        body=b"{}",
        access_key="AK",
        secret_key="SK",
        region="r",
        service="bedrock",
        now=now,
    )
    a = sign_request(url="https://h.example/model/a%3Ab/converse?b=2&a=1&c=", **common)
    b = sign_request(url="https://h.example/model/a%3Ab/converse?c=&a=1&b=2", **common)
    assert a["authorization"] == b["authorization"]  # canonical query is sorted
    assert a["x-amz-date"] == "20260102T030405Z" and "x-amz-security-token" not in a
    c = sign_request(url="https://h.example/model/a%3Ab/converse", session_token="TOKEN", **common)
    assert c["x-amz-security-token"] == "TOKEN" and "x-amz-security-token" in c["authorization"]
    assert "content-type;host;x-amz-date" in a["authorization"]
    # a different path must give a different signature (the path is part of the signed request)
    d = sign_request(url="https://h.example/model/other/converse", **common)
    assert d["authorization"] != a["authorization"]
    # empty path canonicalises to "/"
    assert sign_request(url="https://h.example", **common)["authorization"]


BEDROCK_TEXT = {
    "output": {"message": {"role": "assistant", "content": [{"text": "Ciao"}]}},
    "stopReason": "end_turn",
    "usage": {
        "inputTokens": 100,
        "outputTokens": 20,
        "totalTokens": 120,
        "cacheReadInputTokens": 50,
        "cacheWriteInputTokens": 10,
    },
    "metrics": {"latencyMs": 321},
}
BEDROCK_TOOL = {
    "output": {
        "message": {
            "role": "assistant",
            "content": [
                {"text": "ok"},
                {
                    "toolUse": {
                        "toolUseId": "tu_1",
                        "name": "get_weather",
                        "input": {"city": "Rome"},
                    }
                },
            ],
        }
    },
    "stopReason": "tool_use",
    "usage": {"inputTokens": 1, "outputTokens": 1},
}
MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"


async def test_bedrock_converse_request_signing_and_mapping() -> None:
    clock = FakeClock()
    gw, _ = gateway_for(capture(json_response(BEDROCK_TEXT)), clock=clock)
    req = request(
        "bedrock",
        MODEL_ID,
        tools=True,
        cache=CacheHints(system=True, tools=True),
        params={"max_tokens": 64, "temperature": 0.1, "top_p": 0.5, "stop": ["S"]},
    )
    resp = await free(gw).complete(req)
    r = SEEN[0]
    assert (
        str(r.url)
        == "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse"
    )
    amz_date = r.headers["x-amz-date"]
    assert amz_date == "20260101T000000Z"
    auth = r.headers["authorization"]
    assert auth.startswith(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/us-east-1/bedrock/aws4_request, "
    )
    assert "SignedHeaders=content-type;host;x-amz-date, Signature=" in auth
    assert (
        "bedrock-SECRET-666" not in json.dumps(dict(r.headers))
        and "x-amz-security-token" not in r.headers
    )
    # independent recomputation of the signature from the wire request
    canonical = "\n".join(
        [
            "POST",
            "/model/anthropic.claude-3-5-sonnet-20241022-v2%253A0/converse",
            "",
            "content-type:application/json\nhost:bedrock-runtime.us-east-1.amazonaws.com\nx-amz-date:"
            + amz_date
            + "\n",
            "content-type;host;x-amz-date",
            hashlib.sha256(r.content).hexdigest(),
        ]
    )
    sts = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            "20260101/us-east-1/bedrock/aws4_request",
            hashlib.sha256(canonical.encode()).hexdigest(),
        ]
    )
    import hmac

    sig = hmac.new(
        signing_key("bedrock-SECRET-666", "20260101", "us-east-1", "bedrock"),
        sts.encode(),
        hashlib.sha256,
    ).hexdigest()
    assert auth.endswith("Signature=" + sig)
    assert body() == {
        "messages": [{"role": "user", "content": [{"text": "Hello"}]}],
        "system": [{"text": "Be brief."}, {"cachePoint": {"type": "default"}}],
        "inferenceConfig": {
            "maxTokens": 64,
            "temperature": 0.1,
            "topP": 0.5,
            "stopSequences": ["S"],
        },
        "toolConfig": {
            "tools": [
                {
                    "toolSpec": {
                        "name": "get_weather",
                        "description": "Get weather",
                        "inputSchema": {
                            "json": {"type": "object", "properties": {"city": {"type": "string"}}}
                        },
                    }
                },
                {"cachePoint": {"type": "default"}},
            ]
        },
    }
    assert (
        resp.text == "Ciao"
        and resp.finish_reason is FinishReason.STOP
        and resp.provider == "bedrock"
    )
    assert (
        resp.usage.input_tokens,
        resp.usage.cached_tokens,
        resp.usage.cache_write_tokens,
        resp.usage.output_tokens,
    ) == (160, 50, 10, 20)
    # 100*3 + 50*0.30 + 10*3.75 + 20*15 = 300+15+37.5+300 = 652.5 per 1M
    assert resp.cost_usd == Decimal("0.000652")  # 0.0006525 rounded half-even at 6 dp


async def test_bedrock_session_token_region_prefix_and_structured_output() -> None:
    creds = json.dumps(
        {
            "access_key_id": "AK",
            "secret_access_key": "SK",
            "session_token": "TOK",
            "region": "eu-west-1",
        }
    )
    gw, _ = gateway_for(
        capture(
            json_response(
                {
                    **BEDROCK_TOOL,
                    "output": {
                        "message": {
                            "role": "assistant",
                            "content": [
                                {
                                    "toolUse": {
                                        "toolUseId": "t",
                                        "name": "structured_output",
                                        "input": {"v": 1},
                                    }
                                }
                            ],
                        }
                    },
                }
            )
        ),
        secrets=store(bedrock=creds),
    )
    schema = {"type": "object"}
    resp = await free(gw).complete(
        request("bedrock", "eu.anthropic.claude-sonnet-4-20250514-v1:0", response_schema=schema)
    )
    assert SEEN[0].url.host == "bedrock-runtime.eu-west-1.amazonaws.com"
    assert (
        SEEN[0].headers["x-amz-security-token"] == "TOK"
        and "x-amz-security-token" in SEEN[0].headers["authorization"]
    )
    assert body()["toolConfig"]["toolChoice"] == {"tool": {"name": "structured_output"}}
    assert json.loads(resp.text) == {"v": 1} and resp.tool_calls == () and resp.cost_usd is not None
    await free(gw).complete(request("bedrock", MODEL_ID, tools=True, response_schema=schema))
    assert body()["toolConfig"]["toolChoice"] == {"any": {}}


async def test_bedrock_tool_use_and_message_conversion() -> None:
    gw, _ = gateway_for(capture(json_response(BEDROCK_TOOL)))
    resp = await free(gw).complete(request("bedrock", MODEL_ID, tools=True))
    assert resp.finish_reason is FinishReason.TOOL_CALLS and resp.text == "ok"
    assert [(c.id, c.name, dict(c.arguments)) for c in resp.tool_calls] == [
        ("tu_1", "get_weather", {"city": "Rome"})
    ]
    await free(gw).complete(request("bedrock", MODEL_ID, messages=tool_round_trip_messages()))
    assert body()["messages"][1:] == [
        {
            "role": "assistant",
            "content": [
                {"text": "Checking."},
                {"toolUse": {"toolUseId": "c1", "name": "get_weather", "input": {"city": "Paris"}}},
                {"toolUse": {"toolUseId": "c2", "name": "get_weather", "input": {"city": "Rome"}}},
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": "c1",
                        "content": [{"text": '{"temp": 21}'}],
                        "status": "success",
                    }
                },
                {
                    "toolResult": {
                        "toolUseId": "c2",
                        "content": [{"text": "boom"}],
                        "status": "error",
                    }
                },
            ],
        },
    ]


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("max_tokens", FinishReason.LENGTH),
        ("guardrail_intervened", FinishReason.CONTENT_FILTER),
        ("x", FinishReason.OTHER),
    ],
)
async def test_bedrock_finish_reasons(reason: str, expected: FinishReason) -> None:
    gw, _ = gateway_for(capture(json_response({**BEDROCK_TEXT, "stopReason": reason})))
    assert (await free(gw).complete(request("bedrock", MODEL_ID))).finish_reason is expected
    gw, _ = gateway_for(
        capture(json_response({"stopReason": "end_turn"})),
        retry=__import__("axis_runtime.models", fromlist=["RetryPolicy"]).RetryPolicy(
            max_attempts=1
        ),
    )
    with pytest.raises(ModelError, match="no output message"):
        await free(gw).complete(request("bedrock", MODEL_ID))


@pytest.mark.parametrize(
    "bad",
    [
        "not json",
        "[]",
        json.dumps({"access_key_id": "AK"}),
        json.dumps({"access_key_id": "", "secret_access_key": "s", "region": "r"}),
    ],
)
async def test_bedrock_bad_credentials_never_echo_the_secret(bad: str) -> None:
    gw, _ = gateway_for(capture(json_response(BEDROCK_TEXT)), secrets=store(bedrock=bad))
    with pytest.raises(ModelError) as exc:
        await free(gw).complete(request("bedrock", MODEL_ID))
    assert (
        exc.value.kind is ErrorKind.AUTH
        and bad not in str(exc.value)
        and "not json" not in str(exc.value)
    )


BEDROCK_STREAM = b"".join(
    [
        bedrock_event("messageStart", {"role": "assistant"}),
        bedrock_event("contentBlockDelta", {"contentBlockIndex": 0, "delta": {"text": "Ci"}}),
        bedrock_event("contentBlockDelta", {"contentBlockIndex": 0, "delta": {"text": "ao"}}),
        bedrock_event("contentBlockStop", {"contentBlockIndex": 0}),
        bedrock_event(
            "contentBlockStart",
            {
                "contentBlockIndex": 1,
                "start": {"toolUse": {"toolUseId": "tu_7", "name": "get_weather"}},
            },
        ),
        bedrock_event(
            "contentBlockDelta",
            {"contentBlockIndex": 1, "delta": {"toolUse": {"input": '{"city":'}}},
        ),
        bedrock_event(
            "contentBlockDelta",
            {"contentBlockIndex": 1, "delta": {"toolUse": {"input": ' "Oslo"}'}}},
        ),
        bedrock_event("contentBlockStop", {"contentBlockIndex": 1}),
        bedrock_event("messageStop", {"stopReason": "tool_use"}),
        bedrock_event(
            "metadata",
            {
                "usage": {"inputTokens": 12, "outputTokens": 6, "cacheReadInputTokens": 2},
                "metrics": {"latencyMs": 9},
            },
        ),
    ]
)


@pytest.mark.parametrize("chunk", [1, 5, 50, 100_000])
async def test_bedrock_streaming_event_stream_framing(chunk: int) -> None:
    gw, _ = gateway_for(capture(stream_response(BEDROCK_STREAM, chunk)))
    events = await collect(free(gw).stream(request("bedrock", MODEL_ID, tools=True)))
    assert SEEN[0].url.path.endswith("/converse-stream")
    assert "".join(e.text for e in find(events, "text")) == "Ciao"
    done = events[-1].response
    assert [(c.id, c.name, dict(c.arguments)) for c in done.tool_calls] == [
        ("tu_7", "get_weather", {"city": "Oslo"})
    ]
    assert done.finish_reason is FinishReason.TOOL_CALLS
    assert (done.usage.input_tokens, done.usage.cached_tokens, done.usage.output_tokens) == (
        14,
        2,
        6,
    )


async def test_bedrock_stream_structured_output() -> None:
    data = b"".join(
        [
            bedrock_event(
                "contentBlockStart",
                {
                    "contentBlockIndex": 0,
                    "start": {"toolUse": {"toolUseId": "t", "name": "structured_output"}},
                },
            ),
            bedrock_event(
                "contentBlockDelta",
                {"contentBlockIndex": 0, "delta": {"toolUse": {"input": '{"k": 2}'}}},
            ),
            bedrock_event("messageStop", {"stopReason": "tool_use"}),
            bedrock_event("metadata", {"usage": {"inputTokens": 1, "outputTokens": 1}}),
            bedrock_event("unknownEvent", {}),
        ]
    )
    gw, _ = gateway_for(capture(stream_response(data)))
    done = (
        await collect(
            free(gw).stream(request("bedrock", MODEL_ID, response_schema={"type": "object"}))
        )
    )[-1].response
    assert json.loads(done.text) == {"k": 2} and done.tool_calls == ()


async def test_bedrock_stream_errors_and_corruption() -> None:
    from axis_runtime.models import RetryPolicy

    one = RetryPolicy(max_attempts=1)
    exc_frame = event_frame(
        {":message-type": "exception", ":exception-type": "throttlingException"},
        b'{"message":"slow down"}',
    )
    gw, _ = gateway_for(capture(stream_response(exc_frame)), retry=one)
    with pytest.raises(ModelError) as e1:
        await collect(free(gw).stream(request("bedrock", MODEL_ID)))
    assert e1.value.kind is ErrorKind.RATE_LIMIT and "slow down" not in str(e1.value)
    other = event_frame(
        {":message-type": "exception", ":exception-type": "internalServerException"}, b"{}"
    )
    gw, _ = gateway_for(capture(stream_response(other)), retry=one)
    with pytest.raises(ModelError) as e2:
        await collect(free(gw).stream(request("bedrock", MODEL_ID)))
    assert e2.value.kind is ErrorKind.SERVER
    bad = bedrock_event("messageStop", {"stopReason": "end_turn"})
    for corrupt in (
        bad[:-1] + bytes([bad[-1] ^ 1]),
        bytes([bad[0] ^ 1]) + bad[1:],
    ):  # message crc / prelude length
        gw, _ = gateway_for(capture(stream_response(corrupt)), retry=one)
        with pytest.raises(ModelError, match="corrupt event stream"):
            await collect(free(gw).stream(request("bedrock", MODEL_ID)))
    short = event_frame({":event-type": "x"}, b"{}")
    import struct
    import zlib

    broken = struct.pack(">II", 5, 0)
    broken += struct.pack(">I", zlib.crc32(broken))
    gw, _ = gateway_for(capture(stream_response(broken + short)), retry=one)
    with pytest.raises(ModelError, match="length"):
        await collect(free(gw).stream(request("bedrock", MODEL_ID)))
    gw, _ = gateway_for(
        capture(stream_response(event_frame({":event-type": "messageStart"}, b"{oops"))), retry=one
    )
    with pytest.raises(ModelError, match="malformed stream event"):
        await collect(free(gw).stream(request("bedrock", MODEL_ID)))


async def test_bedrock_event_stream_header_types_are_skipped_correctly() -> None:
    """All fixed-size header value types must be stepped over without desynchronising."""
    import struct
    import zlib

    def hdr(name: str, typ: int, value: bytes) -> bytes:
        return bytes([len(name)]) + name.encode() + bytes([typ]) + value

    headers = (
        hdr("t", 0, b"")
        + hdr("f", 1, b"")
        + hdr("b", 2, b"\x01")
        + hdr("s", 3, b"\x00\x01")
        + hdr("i", 4, b"\x00" * 4)
        + hdr("l", 5, b"\x00" * 8)
        + hdr("ts", 8, b"\x00" * 8)
        + hdr("u", 9, b"\x00" * 16)
        + hdr("raw", 6, b"\x00\x02ab")
        + hdr(":event-type", 7, struct.pack(">H", 11) + b"messageStop")
    )
    payload = json.dumps({"stopReason": "end_turn"}).encode()
    total = 12 + len(headers) + len(payload) + 4
    prelude = struct.pack(">II", total, len(headers))
    prelude += struct.pack(">I", zlib.crc32(prelude))
    msg = prelude + headers + payload
    msg += struct.pack(">I", zlib.crc32(msg))
    gw, _ = gateway_for(
        capture(
            stream_response(
                msg + bedrock_event("metadata", {"usage": {"inputTokens": 1, "outputTokens": 2}})
            )
        )
    )
    done = (await collect(free(gw).stream(request("bedrock", MODEL_ID))))[-1].response
    assert done.finish_reason is FinishReason.STOP and done.usage.output_tokens == 2
    from axis_runtime.models.adapters.bedrock import EventStreamDecoder

    with pytest.raises(ModelError, match="unknown event-stream header type"):
        EventStreamDecoder._headers(hdr("x", 99, b""))  # noqa: SLF001
