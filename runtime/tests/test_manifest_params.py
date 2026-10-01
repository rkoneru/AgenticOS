"""ABL ``maxOutputTokens`` reaches the runtime as ``max_tokens`` (the key adapters and TKI read)."""

from __future__ import annotations

from axis_runtime.manifest import RuntimeManifest
from conftest import manifest_dict


def params_of(params: dict[str, object]) -> dict[str, object]:
    d = manifest_dict()
    d["models"]["primary"]["params"] = params
    d["models"]["fallbacks"] = [
        {"provider": "openai", "model": "gpt-4o-mini", "endpoint": None, "params": dict(params)}
    ]
    m = RuntimeManifest.from_dict(d)
    assert dict(m.fallbacks[0].params) == dict(m.primary.params)
    return dict(m.primary.params)


def test_max_output_tokens_is_mapped_to_max_tokens() -> None:
    assert params_of({"max_output_tokens": 64, "temperature": 0}) == {
        "max_tokens": 64,
        "temperature": 0,
    }


def test_an_explicit_max_tokens_wins_and_other_params_are_untouched() -> None:
    assert params_of({"max_tokens": 10, "max_output_tokens": 99}) == {"max_tokens": 10}
    assert params_of({"temperature": 0.2}) == {"temperature": 0.2}
