"""Per-provider price tables (USD per 1M tokens), versioned.

THE SHIPPED NUMBERS ARE ILLUSTRATIVE DEFAULTS, NOT A BILLING SOURCE.  Verify against each
provider's price page and inject your own ``CostTable`` before relying on ``cost_usd`` for
invoicing (tracked in docs/NEEDS.md).  Unknown models yield ``None``, never a guess.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal

from axis_runtime.models.types import Usage

COST_TABLE_VERSION = "2026-09-30-illustrative"
_PER = Decimal(1_000_000)
_QUANT = Decimal("0.000001")


@dataclass(frozen=True)
class Price:
    input: Decimal
    output: Decimal
    cached_input: Decimal | None = None  # read from cache; defaults to ``input``
    cache_write: Decimal | None = None  # cache creation; defaults to ``input``


def _p(i: str, o: str, c: str | None = None, w: str | None = None) -> Price:
    return Price(
        Decimal(i), Decimal(o), None if c is None else Decimal(c), None if w is None else Decimal(w)
    )


DEFAULT_PRICES: dict[str, dict[str, Price]] = {
    "anthropic": {
        "claude-opus-4": _p("15", "75", "1.50", "18.75"),
        "claude-sonnet-4": _p("3", "15", "0.30", "3.75"),
        "claude-3-5-sonnet": _p("3", "15", "0.30", "3.75"),
        "claude-3-5-haiku": _p("0.80", "4", "0.08", "1.00"),
    },
    "openai": {
        "gpt-4o": _p("2.50", "10", "1.25"),
        "gpt-4o-mini": _p("0.15", "0.60", "0.075"),
        "gpt-4.1": _p("2", "8", "0.50"),
        "gpt-4.1-mini": _p("0.40", "1.60", "0.10"),
    },
    "google": {
        "gemini-2.0-flash": _p("0.10", "0.40"),
        "gemini-2.5-flash": _p("0.30", "2.50"),
        "gemini-2.5-pro": _p("1.25", "10"),
        "gemini-1.5-pro": _p("1.25", "5"),
    },
    "bedrock": {
        "anthropic.claude-sonnet-4": _p("3", "15", "0.30", "3.75"),
        "anthropic.claude-3-5-sonnet": _p("3", "15", "0.30", "3.75"),
        "anthropic.claude-3-5-haiku": _p("0.80", "4", "0.08", "1.00"),
        "amazon.nova-pro": _p("0.80", "3.20"),
        "amazon.nova-lite": _p("0.06", "0.24"),
    },
}

# Providers that bill at another family's list prices unless a table for them is supplied.
_FAMILY = {"azure-openai": "openai"}
_REGION_PREFIX = re.compile(r"^(us|eu|apac|global)\.")


class CostTable:
    def __init__(
        self,
        prices: Mapping[str, Mapping[str, Price]] | None = None,
        version: str = COST_TABLE_VERSION,
    ) -> None:
        self.version = version
        self._prices = {k: dict(v) for k, v in (prices or DEFAULT_PRICES).items()}

    def lookup(self, provider: str, model: str) -> Price | None:
        table = self._prices.get(provider) or self._prices.get(_FAMILY.get(provider, ""))
        if not table:
            return None
        name = _REGION_PREFIX.sub("", model)
        best = max((k for k in table if name.startswith(k)), key=len, default=None)
        return None if best is None else table[best]

    def cost(
        self, provider: str, model: str, usage: Usage, *, pricing_model: str | None = None
    ) -> Decimal | None:
        price = self.lookup(provider, pricing_model or model)
        if price is None:
            return None
        uncached = max(usage.input_tokens - usage.cached_tokens - usage.cache_write_tokens, 0)
        total = (
            uncached * price.input
            + usage.cached_tokens
            * (price.cached_input if price.cached_input is not None else price.input)
            + usage.cache_write_tokens
            * (price.cache_write if price.cache_write is not None else price.input)
            + usage.output_tokens * price.output
        ) / _PER
        return total.quantize(_QUANT)
