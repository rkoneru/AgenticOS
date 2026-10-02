import type { Plan, PriceBook, RateCard } from "./rating.js";

const M = 1_000_000n;
const flat = (amountMicro: bigint, perUnits: bigint) => [
  { upTo: null, price: { amountMicro, perUnits } },
];
const rate = (
  meter: RateCard["meter"],
  dimension: string,
  amountMicro: bigint,
  perUnits: bigint,
): RateCard => ({
  meter,
  dimension,
  tiers: flat(amountMicro, perUnits),
});

/**
 * DEV/TEST price book (illustrative numbers, not a commercial offer). Real price books come from the control plane (NEEDS).
 * Token prices are per 1M tokens, runtime per second, voice per minute, storage per GB-hour (1000 milli-GB-hours).
 */
export const DEV_PRICE_BOOK: PriceBook = {
  id: "axis-dev",
  version: 1,
  currency: "USD",
  modelClasses: [
    { prefix: "claude-haiku", class: "small" },
    { prefix: "gpt-mini", class: "small" },
    { prefix: "claude-opus", class: "frontier" },
  ],
  rates: [
    rate("tokens_in", "small", 250_000n, M),
    rate("tokens_in", "standard", 3n * M, M),
    rate("tokens_in", "frontier", 15n * M, M),
    rate("tokens_in", "", 3n * M, M),
    rate("tokens_out", "small", 1_250_000n, M),
    rate("tokens_out", "standard", 15n * M, M),
    rate("tokens_out", "frontier", 75n * M, M),
    rate("tokens_out", "", 15n * M, M),
    rate("runtime_seconds", "", 100n, 1000n), // $0.0001 per second
    rate("tool_executions", "code", 2_000n, 1n),
    rate("tool_executions", "browser", 5_000n, 1n),
    rate("tool_executions", "", 1_000n, 1n),
    rate("voice_minutes", "", 90_000n, 60_000n), // $0.09 per minute
    rate("storage_gb_hours", "", 100n, 1000n), // $0.0001 per GB-hour
    rate("marketplace_installs", "", 1n * M, 1n),
  ],
};

export const DEV_PLAN: Plan = {
  id: "team",
  name: "Team",
  priceBook: { id: DEV_PRICE_BOOK.id, version: DEV_PRICE_BOOK.version },
  baseFeeMicro: 99n * M,
  included: { tokens_in: 1_000_000n, tokens_out: 200_000n },
  commitMicro: 0n,
};
