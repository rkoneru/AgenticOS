"""MPM (micro-model) stub: interface, tenant-scoped registry, deterministic mocks, routing slot
and a benchmark harness.  No real model is trained or served here (docs/NEEDS.md); the
point is that the contract, the confidence-threshold fallthrough and the measurement loop
exist and are testable.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol

from axis_runtime.nexus.types import ZERO, Hit, Miss, RouteRequest, RouteState, StageOutcome


@dataclass(frozen=True)
class Prediction:
    answer: str
    confidence: float
    tokens: int = 0
    cost: Decimal = ZERO


class MicroModel(Protocol):
    id: str
    capabilities: frozenset[str]

    async def predict(self, tenant_id: str, prompt: str) -> Prediction | None:
        """``None`` = the model abstains."""
        ...


class ManualClock:
    """Deterministic clock: time only moves when ``advance`` is called."""

    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class MicroModelRegistry:
    """Models are registered per tenant (``tenant_id``) or platform-wide (``None``).  Lookups are
    always made on behalf of a tenant: they see that tenant's models plus platform models, never
    another tenant's.  A tenant model shadows a platform model of the same id."""

    def __init__(self) -> None:
        self._models: dict[str | None, dict[str, MicroModel]] = {}

    def register(self, model: MicroModel, *, tenant_id: str | None = None) -> None:
        scope = self._models.setdefault(tenant_id, {})
        if model.id in scope:
            raise ValueError(f"model {model.id!r} already registered in this scope")
        if not model.capabilities:
            raise ValueError("a model must declare at least one capability")
        scope[model.id] = model

    def unregister(self, model_id: str, *, tenant_id: str | None = None) -> bool:
        return self._models.get(tenant_id, {}).pop(model_id, None) is not None

    def get(self, tenant_id: str, model_id: str) -> MicroModel | None:
        return self._visible(tenant_id).get(model_id)

    def list(self, tenant_id: str, capability: str | None = None) -> list[MicroModel]:
        models = self._visible(tenant_id).values()
        return sorted(
            (m for m in models if capability is None or capability in m.capabilities),
            key=lambda m: m.id,
        )

    def _visible(self, tenant_id: str) -> dict[str, MicroModel]:
        if not tenant_id:
            raise ValueError("tenant_id required")
        return {**self._models.get(None, {}), **self._models.get(tenant_id, {})}


# ---- deterministic mock models -------------------------------------------------------


class KeywordModel:
    """Answers with the label whose keywords overlap the prompt most; confidence is the share of the
    prompt's matched keyword hits.  Abstains when nothing matches.  Fully deterministic."""

    def __init__(
        self,
        id: str,
        capability: str,
        labels: Mapping[str, Sequence[str]],
        *,
        cost_per_call: Decimal = Decimal("0.000001"),
        latency_s: float = 0.0,
        clock: ManualClock | None = None,
    ) -> None:
        self.id = id
        self.capabilities = frozenset({capability})
        self._labels = {k: tuple(w.lower() for w in v) for k, v in labels.items()}
        self._cost = cost_per_call
        self._latency = latency_s
        self._clock = clock

    async def predict(self, tenant_id: str, prompt: str) -> Prediction | None:
        if self._clock is not None:
            self._clock.advance(self._latency)
        words = {w for w in "".join(c.lower() if c.isalnum() else " " for c in prompt).split()}
        scores = {
            label: sum(1 for k in kws if k in words) for label, kws in sorted(self._labels.items())
        }
        total = sum(scores.values())
        if total == 0:
            return None
        best = max(scores, key=lambda label: (scores[label], label))
        return Prediction(best, scores[best] / total, tokens=len(words), cost=self._cost)


class FixedModel:
    """Always answers the same thing with a fixed confidence (for routing/threshold tests)."""

    def __init__(
        self,
        id: str,
        capability: str,
        answer: str,
        confidence: float,
        *,
        cost_per_call: Decimal = ZERO,
    ) -> None:
        self.id = id
        self.capabilities = frozenset({capability})
        self._answer, self._confidence, self._cost = answer, confidence, cost_per_call

    async def predict(self, tenant_id: str, prompt: str) -> Prediction | None:
        return Prediction(self._answer, self._confidence, cost=self._cost)


# ---- routing slot --------------------------------------------------------------------


class MpmStage:
    """Routing slot.  Runs every model registered (for the tenant) under the request's
    capability and answers with the most confident prediction iff it reaches
    ``threshold``; otherwise falls through (the cost of the attempt is still attributed to
    this stage)."""

    name = "mpm"

    def __init__(self, registry: MicroModelRegistry, *, threshold: float = 0.8) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be within [0, 1]")
        self._registry = registry
        self._threshold = threshold

    async def run(self, request: RouteRequest, state: RouteState) -> StageOutcome:
        if request.capability is None:
            return Miss("no_capability")
        models = self._registry.list(request.tenant_id, request.capability)
        if not models:
            return Miss("no_model")
        best: tuple[MicroModel, Prediction] | None = None
        cost, tokens = ZERO, 0
        for m in models:
            try:
                pred = await m.predict(request.tenant_id, request.prompt)
            except Exception:  # noqa: S112  one broken model must not hide the others
                continue
            if pred is None:
                continue
            cost += pred.cost
            tokens += pred.tokens
            if best is None or pred.confidence > best[1].confidence:
                best = (m, pred)
        if best is None:
            return Miss("abstained", cost=cost, tokens=tokens)
        model, pred = best
        if pred.confidence >= self._threshold:
            return Hit(
                pred.answer,
                cost=cost,
                confidence=pred.confidence,
                tokens=tokens,
                meta={"model_id": model.id},
            )
        return Miss("below_threshold", cost=cost, tokens=tokens)


# ---- benchmark harness ---------------------------------------------------------------


@dataclass(frozen=True)
class LabeledExample:
    tenant_id: str
    prompt: str
    expected: str


@dataclass(frozen=True)
class BenchmarkReport:
    model_id: str
    n: int
    answered: int
    correct: int
    accuracy: float  # correct / n (abstention counts as wrong)
    coverage: float  # answered / n at the threshold
    selective_accuracy: float  # correct among answered at the threshold (0 when none answered)
    total_cost: Decimal
    mean_cost: Decimal
    mean_latency_ms: float
    p95_latency_ms: float


class _Clock(Protocol):
    def monotonic(self) -> float: ...


async def benchmark(
    model: MicroModel,
    dataset: Sequence[LabeledExample],
    clock: _Clock,
    *,
    threshold: float = 0.8,
) -> BenchmarkReport:
    """Run ``model`` over ``dataset``.  Everything is computed from the observed predictions and the
    injected clock; nothing is hard-coded, so a deterministic model and clock give a reproducible
    report."""
    if not dataset:
        raise ValueError("empty dataset")
    answered = correct = correct_answered = 0
    cost = ZERO
    latencies: list[float] = []
    for ex in dataset:
        t0 = clock.monotonic()
        try:
            pred = await model.predict(ex.tenant_id, ex.prompt)
        except Exception:
            pred = None
        latencies.append((clock.monotonic() - t0) * 1000.0)
        if pred is None:
            continue
        cost += pred.cost
        is_right = pred.answer == ex.expected
        correct += is_right
        if pred.confidence >= threshold:
            answered += 1
            correct_answered += is_right
    n = len(dataset)
    latencies.sort()
    p95 = latencies[min(n - 1, max(0, -(-95 * n // 100) - 1))]
    return BenchmarkReport(
        model_id=model.id,
        n=n,
        answered=answered,
        correct=correct,
        accuracy=correct / n,
        coverage=answered / n,
        selective_accuracy=(correct_answered / answered) if answered else 0.0,
        total_cost=cost,
        mean_cost=cost / n,
        mean_latency_ms=sum(latencies) / n,
        p95_latency_ms=p95,
    )
