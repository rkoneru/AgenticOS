"""NEXUS: the routing pipeline cache -> rules -> MPM -> RAG -> LLM (docs/spec/nexus.md)."""

from axis_runtime.nexus.cache import (
    CacheEntry,
    CacheStage,
    CacheStore,
    InMemoryCache,
    cache_key,
)
from axis_runtime.nexus.llm import LlmStage
from axis_runtime.nexus.mpm import (
    BenchmarkReport,
    FixedModel,
    KeywordModel,
    LabeledExample,
    ManualClock,
    MicroModel,
    MicroModelRegistry,
    MpmStage,
    Prediction,
    benchmark,
)
from axis_runtime.nexus.rag import InMemoryRetriever, RagStage, Retriever
from axis_runtime.nexus.router import NexusConfigError, NexusRouter
from axis_runtime.nexus.rules import Rule, RulesStage, UnsafePatternError, compile_safe
from axis_runtime.nexus.telemetry import (
    EventSink,
    InMemoryEventSink,
    InMemoryTracer,
    NoopTracer,
    NullEventSink,
    Tracer,
)
from axis_runtime.nexus.types import (
    Hit,
    Miss,
    Passage,
    RouteRequest,
    RouteResult,
    RouteState,
    Stage,
    StageRecord,
)

__all__ = [
    "BenchmarkReport",
    "CacheEntry",
    "CacheStage",
    "CacheStore",
    "EventSink",
    "FixedModel",
    "Hit",
    "InMemoryCache",
    "InMemoryEventSink",
    "InMemoryRetriever",
    "InMemoryTracer",
    "KeywordModel",
    "LabeledExample",
    "LlmStage",
    "ManualClock",
    "MicroModel",
    "MicroModelRegistry",
    "Miss",
    "MpmStage",
    "NexusConfigError",
    "NexusRouter",
    "NoopTracer",
    "NullEventSink",
    "Passage",
    "Prediction",
    "RagStage",
    "Retriever",
    "RouteRequest",
    "RouteResult",
    "RouteState",
    "Rule",
    "RulesStage",
    "Stage",
    "StageRecord",
    "Tracer",
    "UnsafePatternError",
    "benchmark",
    "cache_key",
    "compile_safe",
]
