"""Wire and domain types of the eval runner (docs/spec/evals-runner.md).

Everything that crosses the hub boundary is snake_case JSON. ``from_wire`` constructors validate
strictly and raise ``WireError``: a malformed suite, dataset or queued run is refused, never
guessed at (a lenient parse of a threshold or a weight would silently change what "pass" means).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

RUNNER_VERSION = "1.0.0"
AGGREGATION_VERSION = 1

#: Case, grader and run ids: ASCII only so that "sorted by id" means the same thing in every
#: language (Python code points, JS UTF-16 code units) and cannot be confused by look-alikes.
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}@[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

GraderKind = Literal["deterministic", "model", "human"]
GRADER_KINDS = ("deterministic", "model", "human")
Mode = Literal["ci", "online", "manual"]
MODES = ("ci", "online", "manual")


class WireError(ValueError):
    """A hub payload is malformed. The message names the field, never echoes its value."""


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _obj(raw: object, path: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise WireError(f"{path}: expected an object")
    return raw


def _str(
    raw: Mapping[str, Any], key: str, path: str, *, pattern: re.Pattern[str] | None = None
) -> str:
    value = raw.get(key)
    if (
        not isinstance(value, str)
        or not value
        or (pattern is not None and not pattern.match(value))
    ):
        raise WireError(f"{path}.{key}: expected a valid non-empty string")
    return value


def _number(raw: Mapping[str, Any], key: str, path: str, *, default: float | None = None) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float) or value != value:
        raise WireError(f"{path}.{key}: expected a number")
    if value in (float("inf"), float("-inf")):
        raise WireError(f"{path}.{key}: expected a finite number")
    return float(value)


def _unit(raw: Mapping[str, Any], key: str, path: str, *, default: float | None = None) -> float:
    value = _number(raw, key, path, default=default)
    if not 0.0 <= value <= 1.0:
        raise WireError(f"{path}.{key}: expected a number in [0, 1]")
    return value


@dataclass(frozen=True)
class EvalCase:
    id: str
    input: Any
    expected: Any = None
    tags: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def input_text(self) -> str:
        return self.input if isinstance(self.input, str) else canonical(self.input)

    @classmethod
    def from_wire(cls, raw: object, path: str = "case") -> EvalCase:
        o = _obj(raw, path)
        tags = o.get("tags") or []
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            raise WireError(f"{path}.tags: expected a list of strings")
        meta = o.get("metadata") or {}
        if not isinstance(meta, Mapping):
            raise WireError(f"{path}.metadata: expected an object")
        if "input" not in o:
            raise WireError(f"{path}.input: required")
        return cls(
            id=_str(o, "id", path, pattern=ID_RE),
            input=o["input"],
            expected=o.get("expected"),
            tags=tuple(tags),
            metadata=dict(meta),
        )

    def to_wire(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "input": self.input,
            "expected": self.expected,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class GraderSpec:
    """``config`` is kind specific (docs/spec/evals-runner.md section 4)."""

    id: str
    kind: GraderKind
    weight: float = 1.0
    config: Mapping[str, Any] = field(default_factory=dict)
    min_mean: float | None = None

    @classmethod
    def from_wire(cls, raw: object, path: str = "grader") -> GraderSpec:
        o = _obj(raw, path)
        kind = o.get("kind")
        if kind not in GRADER_KINDS:
            raise WireError(f"{path}.kind: expected one of {GRADER_KINDS}")
        weight = _number(o, "weight", path, default=1.0)
        if weight <= 0:
            raise WireError(f"{path}.weight: must be positive")
        config = o.get("config") or {}
        if not isinstance(config, Mapping):
            raise WireError(f"{path}.config: expected an object")
        min_mean = None if o.get("min_mean") is None else _unit(o, "min_mean", path)
        return cls(
            id=_str(o, "id", path, pattern=ID_RE),
            kind=kind,
            weight=weight,
            config=dict(config),
            min_mean=min_mean,
        )


@dataclass(frozen=True)
class Suite:
    ref: str
    dataset_ref: str
    graders: tuple[GraderSpec, ...]
    pass_threshold: float
    tolerance: float = 0.0
    required_for_release: bool = False
    min_case_score: float | None = None
    settings: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_wire(cls, raw: object) -> Suite:
        o = _obj(raw, "suite")
        graders = o.get("graders")
        if not isinstance(graders, list) or not graders:
            raise WireError("suite.graders: expected a non-empty list")
        specs = tuple(GraderSpec.from_wire(g, f"suite.graders[{i}]") for i, g in enumerate(graders))
        if len({g.id for g in specs}) != len(specs):
            raise WireError("suite.graders: duplicate grader id")
        settings = o.get("settings") or {}
        if not isinstance(settings, Mapping):
            raise WireError("suite.settings: expected an object")
        return cls(
            ref=_str(o, "ref", "suite", pattern=REF_RE),
            dataset_ref=_str(o, "dataset_ref", "suite", pattern=REF_RE),
            graders=specs,
            pass_threshold=_unit(o, "pass_threshold", "suite"),
            tolerance=_unit(o, "tolerance", "suite", default=0.0),
            required_for_release=bool(o.get("required_for_release", False)),
            min_case_score=None
            if o.get("min_case_score") is None
            else _unit(o, "min_case_score", "suite"),
            settings=dict(settings),
        )


@dataclass(frozen=True)
class Dataset:
    ref: str
    version_hash: str
    cases: tuple[EvalCase, ...]
    phi: bool = False

    @classmethod
    def from_wire(cls, raw: object) -> Dataset:
        o = _obj(raw, "dataset")
        cases = o.get("cases")
        if not isinstance(cases, list):
            raise WireError("dataset.cases: expected a list")
        parsed = tuple(EvalCase.from_wire(c, f"dataset.cases[{i}]") for i, c in enumerate(cases))
        if len({c.id for c in parsed}) != len(parsed):
            raise WireError("dataset.cases: duplicate case id")
        return cls(
            ref=_str(o, "ref", "dataset", pattern=REF_RE),
            version_hash=_str(o, "version_hash", "dataset", pattern=HASH_RE),
            cases=parsed,
            phi=bool(o.get("phi", False)),
        )

    def computed_hash(self) -> str:
        """The content hash of the cases as the runner received them. A mismatch with
        ``version_hash`` means the hub served different content than it claims (see
        ``dataset_content_hash``)."""
        return dataset_content_hash(self.cases)


def dataset_content_hash(cases: Sequence[EvalCase]) -> str:
    ordered = sorted((c.to_wire() for c in cases), key=lambda c: str(c["id"]))
    return hashlib.sha256(canonical(ordered).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BlueprintRef:
    name: str
    version: str
    content_hash: str

    @classmethod
    def from_wire(cls, raw: object, path: str = "blueprint") -> BlueprintRef:
        o = _obj(raw, path)
        return cls(
            name=_str(o, "name", path),
            version=_str(o, "version", path),
            content_hash=_str(o, "content_hash", path, pattern=HASH_RE),
        )

    def to_wire(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version, "content_hash": self.content_hash}


@dataclass(frozen=True)
class QueuedRun:
    id: str
    tenant_id: str
    suite_ref: str
    blueprint: BlueprintRef
    mode: Mode = "ci"
    seed: int = 0

    @classmethod
    def from_wire(cls, raw: object) -> QueuedRun:
        o = _obj(raw, "run")
        mode = o.get("mode", "ci")
        if mode not in MODES:
            raise WireError("run.mode: unknown mode")
        seed = o.get("seed", 0)
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**31:
            raise WireError("run.seed: expected an integer in [0, 2^31)")
        return cls(
            id=_str(o, "id", "run"),
            tenant_id=_str(o, "tenant_id", "run"),
            suite_ref=_str(o, "suite_ref", "run", pattern=REF_RE),
            blueprint=BlueprintRef.from_wire(o.get("blueprint")),
            mode=mode,
            seed=seed,
        )


# --------------------------------------------------------------------------------------
# Traces and grades
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolCallTrace:
    name: str
    ok: bool
    result_sha256: str
    error: str | None = None


@dataclass(frozen=True)
class GateDecisionTrace:
    action: str
    enforcement_point: str
    decision: str
    reason: str


@dataclass(frozen=True)
class ModelCallTrace:
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_micro_usd: int
    latency_ms: int


@dataclass(frozen=True)
class CaseTrace:
    """What one case's run left behind: the output and the evidence graders may look at. Built from
    the run's event log (``trace.trace_from_state``), never from the agent's own claims."""

    run_id: str
    trace_id: str
    exit_reason: str
    output: str | None
    tool_calls: tuple[ToolCallTrace, ...] = ()
    gate_decisions: tuple[GateDecisionTrace, ...] = ()
    model_calls: tuple[ModelCallTrace, ...] = ()
    latency_ms: int = 0
    events_hash: str = ""
    event_count: int = 0

    @property
    def tokens(self) -> int:
        return sum(m.input_tokens + m.output_tokens for m in self.model_calls)

    @property
    def cost_micro_usd(self) -> int:
        return sum(m.cost_micro_usd for m in self.model_calls)

    @property
    def cost_usd(self) -> str:
        micro = self.cost_micro_usd
        return f"{micro // 1_000_000}.{micro % 1_000_000:06d}"


GradeStatus = Literal["scored", "ungraded", "pending", "error"]


@dataclass(frozen=True)
class Grade:
    """``score`` is meaningful only when ``status == "scored"``; every other status aggregates as 0
    (``pending`` holds the whole run back instead)."""

    grader_id: str
    kind: GraderKind
    status: GradeStatus
    score: float = 0.0
    detail: str = ""
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def to_wire(self) -> dict[str, Any]:
        return {
            "grader_id": self.grader_id,
            "kind": self.kind,
            "status": self.status,
            "score": self.score,
            "detail": self.detail,
            "provenance": dict(self.provenance),
        }


def scored(grader: GraderSpec, passed: bool, detail: str = "") -> Grade:
    return Grade(grader.id, grader.kind, "scored", 1.0 if passed else 0.0, detail)


def errored(grader: GraderSpec, detail: str) -> Grade:
    return Grade(grader.id, grader.kind, "error", 0.0, detail)
