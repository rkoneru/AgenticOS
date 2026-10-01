"""RuntimeManifest v1 (ABL compiler output, runtime input); see docs/plans/phase-2.md."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

TOOL_KINDS = frozenset({"function", "mcp", "code", "browser", "channel", "agent"})
SIDE_EFFECTS = frozenset({"none", "read", "write", "external"})
SUPPORTED_SUPERVISORS = frozenset({"one-for-one"})
SUPPORTED_RESTART_POLICIES = frozenset({"never", "on_failure"})
ROUTING_STAGES = frozenset({"cache", "rules", "mpm", "rag", "llm"})


class ManifestError(ValueError):
    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path


@dataclass(frozen=True)
class ModelSpec:
    provider: str
    model: str
    endpoint: str | None = None
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: str = "function"
    ref: str | None = None
    mcp_server: str | None = None
    side_effects: str = "write"
    timeout_seconds: int = 60


@dataclass(frozen=True)
class Budget:
    soft: float | None = None
    hard: float | None = None


@dataclass(frozen=True)
class Budgets:
    tokens: Budget = field(default_factory=Budget)
    cost_usd: Budget = field(default_factory=Budget)
    runtime_seconds: Budget = field(default_factory=Budget)
    tool_calls: Budget = field(default_factory=Budget)


@dataclass(frozen=True)
class ProcessConfig:
    restart_policy: str = "never"
    max_restarts: int = 0
    max_children: int = 0
    timeout_seconds: float | None = None
    supervisor: str = "one-for-one"


@dataclass(frozen=True)
class RuntimeManifest:
    name: str
    version: str
    content_hash: str
    risk_level: str
    primary: ModelSpec
    fallbacks: tuple[ModelSpec, ...] = ()
    system_prompt: str = ""
    tools: tuple[ToolSpec, ...] = ()
    budgets: Budgets = field(default_factory=Budgets)
    process: ProcessConfig = field(default_factory=ProcessConfig)
    phi: bool = False
    routing_stages: tuple[str, ...] = ("llm",)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> RuntimeManifest:
        if raw.get("manifest_version") != 1:
            raise ManifestError("manifest_version", "unsupported (this runtime speaks v1)")
        bp = _obj(raw, "blueprint")
        models = _obj(raw, "models")
        risk = raw.get("risk") or {}
        proc = raw.get("process") or {}
        tools = []
        for i, t in enumerate(raw.get("tools") or []):
            path = f"tools[{i}]"
            spec = ToolSpec(
                name=_str(t, "name", path),
                kind=t.get("kind", "function"),
                ref=t.get("ref"),
                mcp_server=t.get("mcp_server"),
                side_effects=t.get("side_effects", "write"),
                timeout_seconds=int(t.get("timeout_seconds", 60)),
            )
            if spec.kind not in TOOL_KINDS:
                raise ManifestError(f"{path}.kind", f"unknown kind {spec.kind!r}")
            if spec.side_effects not in SIDE_EFFECTS:
                raise ManifestError(f"{path}.side_effects", f"unknown value {spec.side_effects!r}")
            if spec.kind == "mcp" and not spec.mcp_server:
                raise ManifestError(f"{path}.mcp_server", "required for kind 'mcp'")
            tools.append(spec)
        names = [t.name for t in tools]
        if len(set(names)) != len(names):
            raise ManifestError("tools", "duplicate tool names")
        return cls(
            name=_str(bp, "name", "blueprint"),
            version=_str(bp, "version", "blueprint"),
            content_hash=str(bp.get("content_hash", "")),
            risk_level=str(risk.get("level", "minimal")),
            primary=_model(_obj(models, "primary", "models"), "models.primary"),
            fallbacks=tuple(
                _model(m, f"models.fallbacks[{i}]")
                for i, m in enumerate(models.get("fallbacks") or [])
            ),
            system_prompt=str(raw.get("system_prompt") or ""),
            tools=tuple(tools),
            budgets=_budgets(raw.get("budgets") or {}),
            process=ProcessConfig(
                restart_policy=str(proc.get("restart_policy", "never")),
                max_restarts=int(proc.get("max_restarts", 0)),
                max_children=int(proc.get("max_children", 0)),
                timeout_seconds=proc.get("timeout_seconds"),
                supervisor=str(proc.get("supervisor", "one-for-one")),
            ),
            phi=bool((raw.get("data") or {}).get("phi", False)),
            routing_stages=_routing_stages(raw.get("routing")),
        )

    def validate_supported(self) -> None:
        """Features the schema allows but this runtime does not implement fail at spawn time."""
        if self.process.supervisor not in SUPPORTED_SUPERVISORS:
            raise ManifestError(
                "process.supervisor",
                f"{self.process.supervisor!r} not implemented (one-for-one only)",
            )
        if self.process.restart_policy not in SUPPORTED_RESTART_POLICIES:
            raise ManifestError(
                "process.restart_policy", f"{self.process.restart_policy!r} not implemented"
            )

    def tool(self, name: str) -> ToolSpec | None:
        return next((t for t in self.tools if t.name == name), None)


def _obj(raw: Mapping[str, Any], key: str, path: str = "") -> Mapping[str, Any]:
    value = raw.get(key)
    if not isinstance(value, Mapping):
        raise ManifestError(f"{path + '.' if path else ''}{key}", "required object")
    return value


def _str(raw: Mapping[str, Any], key: str, path: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{path}.{key}", "required non-empty string")
    return value


def _model(raw: Mapping[str, Any], path: str) -> ModelSpec:
    return ModelSpec(
        provider=_str(raw, "provider", path),
        model=_str(raw, "model", path),
        endpoint=raw.get("endpoint"),
        params=dict(raw.get("params") or {}),
    )


def _routing_stages(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ("llm",)
    if not isinstance(raw, Mapping):
        raise ManifestError("routing", "must be an object")
    stages = raw.get("stages")
    if stages is None:
        return ("llm",)
    if not isinstance(stages, list | tuple) or not all(isinstance(s, str) for s in stages):
        raise ManifestError("routing.stages", "must be a list of stage names")
    for s in stages:
        if s not in ROUTING_STAGES:
            raise ManifestError("routing.stages", f"unknown stage {s!r}")
    if len(set(stages)) != len(stages):
        raise ManifestError("routing.stages", "duplicate stage")
    return tuple(stages)


def _budgets(raw: Mapping[str, Any]) -> Budgets:
    def one(key: str) -> Budget:
        b = raw.get(key) or {}
        soft, hard = b.get("soft"), b.get("hard")
        for label, v in (("soft", soft), ("hard", hard)):
            if v is not None and (not isinstance(v, int | float) or isinstance(v, bool) or v < 0):
                raise ManifestError(
                    f"budgets.{key}.{label}", "must be a non-negative number or null"
                )
        if soft is not None and hard is not None and soft > hard:
            raise ManifestError(f"budgets.{key}", "soft exceeds hard")
        return Budget(soft, hard)

    return Budgets(one("tokens"), one("cost_usd"), one("runtime_seconds"), one("tool_calls"))
