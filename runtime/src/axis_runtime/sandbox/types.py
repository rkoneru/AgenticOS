"""Sandbox contracts: what a code run asks for and what it returns.  Pure data (no IO).

The code text is NEVER part of anything the audit log stores: events carry ``code_sha256`` and
``code_bytes`` only (see ``CodeRunAction``).
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Protocol

SUPPORTED_LANGUAGES = ("python", "shell")
_MAX_CODE_BYTES = 256 * 1024
_MAX_ENV_VALUE = 4096
_FORBIDDEN_ENV_PREFIXES = ("LD_", "PYTHON", "BASH_", "ENV", "IFS", "PS4", "SHELLOPTS")


class SandboxError(RuntimeError):
    """Base class of every sandbox failure."""


class SandboxUnavailableError(SandboxError):
    """The required isolation cannot be provided here.  The code is NOT run (fail closed)."""


class SandboxPolicyError(SandboxError):
    """The spec asks for something this backend refuses (language, limits over the ceiling)."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class SandboxLimits:
    """Resource limits.  Every field is positive; the backend also enforces its own ceilings."""

    wall_seconds: float = 10.0  #: wall-clock timeout; the process group is killed at expiry
    cpu_seconds: int = 5  #: RLIMIT_CPU
    memory_bytes: int = 512 * 1024 * 1024  #: RLIMIT_AS (address space)
    max_open_files: int = 64  #: RLIMIT_NOFILE
    max_processes: int = 32  #: RLIMIT_NPROC
    max_file_bytes: int = 8 * 1024 * 1024  #: RLIMIT_FSIZE (largest single file it may write)
    max_disk_bytes: int = 32 * 1024 * 1024  #: working directory total; polled, kills when exceeded
    max_output_bytes: int = 64 * 1024  #: kept per stream (stdout / stderr); the rest is discarded
    max_artifacts: int = 16
    max_artifact_bytes: int = 1024 * 1024  #: per artifact
    max_artifacts_total_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        for name, v in asdict(self).items():
            if isinstance(v, bool) or not isinstance(v, int | float) or not v > 0:
                raise ValueError(f"limit {name} must be a positive number, got {v!r}")
            if name != "wall_seconds" and not isinstance(v, int):
                raise ValueError(f"limit {name} must be an integer, got {v!r}")

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any] | None) -> SandboxLimits:
        raw = dict(raw or {})
        unknown = set(raw) - {f.name for f in fields(cls)}
        if unknown:
            raise ValueError(f"unknown sandbox limits: {sorted(unknown)}")
        return cls(**raw)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def exceeds(self, ceiling: SandboxLimits) -> list[str]:
        """Names of the limits that are larger than ``ceiling`` allows."""
        mine, cap = asdict(self), asdict(ceiling)
        return [name for name, v in mine.items() if v > cap[name]]


@dataclass(frozen=True)
class SandboxSpec:
    language: str
    code: str = field(repr=False)  #: never logged; ``describe()`` is the loggable form
    limits: SandboxLimits = field(default_factory=SandboxLimits)
    #: Outbound network.  False (the default) means a network namespace with no interfaces up.
    #: True is only honoured by a backend explicitly configured with ``allow_network=True`` and is
    #: only ever set by deployment wiring after a policy gate decision, never by the agent.
    network: bool = False
    #: Extra environment variables (the environment is otherwise EMPTY of host variables).
    env: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.language not in SUPPORTED_LANGUAGES:
            raise SandboxPolicyError(f"unsupported language {self.language!r}")
        if len(self.code.encode()) > _MAX_CODE_BYTES:
            raise SandboxPolicyError("code too large")
        for k, v in self.env.items():
            if (
                not k.replace("_", "").isalnum()
                or k.upper().startswith(_FORBIDDEN_ENV_PREFIXES)
                or k.upper() in {"PATH", "HOME", "TMPDIR", "AXIS_OUTPUT_DIR"}
                or len(v) > _MAX_ENV_VALUE
                or "\x00" in v
            ):
                raise SandboxPolicyError(f"environment variable {k!r} is not allowed")

    @property
    def code_sha256(self) -> str:
        return sha256_hex(self.code.encode())

    def describe(self) -> dict[str, Any]:
        """What may be logged: no code text."""
        return {
            "language": self.language,
            "code_sha256": self.code_sha256,
            "code_bytes": len(self.code.encode()),
            "network": self.network,
            "limits": self.limits.to_dict(),
        }


@dataclass(frozen=True)
class Artifact:
    path: str  #: relative to the output directory, ``/`` separated
    size: int
    sha256: str
    content: bytes = field(repr=False)


@dataclass(frozen=True)
class SkippedArtifact:
    path: str
    reason: str


@dataclass(frozen=True)
class ResourceUsage:
    cpu_user_seconds: float = 0.0
    cpu_system_seconds: float = 0.0
    max_rss_kib: int = 0


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int | None  #: None when the process was killed by a signal
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    stdout_bytes: int  #: total bytes the process wrote, including discarded ones
    stderr_bytes: int
    duration_seconds: float
    usage: ResourceUsage = field(default_factory=ResourceUsage)
    artifacts: tuple[Artifact, ...] = ()
    skipped_artifacts: tuple[SkippedArtifact, ...] = ()
    #: wall_timeout | cpu_limit | file_size_limit | output_limit | disk_limit | killed |
    #: signal:<NAME> | cancelled | None
    killed_reason: str | None = None
    signal: str | None = None
    #: What isolation this run actually had, so callers (and the audit trail) never assume.
    isolation: Mapping[str, Any] = field(default_factory=dict)

    @property
    def truncated(self) -> bool:
        return self.stdout_truncated or self.stderr_truncated

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and self.killed_reason is None

    def to_dict(self) -> dict[str, Any]:
        """JSON-able form returned to the agent (artifact bytes base64)."""
        return {
            "exit_code": self.exit_code,
            "ok": self.ok,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "duration_seconds": round(self.duration_seconds, 4),
            "usage": {
                "cpu_user_seconds": self.usage.cpu_user_seconds,
                "cpu_system_seconds": self.usage.cpu_system_seconds,
                "max_rss_kib": self.usage.max_rss_kib,
            },
            "artifacts": [
                {
                    "path": a.path,
                    "size": a.size,
                    "sha256": a.sha256,
                    "content_b64": base64.b64encode(a.content).decode(),
                }
                for a in self.artifacts
            ],
            "skipped_artifacts": [
                {"path": s.path, "reason": s.reason} for s in self.skipped_artifacts
            ],
            "killed_reason": self.killed_reason,
            "signal": self.signal,
            "isolation": dict(self.isolation),
        }

    def audit_summary(self) -> dict[str, Any]:
        """What the audit log stores: hashes and sizes, never output text or artifact bytes."""
        return {
            "exit_code": self.exit_code,
            "ok": self.ok,
            "stdout_sha256": sha256_hex(self.stdout.encode()),
            "stderr_sha256": sha256_hex(self.stderr.encode()),
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "truncated": self.truncated,
            "duration_seconds": round(self.duration_seconds, 4),
            "usage": {
                "cpu_user_seconds": self.usage.cpu_user_seconds,
                "cpu_system_seconds": self.usage.cpu_system_seconds,
                "max_rss_kib": self.usage.max_rss_kib,
            },
            "artifacts": [
                {"path": a.path, "size": a.size, "sha256": a.sha256} for a in self.artifacts
            ],
            "skipped_artifacts": [
                {"path": s.path, "reason": s.reason} for s in self.skipped_artifacts
            ],
            "killed_reason": self.killed_reason,
            "signal": self.signal,
            "isolation": dict(self.isolation),
        }


class SandboxBackend(Protocol):
    """Runs one spec to completion.  Implementations MUST fail closed: raise
    ``SandboxUnavailableError`` rather than run code with weaker isolation than the spec needs."""

    async def run(self, spec: SandboxSpec) -> SandboxResult: ...
