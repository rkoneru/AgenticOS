"""Code sandbox: backend protocol, result types, and the process-level ``LocalProcessBackend``.

Process-level isolation, NOT a hard security boundary: see docs/spec/sandbox.md.
"""

from axis_runtime.sandbox.types import (
    SUPPORTED_LANGUAGES,
    Artifact,
    ResourceUsage,
    SandboxBackend,
    SandboxError,
    SandboxLimits,
    SandboxPolicyError,
    SandboxResult,
    SandboxSpec,
    SandboxUnavailableError,
    SkippedArtifact,
    sha256_hex,
)

__all__ = [
    "SUPPORTED_LANGUAGES",
    "Artifact",
    "ResourceUsage",
    "SandboxBackend",
    "SandboxError",
    "SandboxLimits",
    "SandboxPolicyError",
    "SandboxResult",
    "SandboxSpec",
    "SandboxUnavailableError",
    "SkippedArtifact",
    "sha256_hex",
]
