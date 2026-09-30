# 0005. Code sandbox: gVisor by default, Firecracker for strict tiers

Status: Accepted · Date: 2026-09-30

## Context

Agent-generated code and browser sessions need isolation: no network by default, CPU/memory/time limits, artifact capture. The platform targets managed K8s on three clouds, the k3s home-lab profile, and customer VPCs.

## Options

1. **gVisor (runsc, K8s RuntimeClass)**: runs in any K8s node pool including nested/virtualized ones, OCI-native, fast start; user-space kernel, not hardware isolation.
2. **Firecracker microVMs**: hardware-virtualization isolation and the strongest boundary; requires bare-metal or nested-virt nodes (not available on many managed pools or the home lab) and its own orchestration.

## Decision

Define a `SandboxRuntime` interface. Default implementation is gVisor via a K8s RuntimeClass, with NetworkPolicy deny-all egress, seccomp, read-only root, and ephemeral volumes. Firecracker (via Kata/firecracker-containerd) is a supported second backend selected per tenant tier for regulated/dedicated pools that provide virtualization-capable nodes.

## Consequences

Phase 4 builds the gVisor backend first; Firecracker is `Designed` until a node pool to test on exists (tracked in `docs/NEEDS.md` at that time). Sandbox images run as non-root and never get tenant secrets.
