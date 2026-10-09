# Security documentation index

Labels: "designed for", "evidence-ready". Nothing here claims certification or compliance. Every cited path, test and NEEDS id in the STRIDE files is checked by `make threatmodel-check`; the red-team suite is described in [redteam.md](redteam.md).

## STRIDE threat models (one per component)

Each file has: assets, trust boundaries, data flow, a STRIDE table (threat, mitigation with code path, test file, residual risk or NEEDS id), and dedicated sections for prompt injection and tool misuse.

| Component                                    | File                                               | Earlier per-service model (kept, linked from the STRIDE file)                |
| -------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------- |
| Risk Kernel                                  | [stride-risk-kernel.md](stride-risk-kernel.md)     | [risk-kernel-threat-model.md](risk-kernel-threat-model.md)                   |
| Audit service                                | [stride-audit.md](stride-audit.md)                 |                                                                              |
| Control plane                                | [stride-control-plane.md](stride-control-plane.md) | [control-plane-threat-model.md](control-plane-threat-model.md)               |
| API gateway, run service, AGIL               | [stride-api-gateway.md](stride-api-gateway.md)     | [api-gateway-threat-model.md](api-gateway-threat-model.md)                   |
| Registry                                     | [stride-registry.md](stride-registry.md)           | [registry-marketplace-threat-model.md](registry-marketplace-threat-model.md) |
| Marketplace                                  | [stride-marketplace.md](stride-marketplace.md)     | [registry-marketplace-threat-model.md](registry-marketplace-threat-model.md) |
| Billing                                      | [stride-billing.md](stride-billing.md)             | [billing-threat-model.md](billing-threat-model.md)                           |
| Memory                                       | [stride-memory.md](stride-memory.md)               |                                                                              |
| Channels                                     | [stride-channels.md](stride-channels.md)           | [channels-threat-model.md](channels-threat-model.md)                         |
| Voice                                        | [stride-voice.md](stride-voice.md)                 |                                                                              |
| Approvals                                    | [stride-approvals.md](stride-approvals.md)         |                                                                              |
| Eval Hub and runner                          | [stride-eval-hub.md](stride-eval-hub.md)           | [eval-hub-threat-model.md](eval-hub-threat-model.md)                         |
| Runtime (run loop, TKI, NEXUS, ModelGateway) | [stride-runtime.md](stride-runtime.md)             |                                                                              |
| Code sandbox                                 | [stride-sandbox.md](stride-sandbox.md)             |                                                                              |
| Browser workers                              | [stride-browser.md](stride-browser.md)             | [browser-threat-model.md](browser-threat-model.md)                           |
| MCP client and server                        | [stride-mcp.md](stride-mcp.md)                     |                                                                              |
| Console                                      | [stride-console.md](stride-console.md)             |                                                                              |
| CLI and SDKs                                 | [stride-cli-sdk.md](stride-cli-sdk.md)             |                                                                              |

## Red team

[redteam.md](redteam.md): methodology, the corpus (254 verdicts: 243 attack cases plus 11 API probes), thresholds, the self-check, findings and limits. Run `make redteam` and `make redteam-selfcheck`.

## Reading order for a reviewer

1. [stride-risk-kernel.md](stride-risk-kernel.md) and [stride-runtime.md](stride-runtime.md): the decision path and the model/tool boundary.
2. [redteam.md](redteam.md): what is attacked, what counts as contained, what is not covered.
3. The per-component file of whatever you are about to change.
