/**
 * DEV ENTRY POINT (not production). The gateway needs live control-plane, approvals, audit and billing objects, which the Phase 6
 * stack builds in one process (`e2e/scripts/saas-stack.mjs`); a standalone process wiring is Phase 10. This file documents the
 * environment contract the e2e stack script uses when it embeds the gateway through `wireGateway`:
 *   GW_PORT (0 = random), GW_ALLOWED_ORIGINS (comma separated), GW_RUN_SERVICE_URL, GW_RUN_TOKENS (JSON tenant -> token),
 *   GW_KERNEL_TARGET, GW_KERNEL_TOKENS (JSON tenant -> token).
 */
console.error(
  "api-gateway: embed `wireGateway` from a stack script (see e2e/scripts); no standalone wiring yet (docs/NEEDS.md #218)",
);
process.exit(2);
