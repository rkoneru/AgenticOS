/**
 * DEV ENTRY POINT of the standalone API gateway (not production). All configuration comes from the environment (see
 * `configFromEnv` in `standalone.ts` and docs/spec/api-gateway.md section 7a); it refuses `NODE_ENV=production` because the
 * adapters it composes (static per-tenant token files, fake publisher provers, in-memory blueprint store) are dev-only.
 * Prints one JSON line `{"event":"listening","port":N}` when it serves; exits 0 on SIGTERM/SIGINT after closing the listener.
 */
import { ConfigError, configFromEnv } from "./standalone.js";
import { startStandalone } from "./standalone-wire.js";

try {
  const running = await startStandalone(configFromEnv(process.env));
  console.log(
    JSON.stringify({
      event: "listening",
      port: running.port,
      ...(running.evalRunnerPort !== undefined ? { eval_runner_port: running.evalRunnerPort } : {}),
    }),
  );
  for (const sig of ["SIGTERM", "SIGINT"] as const)
    process.on(sig, () => void running.close().finally(() => process.exit(0)));
} catch (e) {
  console.error(
    e instanceof ConfigError ? `api-gateway: ${e.message}` : "api-gateway: failed to start",
  );
  if (!(e instanceof ConfigError) && e instanceof Error) console.error(e.stack ?? e.message);
  process.exit(e instanceof ConfigError ? 2 : 1);
}
