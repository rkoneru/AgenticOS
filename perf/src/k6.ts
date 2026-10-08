/** Runs the committed k6 scripts when a k6 binary is available (K6 env var or perf/.bin/k6); records the summary or says it was not run. */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ROOT, type StackInfo, type Tenant } from "./stack.js";

export interface K6Run {
  script: string;
  status: "ran" | "not-run";
  exitCode?: number;
  reason?: string;
  version?: string;
  metrics?: Record<string, unknown>;
}

export function k6Binary(): string | undefined {
  const p = process.env["K6"] ?? join(ROOT, "perf/.bin/k6");
  return existsSync(p) ? p : undefined;
}

export function runK6(
  script: string,
  info: StackInfo,
  t: Tenant,
  env: Record<string, string>,
): K6Run {
  const bin = k6Binary();
  if (!bin)
    return { script, status: "not-run", reason: "no k6 binary (run perf/install-k6.sh or set K6)" };
  const out = join(mkdtempSync(join(tmpdir(), "axis-k6-")), "summary.json");
  const r = spawnSync(
    bin,
    ["run", "--quiet", "--summary-export", out, join(ROOT, "perf/k6", script)],
    {
      cwd: ROOT,
      encoding: "utf8",
      env: {
        ...process.env,
        BASE_URL: info.gateway,
        API_KEY: t.apiKey,
        KERNEL: info.kernel_target,
        TENANT_ID: t.tenantId,
        KERNEL_TOKEN: t.kernelToken,
        ...env,
      },
    },
  );
  const v = spawnSync(bin, ["version"], { encoding: "utf8" }).stdout.trim();
  let metrics: Record<string, unknown> | undefined;
  try {
    const raw = JSON.parse(readFileSync(out, "utf8")) as { metrics?: Record<string, unknown> };
    metrics = raw.metrics;
  } catch {
    /* no summary: the script failed to start */
  }
  return {
    script,
    status: "ran",
    exitCode: r.status ?? -1,
    version: v,
    ...(metrics ? { metrics } : {}),
    ...(r.status !== 0 ? { reason: (r.stderr || r.stdout).slice(-600) } : {}),
  };
}
