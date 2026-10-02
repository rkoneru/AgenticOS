import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/index.js";
import type { Deps } from "../src/index.js";
import { createMockServer, type MockOptions } from "../../../packages/sdk-ts/test/mock-server.js";

export const KEY = "axk_test_key_123456";

export interface Result {
  code: number;
  out: string;
  err: string;
  server: ReturnType<typeof createMockServer>;
  home: string;
}

export async function axis(
  argv: string[],
  opts: {
    mock?: MockOptions;
    env?: Record<string, string>;
    stdin?: string;
    secret?: string;
    home?: string;
    tty?: boolean;
  } = {},
): Promise<Result> {
  const server = createMockServer(opts.mock ?? {});
  const home = opts.home ?? mkdtempSync(join(tmpdir(), "axis-cli-"));
  let out = "";
  let err = "";
  const deps: Deps = {
    stdout: (s) => void (out += s),
    stderr: (s) => void (err += s),
    env: { XDG_CONFIG_HOME: home, AXIS_API_KEY: KEY, AXIS_BASE_URL: server.baseUrl, ...opts.env },
    fetch: server.fetch,
    sleep: () => Promise.resolve(),
    now: () => new Date("2026-03-15T10:00:00Z"),
    isTTY: opts.tty ?? false,
    ...(opts.stdin !== undefined ? { readStdin: () => Promise.resolve(opts.stdin as string) } : {}),
    ...(opts.secret !== undefined
      ? { readSecret: () => Promise.resolve(opts.secret as string) }
      : {}),
  };
  for (const k of Object.keys(deps.env)) if (deps.env[k] === "") delete deps.env[k];
  const code = await run(argv, deps);
  return { code, out, err, server, home };
}
