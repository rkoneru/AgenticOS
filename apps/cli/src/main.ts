import {
  ApprovalRequiredError,
  AuthenticationError,
  Axis,
  AxisAbortError,
  AxisConnectionError,
  AxisError,
  AxisTimeoutError,
  AxisWaitTimeoutError,
  PermissionError,
  PolicyDeniedError,
  RateLimitError,
  SDK_VERSION,
  ValidationError,
} from "@axis/sdk";
import { COMMANDS } from "./commands.js";
import { resolveCredentials } from "./config.js";
import {
  helpFor,
  parseArgv,
  suggest,
  type Command,
  type Ctx,
  type Deps,
  type FlagValue,
} from "./cli.js";
import { CliError, EXIT, UsageError } from "./exit.js";
import type { OutputFormat } from "./render.js";

export const CLI_VERSION = "0.1.0";

/** Run `axis` with the given arguments. Never throws: returns the process exit code. */
export async function run(argv: readonly string[], deps: Deps): Promise<number> {
  const err = (line: string) => deps.stderr(`${line}\n`);
  try {
    return await dispatch(argv, deps);
  } catch (e) {
    return report(e, deps, err);
  }
}

async function dispatch(argv: readonly string[], deps: Deps): Promise<number> {
  const parsed = parseArgv(argv, COMMANDS);
  const { flags } = parsed;
  const out = (line: string) => deps.stdout(`${line}\n`);
  if (flags["version"]) {
    out(`axis ${CLI_VERSION} (sdk ${SDK_VERSION})`);
    return EXIT.OK;
  }
  const command: Command | undefined = parsed.command;
  if (argv.length === 0 || (parsed.path.length === 0 && flags["help"])) {
    out(helpFor(undefined, [], COMMANDS, CLI_VERSION));
    return argv.length === 0 ? EXIT.USAGE : EXIT.OK;
  }
  if (parsed.path[0] === "help") {
    const target = COMMANDS.find((c) => c.path.join(" ") === parsed.args.join(" "));
    out(helpFor(target, target ? target.path : [], COMMANDS, CLI_VERSION));
    return EXIT.OK;
  }
  if (!command && parsed.path.length === 0) {
    const word = (argv.find((a) => !a.startsWith("-")) ?? "") as string;
    const guess = suggest(word, [...new Set(COMMANDS.map((c) => c.path[0] as string))]);
    throw new UsageError(`unknown command "${word}"`, [
      guess ? `did you mean "axis ${guess}"?` : "run `axis --help` to list the commands",
    ]);
  }
  if (!command) {
    // a path prefix that is only a group, or an unknown subcommand
    const group = COMMANDS.find((c) => c.path.join(" ") === parsed.path.join(" "));
    if (group || flags["help"]) {
      out(helpFor(group, parsed.path, COMMANDS, CLI_VERSION));
      return flags["help"] ? EXIT.OK : EXIT.USAGE;
    }
    throw new UsageError(`unknown command "${parsed.path.join(" ")}"`);
  }
  if (flags["help"] || !command.run) {
    out(helpFor(command, command.path, COMMANDS, CLI_VERSION));
    return flags["help"] ? EXIT.OK : EXIT.USAGE;
  }
  return command.run(makeCtx(parsed.args, flags, deps, out));
}

function makeCtx(
  args: string[],
  flags: Record<string, FlagValue>,
  deps: Deps,
  out: (l: string) => void,
): Ctx {
  const format = (
    flags["json"] ? "json" : ((flags["output"] as OutputFormat | undefined) ?? "table")
  ) satisfies OutputFormat;
  const color = !flags["no-color"] && !deps.env["NO_COLOR"] && deps.isTTY === true;
  let cached: Axis | undefined;
  const timeout = flags["timeout"];
  return {
    args,
    flags,
    deps,
    format,
    style: { color },
    out,
    err: (l) => deps.stderr(`${l}\n`),
    client: () => {
      if (cached) return cached;
      const creds = resolveCredentials(deps.env, {
        profile: flags["profile"] as string | undefined,
        baseUrl: flags["base-url"] as string | undefined,
      });
      if (!creds) {
        throw new CliError("not logged in: no API key found", EXIT.AUTH, [
          "run: axis login",
          "or set AXIS_API_KEY (and AXIS_BASE_URL)",
        ]);
      }
      try {
        cached = new Axis({
          apiKey: creds.apiKey,
          ...(creds.baseUrl ? { baseUrl: creds.baseUrl } : {}),
          ...(deps.fetch ? { fetch: deps.fetch } : {}),
          ...(typeof timeout === "number" ? { timeoutMs: timeout * 1000 } : {}),
          ...(deps.sleep ? { sleep: deps.sleep } : {}),
        });
      } catch (e) {
        throw new CliError(
          e instanceof Error ? e.message : "invalid client configuration",
          EXIT.USAGE,
        );
      }
      return cached;
    },
    str: (n) => (typeof flags[n] === "string" ? (flags[n] as string) : undefined),
    num: (n) => (typeof flags[n] === "number" ? (flags[n] as number) : undefined),
    bool: (n) => flags[n] === true,
    list: (n) => (Array.isArray(flags[n]) ? (flags[n] as string[]) : []),
  };
}

/** Map any thrown value to a clean message and an exit code. Nothing here can print a credential. */
export function report(e: unknown, deps: Deps, err: (line: string) => void): number {
  if (e instanceof CliError) {
    err(`axis: ${e.message}`);
    for (const h of e.hints) err(`  hint: ${h}`);
    return e.exitCode;
  }
  if (e instanceof AxisError) return reportSdk(e, err);
  if (e instanceof TypeError || e instanceof RangeError) {
    err(`axis: ${e.message}`);
    return EXIT.USAGE;
  }
  err(`axis: unexpected error: ${e instanceof Error ? e.message : "unknown"}`);
  return EXIT.ERROR;
}

function ids(e: AxisError, err: (line: string) => void): void {
  if (e.requestId) err(`  request id: ${e.requestId}`);
  if (e.traceId) err(`  trace id: ${e.traceId}`);
}

function reportSdk(e: AxisError, err: (line: string) => void): number {
  err(`axis: ${e.message}`);
  ids(e, err);
  if (e instanceof AuthenticationError) {
    err("  hint: your API key was rejected; run `axis login` or check AXIS_API_KEY");
    return EXIT.AUTH;
  }
  if (e instanceof PermissionError) {
    err("  hint: this credential is not allowed to do that");
    return EXIT.AUTH;
  }
  if (e instanceof PolicyDeniedError) {
    err(
      "  hint: the policy gate denied this request" +
        (e.traceId ? `; inspect it with: axis audit events --trace-id ${e.traceId}` : ""),
    );
    return EXIT.POLICY_DENIED;
  }
  if (e instanceof ApprovalRequiredError) {
    err(
      "  hint: a human decision is required" +
        (e.approvalId
          ? `; approve with: axis approvals approve ${e.approvalId}`
          : "; see: axis approvals list --status pending"),
    );
    return EXIT.APPROVAL_PENDING;
  }
  if (e instanceof AxisWaitTimeoutError) return EXIT.APPROVAL_PENDING;
  if (e instanceof ValidationError) {
    for (const v of e.errors) err(`  ${v.path}: ${v.message}`);
    return EXIT.ERROR;
  }
  if (e instanceof RateLimitError) {
    err(
      `  hint: rate limited${e.retryAfterSeconds !== undefined ? `; retry in ${e.retryAfterSeconds}s` : ""}`,
    );
    return EXIT.ERROR;
  }
  if (e instanceof AxisTimeoutError)
    err("  hint: the request timed out; raise it with --timeout <seconds>");
  else if (e instanceof AxisConnectionError)
    err("  hint: could not reach the API; check --base-url / AXIS_BASE_URL and your network");
  else if (e instanceof AxisAbortError) err("  hint: interrupted");
  return EXIT.ERROR;
}
