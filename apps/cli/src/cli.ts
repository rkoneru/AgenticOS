import type { Axis } from "@axis/sdk";
import { CliError, EXIT, UsageError } from "./exit.js";
import type { OutputFormat, Style } from "./render.js";

export interface FlagSpec {
  name: string;
  short?: string;
  type: "string" | "boolean" | "number" | "repeat";
  desc: string;
  placeholder?: string;
  /** Allowed values for string flags. */
  choices?: readonly string[];
}

export type FlagValue = string | number | boolean | string[];

export interface Deps {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: Record<string, string | undefined>;
  fetch?: typeof fetch;
  /** Entire stdin as text (for `--with-key-stdin`, `--input -`). */
  readStdin?: () => Promise<string>;
  /** Prompt for a secret without echo. */
  readSecret?: (prompt: string) => Promise<string>;
  isTTY?: boolean;
  now?: () => Date;
  sleep?: (ms: number) => Promise<void>;
}

export interface Ctx {
  /** Positional arguments after the command path. */
  args: string[];
  flags: Record<string, FlagValue>;
  deps: Deps;
  format: OutputFormat;
  style: Style;
  out: (line: string) => void;
  err: (line: string) => void;
  /** Authenticated SDK client (throws a CliError with exit 3 when no credentials are configured). */
  client: () => Axis;
  str: (name: string) => string | undefined;
  num: (name: string) => number | undefined;
  bool: (name: string) => boolean;
  list: (name: string) => string[];
}

export interface Command {
  path: readonly string[];
  summary: string;
  /** Usage tail after the path, e.g. "<id> [--after <n>]". */
  usage?: string;
  description?: string;
  flags?: readonly FlagSpec[];
  examples?: readonly string[];
  /** Absent for group nodes such as `run`. */
  run?: (ctx: Ctx) => Promise<number>;
  /** Command exists but its endpoint is not in the API yet. */
  placeholder?: boolean;
}

export const GLOBAL_FLAGS: readonly FlagSpec[] = [
  { name: "json", type: "boolean", desc: "Shorthand for --output json" },
  {
    name: "output",
    short: "o",
    type: "string",
    placeholder: "<fmt>",
    choices: ["table", "json", "yaml"],
    desc: "Output format: table (default), json or yaml",
  },
  {
    name: "profile",
    type: "string",
    placeholder: "<name>",
    desc: "Credentials profile (default: AXIS_PROFILE, else the default profile)",
  },
  {
    name: "base-url",
    type: "string",
    placeholder: "<url>",
    desc: "API base URL (default: AXIS_BASE_URL, else the profile, else the spec default)",
  },
  {
    name: "timeout",
    type: "number",
    placeholder: "<seconds>",
    desc: "Per-request timeout in seconds (default 30)",
  },
  { name: "no-color", type: "boolean", desc: "Disable colour (also honours NO_COLOR)" },
  { name: "help", short: "h", type: "boolean", desc: "Show help" },
  { name: "version", short: "V", type: "boolean", desc: "Show the CLI version" },
];

export interface Parsed {
  command: Command | undefined;
  /** The command path tokens consumed. */
  path: string[];
  args: string[];
  flags: Record<string, FlagValue>;
}

/** Levenshtein distance, for "did you mean" hints. */
export function distance(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [
    i,
    ...new Array<number>(b.length).fill(0),
  ]);
  for (let j = 1; j <= b.length; j++) (dp[0] as number[])[j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      (dp[i] as number[])[j] = Math.min(
        (dp[i - 1] as number[])[j]! + 1,
        (dp[i] as number[])[j - 1]! + 1,
        (dp[i - 1] as number[])[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
    }
  }
  return (dp[a.length] as number[])[b.length] as number;
}

export function suggest(word: string, candidates: readonly string[]): string | undefined {
  let best: string | undefined;
  let bestD = 3;
  for (const c of candidates) {
    const d = distance(word, c);
    if (d < bestD) {
      best = c;
      bestD = d;
    }
  }
  return best;
}

/** Longest command-path match over the table, then flags/positionals against that command's flag set. */
export function parseArgv(argv: readonly string[], commands: readonly Command[]): Parsed {
  // 1. find the command path: consume leading non-flag tokens while they extend a known path
  const path: string[] = [];
  let i = 0;
  let command: Command | undefined;
  const flagTakesValue = (tok: string): boolean => {
    const name = tok.replace(/^--?/, "");
    const spec = GLOBAL_FLAGS.find((f) => f.name === name || f.short === name);
    return !!spec && spec.type !== "boolean" && !tok.includes("=");
  };
  while (i < argv.length) {
    const tok = argv[i] as string;
    if (tok.startsWith("-")) {
      i += flagTakesValue(tok) ? 2 : 1; // global flags may precede the command
      continue;
    }
    const next = [...path, tok];
    if (
      commands.some((c) => c.path.length >= next.length && next.every((p, k) => c.path[k] === p))
    ) {
      path.push(tok);
      i++;
      const exact = commands.find((c) => c.path.join(" ") === path.join(" "));
      if (exact) command = exact;
      continue;
    }
    break;
  }
  const rest: string[] = [];
  const consumedPath = [...path];
  // 2. split the remaining tokens into flags and positionals
  const specs = [...GLOBAL_FLAGS, ...(command?.flags ?? [])];
  const flags: Record<string, FlagValue> = {};
  const args: string[] = [];
  let pathLeft = [...consumedPath];
  let onlyPositional = false;
  for (let k = 0; k < argv.length; k++) {
    const tok = argv[k] as string;
    if (onlyPositional) {
      args.push(tok);
      continue;
    }
    if (tok === "--") {
      onlyPositional = true;
      continue;
    }
    if (tok.startsWith("-") && tok.length > 1 && !/^-\d/.test(tok)) {
      const long = tok.startsWith("--");
      const [rawName, inline] = splitFlag(tok);
      const spec = specs.find((s) => (long ? s.name === rawName : s.short === rawName));
      if (!spec) {
        const hint = suggest(
          rawName,
          specs.map((s) => s.name),
        );
        throw new UsageError(
          `unknown option ${tok.split("=")[0]}`,
          hint ? [`did you mean --${hint}?`] : ["run with --help to list the options"],
        );
      }
      if (spec.type === "boolean") {
        if (inline !== undefined)
          throw new UsageError(`option --${spec.name} does not take a value`);
        flags[spec.name] = true;
        continue;
      }
      let value = inline;
      if (value === undefined) {
        const nextTok = argv[k + 1];
        if (
          nextTok === undefined ||
          (nextTok.startsWith("-") && nextTok !== "-" && !/^-\d/.test(nextTok))
        ) {
          throw new UsageError(`option --${spec.name} needs a value`);
        }
        value = nextTok;
        k++;
      }
      if (spec.type === "number") {
        const n = Number(value);
        if (value.trim() === "" || !Number.isFinite(n))
          throw new UsageError(`option --${spec.name} needs a number (got "${value}")`);
        flags[spec.name] = n;
      } else if (spec.type === "repeat") {
        const cur = flags[spec.name];
        flags[spec.name] = [...(Array.isArray(cur) ? cur : []), value];
      } else {
        if (spec.choices && !spec.choices.includes(value)) {
          throw new UsageError(
            `option --${spec.name} must be one of ${spec.choices.join(", ")} (got "${value}")`,
          );
        }
        flags[spec.name] = value;
      }
      continue;
    }
    if (pathLeft.length > 0 && tok === pathLeft[0]) {
      pathLeft = pathLeft.slice(1);
      continue;
    }
    rest.push(tok);
    args.push(tok);
  }
  return { command, path: consumedPath, args, flags };
}

function splitFlag(tok: string): [string, string | undefined] {
  const body = tok.replace(/^--?/, "");
  const eq = body.indexOf("=");
  return eq === -1 ? [body, undefined] : [body.slice(0, eq), body.slice(eq + 1)];
}

export function helpFor(
  command: Command | undefined,
  path: readonly string[],
  commands: readonly Command[],
  version: string,
): string {
  const lines: string[] = [];
  const children = (prefix: readonly string[]) =>
    commands.filter(
      (c) =>
        !isHidden(c) &&
        c.path.length === prefix.length + 1 &&
        prefix.every((p, i) => c.path[i] === p),
    );
  if (!command && path.length === 0) {
    lines.push(
      `axis ${version} - AXIS control plane CLI`,
      "",
      "Usage: axis <command> [options]",
      "",
      "Commands:",
    );
    const top = children([]);
    const w = Math.max(...top.map((c) => (c.path[0] as string).length));
    for (const c of top) lines.push(`  ${(c.path[0] as string).padEnd(w)}  ${c.summary}`);
    lines.push(
      "",
      "Run `axis <command> --help` for a command's options.",
      "",
      ...globalHelp(),
      "",
      ...exitCodeHelp(),
    );
    return lines.join("\n");
  }
  const name = `axis ${path.join(" ")}`;
  const sub = children(path);
  lines.push(`${name} - ${command?.summary ?? ""}`.trimEnd(), "");
  if (command?.run)
    lines.push(`Usage: ${name}${command.usage ? ` ${command.usage}` : ""} [options]`);
  if (command?.description) lines.push("", command.description);
  if (sub.length > 0) {
    lines.push("", "Commands:");
    const w = Math.max(...sub.map((c) => c.path.slice(path.length).join(" ").length));
    for (const c of sub)
      lines.push(`  ${c.path.slice(path.length).join(" ").padEnd(w)}  ${c.summary}`);
  }
  if (command?.flags?.length) {
    lines.push("", "Options:", ...flagLines(command.flags));
  }
  if (command?.examples?.length)
    lines.push("", "Examples:", ...command.examples.map((e) => `  ${e}`));
  lines.push("", ...globalHelp());
  return lines.join("\n");
}

const isHidden = (c: Command): boolean => c.path[0] === "docs";

function flagLines(flags: readonly FlagSpec[]): string[] {
  const left = flags.map(
    (f) =>
      `${f.short ? `-${f.short}, ` : "    "}--${f.name}${f.type === "boolean" ? "" : ` ${f.placeholder ?? "<value>"}`}`,
  );
  const w = Math.max(...left.map((l) => l.length));
  return flags.map((f, i) => `  ${(left[i] as string).padEnd(w)}  ${f.desc}`);
}

function globalHelp(): string[] {
  return ["Global options:", ...flagLines(GLOBAL_FLAGS)];
}

export const EXIT_CODE_LINES: readonly string[] = [
  "0  success",
  "1  error (API error, validation failure, network, feature not yet available)",
  "2  usage error (bad command line)",
  "3  authentication or permission failure (also: unsafe config file permissions)",
  "4  denied by policy",
  "5  approval pending, or a wait timed out",
];

function exitCodeHelp(): string[] {
  return ["Exit codes:", ...EXIT_CODE_LINES.map((l) => `  ${l}`)];
}

/** Markdown command reference (docs/spec/cli.md embeds it; a test keeps the two identical). */
export function markdownReference(commands: readonly Command[]): string {
  const out: string[] = [];
  for (const c of commands) {
    if (!c.run || isHidden(c)) continue;
    out.push(
      `### \`axis ${c.path.join(" ")}\``,
      "",
      c.summary + (c.placeholder ? " **(not yet available: the API has no endpoint for it)**" : ""),
      "",
    );
    out.push("```", `axis ${c.path.join(" ")}${c.usage ? ` ${c.usage}` : ""} [options]`, "```", "");
    if (c.description) out.push(c.description, "");
    if (c.flags?.length) {
      out.push("| Option | Description |", "| --- | --- |");
      for (const f of c.flags) {
        out.push(
          `| \`${f.short ? `-${f.short}, ` : ""}--${f.name}${f.type === "boolean" ? "" : ` ${f.placeholder ?? "<value>"}`}\` | ${f.desc} |`,
        );
      }
      out.push("");
    }
  }
  return out.join("\n").trimEnd();
}

export { CliError, EXIT };
