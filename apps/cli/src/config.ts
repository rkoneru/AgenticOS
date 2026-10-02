import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { CliError, EXIT } from "./exit.js";

export interface Profile {
  apiKey: string;
  baseUrl?: string | undefined;
}

export interface ConfigFile {
  version: 1;
  defaultProfile: string;
  profiles: Record<string, Profile>;
}

type Env = Record<string, string | undefined>;

export function configPath(env: Env): string {
  const base = env["XDG_CONFIG_HOME"] || join(env["HOME"] || homedir(), ".config");
  return join(base, "axis", "config.json");
}

export function emptyConfig(): ConfigFile {
  return { version: 1, defaultProfile: "default", profiles: {} };
}

/**
 * Read the config. A file readable by group or others is refused (like ssh does for private keys): the API key
 * inside is a bearer credential.
 */
export function loadConfig(env: Env): ConfigFile {
  const path = configPath(env);
  if (!existsSync(path)) return emptyConfig();
  if (process.platform !== "win32") {
    const mode = statSync(path).mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new CliError(
        `config file ${path} is accessible by other users (mode ${mode.toString(8)})`,
        EXIT.AUTH,
        [`run: chmod 600 ${path}`],
      );
    }
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new CliError(`config file ${path} is not valid JSON`, EXIT.ERROR, [
      "fix or delete it, then run: axis login",
    ]);
  }
  const c = parsed as Partial<ConfigFile>;
  if (!c || typeof c !== "object" || typeof c.profiles !== "object" || c.profiles === null) {
    throw new CliError(`config file ${path} has an unexpected shape`, EXIT.ERROR, [
      "delete it, then run: axis login",
    ]);
  }
  return { version: 1, defaultProfile: c.defaultProfile ?? "default", profiles: c.profiles };
}

/** Write atomically with mode 0600 inside a 0700 directory. */
export function saveConfig(env: Env, config: ConfigFile): string {
  const path = configPath(env);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
  return path;
}

export interface ResolvedCredentials {
  apiKey: string;
  baseUrl: string | undefined;
  profile: string;
  source: "env" | "profile";
}

/** Precedence: AXIS_API_KEY over the profile's key; --base-url over AXIS_BASE_URL over the profile's URL. */
export function resolveCredentials(
  env: Env,
  opts: { profile?: string | undefined; baseUrl?: string | undefined },
): ResolvedCredentials | undefined {
  const config = loadConfig(env);
  const profile = opts.profile ?? env["AXIS_PROFILE"] ?? config.defaultProfile;
  const stored = config.profiles[profile];
  const envKey = env["AXIS_API_KEY"];
  const apiKey = envKey || stored?.apiKey;
  if (!apiKey) return undefined;
  return {
    apiKey,
    baseUrl: opts.baseUrl ?? (env["AXIS_BASE_URL"] || stored?.baseUrl),
    profile,
    source: envKey ? "env" : "profile",
  };
}
