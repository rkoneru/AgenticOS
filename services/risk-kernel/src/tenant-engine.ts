import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { WasmPolicyEngine, type PolicyEngine } from "./engine.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * DEV mechanism (docs/NEEDS.md, Phase 6 wiring; not production): a policy engine that serves EACH TENANT its own compiled policy,
 * read from `<dir>/<tenant uuid>.tar.gz`, the file the control plane writes when a tenant activates a pack (`FileBundleSink`).
 *
 *  - The tenant is the one in the policy input, which the kernel fills from the authenticated gRPC principal (never from the request body).
 *  - FAIL-CLOSED: a tenant with no bundle, an unreadable or invalid bundle, or a tenant id that is not a UUID rejects the evaluation,
 *    which the kernel turns into DENY (and audits). There is no default policy and no fallback to another tenant's bundle.
 *  - A bundle is reloaded when its file changes (inode, size or mtime: the control plane replaces it atomically), so an activation
 *    takes effect on the next evaluation. A bundle that fails to load keeps NOTHING cached (the next evaluation tries again), and
 *    the previous good engine is dropped: a corrupt update denies rather than silently serving a stale policy.
 */
export class TenantBundleEngine implements PolicyEngine {
  private readonly cache = new Map<string, { stamp: string; engine: WasmPolicyEngine }>();
  private readonly loading = new Map<string, Promise<WasmPolicyEngine>>();

  constructor(private readonly dir: string) {}

  async evaluate(input: Record<string, unknown>): Promise<unknown> {
    const tenant = (input["tenant"] as { id?: unknown } | undefined)?.id;
    if (typeof tenant !== "string" || !UUID.test(tenant))
      throw new Error("no valid tenant in the policy input");
    return (await this.engineFor(tenant)).evaluate(input);
  }

  private engineFor(tenant: string): Promise<WasmPolicyEngine> {
    const file = join(this.dir, `${tenant}.tar.gz`);
    let stamp: string;
    try {
      const st = statSync(file);
      stamp = `${st.ino}:${st.size}:${st.mtimeMs}`;
    } catch {
      this.cache.delete(tenant);
      return Promise.reject(new Error("no policy bundle for this tenant"));
    }
    const hit = this.cache.get(tenant);
    if (hit?.stamp === stamp) return Promise.resolve(hit.engine);
    const key = `${tenant}:${stamp}`;
    let p = this.loading.get(key);
    if (!p) {
      this.cache.delete(tenant);
      p = WasmPolicyEngine.fromBundle(readFileSync(file)).then(
        (engine) => {
          this.cache.set(tenant, { stamp, engine });
          this.loading.delete(key);
          return engine;
        },
        (err: unknown) => {
          this.loading.delete(key);
          throw err;
        },
      );
      this.loading.set(key, p);
    }
    return p;
  }
}

/** DEV: the kernel's token table re-read when its file changes, so a tenant created after the kernel started can be given a token. */
export class ReloadingTokenTable<P> {
  private stamp = "";
  private table: Record<string, P> = {};
  constructor(private readonly path: string) {}

  get(token: string): P | undefined {
    try {
      const st = statSync(this.path);
      const stamp = `${st.ino}:${st.size}:${st.mtimeMs}`;
      if (stamp !== this.stamp) {
        this.table = JSON.parse(readFileSync(this.path, "utf8")) as Record<string, P>;
        this.stamp = stamp;
      }
    } catch {
      this.table = {}; // an unreadable table authenticates nobody (fail-closed)
      this.stamp = "";
    }
    return Object.prototype.hasOwnProperty.call(this.table, token) ? this.table[token] : undefined;
  }
}
