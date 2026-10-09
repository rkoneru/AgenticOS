import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { MemoryKillSwitchStore, type KillScope } from "./stores.js";

/**
 * Kill-switch state that survives a kernel restart (single instance, dev/e2e; production uses Redis, docs/NEEDS.md).
 *
 * The in-memory store forgot every engaged switch when the kernel restarted, so a crash or deploy silently RELEASED a tenant's kill-switch:
 * a fail-OPEN found by the Phase 9 chaos suite. Rules:
 *  - ENGAGE takes effect in memory first and is persisted best-effort (an engage must never be blocked by a disk problem);
 *  - RELEASE is persisted first; if that fails the switch stays engaged and the call fails (never release what cannot be recorded);
 *  - a state file that exists but cannot be parsed makes construction THROW: the kernel refuses to start rather than start with an
 *    empty set it cannot tell from "nothing was engaged".
 */
export interface FileIo {
  write(path: string, data: string): void;
}

const realIo: FileIo = {
  write(path, data) {
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, data, { mode: 0o600 });
    renameSync(tmp, path); // atomic on POSIX: a reader sees the old or the new file, never half of one
  },
};

export class FileKillSwitchStore extends MemoryKillSwitchStore {
  constructor(
    private readonly path: string,
    private readonly io: FileIo = realIo,
  ) {
    super();
    if (existsSync(path)) {
      let doc: unknown;
      try {
        doc = JSON.parse(readFileSync(path, "utf8"));
      } catch {
        throw new Error(`kill-switch state file ${path} is corrupt`);
      }
      const list = (doc as { engaged?: unknown } | null)?.engaged;
      if (!Array.isArray(list) || !list.every((x) => typeof x === "string")) {
        throw new Error(`kill-switch state file ${path} is corrupt`);
      }
      for (const k of list as string[]) this.engaged.add(k);
    }
  }

  private persist(): void {
    this.io.write(this.path, JSON.stringify({ engaged: [...this.engaged].sort() }));
  }

  override async set(
    scope: KillScope,
    t: { tenantId?: string | undefined; target?: string | undefined },
    engaged: boolean,
  ): Promise<void> {
    await super.set(scope, t, engaged);
    try {
      this.persist();
    } catch (err) {
      if (engaged) return; // engaged in memory; a disk problem must not un-engage or block it
      await super.set(scope, t, true); // the release could not be recorded: put it back
      throw err;
    }
  }
}
