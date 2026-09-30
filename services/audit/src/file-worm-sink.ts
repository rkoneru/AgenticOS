import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { link, mkdir, open, readdir, readFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { WormNotFoundError, WormOverwriteError } from "./errors.js";
import type { WormSink } from "./types.js";

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

function assertName(name: string): void {
  if (!NAME_RE.test(name)) throw new TypeError(`invalid object name: ${JSON.stringify(name)}`);
}

async function fsyncDir(dir: string): Promise<void> {
  const fd = await open(dir, constants.O_RDONLY);
  try {
    await fd.sync();
  } finally {
    await fd.close();
  }
}

/**
 * Write-once directory sink. `put` writes a temp file, fsyncs it, then hard-links it to the final name (link(2) fails
 * with EEXIST instead of replacing), so an object is either absent or complete and can never be overwritten through
 * this class. This is software-level write-once: someone with filesystem access can still modify files. Real WORM
 * guarantees need S3 Object Lock or similar (planned, docs/NEEDS.md).
 */
export class FileWormSink implements WormSink {
  constructor(private readonly dir: string) {}

  async put(name: string, data: Uint8Array): Promise<void> {
    assertName(name);
    await mkdir(this.dir, { recursive: true });
    const tmp = join(this.dir, `.tmp-${randomBytes(8).toString("hex")}`);
    const fh = await open(tmp, "wx", 0o444);
    try {
      await fh.writeFile(data);
      await fh.sync();
    } finally {
      await fh.close();
    }
    try {
      await link(tmp, join(this.dir, name));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "EEXIST") {
        throw new WormOverwriteError(`refusing to overwrite existing object ${name}`);
      }
      throw err;
    } finally {
      await unlink(tmp);
    }
    await fsyncDir(this.dir);
  }

  async get(name: string): Promise<Uint8Array> {
    assertName(name);
    try {
      return await readFile(join(this.dir, name));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT")
        throw new WormNotFoundError(`no object ${name}`);
      throw err;
    }
  }

  async list(): Promise<string[]> {
    try {
      return (await readdir(this.dir)).filter((n) => !n.startsWith(".")).sort();
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw err;
    }
  }
}
