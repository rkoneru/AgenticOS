import { randomUUID } from "node:crypto";
import { chmod, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AuditExportError,
  FileWormSink,
  MANIFEST_NAME,
  MemoryAuditLog,
  WormNotFoundError,
  WormOverwriteError,
  exportRange,
  verifyExport,
  verifyRange,
  type ExportManifest,
} from "../src/index.js";
import { ev } from "./helpers.js";

const dirs: string[] = [];
const freshDir = async () => {
  const d = await mkdtemp(join(tmpdir(), "axis-worm-"));
  dirs.push(d);
  return d;
};
afterEach(async () => {
  for (const d of dirs.splice(0)) {
    for (const f of await readdir(d)) await chmod(join(d, f), 0o644).catch(() => undefined);
    await rm(d, { recursive: true, force: true });
  }
});

async function filled(n: number) {
  const log = new MemoryAuditLog();
  const t = randomUUID();
  for (let i = 0; i < n; i++) await log.append(ev(t));
  return { log, t };
}

const readManifest = async (dir: string): Promise<ExportManifest> =>
  JSON.parse(await readFile(join(dir, MANIFEST_NAME), "utf8"));

describe("WORM export", () => {
  it("round trip: segments + manifest, offline verification, expected layout", async () => {
    const { log, t } = await filled(7);
    const dir = await freshDir();
    const m = await exportRange(log, t, 1, 7, new FileWormSink(dir), {
      segmentSize: 3,
      now: () => new Date("2031-01-02T03:04:05.006Z"),
    });
    expect(m).toMatchObject({
      tenant_id: t,
      first_seq: 1,
      last_seq: 7,
      count: 7,
      segment_size: 3,
      exported_at: "2031-01-02T03:04:05.006Z",
    });
    expect(m.segments.map((s) => [s.name, s.first_seq, s.last_seq, s.count])).toEqual([
      ["segment-000001.ndjson", 1, 3, 3],
      ["segment-000002.ndjson", 4, 6, 3],
      ["segment-000003.ndjson", 7, 7, 1],
    ]);
    expect(m.head_hash).toBe((await log.head(t))!.hash);
    expect((await readdir(dir)).sort()).toEqual([
      "manifest.json",
      ...m.segments.map((s) => s.name),
    ]);
    expect(await verifyExport(new FileWormSink(dir))).toEqual({
      ok: true,
      tenant_id: t,
      first_seq: 1,
      last_seq: 7,
      head_hash: m.head_hash,
      count: 7,
    });
  });

  it("exports a slice anchored on the preceding event and clamps `to` to the head", async () => {
    const { log, t } = await filled(9);
    const dir = await freshDir();
    const m = await exportRange(log, t, 4, 500, new FileWormSink(dir), { segmentSize: 4 });
    expect([m.first_seq, m.last_seq, m.count]).toEqual([4, 9, 6]);
    expect(m.first_prev_hash).toBe((await log.read(t, { fromSeq: 3, toSeq: 3 }))[0]!.hash);
    expect(await verifyExport(new FileWormSink(dir))).toMatchObject({
      ok: true,
      first_seq: 4,
      last_seq: 9,
    });
  });

  it("refuses bad arguments, empty ranges, and broken chains", async () => {
    const { log, t } = await filled(4);
    const sink = () => new FileWormSink(join(tmpdir(), `axis-never-${randomUUID()}`));
    await expect(exportRange(log, t, 0, 3, sink())).rejects.toThrow(RangeError);
    await expect(exportRange(log, t, 3, 2, sink())).rejects.toThrow(RangeError);
    await expect(exportRange(log, t, 1, 3, sink(), { segmentSize: 0 })).rejects.toThrow(RangeError);
    await expect(exportRange(log, t, 10, 20, sink())).rejects.toThrow(AuditExportError); // anchor missing
    await expect(exportRange(log, randomUUID(), 1, 5, sink())).rejects.toThrow(/nothing to export/);

    class T extends MemoryAuditLog {
      c(t: string) {
        return this.chains.get(t)!;
      }
    }
    const bad = new T();
    const bt = randomUUID();
    for (let i = 0; i < 5; i++) await bad.append(ev(bt));
    bad.c(bt)[3]!.action = "evil";
    await expect(exportRange(bad, bt, 1, 5, sink(), { segmentSize: 2 })).rejects.toThrow(
      /chain broken at seq 4/,
    );
    await expect(exportRange(bad, bt, 5, 5, sink())).rejects.toThrow(/corrupt/); // anchor (seq 4) is tampered
    bad.c(bt)[1]!.tenant_id = randomUUID();
    await expect(exportRange(bad, bt, 1, 5, sink())).rejects.toThrow(/another tenant/);
  });

  it("refuses to overwrite: re-exporting into a used sink fails and changes nothing", async () => {
    const { log, t } = await filled(3);
    const dir = await freshDir();
    await exportRange(log, t, 1, 3, new FileWormSink(dir));
    const before = await readFile(join(dir, MANIFEST_NAME), "utf8");
    await expect(exportRange(log, t, 1, 3, new FileWormSink(dir))).rejects.toBeInstanceOf(
      WormOverwriteError,
    );
    expect(await readFile(join(dir, MANIFEST_NAME), "utf8")).toBe(before);
  });

  describe("tamper detection (offline, no DB)", () => {
    async function exported(n = 6, segmentSize = 2) {
      const { log, t } = await filled(n);
      const dir = await freshDir();
      await exportRange(log, t, 1, n, new FileWormSink(dir), { segmentSize });
      return { dir, sink: new FileWormSink(dir), t, log };
    }
    const seg = (dir: string, i: number) => join(dir, `segment-00000${i}.ndjson`);

    it("a modified segment is detected by its hash", async () => {
      const { dir, sink } = await exported();
      await writeFile(
        seg(dir, 2),
        (await readFile(seg(dir, 2), "utf8")).replace("lookup", "evil0x"),
      );
      expect(await verifyExport(sink)).toMatchObject({
        ok: false,
        reason: "segment_hash_mismatch",
      });
    });

    it("a segment rewritten WITH a matching manifest hash is still caught by the chain", async () => {
      const { dir, sink } = await exported();
      const { createHash } = await import("node:crypto");
      const tampered = (await readFile(seg(dir, 2), "utf8")).replace("lookup", "evil00");
      await writeFile(seg(dir, 2), tampered);
      const m = await readManifest(dir);
      m.segments[1]!.sha256 = createHash("sha256").update(tampered).digest("hex");
      await chmod(join(dir, MANIFEST_NAME), 0o644);
      await writeFile(join(dir, MANIFEST_NAME), JSON.stringify(m));
      expect(await verifyExport(sink)).toMatchObject({
        ok: false,
        reason: "chain_broken",
        brokenAtSeq: 3,
      });
    });

    it("a deleted segment, a missing manifest, a stray segment", async () => {
      const a = await exported();
      await rm(seg(a.dir, 2));
      expect(await verifyExport(a.sink)).toMatchObject({ ok: false, reason: "segment_missing" });
      const b = await exported();
      await rm(join(b.dir, MANIFEST_NAME));
      expect(await verifyExport(b.sink)).toMatchObject({ ok: false, reason: "manifest_missing" });
      const c = await exported();
      await writeFile(join(c.dir, "segment-000009.ndjson"), "");
      expect(await verifyExport(c.sink)).toMatchObject({ ok: false, reason: "unexpected_segment" });
      expect(
        await verifyExport(new FileWormSink(join(tmpdir(), `axis-none-${randomUUID()}`))),
      ).toMatchObject({ reason: "manifest_missing" });
    });

    it("manifest problems: invalid shape, wrong head_hash, wrong ranges", async () => {
      const edit = async (mut: (m: ExportManifest & Record<string, unknown>) => void) => {
        const e = await exported();
        const m = (await readManifest(e.dir)) as ExportManifest & Record<string, unknown>;
        mut(m);
        await rm(join(e.dir, MANIFEST_NAME));
        await writeFile(join(e.dir, MANIFEST_NAME), JSON.stringify(m));
        return verifyExport(e.sink);
      };
      expect(await edit((m) => (m.format = "other" as never))).toMatchObject({
        reason: "manifest_invalid",
      });
      expect(await edit((m) => (m.segments = []))).toMatchObject({ reason: "manifest_invalid" });
      expect(await edit((m) => (m.segments[0]!.sha256 = "zz"))).toMatchObject({
        reason: "manifest_invalid",
      });
      expect(await edit((m) => (m.segments[0] = null as never))).toMatchObject({
        reason: "manifest_invalid",
      });
      expect(await edit((m) => (m.tenant_id = "nope"))).toMatchObject({
        reason: "manifest_invalid",
      });
      expect(await edit((m) => (m.head_hash = "1".repeat(64)))).toMatchObject({
        reason: "head_mismatch",
      });
      expect(await edit((m) => (m.segments[1]!.first_seq = 9))).toMatchObject({
        reason: "segment_range_mismatch",
      });
      expect(await edit((m) => (m.last_seq = 5))).toMatchObject({
        reason: "segment_range_mismatch",
      });
      expect(await edit((m) => (m.first_prev_hash = "1".repeat(64)))).toMatchObject({
        reason: "manifest_invalid",
      });
      expect(await edit((m) => (m.tenant_id = randomUUID()))).toMatchObject({
        reason: "chain_broken",
      });
    });

    it("manifest that is not JSON", async () => {
      const e = await exported();
      await rm(join(e.dir, MANIFEST_NAME));
      await writeFile(join(e.dir, MANIFEST_NAME), "{nope");
      expect(await verifyExport(e.sink)).toMatchObject({ reason: "manifest_invalid" });
      await rm(join(e.dir, MANIFEST_NAME));
      await writeFile(join(e.dir, MANIFEST_NAME), "null");
      expect(await verifyExport(e.sink)).toMatchObject({ reason: "manifest_invalid" });
    });

    it("malformed segment contents (with matching hashes): not JSON, schema-invalid, no trailing newline, wrong count", async () => {
      const { createHash } = await import("node:crypto");
      const variants: Array<(orig: string) => string> = [
        (o) => o + "{not json}\n",
        (o) => o + '{"a":1}\n',
        (o) => o.trimEnd(),
        (o) => o.split("\n").slice(0, 1).join("\n") + "\n", // one event instead of two
      ];
      for (const v of variants) {
        const e = await exported();
        const bytes = v(await readFile(seg(e.dir, 1), "utf8"));
        await rm(seg(e.dir, 1));
        await writeFile(seg(e.dir, 1), bytes);
        const m = await readManifest(e.dir);
        m.segments[0]!.sha256 = createHash("sha256").update(bytes).digest("hex");
        await rm(join(e.dir, MANIFEST_NAME));
        await writeFile(join(e.dir, MANIFEST_NAME), JSON.stringify(m));
        const r = await verifyExport(e.sink);
        expect(r.ok).toBe(false);
        expect(["segment_malformed", "segment_range_mismatch"]).toContain(
          (r as { reason: string }).reason,
        );
      }
    });
  });
});

describe("FileWormSink", () => {
  it("put is write-once, get/list work, names are validated, missing objects raise", async () => {
    const dir = join(await freshDir(), "nested");
    const s = new FileWormSink(dir);
    expect(await s.list()).toEqual([]); // directory does not exist yet
    await s.put("a.txt", Buffer.from("one"));
    await expect(s.put("a.txt", Buffer.from("two"))).rejects.toBeInstanceOf(WormOverwriteError);
    expect(Buffer.from(await s.get("a.txt")).toString()).toBe("one");
    expect(await s.list()).toEqual(["a.txt"]);
    await expect(s.get("nope")).rejects.toBeInstanceOf(WormNotFoundError);
    for (const bad of ["../x", "a/b", ".hidden", "", "a b"]) {
      await expect(s.put(bad, Buffer.from("x"))).rejects.toThrow(TypeError);
      await expect(s.get(bad)).rejects.toThrow(TypeError);
    }
    expect((await readdir(dir)).filter((n) => n.startsWith(".tmp-"))).toEqual([]); // no temp litter
  });

  it("propagates unexpected filesystem errors", async () => {
    const d = await freshDir();
    await writeFile(join(d, "file"), "x");
    await expect(new FileWormSink(join(d, "file")).put("a", Buffer.from("x"))).rejects.toThrow(); // dir is a file
    await expect(new FileWormSink(join(d, "file")).list()).rejects.toThrow();
    await expect(new FileWormSink(d).get("file/../")).rejects.toThrow(TypeError);
    // get on a directory entry => EISDIR, not "not found"
    await import("node:fs/promises").then((fs) => fs.mkdir(join(d, "sub")));
    await expect(new FileWormSink(d).get("sub")).rejects.toMatchObject({ code: "EISDIR" });
  });
});

describe("paged verification", () => {
  it("verifyRange gives the same verdict for any page size, including across page boundaries", async () => {
    const { log, t } = await filled(10);
    for (const pageSize of [1, 2, 3, 10, 11, 500]) {
      expect(await verifyRange(log, t, {}, pageSize)).toEqual({ ok: true, length: 10 });
      expect(await verifyRange(log, t, { fromSeq: 4, toSeq: 9 }, pageSize)).toEqual({
        ok: true,
        length: 6,
      });
    }
  });
});
