import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parse } from "yaml";
import {
  CpError,
  FileBundleSink,
  PolicyBundlePublisher,
  WasmPolicyEngine,
  extractWasm,
  type BundleSink,
} from "../src/index.js";
import { makeWorld, type World } from "./world.js";

const PHI = parse(
  readFileSync(
    fileURLToPath(new URL("../../../policies/phi-redaction/pack.yaml", import.meta.url)),
    "utf8",
  ),
) as unknown;

const wasmOf = async (f: string): Promise<string> =>
  Buffer.from(extractWasm(await readFile(f))).toString("base64");

const puts: { id: string; v: string; packs: string[] }[] = [];

describe("policy bundle publication (dev mechanism for the Risk Kernel)", () => {
  let dir: string;
  let w: World;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "cp-bundles-"));
    const file = new FileBundleSink(dir);
    w = await makeWorld("memory", {
      bundleSink: {
        put: (id, b) => {
          puts.push({ id, v: b.policyVersion, packs: b.packs });
          return file.put(id, b);
        },
      },
    });
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
    await w.close();
  });

  it("signup publishes the baseline-deny bundle; activation and deactivation republish; the bundle loads and decides", async () => {
    const t = await w.tenant();
    const file = join(dir, `${t.tenantId}.tar.gz`);
    const base = await readFile(file);
    const baseWasm = await wasmOf(file);
    const engine = await WasmPolicyEngine.fromBundle(base);
    const deny = (await engine.evaluate({
      tenant: { id: t.tenantId },
      enforcement_point: "tool_call",
      tool: { name: "anything" },
    })) as { decision?: string };
    expect(deny.decision).toBe("DENY");

    const v = await w.cp.admin.publishPolicy(t.owner, PHI);
    expect(await wasmOf(file)).toBe(baseWasm); // publishing alone changes nothing
    const act = await w.cp.admin.activatePolicy(t.owner, v.versionId);
    expect(await wasmOf(file)).not.toBe(baseWasm);
    expect(act.policyVersion).toMatch(/\S/);
    await w.cp.admin.deactivatePolicy(t.owner, "phi-redaction");
    const mine = puts.filter((p) => p.id === t.tenantId);
    expect(mine.map((p) => p.packs)).toEqual([
      ["baseline-deny"],
      ["baseline-deny", "phi-redaction"],
      ["baseline-deny"],
    ]);
    expect(mine[2]?.v).toBe(mine[0]?.v); // back to the baseline-deny floor, same policy version
    expect((await readdir(dir)).filter((f) => f.endsWith(".tmp"))).toEqual([]); // atomic writes leave no temp files
  });

  it("a bundle is per tenant: another tenant's file is untouched", async () => {
    const a = await w.tenant();
    const b = await w.tenant();
    const before = await wasmOf(join(dir, `${b.tenantId}.tar.gz`));
    const v = await w.cp.admin.publishPolicy(a.owner, PHI);
    await w.cp.admin.activatePolicy(a.owner, v.versionId);
    expect(await wasmOf(join(dir, `${b.tenantId}.tar.gz`))).toBe(before);
  });

  it("FileBundleSink refuses a tenant id that is not a UUID (no path traversal)", async () => {
    const sink = new FileBundleSink(dir);
    await expect(
      sink.put("../../etc/passwd", { tarGz: new Uint8Array(1), policyVersion: "v", packs: [] }),
    ).rejects.toMatchObject({ code: "invalid" });
    expect(await readdir(dir)).not.toContain("passwd");
  });

  it("a sink or build failure is `unavailable` and never leaks the cause", async () => {
    const t = await w.tenant();
    const failing: BundleSink = { put: () => Promise.reject(new Error("disk /secret/path full")) };
    const pub = new PolicyBundlePublisher({ policies: w.cp.policies, sink: failing });
    const err = await pub.publish(t.tenantId).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CpError);
    expect((err as CpError).code).toBe("unavailable");
    expect((err as CpError).message).not.toContain("secret");
    const broken = new PolicyBundlePublisher({
      policies: w.cp.policies,
      sink: new FileBundleSink(dir),
      build: () => {
        throw new Error("opa missing");
      },
    });
    await expect(broken.publish(t.tenantId)).rejects.toMatchObject({ code: "unavailable" });
  });

  it("an activation whose publication fails reports it (the kernel keeps what it had; a retry republishes)", async () => {
    let fail = true;
    const sink: BundleSink = {
      put: (id, b) =>
        fail ? Promise.reject(new Error("down")) : new FileBundleSink(dir).put(id, b),
    };
    const w2 = await makeWorld("memory", { bundleSink: sink });
    fail = false;
    const t = await w2.tenant();
    const v = await w2.cp.admin.publishPolicy(t.owner, PHI);
    fail = true;
    await expect(w2.cp.admin.activatePolicy(t.owner, v.versionId)).rejects.toMatchObject({
      code: "unavailable",
    });
    fail = false;
    await w2.cp.admin.activatePolicy(t.owner, v.versionId); // idempotent re-activation republishes
    await w2.close();
  });
});
