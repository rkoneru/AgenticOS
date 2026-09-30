import { readFileSync } from "node:fs";
import { findCaseFiles, opaEval, parseCaseFile } from "@axis/policy";
import { dirname, resolve } from "node:path";
import { compilePolicySet } from "@axis/policy";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { WasmPolicyEngine, extractWasm, validatePolicyResult } from "../src/index.js";
import { opaBuildWasm } from "@axis/policy";
import { compileDefault, policiesDir } from "./helpers.js";

/**
 * Differential test: for every case in every shipped *.cases.yaml, the in-process Wasm engine used by the kernel must return
 * exactly what the reference OPA evaluator returns for the same Rego. Guards against Wasm/Rego divergence (ADR-0004).
 */
describe("Wasm engine == opa eval on every shipped policy case", () => {
  for (const file of findCaseFiles(policiesDir.pathname)) {
    const cf = parseCaseFile(parse(readFileSync(file, "utf8")));
    const docs = cf.packs.map((p) => parse(readFileSync(resolve(dirname(file), p), "utf8")));
    const compiled = compilePolicySet(docs);
    if (!compiled.ok) throw new Error(JSON.stringify(compiled.issues));
    describe(file.split("/policies/")[1] as string, () => {
      let engine: WasmPolicyEngine;
      it("loads", async () => {
        engine = await WasmPolicyEngine.fromBundle(opaBuildWasm(compiled.rego));
      });
      for (const c of cf.cases) {
        it(c.name, async () => {
          const wasm = await engine.evaluate(c.input);
          expect(wasm).toEqual(opaEval(compiled.rego, c.input));
          const v = validatePolicyResult(wasm);
          expect(v.ok).toBe(true);
          if (v.ok) expect(v.value.decision).toBe(c.expect.decision);
        });
      }
    });
  }
});

describe("bundle extraction", () => {
  it("rejects bundles without a policy.wasm", async () => {
    const { gzipSync } = await import("node:zlib");
    expect(() => extractWasm(gzipSync(Buffer.alloc(1024)))).toThrow(/no policy.wasm/);
  });
  it("rejects garbage", () => {
    expect(() => extractWasm(new Uint8Array([1, 2, 3]))).toThrow();
  });
});

describe("validatePolicyResult", () => {
  it("rejects non-objects", () => {
    expect(validatePolicyResult(3)).toMatchObject({ ok: false });
    expect(validatePolicyResult(null)).toMatchObject({ ok: false });
  });
});

describe("WasmPolicyEngine error paths", () => {
  it("rejects (so the kernel denies) when the input cannot be serialised for Wasm", async () => {
    const engine = await WasmPolicyEngine.fromBundle(compileDefault().bundle);
    await expect(engine.evaluate({ n: 10n })).rejects.toThrow();
  });
});
