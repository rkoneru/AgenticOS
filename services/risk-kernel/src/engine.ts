import { gunzipSync } from "node:zlib";
import { loadPolicy } from "@open-policy-agent/opa-wasm";

/** Raw policy evaluation. Output is untrusted: the kernel validates it (`validatePolicyResult`). */
export interface PolicyEngine {
  evaluate(input: Record<string, unknown>): Promise<unknown>;
}

/** Extracts `policy.wasm` from an `opa build -t wasm` bundle (.tar.gz). */
export function extractWasm(tarGz: Uint8Array): Uint8Array {
  const tar = gunzipSync(tarGz);
  let off = 0;
  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break;
    const name = Buffer.from(header.subarray(0, 100)).toString("utf8").replace(/\0.*$/, "");
    const size = parseInt(
      Buffer.from(header.subarray(124, 136)).toString("utf8").replace(/\0.*$/, "").trim() || "0",
      8,
    );
    const data = tar.subarray(off + 512, off + 512 + size);
    if (name.endsWith("policy.wasm")) return new Uint8Array(data);
    off += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error("bundle contains no policy.wasm");
}

type WasmPolicy = { evaluate(input: unknown, entrypoint?: string | number): { result: unknown }[] };

/**
 * Evaluates a compiled Wasm policy bundle in-process (ADR-0004). Evaluation is synchronous CPU work and cannot be
 * pre-empted; the kernel enforces its time budget after the fact and DENIES an over-budget evaluation.
 */
export class WasmPolicyEngine implements PolicyEngine {
  private constructor(private readonly policy: WasmPolicy) {}

  static async fromBundle(tarGz: Uint8Array): Promise<WasmPolicyEngine> {
    return WasmPolicyEngine.fromWasm(extractWasm(tarGz));
  }

  static async fromWasm(wasm: Uint8Array): Promise<WasmPolicyEngine> {
    return new WasmPolicyEngine((await loadPolicy(wasm)) as unknown as WasmPolicy);
  }

  evaluate(input: Record<string, unknown>): Promise<unknown> {
    try {
      const out = this.policy.evaluate(input);
      return Promise.resolve(out[0]?.result);
    } catch (err) {
      return Promise.reject(err);
    }
  }
}
