import { gunzipSync } from "node:zlib";
import { loadPolicy } from "@open-policy-agent/opa-wasm";

/** Raw policy evaluation. The output is untrusted: `Authorizer` validates it and treats anything unexpected as DENY. */
export interface PolicyEngine {
  evaluate(input: Record<string, unknown>): Promise<unknown>;
}

/** Extracts `policy.wasm` from an `opa build -t wasm` bundle (.tar.gz). Same procedure as the Risk Kernel's engine. */
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
    if (name.endsWith("policy.wasm"))
      return new Uint8Array(tar.subarray(off + 512, off + 512 + size));
    off += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error("bundle contains no policy.wasm");
}

type WasmPolicy = { evaluate(input: unknown, entrypoint?: string | number): { result: unknown }[] };

export class WasmPolicyEngine implements PolicyEngine {
  private constructor(private readonly policy: WasmPolicy) {}

  static async fromBundle(tarGz: Uint8Array): Promise<WasmPolicyEngine> {
    return new WasmPolicyEngine((await loadPolicy(extractWasm(tarGz))) as unknown as WasmPolicy);
  }

  evaluate(input: Record<string, unknown>): Promise<unknown> {
    try {
      return Promise.resolve(this.policy.evaluate(input)[0]?.result);
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)));
    }
  }
}
