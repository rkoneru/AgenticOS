import { open, seal } from "./crypto.js";
import { randomBytes } from "node:crypto";

export interface DataKey {
  keyId: string;
  plaintext: Buffer;
  wrapped: Buffer;
}

/**
 * Key management port. The production implementation is a cloud KMS (NEEDS #183); `LocalKms` is a FAKE for tests and dev.
 * The tenant id is bound as encryption context: a wrapped key from tenant A cannot be unwrapped for tenant B.
 */
export interface Kms {
  generateDataKey(tenantId: string): Promise<DataKey>;
  unwrap(tenantId: string, keyId: string, wrapped: Uint8Array): Promise<Buffer>;
}

export class LocalKms implements Kms {
  constructor(
    private readonly keys: Readonly<Record<string, Uint8Array>>,
    private readonly activeKeyId: string,
  ) {
    if (!keys[activeKeyId]) throw new Error("active KMS key id is not in the key ring");
  }

  generateDataKey(tenantId: string): Promise<DataKey> {
    const plaintext = randomBytes(32);
    const master = this.keys[this.activeKeyId] as Uint8Array;
    const wrapped = seal(master, plaintext, `axis-kms:${tenantId}:${this.activeKeyId}`);
    return Promise.resolve({ keyId: this.activeKeyId, plaintext, wrapped });
  }

  unwrap(tenantId: string, keyId: string, wrapped: Uint8Array): Promise<Buffer> {
    const master = this.keys[keyId];
    if (!master) return Promise.reject(new Error("unknown KMS key id"));
    try {
      return Promise.resolve(open(master, wrapped, `axis-kms:${tenantId}:${keyId}`));
    } catch {
      return Promise.reject(new Error("KMS unwrap failed"));
    }
  }
}
