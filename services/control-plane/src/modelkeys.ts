import { randomUUID } from "node:crypto";
import { open, seal } from "./crypto.js";
import { invalid, notFound } from "./errors.js";
import type { Kms } from "./kms.js";
import type { Principal } from "./authz.js";
import type { ControlPlaneStore, ModelCredentialRecord } from "./types.js";

export interface PublicModelKey {
  id: string;
  provider: string;
  label: string;
  createdAt: Date;
  rotatedAt?: Date;
}

const PROVIDER = /^[a-z][a-z0-9_-]{1,31}$/;
const LABEL = /^[a-z0-9][a-z0-9_.-]{0,62}$/;
const MAX_SECRET = 8192;

const aad = (tenantId: string, provider: string, label: string): string =>
  `axis-byo:${tenantId}:${provider}:${label}`;

/**
 * BYO model keys with envelope encryption. One AES-256 data key per tenant, wrapped by the KMS (tenant bound as context); each
 * secret is AES-256-GCM under that key with (tenant, provider, label) as AAD, so a ciphertext copied to another row or tenant fails
 * to decrypt. Plaintext exists only inside `put` and `revealForRuntime`. No method returns it to an admin caller, and no error
 * message contains it.
 */
export class ModelKeyService {
  private readonly newId: () => string;
  constructor(
    private readonly o: {
      store: ControlPlaneStore;
      kms: Kms;
      now?: () => Date;
      newId?: () => string;
    },
  ) {
    this.newId = o.newId ?? randomUUID;
  }
  private now(): Date {
    return this.o.now ? this.o.now() : new Date();
  }

  private async activeKey(tenantId: string): Promise<{ version: number; dek: Buffer }> {
    let rec = await this.o.store.getActiveTenantKey(tenantId);
    if (!rec) {
      const dk = await this.o.kms.generateDataKey(tenantId);
      try {
        await this.o.store.insertTenantKey({
          tenantId,
          version: 1,
          kmsKeyId: dk.keyId,
          wrappedDek: dk.wrapped,
        });
      } catch {
        // A concurrent first write won the race; use its key.
      }
      rec = await this.o.store.getActiveTenantKey(tenantId);
      if (!rec) throw new Error("tenant key unavailable");
    }
    return {
      version: rec.version,
      dek: await this.o.kms.unwrap(tenantId, rec.kmsKeyId, rec.wrappedDek),
    };
  }

  async put(p: Principal, provider: string, label: string, value: string): Promise<PublicModelKey> {
    if (!PROVIDER.test(provider)) throw invalid("provider must match ^[a-z][a-z0-9_-]{1,31}$");
    if (!LABEL.test(label)) throw invalid("label must match ^[a-z0-9][a-z0-9_.-]{0,62}$");
    if (typeof value !== "string" || value.length === 0 || value.length > MAX_SECRET)
      throw invalid(`secret must be 1-${MAX_SECRET} characters`);
    const { version, dek } = await this.activeKey(p.tenantId);
    const box = seal(dek, Buffer.from(value, "utf8"), aad(p.tenantId, provider, label));
    dek.fill(0);
    const rec = await this.o.store.putModelCredential({
      tenantId: p.tenantId,
      id: this.newId(),
      provider,
      label,
      keyVersion: version,
      nonceAndCiphertext: box,
      createdBy: p.memberId,
      createdAt: this.now(),
    });
    return pub(rec);
  }

  async list(p: Principal): Promise<PublicModelKey[]> {
    return (await this.o.store.listModelCredentials(p.tenantId)).map(pub);
  }

  async delete(p: Principal, provider: string, label: string): Promise<void> {
    if (!(await this.o.store.deleteModelCredential(p.tenantId, provider, label)))
      throw notFound("model key not found");
  }

  /** Runtime path only (tenant is an argument here because the caller is a service credential, see runtime-bridge.ts). */
  async revealForRuntime(
    tenantId: string,
    provider: string,
    label: string,
  ): Promise<string | undefined> {
    const rec = await this.o.store.getModelCredential(tenantId, provider, label);
    if (!rec) return undefined;
    const tk = await this.o.store.getTenantKey(tenantId, rec.keyVersion);
    if (!tk) return undefined;
    const dek = await this.o.kms.unwrap(tenantId, tk.kmsKeyId, tk.wrappedDek);
    try {
      return open(dek, rec.nonceAndCiphertext, aad(tenantId, provider, label)).toString("utf8");
    } catch {
      return undefined;
    } finally {
      dek.fill(0);
    }
  }
}

const pub = (r: ModelCredentialRecord): PublicModelKey => ({
  id: r.id,
  provider: r.provider,
  label: r.label,
  createdAt: r.createdAt,
  ...(r.rotatedAt ? { rotatedAt: r.rotatedAt } : {}),
});
