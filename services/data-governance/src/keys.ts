import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { GovernanceError, norm, type Identifier } from "./types.js";

export type KeyPurpose = "lookup" | "seal" | "audit";

/**
 * Per-tenant key material. Production: derived inside a KMS (docs/NEEDS.md); here a master secret and HKDF. Destroying a tenant's
 * material (or the per-subject salt, see governance_subjects.salt) is the crypto-shred of ADR-0080.
 */
export interface KeyProvider {
  tenantKey(tenantId: string, purpose: KeyPurpose): Promise<Buffer>;
}

export class MasterKeyProvider implements KeyProvider {
  private readonly master: Buffer;
  constructor(master: Buffer = randomBytes(32)) {
    if (master.length < 32) throw new GovernanceError("invalid", "master key must be >= 32 bytes");
    this.master = master;
  }
  async tenantKey(tenantId: string, purpose: KeyPurpose): Promise<Buffer> {
    return Buffer.from(
      hkdfSync(
        "sha256",
        this.master,
        Buffer.from(tenantId),
        Buffer.from(`axis-gov.v1:${purpose}`),
        32,
      ),
    );
  }
}

const hmacHex = (key: Buffer, ...parts: (string | Buffer)[]): string => {
  const h = createHmac("sha256", key);
  parts.forEach((p, i) => {
    if (i > 0) h.update("\u0000");
    h.update(p);
  });
  return h.digest("hex");
};

/** Keyed pseudonymisation. Nothing here is reversible; linkability exists only while the mapping rows / salt exist. */
export class Pseudonymiser {
  constructor(private readonly keys: KeyProvider) {}

  /** Deterministic lookup token for an identifier (the only thing governance_subject_identifiers stores). */
  async lookup(tenantId: string, id: Identifier): Promise<string> {
    return hmacHex(await this.keys.tenantKey(tenantId, "lookup"), id.kind, norm(id));
  }

  /** The reference audit events carry: HMAC of the random subject id. Reveals nothing about the person. */
  async subjectRef(tenantId: string, subjectId: string): Promise<string> {
    return `sub_${hmacHex(await this.keys.tenantKey(tenantId, "audit"), "subject", subjectId).slice(0, 32)}`;
  }

  /** Token written INTO a retained row in place of an identifier. Uses the per-subject salt, so shredding the salt unlinks it. */
  async tokenFor(tenantId: string, salt: Buffer, id: Identifier): Promise<string> {
    const k = await this.keys.tenantKey(tenantId, "audit");
    return `anon_${hmacHex(Buffer.concat([k, salt]), "token", id.kind, norm(id)).slice(0, 24)}`;
  }
}

/** AES-256-GCM sealing of the identifiers a request or hold needs after a crash. Bound to the tenant as AAD. */
export class Sealer {
  constructor(private readonly keys: KeyProvider) {}
  async seal(tenantId: string, value: unknown): Promise<Buffer> {
    const key = await this.keys.tenantKey(tenantId, "seal");
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", key, iv);
    c.setAAD(Buffer.from(tenantId));
    const ct = Buffer.concat([c.update(JSON.stringify(value), "utf8"), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]);
  }
  async open<T>(tenantId: string, blob: Buffer): Promise<T> {
    if (blob.length < 29) throw new GovernanceError("invalid", "sealed blob too short");
    const key = await this.keys.tenantKey(tenantId, "seal");
    const d = createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
    d.setAAD(Buffer.from(tenantId));
    d.setAuthTag(blob.subarray(12, 28));
    try {
      return JSON.parse(
        Buffer.concat([d.update(blob.subarray(28)), d.final()]).toString("utf8"),
      ) as T;
    } catch {
      throw new GovernanceError("invalid", "sealed blob failed authentication");
    }
  }
}
