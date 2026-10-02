import { randomToken, safeEqual, sha256 } from "./crypto.js";
import { conflict, invalid, notFound } from "./errors.js";
import { StoreConflict, type ControlPlaneStore, type VerifiedDomain } from "./types.js";

/**
 * DNS TXT lookup port. STUB: no real resolver is wired (NEEDS #705); `FakeDnsResolver` serves tests. A production resolver must use
 * DNSSEC-validating or DoH resolution and bounded timeouts.
 */
export interface DnsResolver {
  resolveTxt(name: string): Promise<string[]>;
}

export class FakeDnsResolver implements DnsResolver {
  readonly records = new Map<string, string[]>();
  resolveTxt(name: string): Promise<string[]> {
    return Promise.resolve(this.records.get(name) ?? []);
  }
}

const DOMAIN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/;
/** Public mail and shared-hosting domains can never be claimed. Starter list (NEEDS #705). */
const FORBIDDEN = new Set(["gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com", "aol.com", "live.com", "example.com", "localhost"]);

export class DomainService {
  constructor(private readonly o: { store: ControlPlaneStore; dns: DnsResolver; now?: () => Date }) {}

  private norm(domain: string): string {
    const d = String(domain).trim().toLowerCase();
    if (d.length > 253 || !DOMAIN.test(d)) throw invalid("invalid domain");
    if (FORBIDDEN.has(d)) throw invalid("this domain cannot be claimed");
    return d;
  }

  /** Returns the TXT record the admin must publish: `_axis-challenge.<domain>` = `axis-verify=<token>`. Only a hash is stored. */
  async begin(tenantId: string, domain: string): Promise<{ domain: string; recordName: string; recordValue: string }> {
    const d = this.norm(domain);
    const existing = await this.o.store.getDomain(tenantId, d);
    if (existing?.status === "verified") throw conflict("domain already verified");
    const token = randomToken(24);
    await this.o.store.upsertDomain({ tenantId, domain: d, status: "pending", challengeHash: sha256(token) });
    return { domain: d, recordName: `_axis-challenge.${d}`, recordValue: `axis-verify=${token}` };
  }

  async verify(tenantId: string, domain: string): Promise<VerifiedDomain> {
    const d = this.norm(domain);
    const rec = await this.o.store.getDomain(tenantId, d);
    if (!rec?.challengeHash) throw notFound("no verification in progress for this domain");
    const txt = await this.o.dns.resolveTxt(`_axis-challenge.${d}`);
    const ok = txt.some((v) => v.startsWith("axis-verify=") && safeEqual(sha256(v.slice("axis-verify=".length)), rec.challengeHash as Buffer));
    if (!ok) throw invalid("verification record not found");
    const next: VerifiedDomain = { tenantId, domain: d, status: "verified", verifiedAt: (this.o.now ?? (() => new Date()))() };
    try {
      await this.o.store.upsertDomain(next);
    } catch (err) {
      if (err instanceof StoreConflict) throw conflict("this domain is verified by another tenant");
      throw err;
    }
    return next;
  }

  list(tenantId: string): Promise<VerifiedDomain[]> {
    return this.o.store.listDomains(tenantId);
  }
}
