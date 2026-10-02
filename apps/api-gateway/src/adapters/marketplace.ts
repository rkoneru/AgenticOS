import type { Marketplace } from "@axis/marketplace";
import {
  type InstallPreviewDto,
  type MarketplaceInstallDto,
  type MarketplaceListingDto,
  type MarketplacePort,
  type Principal,
} from "../ports.js";
import { fromRegistryError, registryPrincipal } from "./registry.js";

type Catalog = Awaited<ReturnType<Marketplace["listings"]["catalog"]>>[number];
type Preview = Awaited<ReturnType<Marketplace["installs"]["preview"]>>;
type Install = Awaited<ReturnType<Marketplace["installs"]["install"]>>;

const listingDto = (e: Catalog): MarketplaceListingDto => ({
  namespace: e.namespace,
  name: e.name,
  title: e.title,
  summary: e.summary,
  categories: e.categories,
  latest: e.latest
    ? {
        version: e.latest.version,
        content_hash: e.latest.contentHash,
        risk_level: e.latest.riskLevel,
        max_severity: e.latest.maxSeverity,
      }
    : null,
  versions: e.versions,
});

const previewDto = (p: Preview): InstallPreviewDto => ({
  namespace: p.namespace,
  name: p.name,
  version: p.version,
  content_hash: p.contentHash,
  risk_level: p.riskLevel,
  max_severity: p.maxSeverity,
  findings: p.findings.map((f) => ({
    id: f.id,
    severity: f.severity,
    path: f.path,
    message: f.message,
  })),
  capabilities: p.capabilities.map((c) => ({ key: c.key, level: c.level })),
  diff: {
    added: p.diff.added.map((a) => ({
      key: a.key,
      change: a.change,
      level: a.level,
      previous_level: a.previousLevel,
    })),
    removed: p.diff.removed.map((r) => ({ key: r.key, level: r.level, new_level: r.newLevel })),
    widening: p.diff.widening,
  },
  consent_digest: p.consentDigest,
});

const installDto = (i: Install): MarketplaceInstallDto => ({
  id: i.id,
  namespace: i.namespace,
  name: i.name,
  version: i.version,
  content_hash: i.contentHash,
  state: i.state,
  granted: i.granted.map((c) => ({ key: c.key, level: c.level })),
  consented_by: i.consentedBy,
  consented_at: i.consentedAt,
  flag_reason: i.flagReason,
});

/**
 * The tenant side of the marketplace: catalog reads, install preview / consent / install / uninstall. The principal is the gateway's
 * authenticated one (tenant and role from the credential); publisher onboarding and reviewer/moderator actions are staff and
 * publisher-console concerns that are NOT part of the public API (docs/spec/marketplace.md).
 */
export class MarketplaceAdapter implements MarketplacePort {
  constructor(private readonly mp: Marketplace) {}

  async listings(q: { text?: string; category?: string }): Promise<MarketplaceListingDto[]> {
    try {
      return (await this.mp.listings.catalog(q)).map(listingDto);
    } catch (e) {
      return fromRegistryError(e);
    }
  }
  async listing(namespace: string, name: string): Promise<MarketplaceListingDto> {
    try {
      return listingDto(await this.mp.listings.entry(namespace, name));
    } catch (e) {
      return fromRegistryError(e);
    }
  }
  async preview(
    p: Principal,
    q: { namespace: string; name: string; range: string },
  ): Promise<InstallPreviewDto> {
    try {
      return previewDto(
        await this.mp.installs.preview(registryPrincipal(p), q.namespace, q.name, q.range),
      );
    } catch (e) {
      return fromRegistryError(e);
    }
  }
  async install(
    p: Principal,
    q: {
      namespace: string;
      name: string;
      version: string;
      content_hash: string;
      consent_digest: string;
    },
  ): Promise<MarketplaceInstallDto> {
    try {
      return installDto(
        await this.mp.installs.install(registryPrincipal(p), {
          namespace: q.namespace,
          name: q.name,
          version: q.version,
          contentHash: q.content_hash,
          consentDigest: q.consent_digest,
        }),
      );
    } catch (e) {
      return fromRegistryError(e);
    }
  }
  async installs(p: Principal): Promise<MarketplaceInstallDto[]> {
    try {
      return (await this.mp.installs.list(registryPrincipal(p))).map(installDto);
    } catch (e) {
      return fromRegistryError(e);
    }
  }
  async uninstall(p: Principal, namespace: string, name: string): Promise<void> {
    try {
      await this.mp.installs.uninstall(registryPrincipal(p), namespace, name);
    } catch (e) {
      return fromRegistryError(e);
    }
  }
}
