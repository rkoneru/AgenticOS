import type { UsageSink } from "@axis/billing";
import type { RegistryService, ServiceAudit } from "@axis/registry";
import { makeCtx } from "./ctx.js";
import type { DocStore } from "./docstore.js";
import { InstallService } from "./installs.js";
import { ListingService } from "./listings.js";
import { PublisherService, type DomainProver, type IdentityProver } from "./publishers.js";
import { ReviewService, type ReviewOptions } from "./reviews.js";

export interface MarketplaceDeps {
  docs: DocStore;
  registry: RegistryService;
  audit: ServiceAudit;
  domain: DomainProver;
  identity: IdentityProver;
  metering?: UsageSink;
  review?: ReviewOptions;
  now?: () => Date;
  newId?: () => string;
}

export interface Marketplace {
  publishers: PublisherService;
  reviews: ReviewService;
  listings: ListingService;
  installs: InstallService;
}

export function createMarketplace(d: MarketplaceDeps): Marketplace {
  const ctx = makeCtx({
    docs: d.docs,
    registry: d.registry,
    audit: d.audit,
    ...(d.now ? { now: d.now } : {}),
    ...(d.newId ? { newId: d.newId } : {}),
  });
  const listings = new ListingService(ctx);
  return {
    publishers: new PublisherService(ctx, { domain: d.domain, identity: d.identity }),
    reviews: new ReviewService(ctx, d.review),
    listings,
    installs: new InstallService(ctx, listings, d.metering),
  };
}
