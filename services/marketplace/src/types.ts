import type { TenantPrincipal } from "@axis/registry";

export type { TenantPrincipal };

/** Platform staff. They are NOT tenant members: `tenantId` (when known) lets us refuse a reviewer who belongs to the publisher. */
export interface StaffPrincipal {
  kind: "reviewer" | "moderator";
  subject: string;
  tenantId?: string;
}

export const MARKETPLACE_SERVICE = {
  kind: "platform",
  subject: "svc:marketplace",
  service: "marketplace",
} as const;

export interface PublisherRecord {
  state: "unverified" | "pending" | "verified" | "rejected";
  legalName: string;
  domain: string;
  contactEmail: string;
  /** Random token the publisher must publish (DNS TXT) to prove domain control. */
  challenge: string;
  /** Everyone who acted for this publisher: a reviewer may never be one of them. */
  subjects: string[];
  submittedBy: string;
  submittedAt: string;
  decidedBy: string | null;
  decidedAt: string | null;
  reason: string | null;
  evidenceCount: number;
}

export interface EvidenceRecord {
  kind: "domain_dns_txt" | "identity";
  subject: string;
  result: "passed" | "failed";
  detail: string;
  at: string;
  by: string;
}

export interface ListingRecord {
  namespace: string;
  name: string;
  publisherTenantId: string;
  title: string;
  summary: string;
  categories: string[];
  status: "draft" | "listed" | "taken_down";
  /** Approved versions, each PINNED to the content hash that was reviewed. The only versions that can be installed. */
  approved: {
    version: string;
    contentHash: string;
    riskLevel: string;
    maxSeverity: string;
    approvedAt: string;
  }[];
  /** Versions blocked by a takedown of a single version. */
  blockedVersions: string[];
  createdAt: string;
  takedownReason: string | null;
}

export interface ReviewRecord {
  namespace: string;
  name: string;
  version: string;
  /** The content hash this review is ABOUT. An approval is pinned to it. */
  contentHash: string;
  riskLevel: string;
  state:
    "submitted" | "automated_scan" | "in_review" | "approved" | "rejected" | "changes_requested";
  publisherTenantId: string;
  submittedBy: string;
  submittedAt: string;
  findings: { id: string; severity: string; path: string; message: string }[];
  maxSeverity: string;
  capabilities: { key: string; level: number }[];
  decidedBy: string | null;
  decidedAt: string | null;
  note: string | null;
  acknowledged: string[];
  approvedHash: string | null;
}

export interface InstallRecord {
  id: string;
  namespace: string;
  name: string;
  version: string;
  contentHash: string;
  publisherTenantId: string;
  state: "active" | "flagged" | "uninstalled";
  granted: { key: string; level: number }[];
  consentedBy: string;
  consentedAt: string;
  flagReason: string | null;
  policyPack: unknown;
  /** Metering is delivered at least once, with an idempotency key; null until the billing hook accepted it. */
  meteredAt: string | null;
  installCount: number;
}
