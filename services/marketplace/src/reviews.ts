import { RegistryError, forbidden, invalid, notFound, type RegistryService } from "@axis/registry";
import type { AblDocument } from "@axis/abl";
import { denyAudit, guarded, iso, mutate, requireRole, requireStaff, type Ctx } from "./ctx.js";
import { DEFAULT_BASELINE } from "./capabilities.js";
import { PLATFORM, tenantScope, type Doc } from "./docstore.js";
import { scanBlueprint, sevRank, type Severity } from "./scan.js";
import { assertReview } from "./states.js";
import {
  MARKETPLACE_SERVICE,
  type ListingRecord,
  type PublisherRecord,
  type ReviewRecord,
  type StaffPrincipal,
  type TenantPrincipal,
} from "./types.js";

export interface ReviewOptions {
  /** If set, blueprints whose worst finding is at or below this severity are approved by the scan without a human. Default: OFF. */
  autoApproveAtOrBelow?: Severity;
}

export const reviewKey = (ns: string, name: string, version: string): string =>
  `${ns}/${name}@${version}`;
/** Reviewers address a review as `<publisher tenant>|<key>`. */
export const reviewId = (tenantId: string, key: string): string => `${tenantId}|${key}`;
export function parseReviewId(id: string): { tenantId: string; key: string } {
  const i = id.indexOf("|");
  if (i < 0) throw invalid("bad review id");
  return { tenantId: id.slice(0, i), key: id.slice(i + 1) };
}

export class ReviewService {
  constructor(
    private readonly c: Ctx,
    private readonly o: ReviewOptions = {},
  ) {}

  private registry(): RegistryService {
    return this.c.registry;
  }

  private async event(
    tenantId: string,
    key: string,
    from: string | null,
    to: string,
    actor: string,
  ): Promise<void> {
    const n = (await this.c.docs.find(PLATFORM, "events", { review: key }, tenantId)).length + 1;
    await this.c.docs.insert(
      PLATFORM,
      tenantId,
      "events",
      `rv:${key}:${String(n).padStart(4, "0")}`,
      { review: key, from, to, actor, at: iso(this.c.now()) },
    );
  }

  private async move(
    tenantId: string,
    doc: Doc<ReviewRecord>,
    to: ReviewRecord["state"],
    actor: string,
    patch: Partial<ReviewRecord> = {},
  ): Promise<Doc<ReviewRecord>> {
    assertReview(doc.data.state, to);
    const next = await guarded(
      () =>
        this.c.docs.update(PLATFORM, tenantId, "reviews", doc.key, doc.rev, {
          ...doc.data,
          ...patch,
          state: to,
        }),
      "review",
    );
    await this.event(tenantId, doc.key, doc.data.state, to, actor);
    return next;
  }

  /** Publisher submits one registry version for review. Verified publishers only; the version must verify in the registry first. */
  async submit(
    p: TenantPrincipal,
    input: { namespace: string; name: string; version: string },
  ): Promise<ReviewRecord> {
    try {
      requireRole(p, "publish");
    } catch (e) {
      return denyAudit(this.c, p.tenantId, p.subject, "marketplace.review.submit", e);
    }
    const pub = await this.c.docs.get<PublisherRecord>(
      tenantScope(p.tenantId),
      p.tenantId,
      "publishers",
      "self",
    );
    if (pub?.data.state !== "verified")
      throw forbidden("only verified publishers can submit blueprints for review");
    const viewer = { tenantId: p.tenantId };
    const bp = await this.registry().getVersion(viewer, input.namespace, input.name, input.version);
    if (bp.record.tenantId !== p.tenantId) throw forbidden("not your namespace");
    const key = reviewKey(bp.namespace, bp.name, bp.version);
    const base: ReviewRecord = {
      namespace: bp.namespace,
      name: bp.name,
      version: bp.version,
      contentHash: bp.contentHash,
      riskLevel: bp.riskLevel,
      state: "submitted",
      publisherTenantId: p.tenantId,
      submittedBy: p.subject,
      submittedAt: iso(this.c.now()),
      findings: [],
      maxSeverity: "info",
      capabilities: [],
      decidedBy: null,
      decidedAt: null,
      note: null,
      acknowledged: [],
      approvedHash: null,
    };
    return mutate(
      this.c,
      p.tenantId,
      { type: "human", id: p.subject },
      "marketplace.review.submit",
      { key, contentHash: bp.contentHash },
      async () => {
        let doc = await guarded(
          () =>
            this.c.docs.insert<ReviewRecord>(
              tenantScope(p.tenantId),
              p.tenantId,
              "reviews",
              key,
              base,
            ),
          "review",
        );
        await this.event(p.tenantId, key, null, "submitted", p.subject);
        doc = await this.move(p.tenantId, doc, "automated_scan", "system:scan");
        const scan = scanBlueprint(bp.abl as AblDocument, DEFAULT_BASELINE);
        const scanned = {
          findings: scan.findings,
          maxSeverity: scan.maxSeverity,
          capabilities: scan.capabilities,
        };
        if (scan.maxSeverity === "critical") {
          doc = await this.move(p.tenantId, doc, "rejected", "system:scan", {
            ...scanned,
            note: "rejected by the automated scan: critical finding",
            decidedBy: "system:scan",
            decidedAt: iso(this.c.now()),
          });
        } else if (
          this.o.autoApproveAtOrBelow !== undefined &&
          sevRank(scan.maxSeverity) <= sevRank(this.o.autoApproveAtOrBelow)
        ) {
          doc = await this.move(p.tenantId, doc, "approved", "system:scan", {
            ...scanned,
            note: "approved by the automated scan (policy)",
            decidedBy: "system:scan",
            decidedAt: iso(this.c.now()),
            approvedHash: bp.contentHash,
          });
          await this.afterApproval(doc.data);
        } else {
          doc = await this.move(p.tenantId, doc, "in_review", "system:scan", scanned);
        }
        return doc.data;
      },
    );
  }

  async mine(p: TenantPrincipal): Promise<ReviewRecord[]> {
    requireRole(p, "read");
    return (await this.c.docs.find<ReviewRecord>(tenantScope(p.tenantId), "reviews")).map(
      (d) => d.data,
    );
  }

  async queue(
    r: StaffPrincipal,
    state: ReviewRecord["state"] = "in_review",
  ): Promise<{ id: string; review: ReviewRecord }[]> {
    requireStaff(r, "reviewer");
    return (await this.c.docs.find<ReviewRecord>(PLATFORM, "reviews", { state })).map((d) => ({
      id: reviewId(d.tenantId, d.key),
      review: d.data,
    }));
  }

  async get(r: StaffPrincipal, id: string): Promise<ReviewRecord> {
    requireStaff(r, "reviewer");
    const { tenantId, key } = parseReviewId(id);
    const d = await this.c.docs.get<ReviewRecord>(PLATFORM, tenantId, "reviews", key);
    if (!d) throw notFound("review not found");
    return d.data;
  }

  /**
   * The human decision. Rules (each is a tested safety property):
   *  - the reviewer is staff and NEVER the submitter, a member of the publisher's tenant, or anyone who acted for the publisher;
   *  - critical findings can never be approved; high findings need every one of them acknowledged by id;
   *  - the blueprint is re-verified NOW and its content hash must equal the hash the review is about (approval is pinned to it);
   *  - the publisher must still be verified.
   */
  async decide(
    r: StaffPrincipal,
    id: string,
    input: {
      decision: "approve" | "reject" | "request_changes";
      note: string;
      acknowledged?: string[];
    },
  ): Promise<ReviewRecord> {
    requireStaff(r, "reviewer");
    const { tenantId, key } = parseReviewId(id);
    const cur = await this.c.docs.get<ReviewRecord>(PLATFORM, tenantId, "reviews", key);
    if (!cur) throw notFound("review not found");
    if (!["approve", "reject", "request_changes"].includes(input.decision))
      throw invalid("unknown decision");
    if (typeof input.note !== "string" || input.note.trim().length < 10 || input.note.length > 2000)
      throw invalid("a note of 10-2000 characters is required");
    const pub = await this.c.docs.get<PublisherRecord>(PLATFORM, tenantId, "publishers", "self");
    const actor = { type: "human" as const, id: r.subject };
    if (
      r.subject === cur.data.submittedBy ||
      r.tenantId === tenantId ||
      pub?.data.subjects.includes(r.subject)
    )
      return denyAudit(
        this.c,
        tenantId,
        r.subject,
        "marketplace.review.decide",
        forbidden("a reviewer cannot review their own organisation's submission"),
      );
    const to =
      input.decision === "approve"
        ? "approved"
        : input.decision === "reject"
          ? "rejected"
          : "changes_requested";
    assertReview(cur.data.state, to);
    const ack = [...new Set(input.acknowledged ?? [])];
    return mutate(
      this.c,
      tenantId,
      actor,
      "marketplace.review.decide",
      { key, decision: input.decision },
      async () => {
        let patch: Partial<ReviewRecord> = {
          note: input.note,
          decidedBy: r.subject,
          decidedAt: iso(this.c.now()),
          acknowledged: ack,
        };
        if (to === "approved") {
          if (cur.data.maxSeverity === "critical")
            throw new RegistryError(
              "conflict",
              "a blueprint with critical findings cannot be approved",
              ["critical_findings"],
            );
          const high = cur.data.findings
            .filter((f) => sevRank(f.severity as Severity) >= sevRank("high"))
            .map((f) => f.id);
          const missing = [...new Set(high)].filter((h) => !ack.includes(h));
          if (missing.length)
            throw new RegistryError(
              "conflict",
              `every high-severity finding must be acknowledged: ${missing.join(", ")}`,
              ["unacknowledged_findings"],
            );
          if (pub?.data.state !== "verified")
            throw new RegistryError("conflict", "publisher is not verified", [
              "publisher_not_verified",
            ]);
          // TOCTOU: re-verify NOW and pin to the reviewed hash.
          const bp = await this.registry().getVersion(
            { tenantId },
            cur.data.namespace,
            cur.data.name,
            cur.data.version,
          );
          if (bp.contentHash !== cur.data.contentHash)
            throw new RegistryError("conflict", "blueprint changed since it was scanned", [
              "content_hash_changed",
            ]);
          patch = { ...patch, approvedHash: bp.contentHash };
        }
        const next = await this.move(tenantId, cur, to, r.subject, patch);
        if (to === "approved") await this.afterApproval(next.data);
        return next.data;
      },
    );
  }

  /** Mirrors the approval into the listing (pinned by hash) and makes the namespace publicly readable. Idempotent. */
  private async afterApproval(rv: ReviewRecord): Promise<void> {
    const hash = rv.approvedHash as string;
    // Only the reviewed version is released; the namespace's other blueprints and versions stay private (ADR 0055).
    await this.registry().setVersionPublic(MARKETPLACE_SERVICE, rv.namespace, rv.name, rv.version);
    const lk = `${rv.namespace}/${rv.name}`;
    const l = await this.c.docs.get<ListingRecord>(PLATFORM, rv.publisherTenantId, "listings", lk);
    if (!l) return; // the publisher has not created a listing yet; createListing() lists approved versions then
    if (l.data.approved.some((a) => a.version === rv.version)) return;
    const approved = [
      ...l.data.approved,
      {
        version: rv.version,
        contentHash: hash,
        riskLevel: rv.riskLevel,
        maxSeverity: rv.maxSeverity,
        approvedAt: iso(this.c.now()),
      },
    ];
    await guarded(
      () =>
        this.c.docs.update(PLATFORM, rv.publisherTenantId, "listings", lk, l.rev, {
          ...l.data,
          approved,
          status: l.data.status === "draft" ? "listed" : l.data.status,
        }),
      "listing",
    );
  }
}
