import { RegistryError, conflict, forbidden, invalid, notFound } from "@axis/registry";
import { randomBytes } from "node:crypto";
import { denyAudit, guarded, iso, mutate, requireRole, requireStaff, type Ctx } from "./ctx.js";
import { PLATFORM, tenantScope } from "./docstore.js";
import { assertVerify } from "./states.js";
import type { EvidenceRecord, PublisherRecord, StaffPrincipal, TenantPrincipal } from "./types.js";

/** Domain control proof (DNS TXT). The real resolver is NEEDS; tests and dev use FakeDomainProver. */
export interface DomainProver {
  check(domain: string, challenge: string): Promise<{ ok: boolean; detail: string }>;
}
/** Legal-identity proof (business registry / IDV vendor). Real vendor is NEEDS. */
export interface IdentityProver {
  verify(i: {
    legalName: string;
    contactEmail: string;
    domain: string;
  }): Promise<{ ok: boolean; detail: string }>;
}

export class FakeDomainProver implements DomainProver {
  /** domain -> TXT records currently "published". */
  records = new Map<string, string[]>();
  async check(domain: string, challenge: string): Promise<{ ok: boolean; detail: string }> {
    await Promise.resolve();
    const ok = (this.records.get(domain) ?? []).includes(`axis-verify=${challenge}`);
    return { ok, detail: ok ? "TXT record matches" : "TXT record not found" };
  }
}
export class FakeIdentityProver implements IdentityProver {
  reject = new Set<string>();
  async verify(i: {
    legalName: string;
    contactEmail: string;
    domain: string;
  }): Promise<{ ok: boolean; detail: string }> {
    await Promise.resolve();
    const ok = !this.reject.has(i.legalName) && i.contactEmail.endsWith(`@${i.domain}`);
    return {
      ok,
      detail: ok ? "identity matches registry (fake)" : "identity could not be confirmed (fake)",
    };
  }
}

const DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,253}$/;

export interface PublisherDeps {
  domain: DomainProver;
  identity: IdentityProver;
}

export class PublisherService {
  constructor(
    private readonly c: Ctx,
    private readonly d: PublisherDeps,
  ) {}

  async get(p: TenantPrincipal): Promise<PublisherRecord | undefined> {
    requireRole(p, "read");
    return (
      await this.c.docs.get<PublisherRecord>(
        tenantScope(p.tenantId),
        p.tenantId,
        "publishers",
        "self",
      )
    )?.data;
  }

  async isVerified(tenantId: string): Promise<boolean> {
    return (
      (await this.c.docs.get<PublisherRecord>(PLATFORM, tenantId, "publishers", "self"))?.data
        .state === "verified"
    );
  }

  /** unverified|rejected -> pending. Issues the DNS challenge. */
  async start(
    p: TenantPrincipal,
    input: { legalName: string; domain: string; contactEmail: string },
  ): Promise<PublisherRecord> {
    try {
      requireRole(p, "admin");
    } catch (e) {
      return denyAudit(this.c, p.tenantId, p.subject, "marketplace.publisher.start", e);
    }
    const legalName = input.legalName?.trim();
    if (typeof legalName !== "string" || legalName.length < 2 || legalName.length > 200)
      throw invalid("legalName must be 2-200 characters");
    const domain = typeof input.domain === "string" ? input.domain.toLowerCase() : "";
    if (!DOMAIN_RE.test(domain)) throw invalid("domain is not a valid DNS name");
    if (typeof input.contactEmail !== "string" || !EMAIL_RE.test(input.contactEmail))
      throw invalid("contactEmail is not valid");
    const scope = tenantScope(p.tenantId);
    const cur = await this.c.docs.get<PublisherRecord>(scope, p.tenantId, "publishers", "self");
    const from = cur?.data.state ?? "unverified";
    assertVerify(from, "pending");
    const rec: PublisherRecord = {
      state: "pending",
      legalName,
      domain,
      contactEmail: input.contactEmail,
      challenge: randomBytes(16).toString("hex"),
      subjects: [...new Set([...(cur?.data.subjects ?? []), p.subject])],
      submittedBy: p.subject,
      submittedAt: iso(this.c.now()),
      decidedBy: null,
      decidedAt: null,
      reason: null,
      evidenceCount: cur?.data.evidenceCount ?? 0,
    };
    return mutate(
      this.c,
      p.tenantId,
      { type: "human", id: p.subject },
      "marketplace.publisher.start",
      { domain },
      async () => {
        await guarded(
          () =>
            cur
              ? this.c.docs.update(scope, p.tenantId, "publishers", "self", cur.rev, rec)
              : this.c.docs.insert(scope, p.tenantId, "publishers", "self", rec),
          "publisher",
        );
        return rec;
      },
    );
  }

  /** Runs the domain and identity proofs (fakes in dev) and records each result as append-only evidence. */
  async submitEvidence(p: TenantPrincipal): Promise<EvidenceRecord[]> {
    requireRole(p, "admin");
    const scope = tenantScope(p.tenantId);
    const cur = await this.c.docs.get<PublisherRecord>(scope, p.tenantId, "publishers", "self");
    if (!cur || cur.data.state !== "pending") throw conflict("verification is not pending");
    const now = iso(this.c.now());
    const [dom, idn] = await Promise.all([
      this.d.domain.check(cur.data.domain, cur.data.challenge),
      this.d.identity.verify({
        legalName: cur.data.legalName,
        contactEmail: cur.data.contactEmail,
        domain: cur.data.domain,
      }),
    ]);
    const evidence: EvidenceRecord[] = [
      {
        kind: "domain_dns_txt",
        subject: cur.data.domain,
        result: dom.ok ? "passed" : "failed",
        detail: dom.detail,
        at: now,
        by: p.subject,
      },
      {
        kind: "identity",
        subject: cur.data.legalName,
        result: idn.ok ? "passed" : "failed",
        detail: idn.detail,
        at: now,
        by: p.subject,
      },
    ];
    return mutate(
      this.c,
      p.tenantId,
      { type: "human", id: p.subject },
      "marketplace.publisher.evidence",
      { results: evidence.map((e) => `${e.kind}=${e.result}`) },
      async () => {
        let n = cur.data.evidenceCount;
        for (const e of evidence)
          await guarded(
            () =>
              this.c.docs.insert(
                scope,
                p.tenantId,
                "evidence",
                `ev-${String(++n).padStart(6, "0")}`,
                e,
              ),
            "evidence",
          );
        await guarded(
          () =>
            this.c.docs.update(scope, p.tenantId, "publishers", "self", cur.rev, {
              ...cur.data,
              evidenceCount: n,
              subjects: [...new Set([...cur.data.subjects, p.subject])],
            }),
          "publisher",
        );
        return evidence;
      },
    );
  }

  async evidence(p: TenantPrincipal): Promise<EvidenceRecord[]> {
    requireRole(p, "read");
    return (await this.c.docs.find<EvidenceRecord>(tenantScope(p.tenantId), "evidence")).map(
      (d) => d.data,
    );
  }

  // ------------------------------------------------------------------ reviewer side
  async queue(r: StaffPrincipal): Promise<{ tenantId: string; record: PublisherRecord }[]> {
    requireStaff(r, "reviewer");
    return (
      await this.c.docs.find<PublisherRecord>(PLATFORM, "publishers", { state: "pending" })
    ).map((d) => ({ tenantId: d.tenantId, record: d.data }));
  }

  async evidenceFor(r: StaffPrincipal, publisherTenantId: string): Promise<EvidenceRecord[]> {
    requireStaff(r, "reviewer");
    return (
      await this.c.docs.find<EvidenceRecord>(PLATFORM, "evidence", {}, publisherTenantId)
    ).map((d) => d.data);
  }

  /** approve: needs a pending request with PASSED domain + identity evidence. The reviewer must not be anyone who acted for the publisher. */
  async decide(
    r: StaffPrincipal,
    publisherTenantId: string,
    input: { decision: "approve" | "reject"; reason: string },
  ): Promise<PublisherRecord> {
    requireStaff(r, "reviewer");
    if (input.decision !== "approve" && input.decision !== "reject")
      throw invalid("decision must be approve or reject");
    if (
      typeof input.reason !== "string" ||
      input.reason.trim().length < 5 ||
      input.reason.length > 500
    )
      throw invalid("a reason of 5-500 characters is required");
    const cur = await this.c.docs.get<PublisherRecord>(
      PLATFORM,
      publisherTenantId,
      "publishers",
      "self",
    );
    if (!cur) throw notFound("publisher not found");
    const actor = { type: "human" as const, id: r.subject };
    if (r.tenantId === publisherTenantId || cur.data.subjects.includes(r.subject))
      return denyAudit(
        this.c,
        publisherTenantId,
        r.subject,
        "marketplace.publisher.decide",
        forbidden("a reviewer cannot review their own organisation"),
      );
    const to = input.decision === "approve" ? "verified" : "rejected";
    assertVerify(cur.data.state, to);
    return mutate(
      this.c,
      publisherTenantId,
      actor,
      "marketplace.publisher.decide",
      { decision: input.decision },
      async () => {
        if (to === "verified") {
          const ev = await this.c.docs.find<EvidenceRecord>(
            PLATFORM,
            "evidence",
            {},
            publisherTenantId,
          );
          const latest = (kind: EvidenceRecord["kind"]): EvidenceRecord | undefined =>
            ev
              .map((e) => e.data)
              .filter((e) => e.kind === kind && e.at >= cur.data.submittedAt)
              .at(-1);
          if (
            latest("domain_dns_txt")?.result !== "passed" ||
            latest("identity")?.result !== "passed"
          )
            throw new RegistryError(
              "conflict",
              "cannot verify without passed domain and identity evidence",
              ["evidence_missing"],
            );
        }
        const next: PublisherRecord = {
          ...cur.data,
          state: to,
          decidedBy: r.subject,
          decidedAt: iso(this.c.now()),
          reason: input.reason,
        };
        await guarded(
          () =>
            this.c.docs.update(PLATFORM, publisherTenantId, "publishers", "self", cur.rev, next),
          "publisher",
        );
        return next;
      },
    );
  }

  /** Moderation: a verified publisher is suspended (verified -> rejected). Their listings are the moderator's separate decision. */
  async suspend(m: StaffPrincipal, publisherTenantId: string, reason: string): Promise<void> {
    requireStaff(m, "moderator");
    if (typeof reason !== "string" || reason.trim().length < 5)
      throw invalid("a reason is required");
    const cur = await this.c.docs.get<PublisherRecord>(
      PLATFORM,
      publisherTenantId,
      "publishers",
      "self",
    );
    if (!cur) throw notFound("publisher not found");
    assertVerify(cur.data.state, "rejected");
    await mutate(
      this.c,
      publisherTenantId,
      { type: "human", id: m.subject },
      "marketplace.publisher.suspend",
      { reason },
      () =>
        guarded(
          () =>
            this.c.docs.update(PLATFORM, publisherTenantId, "publishers", "self", cur.rev, {
              ...cur.data,
              state: "rejected",
              decidedBy: m.subject,
              decidedAt: iso(this.c.now()),
              reason,
            }),
          "publisher",
        ),
    );
  }
}
